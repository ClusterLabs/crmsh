import logging
import os
import pwd
import re
import subprocess
import tempfile
import typing
from io import StringIO

from crmsh import sh


logger = logging.getLogger(__name__)


class Error(ValueError):
    def __init__(self, msg: str):
        super().__init__(msg)


class AgentNotAvailableError(Error):
    def __init__(self, msg):
        super().__init__(f'{msg}{self.diagnose()}')

    @staticmethod
    def diagnose() -> str:
        with StringIO() as buf:
            if 'SSH_AUTH_SOCK' not in os.environ:
                buf.write(' Environment variable SSH_AUTH_SOCK does not exist.')
                if 'SUDO_USER' in os.environ:
                    buf.write(' Please check whether ssh-agent is available and consider using "sudo --preserve-env=SSH_AUTH_SOCK".')
            return buf.getvalue()


class NoKeysInAgentError(Error):
    def __init__(self, msg):
        super().__init__(f'{msg}{self.diagnose()}')

    @staticmethod
    def diagnose() -> str:
        ssh_auth_sock = os.environ["SSH_AUTH_SOCK"]
        st = os.stat(ssh_auth_sock)
        owner_name = pwd.getpwuid(st.st_uid).pw_name
        return f' crmsh is using an ssh-agent listening at {ssh_auth_sock}, owned by {owner_name}. Please add at least one key pair with `ssh-add`'


class Key:
    def public_key(self) -> str:
        raise NotImplementedError

    def fingerprint(self) -> str:
        raise NotImplementedError


class KeyFile(Key):
    def __init__(self, path: str):
        self._path = os.path.realpath(path)
        self._public_key = None
        self._fingerprint = None

    def public_key_file(self) -> typing.Optional[str]:
        return self._path

    def public_key(self) -> str:
        if self._public_key:
            return self._public_key
        else:
            with open(self._path, 'r', encoding='utf-8') as f:
                self._public_key = f.read().strip()
            return self._public_key

    def fingerprint(self) -> str:
        if self._fingerprint:
            return self._fingerprint
        else:
            result = subprocess.run(
                ['ssh-keygen', '-l', '-f', self.public_key_file()],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
            )
            if result.returncode == 0:
                self._fingerprint = result.stdout.decode('utf-8', 'backslashreplace').strip()
                return self._fingerprint
            else:
                raise ValueError(f'Failed to generate fingerprint: {result.returncode}.')

    def __eq__(self, other):
        return isinstance(other, KeyFile) and self._path == other._path and self.public_key() == other.public_key()

    def __repr__(self):
        return f'KeyFile(path={self._path}, key={self.public_key()})'


class InMemoryPublicKey(Key):
    def __init__(self, content: str):
        self.content = content.strip()
        self._fingerprint = None

    def public_key(self) -> str:
        return self.content

    def fingerprint(self) -> str:
        if self._fingerprint:
            return self._fingerprint
        else:
            child = subprocess.Popen(
                ['ssh-keygen', '-l', '-f', '/dev/stdin'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
            )
            stdout, _ = child.communicate(self.public_key().encode('utf-8'))
            if child.returncode == 0:
                self._fingerprint = stdout.decode('utf-8', 'backslashreplace').strip()
                return self._fingerprint
            else:
                raise ValueError(f'Failed to generate fingerprint: {child.returncode}.')

    def __eq__(self, other):
        return isinstance(other, InMemoryPublicKey) and self.content == other.content


class AuthorizedKeyManager:
    def __init__(self, shell: sh.SSHShell):
        self._shell = shell

    def add(self, host: typing.Optional[str], user: str, key: Key):
        if host is None:
            self._add_local(user, key)
        else:
            self._add_remote(host, user, key)

    def _add_local(self, user: str, key: Key):
        cmd = self._add_by_editing_file(user, key)
        rc, output = self._shell.local_shell.get_rc_and_error(user, cmd)
        if rc != 0:
            # unlikely
            raise Error(output)

    def _add_remote(self, host: str, user: str, key: Key):
        if self._shell.can_run_as(host, user):
            shell_user = user
        elif self._shell.can_run_as(host, 'root'):
            shell_user = 'root'
        else:
            shell_user = None
        if shell_user is not None:
            cmd = self._add_by_editing_file(user, key)
            rc, msg = self._shell.get_rc_and_error(host, shell_user, cmd)
            if rc != 0:
                raise Error(f'Failed configuring SSH passwordless with {user}@{host}: {msg}')
        else:
            user_info = pwd.getpwnam(user)
            if isinstance(key, KeyFile) and key.public_key_file() is not None:
                if os.stat(key.public_key_file()).st_uid == user_info.pw_uid:
                    self._add_by_ssh_copy_id(user, host, key.public_key_file())
                else:
                    with tempfile.NamedTemporaryFile('w', encoding='utf-8', suffix='.pub') as tmp:
                        os.chown(tmp.fileno(), user_info.pw_uid, user_info.pw_gid)
                        print(key.public_key(), file=tmp)
                        tmp.flush()
                        self._add_by_ssh_copy_id(user, host, tmp.name)
            else:
                with tempfile.NamedTemporaryFile('w', encoding='utf-8', suffix='.pub') as tmp:
                    os.chown(tmp.fileno(), user_info.pw_uid, user_info.pw_gid)
                    print(key.public_key(), file=tmp)
                    tmp.flush()
                    self._add_by_ssh_copy_id(user, host, tmp.name)

    @staticmethod
    def _add_by_editing_file(user: str, key: Key):
        public_key = key.public_key()
        dir = f'~{user}/.ssh'
        file = f'{dir}/authorized_keys'
        cmd = f'''if ! grep -F '{public_key}' {file} > /dev/null; then
    if [ -s {file} ]; then
        sed -i '$a {public_key}' {file}
    else
        mkdir -p {dir}
        chown {user}: {dir}
        chmod 0700 {dir}
        echo '{public_key}' > {file}
        chmod 0600 {file}
    fi
    chown {user}: {file}
fi'''
        return cmd

    def _add_by_ssh_copy_id(self, user, host, key_path):
        cmd = "ssh-copy-id -f -i '{}' '{}@{}' &> /dev/null".format(key_path, user, host)
        logger.info("Configuring SSH passwordless with %s@%s", user, host)
        result = self._shell.local_shell.su_subprocess_run(
            self._shell.local_user, cmd,
            tty=True,
        )
        if result.returncode != 0:
            raise Error(f'Failed configuring SSH passwordless with {user}@{host}.')


class AgentClient:
    def __init__(self, socket_path: typing.Optional[str] = None):
        if socket_path is None:
            if 'SSH_AUTH_SOCK' not in os.environ:
                raise AgentNotAvailableError("ssh-agent is not available.")
            self.socket_path = None
        else:
            self.socket_path = socket_path
        self.shell = sh.LocalShell(additional_environ={'SSH_AUTH_SOCK': self.socket_path} if self.socket_path else None)

    def list(self) -> typing.List[Key]:
        cmd = 'ssh-add -L'
        rc, stdout, stderr = self.shell.get_rc_stdout_stderr(None, cmd)
        if rc == 1:
            raise NoKeysInAgentError(stderr)
        elif rc == 2:
            raise AgentNotAvailableError(stderr)
        elif rc != 0:
            raise sh.CommandFailure(cmd, None, None, stderr)
        return [InMemoryPublicKey(line) for line in stdout.splitlines()]


class KeyFileManager:
    DEFAULT_KEY_TYPE = 'rsa'
    KNOWN_KEY_TYPES = ['rsa', 'ed25519', 'ecdsa']   # dsa is not listed here as it is not so secure
    KNOWN_PUBLIC_KEY_FILENAME_PATTERN = re.compile('/id_(?:{})\\.pub$'.format('|'.join(KNOWN_KEY_TYPES)))

    def __init__(self, shell: sh.ClusterShell):
        self.cluster_shell = sh.ClusterShell(shell.local_shell, shell.user_of_host, raise_ssh_error=True)

    def list_public_key_for_user(self, host: typing.Optional[str], user: str) -> typing.List[str]:
        result = self.cluster_shell.subprocess_run_without_input(
            host, user,
            'ls ~/.ssh/id_*.pub',
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode != 0:
            return list()
        return [
            filename
            for filename in sh.Utils.decode_str(result.stdout).splitlines()
            if self.KNOWN_PUBLIC_KEY_FILENAME_PATTERN.search(filename)
        ]

    def load_public_keys_for_user(self, host: typing.Optional[str], user: str) -> typing.List[InMemoryPublicKey]:
        filenames = self.list_public_key_for_user(host, user)
        if not filenames:
            return list()
        cmd = f'cat {",".join(filenames)}'
        result = self.cluster_shell.subprocess_run_without_input(
            host, user,
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode != 0:
            raise sh.CommandFailure(cmd, host, user, sh.Utils.decode_str(result.stderr).strip())
        return [InMemoryPublicKey(line) for line in sh.Utils.decode_str(result.stdout).splitlines()]

    def ensure_key_pair_exists_for_user(
            self,
            host: typing.Optional[str],
            user: str,
    ) -> typing.Tuple[bool, typing.List[InMemoryPublicKey]]:
        """Ensure at least one keypair exists for the specified user. If it does not exist, generate a new one.

        Return (is_generated, list_of_public_keys):

        * is_generated: whether a new keypair is generated
        * list_of_public_keys: all public keys of known types, including the newly generated one
        """
        script = '''set -e
if [ ! \\( {condition} \\) ]; then
    ssh-keygen -t {key_type} -f ~/.ssh/id_{key_type} -q -C "Cluster internal on $(hostname)" -N '' <> /dev/null
    echo 'GENERATED=1'
fi
for file in ~/.ssh/id_{{{pattern}}}; do
    if [ -f "$file" ]; then
        if ! [ -f "$file".pub ]; then
            ssh-keygen -y -f "$file" > "$file".pub
        fi
        cat "$file".pub
    fi
done
'''.format(
            condition=' -o '.join([f'-f ~/.ssh/id_{t}' for t in self.KNOWN_KEY_TYPES]),
            key_type=self.DEFAULT_KEY_TYPE,
            pattern=','.join(self.KNOWN_KEY_TYPES),
        )
        result = self.cluster_shell.subprocess_run_without_input(
            host, user,
            script,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode != 0:
            print(script)
            print(result.stdout)
            raise sh.CommandFailure(f'Script({script[:16]}...) failed. rc = {result.returncode}', host, user, sh.Utils.decode_str(result.stderr).strip())
        generated = False
        keys = list()
        for line in sh.Utils.decode_str(result.stdout).splitlines():
            if line == 'GENERATED=1':
                generated = True
            else:
                keys.append(InMemoryPublicKey(line))
        return generated, keys


def fetch_public_key_file_list(
        host: typing.Optional[str],
        user: str,
        generate_key_pair: bool = False
) -> typing.List[str]:
    """
    Fetch the public key file list for the specified user on the specified host.

    :param host: the host where the user is located. If None, the local host is assumed.
    :param user: the user name
    :param generate_key_pair: whether to generate a new key pair if no key pair is found,
     default is False

    :return: a list of public key file paths

    :raise Error: if no public key file is found for the user
    """
    key_file_manager = KeyFileManager(sh.cluster_shell())
    if generate_key_pair:
        key_file_manager.ensure_key_pair_exists_for_user(host, user)
    public_keys = key_file_manager.list_public_key_for_user(host, user)
    if not public_keys:
        host_str = f'@{host}' if host else ' locally'
        raise Error(f'No public key file found for {user}{host_str}')
    return public_keys


def fetch_public_key_content_list(
        host: typing.Optional[str],
        user: str,
        generate_key_pair: bool = False
) -> typing.List[str]:
    """
    Fetch the public key content list for the specified user on the specified host.

    :param host: the host where the user is located. If None, the local host is assumed.
    :param user: the user name
    :param generate_key_pair: whether to generate a new key pair if no key pair is found,
     default is False

    :return: a list of public key strings

    :raise Error: if no public key file is found for the user
    """
    key_file_manager = KeyFileManager(sh.cluster_shell())
    if generate_key_pair:
        key_file_manager.ensure_key_pair_exists_for_user(host, user)
    keys_in_memory = key_file_manager.load_public_keys_for_user(host, user)
    public_keys = [key.public_key() for key in keys_in_memory]
    if not public_keys:
        host_str = f'@{host}' if host else ' locally'
        raise Error(f'No public key file found for {user}{host_str}')
    return public_keys
