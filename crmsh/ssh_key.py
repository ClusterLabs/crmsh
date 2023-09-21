import logging
import os
import pwd
import tempfile
import typing

from crmsh import utils
from crmsh import sh


logger = logging.getLogger(__name__)


class Error(ValueError):
    def __init__(self, msg: str):
        super().__init__(msg)


class Key:
    def public_key(self) -> str:
        raise NotImplementedError


class KeyFile(Key):
    def __init__(self, path: str):
        self._path = os.path.realpath(path)
        self._public_key = None

    def public_key_file(self) -> typing.Optional[str]:
        return self._path

    def public_key(self) -> str:
        if self._public_key:
            return self._public_key
        else:
            with open(self._path, 'r', encoding='utf-8') as f:
                self._public_key = f.read().strip()
            return self._public_key


class AuthorizedKeyManager:
    def __init__(self, shell: sh.SSHShell):
        self._shell = shell

    def add(self, host: typing.Optional[str], user: str, key: Key):
        if host is None:
            self._add_local(user, key)
        else:
            self._add_remote(host, user, key)

    def _add_local(self, user: str, key: Key):
        public_key = key.public_key()
        file = f'~{user}/.ssh/authorized_keys'
        cmd = f'''grep "{public_key}" {file} > /dev/null || sed -i '$a {public_key}' {file}'''
        rc, output = self._shell.local_shell.get_rc_and_error(user, cmd)
        if rc != 0:
            # unlikely
            raise Error(output)

    def _add_remote(self, host: str, user: str, key: Key):
        if self._shell.can_run_as(host, user):
            rc, _ = self._shell.get_rc_and_error(
                host, user,
                f"grep '{key.public_key()}' ~{user}/.ssh/authorized_key > /dev/null",
            )
            if rc == 0:
                return
        if isinstance(key, KeyFile) and key.public_key_file() is not None:
            user_info = pwd.getpwnam(user)
            if os.stat(key.public_key_file()).st_uid == user_info.pw_uid:
                cmd = "ssh-copy-id -f -i '{}' '{}@{}' &> /dev/null".format(key.public_key_file(), user, host)
                logger.info("Configuring SSH passwordless with %s@%s", user, host)
                result = self._shell.local_shell.su_subprocess_run(self._shell.local_user, cmd, tty=True, preserve_env=['SSH_AUTH_SOCK'])
            else:
                with tempfile.NamedTemporaryFile('w', encoding='utf-8') as tmp:
                    os.chown(tmp.fileno(), user_info.pw_uid, user_info.pw_gid)
                    print(key.public_key(), file=tmp)
                    cmd = "ssh-copy-id -f -i '{}' '{}@{}' &> /dev/null".format(tmp.name, user, host)
                    logger.info("Configuring SSH passwordless with %s@%s", user, host)
                    result = self._shell.local_shell.su_subprocess_run(self._shell.local_user, cmd, tty=True)
            if result.returncode != 0:
                raise Error(f'Failed configuring SSH passwordless with {user}@{host}.')
            # TODO: error handling
