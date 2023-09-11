"""Run shell commands.

This module provides various methods to run shell commands, on both local and remote hosts, as current or another user.
There many variant of the methods to allow fine-gain control of parameter passing and error handling.

3 different implementations are provided:

1. LocalShell allows to run command on local host as various users. It is the most feature-rich one, allowing
   interactive I/O from/to the terminal.
2. SshShell allows to run command on both local and remote hosts. When running on a remote host, it creates a direct
   connection from a specified local_user to the destination host and user. User input from terminal is not allowed, as
   the command is passed through the stdin.
3. AutoShell runs command on cluster nodes. It leverages su, sudo and ssh to obtain a appreciated session on a
   destination node. It is only available after ssh bootstrap as it depends on the knowledge about cluster node and user
   configurations.

The LocalShell and SshShell is expected to be used in ssh bootstrap. Once the ssh bootstrap finishes, AuthShell should
be used.
"""
import logging
import os
import pwd
import socket
import subprocess
import typing

from . import constants
from .pyshim import cache
from . import user_of_host
from .user_of_host import UserOfHost

logger = logging.getLogger(__name__)


class Error(ValueError):
    def __init__(self, msg, cmd):
        super().__init__(msg)
        self.cmd = cmd


class AuthorizationError(Error):
    def __init__(self, cmd: str, host: typing.Optional[str], user: str, msg: str):
        super().__init__(
            'Failed to run command on {optional_user}{host}: {msg}: {cmd}'.format(
                optional_user=f'{user}@' if user is not None else '',
                host=host, msg=msg, cmd=cmd
            ),
            cmd
        )
        self.host = host
        self.user = user


class CommandFailure(Error):
    def __init__(self, cmd: str, host: typing.Optional[str], user: typing.Optional[str], msg: str):
        if host is None and user is None:
            super().__init__("Failed to run '{}': {}".format(cmd, msg), cmd)
        elif user is None:
            super().__init__("Failed to run command on {}: '{}': {}".format(host, cmd, msg), cmd)
        elif host is None:
            super().__init__("Failed to run command as {}: '{}': {}".format(user, cmd, msg), cmd)
        else:
            super().__init__("Failed to run command as {}@{}: '{}': {}".format(user, host, cmd, msg), cmd)
        self.host = host
        self.user = user


class Utils:
    @staticmethod
    def decode_str(x: bytes):
        try:
            return x.decode('utf-8')
        except UnicodeDecodeError as e:
            logger.debug('UTF-8 decode failure', exc_info=e)
            return x.decode('utf-8', errors='backslashreplace')


class LocalShell:
    """Provides methods to run commands on localhost, both as current user and switching to another user"""
    @staticmethod
    @cache
    def hostname():
        return socket.gethostname()

    @staticmethod
    @cache
    def geteuid() -> int:
        return os.geteuid()

    @staticmethod
    @cache
    def get_effective_user_name() -> str:
        return pwd.getpwuid(LocalShell.geteuid()).pw_name

    def can_run_as(self, user: str):
        return self.geteuid() == 0 or self.get_effective_user_name() == user

    def su_subprocess_run(
            self,
            user: str,
            cmd: str,
            tty=False,
            preserve_env: typing.Optional[typing.List[str]] = None,
            **kwargs
    ):
        if self.get_effective_user_name() == user:
            args = ['/bin/sh', '-c', cmd]
        elif 0 == self.geteuid():
            args = ['su', user, '--login', '-c', cmd]
            if tty:
                args.append('--pty')
            if preserve_env:
                args.append('-w')
                args.append(','.join(preserve_env))
        else:
            raise AuthorizationError(
                cmd, None, user,
                f"non-root user '{self.get_effective_user_name()}' cannot switch to another user"
            )
        logger.debug('su_subprocess_run: %s, %s', args, kwargs)
        return subprocess.run(args, **kwargs)

    def get_stdout_stderr_raw(self, user: str, cmd: str, input: typing.Optional[bytes] = None):
        result = self.su_subprocess_run(
            user, cmd,
            input=input,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return result.returncode, result.stdout, result.stderr

    def get_stdout_stderr(self, user: str, cmd: str, input: typing.Optional[str] = None):
        rc, stdout, stderr = self.get_stdout_stderr_raw(user, cmd, input.encode('utf-8') if input is not None else None)
        return rc, Utils.decode_str(stdout).strip(), Utils.decode_str(stderr).strip()

    def get_rc_and_error(
            self,
            user: str,
            cmd: str,
    ) -> typing.Tuple[int, typing.Optional[str]]:
        """Run a command for its side effects. Returns (rc, error_message)

        If the return code is 0, outputs from the command will be ignored and (0, None) is returned.
        If the return code is not 0, outputs from the stdout and stderr is combined as a single message.
        """
        if self.get_effective_user_name() == user:
            args = ['/bin/sh', '-c', cmd]
        elif self.geteuid() == 0:
            args = ['su', user, '--login', '-c', cmd]
        else:
            raise AuthorizationError(
                cmd, None, user,
                f"non-root user '{self.get_effective_user_name()}' cannot switch to another user"
            )
        result = subprocess.run(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        if result.returncode == 0:
            return 0, None
        else:
            return result.returncode, Utils.decode_str(result.stdout).strip()

    def get_stdout_or_raise_error(
            self,
            user: str,
            cmd: str,
            success_exit_status: typing.Optional[typing.Set[int]] = None,
    ):
        result = self.su_subprocess_run(
            user, cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        to_raise = False
        if success_exit_status is None:
            if result.returncode != 0:
                to_raise = True
        else:
            if result.returncode not in success_exit_status:
                to_raise = True
        if not to_raise:
            return Utils.decode_str(result.stdout).strip()
        else:
            raise CommandFailure(cmd, None, user, Utils.decode_str(result.stderr).strip())


class SshShell:
    """Provides methods to run commands on both local and remote hosts as various users.

    For remote commands, SSH sessions are created to the destination host and user from a specified local_user.
    """
    def __init__(self, local_shell: LocalShell, local_user):
        self.local_shell = local_shell
        self.local_user = local_user

    def can_run_as(self, host: typing.Optional[str], user: str) -> bool:
        if host is None or host == self.local_shell.hostname():
            return self.local_shell.can_run_as(user)
        else:
            ssh_options = "-o StrictHostKeyChecking=no -o EscapeChar=none -o ConnectTimeout=15"
            ssh_cmd = "ssh {} -T -o Batchmode=yes {}@{} true".format(ssh_options, user, host)
            rc, output = self.local_shell.get_rc_and_error(self.local_user, ssh_cmd)
            return rc == 0

    def get_rc_and_error(
            self,
            host: typing.Optional[str],
            user: str,
            cmd: str,
    ) -> typing.Tuple[int, typing.Optional[str]]:
        """Run a command for its side effects. Returns (rc, error_message)

        If the return code is 0, outputs from the command will be ignored and (0, None) is returned.
        If the return code is not 0, outputs from the stdout and stderr is combined as a single message.
        """
        result = self.subprocess_run_no_input(
            host, user, cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        if result.returncode == 0:
            return 0, None
        else:
            return result.returncode, Utils.decode_str(result.stdout).strip()

    def subprocess_run_no_input(self, host: typing.Optional[str], user: str, cmd: str, **kwargs):
        assert 'input' not in kwargs and 'stdin' not in kwargs
        if host is None or host == self.local_shell.hostname():
            if user == self.local_shell.get_effective_user_name():
                args = ['/bin/sh']
            else:
                args = ['sudo', '-H', '-u', user, '/bin/sh']
            return subprocess.run(
                args,
                input=cmd.encode('utf-8'),
                **kwargs,
            )
        else:
            return self.local_shell.su_subprocess_run(
                self.local_user,
                'ssh {} {}@{} /bin/sh'.format(constants.SSH_OPTION, user, host),
                input=cmd.encode('utf-8'),
                **kwargs,
            )


class AutoShell:
    def __init__(self, local_shell: LocalShell, user_of_host: UserOfHost):
        self.local_shell = local_shell
        self.user_of_host = user_of_host

    def subprocess_run_no_input(self, host: typing.Optional[str], user: typing.Optional[str], cmd: str, **kwargs):
        assert 'input' not in kwargs and 'stdin' not in kwargs
        if host is None or host == self.local_shell.hostname():
            return subprocess.run(
                ['/bin/sh'],
                input=cmd.encode('utf-8'),
                **kwargs,
            )
        else:
            if user is None:
                user = 'root'
            local_user, remote_user = self.user_of_host.user_pair_for_ssh(host)
            return self.local_shell.su_subprocess_run(
                local_user,
                'ssh {} {}@{} sudo -H -u {} /bin/sh'.format(constants.SSH_OPTION, remote_user, host, user),
                input=cmd.encode('utf-8'),
                **kwargs,
            )

    def get_raw_stdout_stderr_no_input(self, host, cmd) -> typing.Tuple[int, bytes, bytes]:
        result = self.subprocess_run_no_input(
            host, None, cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return result.returncode, result.stdout, result.stderr

    def get_stdout_stderr_no_input(self, host, cmd) -> typing.Tuple[int, str, str]:
        rc, stdout, stderr = self.get_raw_stdout_stderr_no_input(host, cmd)
        return rc, Utils.decode_str(stdout).strip(), Utils.decode_str(stderr).strip()

    def get_stdout_or_raise_error(
            self,
            cmd: str,
            host: typing.Optional[str] = None,
            success_exit_status: typing.Optional[typing.Set[int]] = None,
    ):
        rc, stdout, stderr = self.get_raw_stdout_stderr_no_input(host, cmd)
        to_raise = False
        if success_exit_status is None:
            if rc != 0:
                to_raise = True
        else:
            if rc not in success_exit_status:
                to_raise = True
        if not to_raise:
            return Utils.decode_str(stdout).strip()
        else:
            raise CommandFailure(cmd, host, None, Utils.decode_str(stderr).strip())


class LocalOnlyAutoShell(AutoShell):
    def __init__(self, local_shell: LocalShell):
        super().__init__(local_shell, None)

    def subprocess_run_no_input(self, host: str, user: typing.Optional[str], cmd: str, **kwargs):
        assert 'input' not in kwargs and 'stdin' not in kwargs
        assert host is None or host == self.local_shell.hostname()
        if user is None:
            user = 'root'
        return self.local_shell.su_subprocess_run(user, cmd, **kwargs)


def auto_shell():
    return AutoShell(LocalShell(), user_of_host.instance())
