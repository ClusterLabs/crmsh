import subprocess
import typing

import crmsh.pyshim
import crmsh.sh
import crmsh.userdir

import os


class Shell:
    @classmethod
    def local_shell(cls):
        if 'SSH_AUTH_SOCK' in os.environ:
            return crmsh.sh.LocalShell(additional_environ={'SSH_AUTH_SOCK': os.environ.get('SSH_AUTH_SOCK')})
        else:
            return crmsh.sh.LocalShell()

    @classmethod
    def find_shell(cls, cluster_shell: crmsh.sh.ClusterShell, host: str, user: typing.Optional[str]):
        if cluster_shell.can_run_as(host, 'root'):
            return ClusterShellAdaptor(cluster_shell, host)
        local_shell = cls.local_shell()
        if user:
            ret = cls._try_create_report_shell(local_shell, host, user)
            if ret:
                return ret
        sudoer = crmsh.userdir.get_sudoer()
        if sudoer and sudoer != user:
            ret = cls._try_create_report_shell(local_shell, host, sudoer)
            if ret:
                return ret
        current_user = crmsh.userdir.getuser()
        if current_user != sudoer and current_user != user:
            ret = cls._try_create_report_shell(local_shell, host, current_user)
            if ret:
                return ret
        return None

    @staticmethod
    def _try_create_report_shell(local_shell: crmsh.sh.LocalShell, host: str, user: str):
        ssh_shell = crmsh.sh.SSHShell(local_shell, user)
        # call can_run_as here to populate know_hosts
        if not ssh_shell.can_run_as(host, user):
            return None
        if user == 'root' or user == 'hacluster':
            return SSHShell(ssh_shell, host, user)
        else:
            # check for root/hacluster privilege
            ret = ssh_shell.subprocess_run_without_input(
                    host, user,
                    'sudo true',
                    start_new_session=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
            )
            if ret.returncode == 0:
                return SSHSudoShell(ssh_shell, host, user)
            else:
                return None

    def subprocess_run_without_input(self, cmd: str, **kwargs):
        raise NotImplementedError


class ClusterShellAdaptor(Shell):
    def __init__(self, cluster_shell: crmsh.sh.ClusterShell, host):
        self.cluster_shell = cluster_shell
        self._host = host

    def subprocess_run_without_input(self, cmd: str, **kwargs):
        return self.cluster_shell.subprocess_run_without_input(self._host, None, cmd, **kwargs)


class SSHShell(Shell):
    def __init__(self, ssh_shell: crmsh.sh.SSHShell, host, user):
        self.ssh_shell = ssh_shell
        self._host = host
        self._user = user

    def subprocess_run_without_input(self, cmd: str, **kwargs):
        return self.ssh_shell.subprocess_run_without_input(
            self._host, self._user,
            cmd,
            **kwargs,
        )


class SSHSudoShell(Shell):
    def __init__(self, ssh_shell: crmsh.sh.SSHShell, host, user):
        self.ssh_shell = ssh_shell
        self._host = host
        self._user = user

    def subprocess_run_without_input(self, cmd: str, **kwargs):
        return self.ssh_shell.subprocess_run_without_input(
            self._host, self._user,
            f'sudo {cmd}',
            **kwargs,
        )
