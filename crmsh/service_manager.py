import typing

import crmsh.parallax
import crmsh.sh


class ServiceManager(object):
    """
    Class to manage systemctl services
    """

    def __init__(self, shell: crmsh.sh.AutoShell = None):
        if shell is None:
            self._shell = crmsh.sh.auto_shell()
        else:
            self._shell = shell

    def service_is_available(self, name, remote_addr=None):
        """
        Check whether service is available
        """
        return 0 == self._run_on_single_host("systemctl list-unit-files '{}'".format(name), remote_addr)

    def service_is_enabled(self, name, remote_addr=None):
        """
        Check whether service is enabled
        """
        return 0 == self._run_on_single_host("systemctl is-enabled '{}'".format(name), remote_addr)

    def service_is_active(self, name, remote_addr=None):
        """
        Check whether service is active
        """
        return 0 == self._run_on_single_host("systemctl is-active '{}'".format(name), remote_addr)

    def start_service(self, name, enable=False, remote_addr=None, node_list=[]):
        """
        Start service
        Return success node list
        """
        if enable:
            cmd = "systemctl enable --now '{}'".format(name)
        else:
            cmd = "systemctl start '{}'".format(name)
        return self._call(remote_addr, node_list, cmd)

    def _call(self, remote_addr: str, node_list: typing.List[str], cmd: str) -> typing.List[str]:
        assert not (bool(remote_addr) and bool(node_list))
        if len(node_list) == 1:
            remote_addr = node_list[0]
            node_list = list()
        if node_list:
            results = ServiceManager._call_with_parallax(cmd, node_list)
            return [host for host, result in results.items() if isinstance(result, tuple) and result[0] == 0]
        else:
            rc = self._run_on_single_host(cmd, remote_addr)
            if rc == 0:
                return [remote_addr]
            else:
                return list()

    def _run_on_single_host(self, cmd, host):
        rc, _, _ = self._shell.get_stdout_stderr_no_input(host, cmd)
        if rc == 255:
            raise ValueError("Failed to run command on host {}: {}".format(host, cmd))
        return rc

    @staticmethod
    def _call_with_parallax(cmd, host_list):
        ret = crmsh.parallax.parallax_run(host_list, cmd)
        if ret is crmsh.parallax.Error:
            raise ret
        return ret

    def stop_service(self, name, disable=False, remote_addr=None, node_list=[]):
        """
        Stop service
        Return success node list
        """
        if disable:
            cmd = "systemctl disable --now '{}'".format(name)
        else:
            cmd = "systemctl stop '{}'".format(name)
        return self._call(remote_addr, node_list, cmd)

    def enable_service(self, name, remote_addr=None, node_list=[]):
        """
        Enable service
        Return success node list
        """
        cmd = "systemctl enable '{}'".format(name)
        return self._call(remote_addr, node_list, cmd)

    def disable_service(self, name, remote_addr=None, node_list=[]):
        """
        Disable service
        Return success node list
        """
        cmd = "systemctl disable '{}'".format(name)
        return self._call(remote_addr, node_list, cmd)
