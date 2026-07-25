import re
from . import utils
from .sh import ShellUtils
from . import sbd


class Watchdog(object):
    """
    Class to find valid watchdog device name
    """
    WATCHDOG_CFG = "/etc/modules-load.d/watchdog.conf"
    QUERY_CMD = "sudo sbd query-watchdog"
    DEVICE_FIND_REGREX = "\\[[0-9]+\\] (/dev/.*)\n.*\nDriver: (.*)"

    def __init__(self, _input=None, cluster_is_running=True):
        """
        Init function
        """
        self._input = _input
        self._cluster_is_running = cluster_is_running
        self._watchdog_info_dict = {}
        self._watchdog_device_name = None

    @property
    def watchdog_device_name(self):
        return self._watchdog_device_name

    @staticmethod
    def verify_watchdog_device(dev):
        """
        Use wdctl to verify watchdog device
        """
        rc, _, err = ShellUtils().get_stdout_stderr(f"wdctl {dev}")
        if rc != 0:
            utils.fatal(f"Invalid watchdog device {dev}: {err}")
        return True

    @staticmethod
    def _configure_and_load_driver(driver, node_list=None):
        """
        Write the driver name to WATCHDOG_CFG and (re)load the kernel module,
        on node_list (or cluster-wide, discovered from the running CIB, when
        node_list is None).
        """
        cmd = f"echo {driver} > {Watchdog.WATCHDOG_CFG} && systemctl restart systemd-modules-load"
        utils.cluster_run_cmd(cmd, node_list)

    @staticmethod
    def _reload_driver(node_list):
        """
        Reload the already-configured watchdog kernel module on node_list,
        without touching WATCHDOG_CFG (e.g. when joining a cluster: the config
        file has already been synced from the cluster).
        """
        utils.cluster_run_cmd("systemctl restart systemd-modules-load", node_list)

    @staticmethod
    def get_watchdog_device_from_sbd_config():
        """
        Try to get watchdog device name from sbd config file
        """
        conf = utils.parse_sysconfig(sbd.SBDManager.SYSCONFIG_SBD)
        return conf.get("SBD_WATCHDOG_DEV")

    @staticmethod
    def _driver_is_loaded(driver, node_list=None):
        """
        Check if the driver is already loaded on all the given nodes. When
        node_list is None, the node list is discovered from the running CIB.
        """
        results = utils.cluster_run_cmd("lsmod", node_list)
        for _, (_, out, _) in results:
            if not re.search("\n{}\\s+".format(driver), utils.to_ascii(out)):
                return False
        return True

    def _set_watchdog_info(self):
        """
        Set watchdog info through sbd query-watchdog command
        Content in self._watchdog_info_dict: {device_name: driver_name}
        """
        rc, out, err = ShellUtils().get_stdout_stderr(self.QUERY_CMD)
        if rc == 0 and out:
            # output format might like:
            #   [1] /dev/watchdog\nIdentity: Software Watchdog\nDriver: softdog\n
            self._watchdog_info_dict = dict(re.findall(self.DEVICE_FIND_REGREX, out))
        else:
            utils.fatal("Failed to run {}: {}".format(self.QUERY_CMD, err))

    def _get_device_through_driver(self, driver_name):
        """
        Get watchdog device name which has driver_name
        """
        for device, driver in self._watchdog_info_dict.items():
            if driver == driver_name and self.verify_watchdog_device(device):
                return device
        return None

    def _set_input(self):
        if self._input:
            return

        for dev, driver in self._watchdog_info_dict.items():
            if driver != "softdog":
                self._input = dev
                return

        self._input = "softdog"

    def _valid_device(self, dev):
        """
        Is an unused watchdog device
        """
        if dev in self._watchdog_info_dict and self.verify_watchdog_device(dev):
            return True
        return False

    def join_watchdog(self):
        self._set_watchdog_info()

        res = self.get_watchdog_device_from_sbd_config()
        if not res:
            utils.fatal("Failed to get watchdog device from {}".format(sbd.SBDManager.SYSCONFIG_SBD))
        self._input = res

        if not self._valid_device(self._input):
            self._reload_driver([utils.this_node()])

    def init_watchdog(self):
        """
        In init process, find valid watchdog device
        """
        self._set_watchdog_info()
        self._set_input()

        # self._input is a device name
        if self._valid_device(self._input):
            self._watchdog_device_name = self._input
            return

        # self._input is invalid, exit
        rc, _, _ = ShellUtils().get_stdout_stderr(f"modinfo {self._input}")
        if rc != 0:
            utils.fatal("Should provide valid watchdog device or driver name")

        # self._input is a driver name, load it if it was unloaded
        node_list = None if self._cluster_is_running else [utils.this_node()]
        if not self._driver_is_loaded(self._input, node_list=node_list):
            self._configure_and_load_driver(self._input, node_list=node_list)
            self._set_watchdog_info()

        # self._input is a loaded driver name, find corresponding device name
        res = self._get_device_through_driver(self._input)
        if res:
            self._watchdog_device_name = res
            return

    @classmethod
    def get_watchdog_device(cls, dev_or_driver=None, cluster_is_running=True):
        w = cls(_input=dev_or_driver, cluster_is_running=cluster_is_running)
        w.init_watchdog()
        return w.watchdog_device_name
