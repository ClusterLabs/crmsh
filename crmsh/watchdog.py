import logging
import re

from . import utils
from .sh import ShellUtils
from . import sbd


logger = logging.getLogger(__name__)


class Watchdog(object):
    """
    Class to find valid watchdog device name
    """
    WATCHDOG_CFG = "/etc/modules-load.d/watchdog.conf"
    QUERY_CMD = "sudo sbd query-watchdog"
    # output format might like:
    #   [1] /dev/watchdog\nIdentity: Software Watchdog\nDriver: softdog\n
    DEVICE_FIND_REGREX = r"[ \t]*\[[0-9]+\] (/dev/[^\n]+)\n[ \t]*Identity: ([^\n]+)\n[ \t]*Driver: ([^\n]+)"

    def __init__(self, _input=None, node_list=None):
        """
        Init function

        node_list: the nodes to act on when loading the driver. When None, the
        node list is discovered from the running CIB (cluster-wide); otherwise
        it is the list of node names to use directly. Watchdog itself stays
        unaware of the cluster state and only trusts the nodes it is given.
        """
        self._input = _input
        self._node_list = node_list
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
    def _write_watchdog_config(driver, node_list=None):
        """
        Write the driver name to WATCHDOG_CFG on node_list (or cluster-wide,
        discovered from the running CIB, when node_list is None). This must
        always be done when configuring a driver, so it is loaded on every
        boot and synced to joining nodes, regardless of whether the module
        happens to already be loaded in the running kernel.
        """
        utils.cluster_run_cmd(f"echo {driver} > {Watchdog.WATCHDOG_CFG}", node_list)

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

    @classmethod
    def get_watchdog_info(cls, out, sbd_only=False):
        """
        Parse sbd query-watchdog output into {device_name: driver_name}.
        """
        if not out:
            return {}

        watchdog_info = {}
        for device, identity, driver in re.findall(cls.DEVICE_FIND_REGREX, out):
            if sbd_only and not re.search(r"Busy: .*sbd", identity):
                continue
            watchdog_info[device] = driver
        return watchdog_info

    @staticmethod
    def warn_if_using_softdog():
        """
        Warn if SBD is using softdog as watchdog driver.
        """
        rc, out, err = ShellUtils().get_stdout_stderr(Watchdog.QUERY_CMD)
        if rc != 0 or not out:
            logger.debug("Failed to run %s: %s", Watchdog.QUERY_CMD, err)
            return

        if "softdog" in Watchdog.get_watchdog_info(out, sbd_only=True).values():
            logger.warning("It's not recommended to use softdog as watchdog driver in production environment")

    def _set_watchdog_info(self):
        """
        Set watchdog info through sbd query-watchdog command
        Content in self._watchdog_info_dict: {device_name: driver_name}
        """
        rc, out, err = ShellUtils().get_stdout_stderr(self.QUERY_CMD)
        if rc == 0 and out:
            self._watchdog_info_dict = self.get_watchdog_info(out)
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

        # self._input is a driver name: always persist it to WATCHDOG_CFG so
        # it survives reboot and gets synced to joining nodes, and reload the
        # module now only if it wasn't already loaded in the kernel.
        self._write_watchdog_config(self._input, node_list=self._node_list)
        if not self._driver_is_loaded(self._input, node_list=self._node_list):
            self._reload_driver(self._node_list)
            self._set_watchdog_info()

        # self._input is a loaded driver name, find corresponding device name
        res = self._get_device_through_driver(self._input)
        if res:
            self._watchdog_device_name = res
            return

    @classmethod
    def get_watchdog_device(cls, dev_or_driver=None, node_list=None):
        w = cls(_input=dev_or_driver, node_list=node_list)
        w.init_watchdog()
        return w.watchdog_device_name
