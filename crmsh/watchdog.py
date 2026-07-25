import logging
import re

from . import utils
from .sh import ShellUtils
from . import sh
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

    def __init__(self, _input=None, remote_user=None, peer_host=None):
        """
        Init function
        """
        self._input = _input
        self._remote_user = remote_user
        self._peer_host = peer_host
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
    def _load_watchdog_driver(driver, join=False):
        """
        Load specific watchdog driver
        """
        cmd = f"echo {driver} > {Watchdog.WATCHDOG_CFG} && systemctl restart systemd-modules-load"
        node_list = utils.this_node() if join else None
        utils.cluster_run_cmd(cmd, node_list)

    @staticmethod
    def get_watchdog_device_from_sbd_config():
        """
        Try to get watchdog device name from sbd config file
        """
        conf = utils.parse_sysconfig(sbd.SBDManager.SYSCONFIG_SBD)
        return conf.get("SBD_WATCHDOG_DEV")

    @staticmethod
    def _driver_is_loaded(driver):
        """
        Check if driver was already loaded
        """
        _, out, _ = ShellUtils().get_stdout_stderr("lsmod")
        return re.search("\n{}\\s+".format(driver), out)

    @staticmethod
    def _get_configured_watchdog_driver():
        """
        Get watchdog driver name from modules-load config.
        """
        try:
            with open(Watchdog.WATCHDOG_CFG) as f:
                return f.readline().strip()
        except OSError:
            return None

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
            if driver == "<unknown>":
                configured_driver = cls._get_configured_watchdog_driver()
                if configured_driver and cls._driver_is_loaded(configured_driver):
                    driver = configured_driver
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

    def _get_driver_through_device_remotely(self, dev_name):
        """
        Given watchdog device name, get driver name on remote node
        """
        rc, out, err = sh.cluster_shell().get_rc_stdout_stderr_without_input(self._peer_host, self.QUERY_CMD)
        if rc == 0 and out:
            device_driver_dict = self.get_watchdog_info(out)
            if dev_name in device_driver_dict:
                return device_driver_dict[dev_name]
            else:
                return None
        else:
            utils.fatal("Failed to run {} remotely: {}".format(self.QUERY_CMD, err))

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
        """
        In join process, get watchdog device from config
        If that device not exist, get driver name from init node, and load that driver
        """
        self._set_watchdog_info()

        res = self.get_watchdog_device_from_sbd_config()
        if not res:
            utils.fatal("Failed to get watchdog device from {}".format(sbd.SBDManager.SYSCONFIG_SBD))
        self._input = res

        if not self._valid_device(self._input):
            driver = self._get_driver_through_device_remotely(self._input)
            self._load_watchdog_driver(driver, join=True)

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
        if not self._driver_is_loaded(self._input):
            self._load_watchdog_driver(self._input)
            self._set_watchdog_info()

        # self._input is a loaded driver name, find corresponding device name
        res = self._get_device_through_driver(self._input)
        if res:
            self._watchdog_device_name = res
            return

    @classmethod
    def get_watchdog_device(cls, dev_or_driver=None):
        w = cls(_input=dev_or_driver)
        w.init_watchdog()
        return w.watchdog_device_name
