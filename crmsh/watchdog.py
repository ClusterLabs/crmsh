import re
from . import utils
from .constants import SSH_OPTION
from .bootstrap import invoke, invokerc, WATCHDOG_CFG, SYSCONFIG_SBD


class Watchdog(object):
    """
    Class to find valid watchdog device name
    """
    QUERY_CMD = "sudo sbd query-watchdog"
    DEVICE_FIND_REGREX = "\[[0-9]+\] (/dev/.*)\n.*\nDriver: (.*)"

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
    def _verify_watchdog_device(dev, ignore_error=False):
        """
        Use wdctl to verify watchdog device
        """
        rc, _, err = utils.get_stdout_stderr("wdctl {}".format(dev))
        if rc != 0:
            if ignore_error:
                return False
            else:
                utils.fatal("Invalid watchdog device {}: {}".format(dev, err))
        return True

    @staticmethod
    def _load_watchdog_driver(driver):
        """
        Load specific watchdog driver
        """
        invoke("echo {} > {}".format(driver, WATCHDOG_CFG))
        invoke("systemctl restart systemd-modules-load")

    @staticmethod
    def _get_watchdog_device_from_sbd_config():
        """
        Try to get watchdog device name from sbd config file
        """
        conf = utils.parse_sysconfig(SYSCONFIG_SBD)
        return conf.get("SBD_WATCHDOG_DEV")

    @staticmethod
    def _driver_is_loaded(driver):
        """
        Check if driver was already loaded
        """
        _, out, _ = utils.get_stdout_stderr("lsmod")
        return re.search("\n{}\s+".format(driver), out)

    def _set_watchdog_info(self):
        """
        Set watchdog info through sbd query-watchdog command
        Content in self._watchdog_info_dict: {device_name: driver_name}
        """
        rc, out, err = utils.get_stdout_stderr(self.QUERY_CMD)
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
            if driver == driver_name and self._verify_watchdog_device(device):
                return device
        return None

    def _get_driver_through_device_remotely(self, dev_name):
        """
        Given watchdog device name, get driver name on remote node
        """
        # FIXME
        cmd = "ssh {} {}@{} {}".format(SSH_OPTION, self._remote_user, self._peer_host, self.QUERY_CMD)
        rc, out, err = utils.get_stdout_stderr(cmd)
        if rc == 0 and out:
            # output format might like:
            #   [1] /dev/watchdog\nIdentity: Software Watchdog\nDriver: softdog\n
            device_driver_dict = dict(re.findall(self.DEVICE_FIND_REGREX, out))
            if device_driver_dict and dev_name in device_driver_dict:
                return device_driver_dict[dev_name]
            else:
                return None
        else:
            utils.fatal("Failed to run {} remotely: {}".format(self.QUERY_CMD, err))

    def _get_first_unused_device(self):
        """
        Get first unused watchdog device name
        """
        for dev in self._watchdog_info_dict:
            if self._verify_watchdog_device(dev, ignore_error=True):
                return dev
        return None

    def _set_input(self):
        """
        If self._input was not provided by option:
          1. Try to get it from sbd config file
          2. Try to get the first valid device from result of sbd query-watchdog
          3. Set the self._input as softdog
        """
        if not self._input:
            dev = self._get_watchdog_device_from_sbd_config()
            if dev and self._verify_watchdog_device(dev, ignore_error=True):
                self._input = dev
                return
            first_unused = self._get_first_unused_device()
            self._input = first_unused if first_unused else "softdog"

    def _valid_device(self, dev):
        """
        Is an unused watchdog device
        """
        if dev in self._watchdog_info_dict and self._verify_watchdog_device(dev):
            return True
        return False

    def join_watchdog(self):
        """
        In join proces, get watchdog device from config
        If that device not exist, get driver name from init node, and load that driver
        """
        self._set_watchdog_info()

        res = self._get_watchdog_device_from_sbd_config()
        if not res:
            utils.fatal("Failed to get watchdog device from {}".format(SYSCONFIG_SBD))
        self._input = res

        if not self._valid_device(self._input):
            driver = self._get_driver_through_device_remotely(self._input)
            self._load_watchdog_driver(driver)

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
        if not invokerc("modinfo {}".format(self._input)):
            utils.fatal("Should provide valid watchdog device or driver name by -w option")

        # self._input is a driver name, load it if it was unloaded
        if not self._driver_is_loaded(self._input):
            self._load_watchdog_driver(self._input)
            self._set_watchdog_info()

        # self._input is a loaded driver name, find corresponding device name
        res = self._get_device_through_driver(self._input)
        if res:
            self._watchdog_device_name = res
            return
