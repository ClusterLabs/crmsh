import logging
import typing
import re
import os

from crmsh import sbd
from crmsh import watchdog
from crmsh import command
from crmsh import utils
from crmsh import bootstrap
from crmsh import completers
from crmsh import sh
from crmsh import xmlutil
from crmsh import constants
from crmsh.service_manager import ServiceManager
from crmsh.bootstrap import SYSCONFIG_SBD


logger = logging.getLogger(__name__)


def sbd_devices_completer(completed_list: typing.List[str]) -> typing.List[str]:
    '''
    completion for sbd devices
    '''
    if not ServiceManager().service_is_active(constants.SBD_SERVICE):
        return []
    dev_list = sbd.SBDUtils.get_sbd_device_from_config()
    if dev_list:
        return [dev for dev in dev_list if dev not in completed_list]
    return []


def sbd_configure_completer(completed_list: typing.List[str]) -> typing.List[str]:
    '''
    completion for sbd configure command
    '''
    if not ServiceManager().service_is_active(constants.PCMK_SERVICE):
        return []
    sbd_service_is_enabled = service_manager.service_is_enabled(constants.SBD_SERVICE)
    dev_list = sbd.SBDUtils.get_sbd_device_from_config()
    # Show disk-based sbd configure options
    # if there are devices in config or sbd.service is not enabled
    is_diskbased = bool(dev_list) or not sbd_service_is_enabled

    parameters_pool = []
    if completed_list[1] == '':
        parameters_pool = ["show"]
    elif completed_list[1] == "show":
        if len(completed_list) == 3:
            show_types = SBD.SHOW_TYPES if is_diskbased else SBD.DISKLESS_SHOW_TYPES
            return [t for t in show_types if t not in completed_list]
        else:
            return []
    if completed_list[-1] == "device=":
        return []

    timeout_types = SBD.TIMEOUT_TYPES if is_diskbased else SBD.DISKLESS_TIMEOUT_TYPES
    parameters_pool.extend([f"{t}-timeout=" for t in timeout_types])
    parameters_pool.append("watchdog-device=")
    parameters_pool = [
        p
        for p in parameters_pool
        if not any(c.startswith(p) for c in completed_list)
    ]

    if is_diskbased:
        dev_count = sum(1 for c in completed_list if c.startswith("device="))
        if dev_count < sbd.SBDManager.SBD_DEVICE_MAX:
            parameters_pool.append("device=")

    return parameters_pool


class SBD(command.UI):
    '''
    Class for sbd sub-level

    Includes commands:
    - sbd configure
    - sbd remove
    - sbd status
    '''
    name = "sbd"
    TIMEOUT_TYPES = ("watchdog", "allocate", "loop", "msgwait")
    DISKLESS_TIMEOUT_TYPES = ("watchdog",)
    SHOW_TYPES = ("disk_metadata", "sysconfig", "property")
    DISKLESS_SHOW_TYPES = ("sysconfig", "property")
    RESTART_INFO = "Requires to restart cluster service to take effect"
    PCMK_ATTRS = (
        "have-watchdog",
        "stonith-timeout",
        "stonith-watchdog-timeout",
        "stonith-enabled",
        "priority-fencing-delay",
        "pcmk_delay_max"
    )
    PARSE_RE = re.compile(
		# Match "device" key with any value, including empty
        r'(device)=("[^"]*"|[\w/\d;]*)'
		# Match other keys with non-empty values, capturing possible suffix
        r'|(\w+)(?:-(\w+))?=("[^"]+"|[\w/\d;]+)'
	    # Match standalone device path
        r'|(/dev/[\w\d]+)'
    )

    class SyntaxError(Exception):
        pass

    def __init__(self):
        self.device_list_from_config: list[str] = None
        self.device_meta_dict_runtime: dict[str, int] = None
        self.watchdog_timeout_from_config: int = None
        self.watchdog_device_from_config: str = None
        self.service_manager: ServiceManager = None
        self.cluster_shell: sh.cluster_shell = None
        self.cluster_nodes: list[str] = None
        self.crm_mon_xml_parser: xmlutil.CrmMonXmlParser = None

        command.UI.__init__(self)

    def _load_attributes(self):
        self.device_list_from_config = sbd.SBDUtils.get_sbd_device_from_config()
        self.device_meta_dict_runtime = {}
        if self.device_list_from_config:
            self.device_meta_dict_runtime = sbd.SBDUtils.get_sbd_device_metadata(self.device_list_from_config[0], timeout_only=True)
        try:
            self.watchdog_timeout_from_config = sbd.SBDTimeout.get_sbd_watchdog_timeout()
        except:
            self.watchdog_timeout_from_config = None
        self.watchdog_device_from_config = watchdog.Watchdog.get_watchdog_device_from_sbd_config()

        self.service_manager = ServiceManager()
        self.cluster_shell = sh.cluster_shell()
        self.cluster_nodes = utils.list_cluster_nodes() or [utils.this_node()]
        self.crm_mon_xml_parser = xmlutil.CrmMonXmlParser()

    def requires(self) -> bool:
        '''
        Requirements check when entering sbd sub-level
        '''
        if not utils.package_is_installed("sbd"):
            logger.error("sbd is not installed")
            return False
        return True

    @property
    def configure_usage(self) -> str:
        '''
        Build usage string for sbd configure command,
        including disk-based and diskless sbd cases
        '''
        def build_timeout_usage_str(timeout_types: tuple[str]) -> str:
            return " ".join([f"[{t}-timeout=<integer>]" for t in timeout_types])
        timeout_usage_str = build_timeout_usage_str(self.TIMEOUT_TYPES)
        timeout_usage_str_diskless = build_timeout_usage_str(self.DISKLESS_TIMEOUT_TYPES)
        show_usage_str = f"[{'|'.join(self.SHOW_TYPES)}]"
        show_usage_str_diskless = f"[{'|'.join(self.DISKLESS_SHOW_TYPES)}]"
        return ("Usage for disk-based SBD:\n"
                f"crm sbd configure show {show_usage_str}\n"
                f"crm sbd configure [device=<dev>]... {timeout_usage_str} [watchdog-device=<dev>]\n\n"
                "Usage for diskless SBD:\n"
                f"crm sbd configure show {show_usage_str_diskless}\n"
                f"crm sbd configure device=\"\" {timeout_usage_str_diskless} [watchdog-device=<dev>]\n")

    @staticmethod
    def _show_sysconfig() -> None:
        '''
        Show pure content of /etc/sysconfig/sbd
        '''
        with open(SYSCONFIG_SBD) as f:
            content_list = [line.strip() for line in f.readlines()
                            if not line.startswith("#")
                            and line.strip()]
        if content_list:
            logger.info("crm sbd configure show sysconfig")
        for line in content_list:
            print(line)

    def _show_disk_metadata(self) -> None:
        '''
        Show sbd disk metadata for each configured device
        '''
        if self.device_list_from_config:
            logger.info("crm sbd configure show disk_metadata")
        for dev in self.device_list_from_config:
            print(self.cluster_shell.get_stdout_or_raise_error(f"sbd -d {dev} dump"))
            print()

    def _show_property(self) -> None:
        '''
        Show sbd-related properties from cluster and systemd
        '''
        out = self.cluster_shell.get_stdout_or_raise_error("crm configure show")

        logger.info("crm sbd configure show property")
        regex = f"({'|'.join(self.PCMK_ATTRS)})=([^\s]+)"
        matches = re.findall(regex, out)
        for match in matches:
            print(f"{match[0]}={match[1]}")

        print()
        logger.info("systemctl show -p TimeoutStartUSec sbd --value")
        systemd_start_timeout = sbd.SBDTimeout.get_sbd_systemd_start_timeout()
        print(f"TimeoutStartUSec={systemd_start_timeout}")

    def _configure_show(self, args) -> None:
        if len(args) > 2:
            raise self.SyntaxError("Invalid argument")
        elif len(args) == 2:
            match args[1]:
                case "disk_metadata":
                    self._show_disk_metadata()
                case "sysconfig":
                    SBD._show_sysconfig()
                case "property":
                    self._show_property()
                case _:
                    raise self.SyntaxError(f"Unknown argument: {args[1]}")
        else:
            self._show_disk_metadata()
            if self.device_list_from_config:
                print()
            SBD._show_sysconfig()
            print()
            self._show_property()

    def _parse_args(self, args: typing.List[str]) -> dict[str, int|str|list[str]]:
        '''
        Parse arguments and verify them

        Possible arguments format like:
        device="/dev/sdb5;/dev/sda6"
        device="" watchdog-timeout=10
        /dev/sda5 watchdog-timeout=10 watchdog-device=/dev/watchdog
        device=/dev/sdb5 device=/dev/sda6 watchdog-timeout=10 msgwait-timeout=20
        '''
        parameter_dict = {"device-list": []}

        for arg in args:
            match = self.PARSE_RE.match(arg)
            if not match:
                raise self.SyntaxError(f"Invalid argument: {arg}")
            device_key, device_value, key, suffix, value, device_path = match.groups()

            # device=<device name> parameter
            if device_key:
                if device_value:
                    parameter_dict.setdefault("device-list", []).extend(device_value.split(";"))
                # explicitly set empty value, stands for diskless sbd
                elif not parameter_dict.get("device-list"):
                    parameter_dict.pop("device-list", None)
            # standalone device parameter
            elif device_path:
                parameter_dict.setdefault("device-list", []).append(device_path)
            # timeout related parameters
            elif key in self.TIMEOUT_TYPES and suffix and suffix == "timeout":
                if not value.isdigit():
                    raise self.SyntaxError(f"Invalid timeout value: {value}")
                parameter_dict[key] = int(value)
            # watchdog device parameter
            elif key == "watchdog" and suffix == "device":
                parameter_dict["watchdog-device"] = value
            else:
                raise self.SyntaxError(f"Unknown argument: {arg}")

        watchdog_device = parameter_dict.get("watchdog-device")
        parameter_dict["watchdog-device"] = watchdog.Watchdog.get_watchdog_device(watchdog_device)

        logger.debug("Parsed arguments: %s", parameter_dict)
        return parameter_dict

    @staticmethod
    def _adjust_timeout_dict(timeout_dict: dict, diskless: bool = False) -> dict:
        watchdog_timeout = timeout_dict.get("watchdog")
        if not watchdog_timeout:
            watchdog_timeout, _ = sbd.SBDTimeout.get_advised_sbd_timeout(diskless)
            logger.info("No watchdog timeout specified, use advised value: %s", watchdog_timeout)
            timeout_dict["watchdog"] = watchdog_timeout

        if diskless:
            return timeout_dict

        msgwait_timeout = timeout_dict.get("msgwait")
        if not msgwait_timeout:
            msgwait_timeout = 2*watchdog_timeout
            logger.info("No msgwait timeout specified, use 2*watchdog timeout: %s", msgwait_timeout)
            timeout_dict["msgwait"] = msgwait_timeout

        if msgwait_timeout < 2*watchdog_timeout:
            logger.warning("It's recommended to set msgwait timeout >= 2*watchdog timeout")

        return timeout_dict

    def _configure_diskbase(self, parameter_dict: dict):
        '''
        Configure disk-based SBD based on input parameters and runtime config
        '''
        if not self.device_list_from_config:
            self.watchdog_timeout_from_config = None
            self.watchdog_device_from_config = None

        update_dict = {}
        device_list = parameter_dict.get("device-list", [])
        if not device_list and not self.device_list_from_config:
            raise self.SyntaxError("No device specified")
        if len(device_list) > len(set(device_list)):
            raise self.SyntaxError("Duplicate device")
        watchdog_device = parameter_dict.get("watchdog-device")
        if watchdog_device != self.watchdog_device_from_config:
            update_dict["SBD_WATCHDOG_DEV"] = watchdog_device
        timeout_dict = {k: v for k, v in parameter_dict.items() if k in self.TIMEOUT_TYPES}

        all_device_list = list(
            dict.fromkeys(self.device_list_from_config + device_list)
        )
        sbd.SBDUtils.verify_sbd_device(all_device_list)

        new_device_list = list(
            set(device_list) - set(self.device_list_from_config)
        )
        no_overwrite_dev_map : dict[str, bool] = {
            dev: sbd.SBDUtils.no_overwrite_device_check(dev) for dev in new_device_list
        }
        if new_device_list:
            update_dict["SBD_DEVICE"] = ";".join(all_device_list)

        device_list_to_init = []
        # initialize new devices only if no timeout parameter specified or timeout parameter is already in runtime config
        if not timeout_dict or utils.is_subdict(timeout_dict, self.device_meta_dict_runtime):
            device_list_to_init = new_device_list
        # initialize all devices
        else:
            device_list_to_init = all_device_list

        # merge runtime timeout dict with new timeout dict
        timeout_dict = self.device_meta_dict_runtime | timeout_dict
        # adjust watchdog and msgwait timeout
        timeout_dict = self._adjust_timeout_dict(timeout_dict)
        watchdog_timeout = timeout_dict.get("watchdog")
        if watchdog_timeout != self.watchdog_timeout_from_config:
            update_dict["SBD_WATCHDOG_TIMEOUT"] = str(watchdog_timeout)

        sbd_manager = sbd.SBDManager(
            device_list_to_init=device_list_to_init,
            timeout_dict=timeout_dict,
            update_dict=update_dict,
            no_overwrite_dev_map=no_overwrite_dev_map,
            new_config=False if self.device_list_from_config else True
        )
        sbd_manager.init_and_deploy_sbd()
        
    def _configure_diskless(self, parameter_dict: dict):
        '''
        Configure diskless SBD based on input parameters and runtime config
        '''
        if self.device_list_from_config:
            self.watchdog_timeout_from_config = None
            self.watchdog_device_from_config = None

        update_dict = {}
        parameter_dict = self._adjust_timeout_dict(parameter_dict, diskless=True)
        watchdog_timeout = parameter_dict.get("watchdog")
        if watchdog_timeout and watchdog_timeout != self.watchdog_timeout_from_config:
            update_dict["SBD_WATCHDOG_TIMEOUT"] = str(watchdog_timeout)
        watchdog_device = parameter_dict.get("watchdog-device")
        if watchdog_device != self.watchdog_device_from_config:
            update_dict["SBD_WATCHDOG_DEV"] = watchdog_device

        sbd_manager = sbd.SBDManager(
            update_dict=update_dict,
            diskless_sbd=True,
            new_config=True if self.device_list_from_config else False
        )
        sbd_manager.init_and_deploy_sbd()

    @command.completers_repeating(sbd_configure_completer)
    def do_configure(self, context, *args) -> bool:
        '''
        Implement sbd configure command
        '''
        self._load_attributes()

        try:
            if not args:
                raise self.SyntaxError("No argument")

            if args[0] == "show":
                self._configure_show(args)
                return True

            if not self.service_manager.service_is_active(constants.PCMK_SERVICE):
                logger.error("%s is not active", constants.PCMK_SERVICE)
                return False

            parameter_dict = self._parse_args(args)
            # disk-based sbd case
            if "device-list" in parameter_dict:
                return self._configure_diskbase(parameter_dict)
            # diskless sbd case
            else:
                return self._configure_diskless(parameter_dict)

        except self.SyntaxError as e:
            logger.error(str(e))
            print(self.configure_usage)
            return False

    @command.completers_repeating(sbd_devices_completer)
    def do_remove(self, context, *args) -> bool:
        '''
        Implement sbd remove command
        '''
        self._load_attributes()

        if not self.service_manager.service_is_active(constants.SBD_SERVICE):
            logger.error("%s is not active", constants.SBD_SERVICE)
            return False

        parameter_dict = self._parse_args(args)
        dev_list = parameter_dict.get("device-list", [])
        if dev_list:
            if not self.device_list_from_config:
                logger.error("No sbd device found in config")
                return False
            for dev in dev_list:
                if dev not in self.device_list_from_config:
                    logger.error("Device %s is not in config", dev)
                    return False
            changed_dev_list = set(self.device_list_from_config) - set(dev_list)
            # remove part of devices from config
            if changed_dev_list:
                logger.info("Remove '%s' from %s", ";".join(dev_list), SYSCONFIG_SBD)
                sbd.SBDManager.update_sbd_configuration({"SBD_DEVICE": ";".join(changed_dev_list)})
            # remove all devices, equivalent to stop sbd.service
            else:
                sbd.disable_sbd_from_cluster()
        else:
            sbd.disable_sbd_from_cluster()

        logger.info(self.RESTART_INFO)
        return True

    def do_status(self, context) -> bool:
        '''
        Implement sbd status command
        '''
        self._load_attributes()

        print(f"{constants.SBD_SERVICE} status: (active|enabled|since)")
        for node in self.cluster_nodes:
            is_active = self.service_manager.service_is_active(constants.SBD_SERVICE, node)
            is_active_str = "YES" if is_active else "NO"
            is_enabled = self.service_manager.service_is_enabled(constants.SBD_SERVICE, node)
            is_enabled_str = "YES" if is_enabled else "NO"
            systemd_property = "ActiveEnterTimestamp" if is_active else "ActiveExitTimestamp"
            since_str_prefix = "active since" if is_active else "disactive since"
            systemctl_show_cmd = f"systemctl show {constants.SBD_SERVICE} --property={systemd_property} --value"
            since = self.cluster_shell.get_stdout_or_raise_error(systemctl_show_cmd, node) or "N/A"
            print(f"{node}: {is_active_str:<4}|{is_enabled_str:<4}|{since_str_prefix}: {since}")
        print()

        print("watchdog info: (device|driver|kernel timeout)")
        watchdog_sbd_re = "\[[0-9]+\] (/dev/.*)\nIdentity: Busy: .*sbd.*\nDriver: (.*)"
        for node in self.cluster_nodes:
            out = self.cluster_shell.get_stdout_or_raise_error("sbd query-watchdog", node)
            res = re.search(watchdog_sbd_re, out)
            if res:
                device, driver = res.groups()
                kernel_timeout = self.cluster_shell.get_stdout_or_raise_error("cat /proc/sys/kernel/watchdog_thresh", node)
                print(f"{node}: {device}|{driver}|{kernel_timeout}")
            else:
                logger.error("Failed to get watchdog info from %s", node)
        print()

        if self.crm_mon_xml_parser.is_resource_configured(sbd.SBDManager.SBD_RA):
            print("fence_sbd status: ")
            sbd_id_list = self.crm_mon_xml_parser.get_resource_id_list_via_type(sbd.SBDManager.SBD_RA)
            for sbd_id in sbd_id_list:
                rc, out, err = self.cluster_shell.get_rc_stdout_stderr_without_input(None, f"crm resource status {sbd_id}")
                if out:
                    print(out)
                if err:
                    print(err)
