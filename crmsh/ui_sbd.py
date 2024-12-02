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


logger = logging.getLogger(__name__)


def sbd_device_completer(completed_list: typing.List[str]) -> typing.List[str]:
    '''
    Completion for sbd device command
    '''
    if not sbd.SBDUtils.is_using_disk_based_sbd():
        return []
    if len(completed_list) == 2:
        return ["add", "remove"]
    if len(completed_list) > 2 and completed_list[1] != "remove":
        return []

    # completer for sbd device remove
    dev_list = sbd.SBDUtils.get_sbd_device_from_config()
    not_complete_list = [dev for dev in dev_list if dev not in completed_list[2:]]
    # not allow to remove the last device
    if len(not_complete_list) == 1:
        return []
    return not_complete_list


def sbd_configure_completer(completed_list: typing.List[str]) -> typing.List[str]:
    '''
    completion for sbd configure command
    '''
    service_manager = ServiceManager()
    pcmk_is_active = service_manager.service_is_active(constants.PCMK_SERVICE)
    sbd_is_active = service_manager.service_is_active(constants.SBD_SERVICE)
    if not pcmk_is_active or not sbd_is_active:
        return []

    is_diskbased = sbd.SBDUtils.is_using_disk_based_sbd()
    is_diskless = sbd.SBDUtils.is_using_diskless_sbd()
    show_types, timeout_types = (), ()
    if is_diskbased:
        show_types = SBD.SHOW_TYPES
        timeout_types = SBD.TIMEOUT_TYPES
    elif is_diskless:
        show_types = SBD.DISKLESS_SHOW_TYPES
        timeout_types = SBD.DISKLESS_TIMEOUT_TYPES

    if completed_list[1] == "show":
        if len(completed_list) == 3:
            return [t for t in show_types if t not in completed_list]
        else:
            return []

    parameters_pool = []
    if completed_list[1] == '':
        parameters_pool = ["show"]
    parameters_pool.extend([f"{t}-timeout=" for t in timeout_types])
    parameters_pool.append("watchdog-device=")
    parameters_pool = [
        p
        for p in parameters_pool
        if not any(c.startswith(p) for c in completed_list)
    ]
    return parameters_pool


class SBD(command.UI):
    '''
    Class for sbd sub-level

    Includes commands:
    - sbd configure
    - sbd device
    - sbd status
    - sbd purge
    '''
    name = "sbd"
    TIMEOUT_TYPES = ("watchdog", "allocate", "loop", "msgwait")
    DISKLESS_TIMEOUT_TYPES = ("watchdog",)
    SHOW_TYPES = ("disk_metadata", "sysconfig", "property")
    DISKLESS_SHOW_TYPES = ("sysconfig", "property")
    PCMK_ATTRS = (
        "have-watchdog",
        "stonith-timeout",
        "stonith-watchdog-timeout",
        "stonith-enabled",
        "priority-fencing-delay",
        "pcmk_delay_max"
    )
    PARSE_RE = re.compile(
		# Match keys with non-empty values, capturing possible suffix
        r'(\w+)(?:-(\w+))?=("[^"]+"|[\w/\d;]+)'
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

        self._load_attributes()
        command.UI.__init__(self)

    def _load_attributes(self):
        self.device_list_from_config = sbd.SBDUtils.get_sbd_device_from_config()
        self.device_meta_dict_runtime = {}
        if self.device_list_from_config:
            self.device_meta_dict_runtime = sbd.SBDUtils.get_sbd_device_metadata(self.device_list_from_config[0], timeout_only=True)
        try:
            self.watchdog_timeout_from_config = sbd.SBDTimeout.get_sbd_watchdog_timeout()
        except Exception:
            self.watchdog_timeout_from_config = None
        self.watchdog_device_from_config = watchdog.Watchdog.get_watchdog_device_from_sbd_config()

        self.service_manager = ServiceManager()
        self.cluster_shell = sh.cluster_shell()
        self.cluster_nodes = utils.list_cluster_nodes() or [utils.this_node()]
        for node in self.cluster_nodes[:]:
            try:
                utils.node_reachable_check(node)
            except Exception as e:
                logger.error(e)
                self.cluster_nodes.remove(node)

    def requires(self) -> bool:
        '''
        Requirements check when entering sbd sub-level
        '''
        if not utils.package_is_installed("sbd"):
            logger.error('%s', sbd.SBDManager.SBD_NOT_INSTALLED_MSG)
            return False
        return True

    def service_is_active(self, service: str) -> bool:
        if not self.service_manager.service_is_active(service):
            logger.error("%s is not active", service)
            return False
        return True

    @property
    def configure_usage(self) -> str:
        '''
        Build usage string for sbd configure command,
        including disk-based and diskless sbd cases
        '''
        timeout_types, show_types = (), ()
        if sbd.SBDUtils.is_using_disk_based_sbd():
            timeout_types, show_types = self.TIMEOUT_TYPES, self.SHOW_TYPES
        elif sbd.SBDUtils.is_using_diskless_sbd():
            timeout_types, show_types = self.DISKLESS_TIMEOUT_TYPES, self.DISKLESS_SHOW_TYPES
        else:
            return ""

        timeout_usage_str = " ".join([f"[{t}-timeout=<integer>]" for t in timeout_types])
        show_usage = f"crm sbd configure show [{'|'.join(show_types)}]"
        return f"Usage:\n{show_usage}\ncrm sbd configure {timeout_usage_str} [watchdog-device=<device>]\n"

    def _show_sysconfig(self) -> None:
        '''
        Show pure content of /etc/sysconfig/sbd
        '''
        with open(sbd.SBDManager.SYSCONFIG_SBD) as f:
            content_list = [
                line.strip()
                for line in f.readlines()
                if not line.startswith("#") and line.strip()
            ]
        if content_list:
            logger.info("crm sbd configure show sysconfig")
        for line in content_list:
            if line.startswith("SBD_WATCHDOG_TIMEOUT") and bool(self.device_list_from_config):
                continue
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
        regex = f"({'|'.join(self.PCMK_ATTRS)})=(\\S+)"
        matches = re.findall(regex, out)
        for match in matches:
            print(f"{match[0]}={match[1]}")

        print()
        logger.info('%s', sbd.SBDTimeout.SHOW_SBD_START_TIMEOUT_CMD)
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
                    self._show_sysconfig()
                case "property":
                    self._show_property()
                case _:
                    raise self.SyntaxError(f"Unknown argument: {args[1]}")
        else:
            self._show_disk_metadata()
            if self.device_list_from_config:
                print()
            self._show_sysconfig()
            print()
            self._show_property()

    def _parse_args(self, args: tuple[str, ...]) -> dict[str, int|str]:
        '''
        Parse arguments and verify them
        '''
        parameter_dict = {}

        for arg in args:
            match = self.PARSE_RE.match(arg)
            if not match:
                raise self.SyntaxError(f"Invalid argument: {arg}")
            key, suffix, value = match.groups()
            # timeout related parameters
            if key in self.TIMEOUT_TYPES and suffix and suffix == "timeout":
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
    def _adjust_timeout_dict(timeout_dict: dict) -> dict:
        watchdog_timeout = timeout_dict.get("watchdog")
        msgwait_timeout = timeout_dict.get("msgwait")
        if watchdog_timeout and msgwait_timeout and msgwait_timeout < 2*watchdog_timeout:
            logger.warning("It's recommended to set msgwait timeout >= 2*watchdog timeout")
            return timeout_dict
        if watchdog_timeout and not msgwait_timeout:
            timeout_dict["msgwait"] = 2*watchdog_timeout
            logger.info("No msgwait timeout specified, use 2*watchdog timeout: %s", 2*watchdog_timeout)
            return timeout_dict
        if msgwait_timeout and not watchdog_timeout:
            watchdog_timeout = msgwait_timeout//2
            timeout_dict["watchdog"] = watchdog_timeout
            logger.info("No watchdog timeout specified, use msgwait timeout/2: %s", watchdog_timeout)
            return timeout_dict

    def _configure_diskbase(self, parameter_dict: dict):
        '''
        Configure disk-based SBD based on input parameters and runtime config
        '''
        update_dict = {}
        watchdog_device = parameter_dict.get("watchdog-device")
        if watchdog_device != self.watchdog_device_from_config:
            update_dict["SBD_WATCHDOG_DEV"] = watchdog_device
        timeout_dict = {k: v for k, v in parameter_dict.items() if k in self.TIMEOUT_TYPES}
        is_subdict_timeout = utils.is_subdict(timeout_dict, self.device_meta_dict_runtime)

        if is_subdict_timeout and not update_dict:
            logger.info("No change in SBD configuration")
            return

        if not is_subdict_timeout:
            timeout_dict = self._adjust_timeout_dict(timeout_dict)
            # merge runtime timeout dict into parameter timeout dict without overwriting
            timeout_dict = {**self.device_meta_dict_runtime, **timeout_dict}

        sbd_manager = sbd.SBDManager(
            device_list_to_init=self.device_list_from_config,
            timeout_dict=timeout_dict,
            update_dict=update_dict
        )
        sbd_manager.init_and_deploy_sbd()
        
    def _configure_diskless(self, parameter_dict: dict):
        '''
        Configure diskless SBD based on input parameters and runtime config
        '''
        update_dict = {}
        watchdog_timeout = parameter_dict.get("watchdog")
        if watchdog_timeout and watchdog_timeout != self.watchdog_timeout_from_config:
            update_dict["SBD_WATCHDOG_TIMEOUT"] = str(watchdog_timeout)
        watchdog_device = parameter_dict.get("watchdog-device")
        if watchdog_device != self.watchdog_device_from_config:
            update_dict["SBD_WATCHDOG_DEV"] = watchdog_device
        if not update_dict:
            logger.info("No change in SBD configuration")
            return

        sbd_manager = sbd.SBDManager(
            update_dict=update_dict,
            diskless_sbd=True
        )
        sbd_manager.init_and_deploy_sbd()

    def _device_add(self, devices_to_add: typing.List[str]):
        '''
        Implement sbd device add command, add devices to sbd configuration
        '''
        all_device_list = self.device_list_from_config + devices_to_add
        sbd.SBDUtils.verify_sbd_device(all_device_list)

        devices_to_init, _ = sbd.SBDUtils.handle_input_sbd_devices(
            devices_to_add,
            self.device_list_from_config
        )

        logger.info("Append devices: %s", ';'.join(devices_to_add))
        update_dict = {"SBD_DEVICE": ";".join(all_device_list)}
        sbd_manager = sbd.SBDManager(
            device_list_to_init=devices_to_init,
            update_dict=update_dict,
            timeout_dict=self.device_meta_dict_runtime
        )
        sbd_manager.init_and_deploy_sbd()

    def _device_remove(self, devices_to_remove: typing.List[str]):
        '''
        Implement sbd device remove command, remove devices from sbd configuration
        '''
        for dev in devices_to_remove:
            if dev not in self.device_list_from_config:
                raise self.SyntaxError(f"Device {dev} is not in config")
        # To keep the order of devices during removal
        left_device_list = [dev for dev in self.device_list_from_config if dev not in devices_to_remove]
        if len(left_device_list) == 0:
            raise self.SyntaxError("Not allowed to remove all devices")

        logger.info("Remove devices: %s", ';'.join(devices_to_remove))
        update_dict = {"SBD_DEVICE": ";".join(left_device_list)}
        sbd.SBDManager.update_sbd_configuration(update_dict)
        sbd.SBDManager.restart_cluster_if_possible()

    @command.completers_repeating(sbd_device_completer)
    def do_device(self, context, *args) -> bool:
        '''
        Implement sbd device command
        '''
        if not self.service_is_active(constants.PCMK_SERVICE):
            return False
        if not sbd.SBDUtils.is_using_disk_based_sbd():
            logger.error("Only works for disk-based SBD")
            logger.info("Please use 'crm cluster init sbd -s <dev1> [-s <dev2> [-s <dev3>]]' to configure the disk-based SBD first")
            return False

        try:
            if not args:
                raise self.SyntaxError("No argument")
            if args[0] not in ("add", "remove"):
                raise self.SyntaxError(f"Invalid argument: {args[0]}")
            if len(args) < 2:
                raise self.SyntaxError("No device specified")

            logger.info("Configured sbd devices: %s", ';'.join(self.device_list_from_config))
            if len(args) == 2 and ";" in args[1]:
                device_list_from_args = args[1].split(";")
            else:
                device_list_from_args = list(args[1:])
            match args[0]:
                case "add":
                    self._device_add(device_list_from_args)
                case "remove":
                    self._device_remove(device_list_from_args)
            return True

        except self.SyntaxError as e:
            logger.error('%s', str(e))
            logger.info("Usage: crm sbd device <add|remove> <device>...")
            return False

    @command.completers_repeating(sbd_configure_completer)
    def do_configure(self, context, *args) -> bool:
        '''
        Implement sbd configure command
        '''
        try:
            for service in (constants.PCMK_SERVICE, constants.SBD_SERVICE):
                if not self.service_is_active(service):
                    return False
            if not args:
                raise self.SyntaxError("No argument")

            if args[0] == "show":
                self._configure_show(args)
                return True
            parameter_dict = self._parse_args(args)
            if sbd.SBDUtils.is_using_disk_based_sbd():
                self._configure_diskbase(parameter_dict)
            elif sbd.SBDUtils.is_using_diskless_sbd():
                self._configure_diskless(parameter_dict)
            return True

        except self.SyntaxError as e:
            logger.error('%s', str(e))
            usage = self.configure_usage
            if usage:
                print(usage)
            return False

    def do_purge(self, context) -> bool:
        '''
        Implement sbd purge command
        '''
        if not self.service_is_active(constants.SBD_SERVICE):
            return False
        sbd.purge_sbd_from_cluster()
        sbd.SBDManager.restart_cluster_if_possible()
        return True

    def _print_sbd_type(self):
        if not self.service_manager.service_is_active(constants.SBD_SERVICE):
            return
        print("# Type of SBD:")
        if self.device_list_from_config:
            print("Disk-based SBD configured")
        else:
            print("Diskless SBD configured")
        print()

    def _print_sbd_status(self):
        padding = 2
        status_len = 8
        max_node_len = max(len(node) for node in self.cluster_nodes) + padding

        print(f"# Status of {constants.SBD_SERVICE}:")
        print(f"{'Node':<{max_node_len}}|{'Active':<{status_len}}|{'Enabled':<{status_len}}|Since")
        for node in self.cluster_nodes:
            is_active = self.service_manager.service_is_active(constants.SBD_SERVICE, node)
            is_active_str = "YES" if is_active else "NO"
            is_enabled = self.service_manager.service_is_enabled(constants.SBD_SERVICE, node)
            is_enabled_str = "YES" if is_enabled else "NO"
            systemd_property = "ActiveEnterTimestamp" if is_active else "ActiveExitTimestamp"
            since_str_prefix = "active since" if is_active else "disactive since"
            systemctl_show_cmd = f"systemctl show {constants.SBD_SERVICE} --property={systemd_property} --value"
            since = self.cluster_shell.get_stdout_or_raise_error(systemctl_show_cmd, node) or "N/A"
            print(f"{node:<{max_node_len}}|{is_active_str:<{status_len}}|{is_enabled_str:<{status_len}}|{since_str_prefix}: {since}")
        print()

    def _print_watchdog_info(self):
        padding = 2
        max_node_len = max(len(node) for node in self.cluster_nodes) + padding
        watchdog_sbd_re = r"\[[0-9]+\] (/dev/.*)\nIdentity: Busy: .*sbd.*\nDriver: (.*)"
        device_list, driver_list, kernel_timeout_list = [], [], []

        for node in self.cluster_nodes:
            out = self.cluster_shell.get_stdout_or_raise_error("sbd query-watchdog", node)
            res = re.search(watchdog_sbd_re, out)
            if res:
                device, driver = res.groups()
                kernel_timeout = self.cluster_shell.get_stdout_or_raise_error("cat /proc/sys/kernel/watchdog_thresh", node)
            else:
                device, driver, kernel_timeout = "N/A", "N/A", "N/A"
            device_list.append(device)
            driver_list.append(driver)
            kernel_timeout_list.append(kernel_timeout)

        print("# Watchdog info:")
        max_dev_len = max(len(dev) for dev in device_list+["Device"]) + padding
        max_driver_len = max(len(driver) for driver in driver_list+["Driver"]) + padding
        print(f"{'Node':<{max_node_len}}|{'Device':<{max_dev_len}}|{'Driver':<{max_driver_len}}|Kernel Timeout")
        for i, node in enumerate(self.cluster_nodes):
            print(f"{node:<{max_node_len}}|{device_list[i]:<{max_dev_len}}|{driver_list[i]:<{max_driver_len}}|{kernel_timeout_list[i]}")
        print()

    def _print_sbd_agent_status(self):
        for node in self.cluster_nodes:
            crm_mon_xml_parser = xmlutil.CrmMonXmlParser(node)
            if crm_mon_xml_parser.is_resource_configured(sbd.SBDManager.SBD_RA):
                print("# Status of fence_sbd:")
                sbd_id_list = crm_mon_xml_parser.get_resource_id_list_via_type(sbd.SBDManager.SBD_RA)
                for sbd_id in sbd_id_list:
                    rc, output = self.cluster_shell.get_rc_output_without_input(node, f"crm resource status {sbd_id}")
                    if output:
                        print(output)
                return

    def _print_sbd_cgroup_status(self):
        scripts_in_shell = '''#!/bin/bash
cgroup_procs_file="/sys/fs/cgroup/system.slice/sbd.service/cgroup.procs"
if [ ! -f "$cgroup_procs_file" ]; then
    exit
fi
pids=$(cat "$cgroup_procs_file")
for pid in $pids; do
    cmdline_file="/proc/$pid/cmdline"
    if [ -f "$cmdline_file" ]; then
        cmdline=$(tr '\0' ' ' < "$cmdline_file")
        if [[ "$cmdline" == *"slot:"* ]]; then
            echo "├─$pid \"$cmdline\""
        fi
    fi
done
        '''
        for node in self.cluster_nodes:
            out = self.cluster_shell.get_stdout_or_raise_error(scripts_in_shell, node)
            if out:
                print(f"# Status of the sbd disk watcher process on {node}:")
                print(out + "\n")

    def do_status(self, context) -> bool:
        '''
        Implement sbd status command
        '''
        self._print_sbd_type()
        self._print_sbd_status()
        self._print_sbd_cgroup_status()
        self._print_watchdog_info()
        self._print_sbd_agent_status()
        return True
