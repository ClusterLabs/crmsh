import os
import re
import typing
import shutil
import time
import logging
from enum import Enum, IntEnum, auto
from . import utils, sh
from . import bootstrap
from . import log
from . import constants
from . import corosync
from . import xmlutil
from . import watchdog
from . import cibquery
from .service_manager import ServiceManager
from .sh import ShellUtils

logger = log.setup_logger(__name__)


class SBDUtils:
    '''
    Consolidate sbd related utility methods
    '''
    @staticmethod
    def get_sbd_device_metadata(dev, timeout_only=False, remote=None) -> dict:
        '''
        Extract metadata from sbd device header
        '''
        sbd_info = {}
        pattern = r"UUID\s+:\s+(\S+)|Timeout\s+\((\w+)\)\s+:\s+(\d+)"

        out = sh.cluster_shell().get_stdout_or_raise_error(f"sbd -d {dev} dump", remote)
        matches = re.findall(pattern, out)
        for uuid, timeout_type, timeout_value in matches:
            if uuid and not timeout_only:
                sbd_info["uuid"] = uuid
            elif timeout_type and timeout_value:
                sbd_info[timeout_type] = int(timeout_value)

        if "msgwait" not in sbd_info:
            raise ValueError(f"Cannot find msgwait timeout in sbd device {dev}")
        if "watchdog" not in sbd_info:
            raise ValueError(f"Cannot find watchdog timeout in sbd device {dev}")

        return sbd_info

    @staticmethod
    def get_device_uuid(dev, node=None):
        '''
        Get UUID for specific device and node
        '''
        res = SBDUtils.get_sbd_device_metadata(dev, remote=node).get("uuid")
        if not res:
            raise ValueError(f"Cannot find sbd device UUID for {dev}")
        return res

    @staticmethod
    def compare_device_uuid(dev, node_list):
        '''
        Compare local sbd device UUID with other node's sbd device UUID
        '''
        if not node_list:
            return
        local_uuid = SBDUtils.get_device_uuid(dev)
        for node in node_list:
            remote_uuid = SBDUtils.get_device_uuid(dev, node)
            if local_uuid != remote_uuid:
                raise ValueError(f"Device {dev} doesn't have the same UUID with {node}")

    @staticmethod
    def verify_sbd_device(dev_list, compare_node_list=[]):
        if len(dev_list) > SBDManager.SBD_DEVICE_MAX:
            raise ValueError(f"Maximum number of SBD device is {SBDManager.SBD_DEVICE_MAX}")
        for dev in dev_list:
            if not utils.is_block_device(dev):
                raise ValueError(f"{dev} doesn't look like a block device")
            SBDUtils.compare_device_uuid(dev, compare_node_list)
        utils.detect_duplicate_device_path(dev_list)

    @staticmethod
    def get_sbd_value_from_config(key):
        '''
        Get value from /etc/sysconfig/sbd
        '''
        return utils.parse_sysconfig(SBDManager.SYSCONFIG_SBD).get(key)

    @staticmethod
    def get_crashdump_watchdog_timeout() -> typing.Optional[int]:
        res = SBDUtils.get_sbd_value_from_config("SBD_OPTS")
        if not res:
            return None
        matched = re.search(r"-C\s+(\d+)", res)
        return int(matched.group(1)) if matched else None

    @staticmethod
    def get_sbd_device_from_config():
        '''
        Get sbd device list from config
        '''
        res = SBDUtils.get_sbd_value_from_config("SBD_DEVICE")
        return res.split(';') if res else []

    @staticmethod
    def is_using_diskless_sbd():
        '''
        Check if using diskless SBD
        '''
        if not ServiceManager().service_is_active(constants.SBD_SERVICE):
            return False
        return not bool(SBDUtils.get_sbd_device_from_config())

    @staticmethod
    def is_using_disk_based_sbd():
        '''
        Check if using disk-based SBD
        '''
        if not ServiceManager().service_is_active(constants.SBD_SERVICE):
            return False
        return bool(SBDUtils.get_sbd_device_from_config())

    @staticmethod
    def has_sbd_device_already_initialized(dev) -> bool:
        '''
        Check if sbd device already initialized
        '''
        cmd = "sbd -d {} dump".format(dev)
        rc, _, _ = ShellUtils().get_stdout_stderr(cmd)
        return rc == 0

    @staticmethod
    def no_overwrite_device_check(dev) -> bool:
        '''
        Check if device already initialized and ask if need to overwrite
        '''
        initialized = SBDUtils.has_sbd_device_already_initialized(dev)
        return initialized and \
                not bootstrap.confirm(f"{dev} has already been initialized by SBD - overwrite?")

    @staticmethod
    def check_devices_metadata_consistent(dev_list, quiet=False) -> bool:
        '''
        Check if all devices have the same metadata
        '''
        consistent = True
        if len(dev_list) < 2:
            return consistent
        first_dev_metadata = SBDUtils.get_sbd_device_metadata(dev_list[0], timeout_only=True)
        for dev in dev_list[1:]:
            this_dev_metadata = SBDUtils.get_sbd_device_metadata(dev, timeout_only=True)
            if this_dev_metadata != first_dev_metadata:
                if not quiet:
                    logger.error("Device %s doesn't have the same metadata as %s", dev, dev_list[0])
                consistent = False
        return consistent

    @staticmethod
    def handle_input_sbd_devices(dev_list, dev_list_from_config=None):
        '''
        Given a list of devices, split them into two lists:
        - overwrite_list: devices that need to be overwritten
        - no_overwrite_list: devices that don't need to be overwritten

        Raise TerminateSubCommand if the metadata of no_overwrite_list is not consistent
        '''
        no_overwrite_list = dev_list_from_config or []
        overwrite_list = []

        for dev in dev_list:
            if SBDUtils.no_overwrite_device_check(dev):
                no_overwrite_list.append(dev)
            else:
                overwrite_list.append(dev)

        if no_overwrite_list and not SBDUtils.check_devices_metadata_consistent(no_overwrite_list):
            raise utils.TerminateSubCommand

        return overwrite_list, no_overwrite_list

    @staticmethod
    def diskbased_sbd_configured() -> bool:
        return bool(SBDUtils.get_sbd_device_from_config())

    @staticmethod
    def diskless_sbd_configured() -> bool:
        value = utils.get_property("fencing-watchdog-timeout")
        return value and utils.crm_msec(value) > 0


class SBDTimeout(object):
    '''
    Consolidate sbd related timeout methods and constants
    '''
    SBD_WATCHDOG_TIMEOUT_DEFAULT = 5
    SBD_WATCHDOG_TIMEOUT_DEFAULT_S390 = 15
    SBD_WATCHDOG_TIMEOUT_DEFAULT_WITH_QDEVICE = 35
    QDEVICE_SYNC_TIMEOUT_MARGIN = 5
    SHOW_SBD_START_TIMEOUT_CMD = "systemctl daemon-reload; systemctl show -p TimeoutStartUSec sbd.service --value"
    SHOW_DEFAULT_START_TIMEOUT_CMD = "systemctl show -p DefaultTimeoutStartUSec --value"

    def __init__(self, context=None):
        '''
        Init function
        '''
        self.context = context
        self.disk_based = None
        self.sbd_msgwait = None
        self.fencing_timeout = None
        self.sbd_watchdog_timeout = self.SBD_WATCHDOG_TIMEOUT_DEFAULT
        self.fencing_watchdog_timeout = None
        self.two_node_without_qdevice = False
        self.crashdump_watchdog_timeout = None
        self.sbd_msgwait_expected = None
        self.sbd_watchdog_timeout_expected = None
        self.quiet = False
        if self.context:
            self.quiet = self.context.quiet
            self._initialize_timeout_from_bootstrap()

    def _log_when_not_quiet(self, level, message, *args, **kwargs):
        if not self.quiet:
            logger.log(level, message, *args, **kwargs)

    def _initialize_timeout_from_bootstrap(self):
        self._set_sbd_watchdog_timeout()
        if self.context.diskless_sbd:
            self._adjust_sbd_watchdog_timeout_with_diskless_and_qdevice()
        else:
            self._set_sbd_msgwait()

    def _set_sbd_watchdog_timeout(self):
        '''
        Set sbd_watchdog_timeout from profiles.yml if exists
        Then adjust it if in s390 environment
        '''
        if "sbd.watchdog_timeout" in self.context.profiles_dict:
            self.sbd_watchdog_timeout = int(self.context.profiles_dict["sbd.watchdog_timeout"])
        if self.context.is_s390 and self.sbd_watchdog_timeout < self.SBD_WATCHDOG_TIMEOUT_DEFAULT_S390:
            self._log_when_not_quiet(
                logging.WARNING,
                "sbd watchdog_timeout is set to %d for s390, it was %d",
                self.SBD_WATCHDOG_TIMEOUT_DEFAULT_S390, self.sbd_watchdog_timeout
            )
            self.sbd_watchdog_timeout = self.SBD_WATCHDOG_TIMEOUT_DEFAULT_S390

    def _set_sbd_msgwait(self):
        '''
        Set sbd msgwait from profiles.yml if exists
        Default is 2 * sbd_watchdog_timeout
        '''
        sbd_msgwait_default = 2 * self.sbd_watchdog_timeout
        sbd_msgwait = sbd_msgwait_default
        if "sbd.msgwait" in self.context.profiles_dict:
            sbd_msgwait = int(self.context.profiles_dict["sbd.msgwait"])
            if sbd_msgwait < sbd_msgwait_default:
                self._log_when_not_quiet(
                    logging.WARNING,
                    "sbd msgwait is set to %d, it was %d",
                    sbd_msgwait_default, sbd_msgwait
                )
                sbd_msgwait = sbd_msgwait_default
        self.sbd_msgwait = sbd_msgwait

    def _adjust_sbd_watchdog_timeout_with_diskless_and_qdevice(self):
        '''
        When using diskless SBD with Qdevice, adjust value of sbd_watchdog_timeout
        '''
        # add sbd after qdevice started
        if corosync.is_qdevice_configured() and ServiceManager().service_is_active("corosync-qdevice.service"):
            qdevice_sync_timeout = utils.get_qdevice_sync_timeout()
            if self.sbd_watchdog_timeout <= qdevice_sync_timeout:
                watchdog_timeout_with_qdevice = qdevice_sync_timeout + self.QDEVICE_SYNC_TIMEOUT_MARGIN
                self._log_when_not_quiet(
                    logging.WARNING,
                    "SBD_WATCHDOG_TIMEOUT should not less than %d for qdevice, it was %d",
                    watchdog_timeout_with_qdevice, self.sbd_watchdog_timeout
                )
                self.sbd_watchdog_timeout = watchdog_timeout_with_qdevice
        # add sbd and qdevice together from beginning
        elif self.context.qdevice_inst:
            if self.sbd_watchdog_timeout < self.SBD_WATCHDOG_TIMEOUT_DEFAULT_WITH_QDEVICE:
                self._log_when_not_quiet(
                    logging.WARNING,
                    "SBD_WATCHDOG_TIMEOUT should not less than %d for qdevice, it was %d",
                    self.SBD_WATCHDOG_TIMEOUT_DEFAULT_WITH_QDEVICE, self.sbd_watchdog_timeout
                )
                self.sbd_watchdog_timeout = self.SBD_WATCHDOG_TIMEOUT_DEFAULT_WITH_QDEVICE

    @staticmethod
    def get_sbd_watchdog_timeout() -> int:
        '''
        Get SBD_WATCHDOG_TIMEOUT from /etc/sysconfig/sbd
        '''
        res = SBDUtils.get_sbd_value_from_config("SBD_WATCHDOG_TIMEOUT")
        if not res:
            raise ValueError("Cannot get the value of SBD_WATCHDOG_TIMEOUT")
        return int(res)

    def get_fencing_watchdog_timeout_expected(self):
        if self.crashdump_watchdog_timeout:
            return SBDTimeout.get_sbd_watchdog_timeout() + self.crashdump_watchdog_timeout
        else:
            return 2 * SBDTimeout.get_sbd_watchdog_timeout()

    def _load_configurations_from_runtime(self):
        '''
        Load necessary configurations for both disk-based/disk-less sbd
        '''
        self.two_node_without_qdevice = utils.is_2node_cluster_without_qdevice()
        self.crashdump_watchdog_timeout = SBDUtils.get_crashdump_watchdog_timeout()
        dev_list = SBDUtils.get_sbd_device_from_config()
        if dev_list:  # disk-based
            self.disk_based = True
            first_dev = dev_list[0]
            device_metadata = SBDUtils.get_sbd_device_metadata(first_dev)
            self.sbd_msgwait = device_metadata.get("msgwait")
            self.sbd_watchdog_timeout = device_metadata.get("watchdog")
            self.pcmk_delay_max = utils.get_pcmk_delay_max(self.two_node_without_qdevice)
        else:  # disk-less
            self.disk_based = False
            self.sbd_watchdog_timeout = SBDTimeout.get_sbd_watchdog_timeout()
            self.fencing_watchdog_timeout = self.get_fencing_watchdog_timeout_expected()
        self.sbd_delay_start_value_expected = self.get_sbd_delay_start_expected() if utils.detect_virt() else "no"
        self.sbd_delay_start_value_from_config = SBDUtils.get_sbd_value_from_config("SBD_DELAY_START")
        if not self.sbd_delay_start_value_from_config:
            logger.error("No SBD_DELAY_START entry found in %s", SBDManager.SYSCONFIG_SBD)
            raise utils.TerminateSubCommand
        self.sbd_systemd_start_timeout_expected = self.get_sbd_systemd_start_timeout_expected()

        logger.debug("Inspect SBDTimeout: %s", vars(self))

    @classmethod
    def get_sbd_metadata_expected(cls) -> tuple[int, int]:
        '''
        Get the expected sbd watchdog timeout and msgwait for disk-based sbd
        Make sure the expected msgwait >= 2 * expected watchdog timeout
        '''
        instance = cls()
        instance._load_configurations_from_runtime()
        expected_watchdog_timeout = max(SBDTimeout.get_sbd_watchdog_timeout_expected(), instance.sbd_watchdog_timeout)
        if instance.crashdump_watchdog_timeout:
            msgwait_from_formula = 2 * expected_watchdog_timeout + instance.crashdump_watchdog_timeout
        else:
            msgwait_from_formula = 2 * expected_watchdog_timeout
        expected_msgwait = max(msgwait_from_formula, instance.sbd_msgwait)

        return expected_watchdog_timeout, expected_msgwait

    @classmethod
    def get_sbd_watchdog_timeout_expected(cls, diskless: bool = False) -> int:
        '''
        Get the expected:
        - watchdog timeout for disk-based sbd
        - SBD_WATCHDOG_TIMEOUT for disk-less sbd

        The value might be from profiles.yml, or the default values
        '''
        context = bootstrap.Context()
        context.diskless_sbd = diskless
        context.quiet = True
        context.load_profiles()
        return cls(context).sbd_watchdog_timeout

    def get_fencing_timeout_expected(self) -> int:
        '''
        Get fencing-timeout value for sbd cases, formulas are:

        value_from_sbd = 1.2 * msgwait # for disk-based sbd
        value_from_sbd = 1.2 * max (fencing_watchdog_timeout, 2*SBD_WATCHDOG_TIMEOUT) # for disk-less sbd

        fencing_timeout = max(value_from_sbd, constants.FENCING_TIMEOUT_DEFAULT) + token + consensus
        '''
        if self.disk_based:
            value_from_sbd = int(1.2*self.sbd_msgwait)
        else:
            value_from_sbd = int(1.2*max(self.fencing_watchdog_timeout, 2*self.sbd_watchdog_timeout))

        value = max(value_from_sbd, constants.FENCING_TIMEOUT_DEFAULT) + corosync.token_and_consensus_timeout()
        logger.debug("Result of SBDTimeout.get_fencing_timeout_expected %d", value)
        return value

    @classmethod
    def get_fencing_timeout(cls) -> int:
        cls_inst = cls()
        cls_inst._load_configurations_from_runtime()
        return cls_inst.get_fencing_timeout_expected()

    def get_sbd_delay_start_expected(self) -> int:
        '''
        Get the value for SBD_DELAY_START, formulas are:

        SBD_DELAY_START = (token + consensus + pcmk_delay_max + msgwait)  # for disk-based sbd
        SBD_DELAY_START = (token + consensus + 2*SBD_WATCHDOG_TIMEOUT) # for disk-less sbd
        '''
        token_and_consensus_timeout = corosync.token_and_consensus_timeout()
        if self.disk_based:
            value = token_and_consensus_timeout + self.pcmk_delay_max + self.sbd_msgwait
        else:
            value = token_and_consensus_timeout + 2*self.sbd_watchdog_timeout
        return value

    def get_sbd_systemd_start_timeout_expected(self) -> int:
        default_value = SBDTimeout.get_default_systemd_start_timeout()
        if self.sbd_delay_start_value_from_config.isdigit():
            calculated_value = int(1.2*int(self.sbd_delay_start_value_from_config))
            return max(calculated_value, default_value)
        else:
            return default_value

    @staticmethod
    def is_sbd_delay_start() -> bool:
        '''
        Check if SBD_DELAY_START is not no or not set
        '''
        res = SBDUtils.get_sbd_value_from_config("SBD_DELAY_START")
        return res and res != "no"

    @staticmethod
    def get_sbd_systemd_start_timeout(host=None) -> int:
        out = sh.cluster_shell().get_stdout_or_raise_error(SBDTimeout.SHOW_SBD_START_TIMEOUT_CMD, host)
        return utils.get_systemd_timeout_start_in_sec(out)

    @staticmethod
    def get_default_systemd_start_timeout() -> int:
        out = sh.cluster_shell().get_stdout_or_raise_error(SBDTimeout.SHOW_DEFAULT_START_TIMEOUT_CMD)
        return utils.get_systemd_timeout_start_in_sec(out)

    @staticmethod
    def able_to_set_fencing_watchdog_timeout(name: str, value: int) -> bool:
        '''
        Check if able to set fencing-watchdog-timeout or stonith-watchdog-timeout property
        '''
        if not ServiceManager().service_is_active(constants.SBD_SERVICE):
            logger.error("Can't set %s because sbd.service is not active", name)
            return False

        expected_fencing_watchdog_timeout = 2 * SBDTimeout.get_sbd_watchdog_timeout()
        if value == -1:
            logger.warning(
                "It's recommended to set %s to a positive value (at least 2*SBD_WATCHDOG_TIMEOUT: %d)",
                name, expected_fencing_watchdog_timeout
            )
            return True
        elif value < expected_fencing_watchdog_timeout:
            logger.error(
                "It's required to set %s to at least 2*SBD_WATCHDOG_TIMEOUT: %d",
                name, expected_fencing_watchdog_timeout
            )
            return False
        return True

    @staticmethod
    def get_timeout_minimum_value(timeout_type: str, diskless: bool = False) -> int:
        match timeout_type:
            case "allocate":
                return 2
            case "loop":
                return 1
            case "crashdump-watchdog":
                return 1
            case "watchdog":
                return SBDTimeout.get_sbd_watchdog_timeout_expected(diskless=diskless)
            case "msgwait":
                return 2 * SBDTimeout.get_sbd_watchdog_timeout_expected()
            case _:
                raise ValueError(f"Unknown timeout type: {timeout_type}")


class FixFailure(ValueError):
    pass


class FixAborted(ValueError):
    pass


class CheckResult(Enum):
    SUCCESS = 0
    WARNING = 1
    ERROR = 2
    __str__ = lambda self: self.name


class SBDCheckItem(IntEnum):
    SBD_DISK_METADATA = 0
    SBD_DEVICE_METADATA_CONSISTENCY = auto()
    SBD_WATCHDOG_TIMEOUT = auto()
    FENCE_SBD_AGENT = auto()
    SBD_DELAY_START = auto()
    SBD_SYSTEMD_START_TIMEOUT = auto()
    FENCING_WATCHDOG_TIMEOUT_PROPERTY = auto()
    FENCING_TIMEOUT_PROPERTY = auto()
    STONITH_ENABLED_PROPERTY = auto()
    UNSET_SBD_DELAY_START_IN_DROPIN = auto()
    ENABLE_SBD_SERVICE = auto()


class SBDConfigChecker(SBDTimeout):

    def __init__(self, quiet=False, fix=False):
        super().__init__()
        self.quiet = quiet
        self.fix = fix
        self.peer_node_list = []
        self.service_disabled_node_list = []

    @staticmethod
    def _return_helper(check_res_list: list[CheckResult]) -> CheckResult:
        if all(res == CheckResult.SUCCESS for res in check_res_list):
            return CheckResult.SUCCESS
        elif any(res == CheckResult.ERROR for res in check_res_list):
            return CheckResult.ERROR
        else:
            return CheckResult.WARNING

    @staticmethod
    def log_and_return(check_res: CheckResult, fix_flag: bool = False) -> bool:
        if check_res == CheckResult.SUCCESS:
            logger.info('SBD: Check sbd timeout configuration: OK.')
            return True
        cmd = "crm cluster health sbd --fix"
        issue_type = "error" if check_res == CheckResult.ERROR else "warning"
        if not fix_flag:
            logger.info(f'Please run "{cmd}" to fix the above {issue_type} on the running cluster')
        if check_res == CheckResult.ERROR:
            logger.error("SBD: Check sbd timeout configuration: FAIL.")
            return False
        elif check_res == CheckResult.WARNING:
            logger.info('SBD: Check sbd timeout configuration: OK.')
            return True

    def _check_and_fix_items(self) -> list[tuple]:
        return  [
            # issue name, check method, fix method, SSH required, prerequisites checks
            (
                "SBD disk metadata",
                self._check_sbd_disk_metadata,
                self._fix_sbd_disk_metadata,
                True,
                []
            ),

            (
                "SBD devices metadata consistency",
                self._check_sbd_device_metadata_consistency,
                self._fix_sbd_device_metadata_consistency,
                True,
                [SBDCheckItem.SBD_DISK_METADATA]
            ),

            (
                "SBD_WATCHDOG_TIMEOUT",
                self._check_sbd_watchdog_timeout,
                self._fix_sbd_watchdog_timeout,
                True,
                []
            ),

            (
                "fence_sbd agent",
                self._check_fence_sbd,
                self._fix_fence_sbd,
                False,
                []
            ),

            (
                "SBD_DELAY_START",
                self._check_sbd_delay_start,
                self._fix_sbd_delay_start,
                True,
                [
                    SBDCheckItem.SBD_DISK_METADATA,
                    SBDCheckItem.SBD_WATCHDOG_TIMEOUT,
                    SBDCheckItem.FENCE_SBD_AGENT
                ]
            ),

            (
                "systemd start timeout for sbd.service",
                self._check_sbd_systemd_start_timeout,
                self._fix_sbd_systemd_start_timeout,
                True,
                [SBDCheckItem.SBD_DELAY_START]
            ),

            (
                "fencing-watchdog-timeout property",
                self._check_fencing_watchdog_timeout,
                self._fix_fencing_watchdog_timeout,
                False,
                [SBDCheckItem.SBD_WATCHDOG_TIMEOUT]
            ),

            (
                "fencing-timeout property",
                self._check_fencing_timeout,
                self._fix_fencing_timeout,
                False,
                [
                    SBDCheckItem.SBD_DISK_METADATA,
                    SBDCheckItem.SBD_WATCHDOG_TIMEOUT
                ]
            ),

            (
                "fencing-enabled property",
                self._check_fencing_enabled,
                self._fix_fencing_enabled,
                False,
                []
            ),

            (
                "unset SBD_DELAY_START in drop-in file",
                self._check_sbd_delay_start_unset_dropin,
                self._fix_sbd_delay_start_unset_dropin,
                True,
                []
            ),

            (
                "sbd.service should be enabled",
                self._check_sbd_service_is_enabled,
                self._fix_sbd_service_is_enabled,
                True,
                []
            ),
        ]

    def check_and_fix(self) -> CheckResult:
        if not ServiceManager().service_is_active(constants.SBD_SERVICE):
            if self.fix:
                raise FixAborted("%s is not active, skip fixing SBD timeout issues" % constants.SBD_SERVICE)
            elif not SBDUtils.diskbased_sbd_configured() and not SBDUtils.diskless_sbd_configured():
                raise FixAborted("Neither disk-based nor disk-less SBD is configured, skip checking SBD timeout issues")

        all_nodes_reachable = True
        self.peer_node_list = utils.list_cluster_nodes_except_me()
        error_msg = ""
        try:
            utils.check_all_nodes_reachable("check and fix SBD timeout configurations")
        except (utils.DeadNodeError, utils.UnreachableNodeError) as e:
            self.peer_node_list = e.summary.reachable_nodes
            all_nodes_reachable = False
            error_msg = str(e)

        if not self._check_config_consistency(error_msg):
            raise FixAborted("All other checks aborted due to inconsistent configurations")

        self._load_configurations_from_runtime()

        check_and_fix_items = self._check_and_fix_items()
        check_res_list = [CheckResult.SUCCESS for _ in range(len(check_and_fix_items))]
        for index, (name, check_method, fix_method, ssh_required, prereq_checks) in enumerate(check_and_fix_items):
            if prereq_checks and any(check_res_list[p.value] != CheckResult.SUCCESS for p in prereq_checks):
                check_res_list[index] = CheckResult.ERROR
                continue
            check_res = check_method()
            logger.debug("SBD Checking: %s, result: %s", name, check_res)
            check_res_list[index] = check_res
            if check_res == CheckResult.SUCCESS:
                continue
            elif ssh_required and not all_nodes_reachable:
                raise FixAborted(f"Cannot fix {name} issue: {error_msg}")
            elif self.fix:
                fix_method()
                self._load_configurations_from_runtime()
                check_res = check_method()
                logger.debug("SBD Re-Checking after fixing: %s, result: %s", name, check_res)
                if check_res == CheckResult.SUCCESS:
                    check_res_list[index] = check_res
                else:
                    raise FixFailure(f"Failed to fix {name} issue")

        return SBDConfigChecker._return_helper(check_res_list)

    def _check_config_consistency(self, error_msg: str = "") -> bool:
        consistent = True

        if not self.peer_node_list:
            if error_msg:
                logger.warning("Skipping configuration consistency check: %s", error_msg)
            return consistent

        # ignore comments and blank lines
        ignore_pattern = "^#\\|^[[:space:]]*$"
        me = utils.this_node()
        for target_file in (corosync.conf(), SBDManager.SYSCONFIG_SBD):
            diff_output = utils.remote_diff_this(
                target_file,
                self.peer_node_list,
                me,
                ignore_pattern=ignore_pattern,
                quiet=True
            )
            if diff_output:
                logger.error("%s is not consistent across cluster nodes", target_file)
                print(diff_output)
                consistent = False

        if not consistent and error_msg:
            logger.warning(error_msg)
        return consistent

    def _check_sbd_device_metadata_consistency(self) -> CheckResult:
        configured_devices = SBDUtils.get_sbd_device_from_config()
        if not SBDUtils.check_devices_metadata_consistent(configured_devices, self.quiet):
            return CheckResult.ERROR
        return CheckResult.SUCCESS

    def _fix_sbd_device_metadata_consistency(self) -> None:
        first_dev = SBDUtils.get_sbd_device_from_config()[0]
        logger.info("Syncing sbd metadata from %s to other devices", first_dev)
        self._fix_sbd_disk_metadata()

    def _check_sbd_disk_metadata(self) -> CheckResult:
        '''
        For disk-based SBD, check if the sbd msgwait and watchdog timeout are below expected values
        '''
        if self.disk_based:
            self.sbd_watchdog_timeout_expected, self.sbd_msgwait_expected = SBDTimeout.get_sbd_metadata_expected()
            if self.sbd_watchdog_timeout < self.sbd_watchdog_timeout_expected:
                self._log_when_not_quiet(
                    logging.ERROR,
                    "It's required that SBD watchdog timeout(now %d) >= %d",
                    self.sbd_watchdog_timeout, self.sbd_watchdog_timeout_expected
                )
                return CheckResult.ERROR
            if self.sbd_msgwait < self.sbd_msgwait_expected:
                self._log_when_not_quiet(
                    logging.ERROR,
                    "It's required that SBD msgwait(now %d) >= %d",
                    self.sbd_msgwait, self.sbd_msgwait_expected
                )
                return CheckResult.ERROR
        return CheckResult.SUCCESS

    def _fix_sbd_disk_metadata(self) -> None:
        if self.sbd_msgwait_expected is None or self.sbd_watchdog_timeout_expected is None:
            self.sbd_watchdog_timeout_expected, self.sbd_msgwait_expected = SBDTimeout.get_sbd_metadata_expected()
        logger.info("Adjusting sbd msgwait to %d, watchdog timeout to %d", self.sbd_msgwait_expected, self.sbd_watchdog_timeout_expected)
        cmd = f"crm sbd configure msgwait-timeout={self.sbd_msgwait_expected} watchdog-timeout={self.sbd_watchdog_timeout_expected}"
        output = sh.cluster_shell().get_stdout_or_raise_error(cmd)
        if output:
            print(output)

    def _check_sbd_watchdog_timeout(self) -> CheckResult:
        '''
        For diskless SBD, check if SBD_WATCHDOG_TIMEOUT is below expected value
        '''
        if not self.disk_based:
            self.sbd_watchdog_timeout_expected = SBDTimeout.get_sbd_watchdog_timeout_expected(diskless=True)
            if self.sbd_watchdog_timeout < self.sbd_watchdog_timeout_expected:
                self._log_when_not_quiet(
                    logging.ERROR,
                    "It's required that SBD_WATCHDOG_TIMEOUT(now %d) >= %d",
                    self.sbd_watchdog_timeout, self.sbd_watchdog_timeout_expected
                )
                return CheckResult.ERROR
        return CheckResult.SUCCESS

    def _fix_sbd_watchdog_timeout(self):
        SBDManager.update_sbd_configuration({"SBD_WATCHDOG_TIMEOUT": str(self.sbd_watchdog_timeout_expected)})

    def _check_sbd_delay_start(self) -> CheckResult:
        expected_value = str(self.sbd_delay_start_value_expected)
        config_value = self.sbd_delay_start_value_from_config
        if config_value == expected_value:
            return CheckResult.SUCCESS
        elif config_value.isdigit() and expected_value.isdigit():
            if int(config_value) < int(expected_value):
                self._log_when_not_quiet(
                    logging.ERROR,
                    "It's required that SBD_DELAY_START is set to %s, now is %s",
                    expected_value, config_value
                )
                return CheckResult.ERROR
            else:
                self._log_when_not_quiet(
                    logging.WARNING,
                    "It's recommended that SBD_DELAY_START is set to %s, now is %s",
                    expected_value, config_value
                )
                return CheckResult.WARNING
        else:
            self._log_when_not_quiet(
                logging.ERROR,
                "It's required that SBD_DELAY_START is set to %s, now is %s",
                expected_value, config_value
            )
            return CheckResult.ERROR

    def _fix_sbd_delay_start(self):
        advised_value = str(self.sbd_delay_start_value_expected)
        SBDManager.update_sbd_configuration({"SBD_DELAY_START": advised_value})

    def _check_sbd_systemd_start_timeout(self) -> CheckResult:
        expected_start_timeout = self.sbd_systemd_start_timeout_expected
        check_res_list = []
        for node in [utils.this_node()] + self.peer_node_list:
            actual_start_timeout = SBDTimeout.get_sbd_systemd_start_timeout(node)
            if actual_start_timeout == expected_start_timeout:
                check_res_list.append(CheckResult.SUCCESS)
            elif actual_start_timeout < expected_start_timeout:
                self._log_when_not_quiet(
                    logging.ERROR,
                    "It's required that systemd start timeout for sbd.service is set to %ds, now is %ds on node %s",
                    expected_start_timeout, actual_start_timeout, node
                )
                check_res_list.append(CheckResult.ERROR)
            else:
                self._log_when_not_quiet(
                    logging.WARNING,
                    "It's recommended that systemd start timeout for sbd.service is set to %ds, now is %ds on node %s",
                    expected_start_timeout, actual_start_timeout, node
                )
                check_res_list.append(CheckResult.WARNING)

        return SBDConfigChecker._return_helper(check_res_list)

    def _fix_sbd_systemd_start_timeout(self):
        logger.info("Adjusting systemd start timeout for sbd.service to %ds", self.sbd_systemd_start_timeout_expected)
        utils.mkdirp(SBDManager.SBD_SYSTEMD_DELAY_START_DIR)
        sbd_delay_start_file = os.path.join(SBDManager.SBD_SYSTEMD_DELAY_START_DIR, "sbd_delay_start.conf")
        utils.str2file(f"[Service]\nTimeoutStartSec={self.sbd_systemd_start_timeout_expected}", sbd_delay_start_file)
        bootstrap.sync_path(SBDManager.SBD_SYSTEMD_DELAY_START_DIR)
        utils.cluster_run_cmd("systemctl daemon-reload")

    def _check_fencing_watchdog_timeout(self) -> CheckResult:
        value = utils.get_property("fencing-watchdog-timeout", quiet=self.quiet)
        if value and int(value) == -1:
            self._log_when_not_quiet(
                logging.WARNING,
                "It's recommended that fencing-watchdog-timeout is set to %d, now is -1",
                self.fencing_watchdog_timeout
            )
            return CheckResult.WARNING
        value = int(utils.crm_msec(value)/1000)
        if self.disk_based:
            if value > 0:
                self._log_when_not_quiet(
                    logging.WARNING,
                    "It's recommended that fencing-watchdog-timeout is not set when using disk-based SBD"
                )
                return CheckResult.WARNING
        else:
            if value == 0:
                self._log_when_not_quiet(
                    logging.ERROR,
                    "It's required that fencing-watchdog-timeout is set to %d, now is not set",
                    self.fencing_watchdog_timeout
                )
                return CheckResult.ERROR
            if value < self.fencing_watchdog_timeout:
                self._log_when_not_quiet(
                    logging.ERROR,
                    "It's required that fencing-watchdog-timeout is set to %d, now is %d",
                    self.fencing_watchdog_timeout, value
                )
                return CheckResult.ERROR
            elif value > self.fencing_watchdog_timeout:
                self._log_when_not_quiet(
                    logging.WARNING,
                    "It's recommended that fencing-watchdog-timeout is set to %d, now is %d",
                    self.fencing_watchdog_timeout, value
                )
                return CheckResult.WARNING
        return CheckResult.SUCCESS

    def _fix_fencing_watchdog_timeout(self):
        utils.remove_legacy_properties("stonith-watchdog-timeout")
        if self.disk_based:
            logger.info("Removing fencing-watchdog-timeout property")
            utils.delete_property("fencing-watchdog-timeout")
        else:
            logger.info("Adjusting fencing-watchdog-timeout to %d", self.fencing_watchdog_timeout)
            utils.set_property("fencing-watchdog-timeout", self.fencing_watchdog_timeout)

    def _check_fencing_timeout(self) -> CheckResult:
        expected_value = self.get_fencing_timeout_expected()
        value = utils.get_property("fencing-timeout", quiet=self.quiet)
        # will get default value from pacemaker metadata if not set
        value = int(utils.crm_msec(value)/1000)
        if value < expected_value:
            self._log_when_not_quiet(
                logging.ERROR,
                "It's required that fencing-timeout is set to %d, now is %d",
                expected_value, value
            )
            return CheckResult.ERROR
        elif value > expected_value:
            self._log_when_not_quiet(
                logging.WARNING,
                "It's recommended that fencing-timeout is set to %d, now is %d",
                expected_value, value
            )
            return CheckResult.WARNING
        return CheckResult.SUCCESS

    def _fix_fencing_timeout(self):
        utils.remove_legacy_properties("stonith-timeout")
        expected_value = self.get_fencing_timeout_expected()
        logger.info("Adjusting fencing-timeout to %d", expected_value)
        utils.set_property("fencing-timeout", expected_value)

    def _check_fencing_enabled(self) -> CheckResult:
        value = utils.get_property("fencing-enabled", get_default=False, quiet=self.quiet)
        if utils.is_boolean_false(value):
            self._log_when_not_quiet(
                logging.ERROR,
                "It's required that fencing-enabled is set to true, now is false"
            )
            return CheckResult.ERROR
        return CheckResult.SUCCESS

    def _fix_fencing_enabled(self):
        utils.remove_legacy_properties("stonith-enabled")
        logger.info("Setting fencing-enabled to true")
        utils.set_property("fencing-enabled", "true")

    def _check_sbd_delay_start_unset_dropin(self) -> CheckResult:
        if not SBDTimeout.is_sbd_delay_start():
            return CheckResult.SUCCESS

        shell = sh.cluster_shell()
        check_res_list = []
        for node in [utils.this_node()] + self.peer_node_list:
            cmd = f"test -f {SBDManager.SBD_SYSTEMD_DELAY_START_DISABLE_FILE}"
            rc, _ = shell.get_rc_and_error(node, None, cmd)
            if rc == 0:
                check_res_list.append(CheckResult.SUCCESS)
            else:
                self._log_when_not_quiet(
                    logging.WARNING,
                    "Runtime drop-in file %s to unset SBD_DELAY_START is missing on node %s",
                    SBDManager.SBD_SYSTEMD_DELAY_START_DISABLE_FILE, node
                )
                check_res_list.append(CheckResult.WARNING)

        return SBDConfigChecker._return_helper(check_res_list)

    def _fix_sbd_delay_start_unset_dropin(self):
        logger.info("Createing runtime drop-in file %s to unset SBD_DELAY_START",
                    SBDManager.SBD_SYSTEMD_DELAY_START_DISABLE_FILE)
        SBDManager.unset_sbd_delay_start()

    def _check_sbd_service_is_enabled(self) -> CheckResult:
        service_manager = ServiceManager()
        check_res_list = []
        for node in [utils.this_node()] + self.peer_node_list:
            if service_manager.service_is_enabled(constants.SBD_SERVICE, node):
                check_res_list.append(CheckResult.SUCCESS)
            else:
                self._log_when_not_quiet(
                    logging.ERROR,
                    "%s is not enabled on node %s",
                    constants.SBD_SERVICE, node
                )
                self.service_disabled_node_list.append(node)
                check_res_list.append(CheckResult.ERROR)
        return SBDConfigChecker._return_helper(check_res_list)

    def _fix_sbd_service_is_enabled(self):
        service_manager = ServiceManager()
        for node in self.service_disabled_node_list:
            logger.info("Enabling %s on node %s", constants.SBD_SERVICE, node)
            service_manager.enable_service(constants.SBD_SERVICE, node)

    def _check_fence_sbd(self) -> CheckResult:
        if not self.disk_based:
            return CheckResult.SUCCESS
        xml_inst = xmlutil.CrmMonXmlParser()
        if xml_inst.not_connected():
            cib = xmlutil.text2elem(sh.cluster_shell().get_stdout_or_raise_error("crm configure show xml"))
            ra = cibquery.ResourceAgent("stonith", "", "fence_sbd")
            configured = cibquery.get_primitives_with_ra(cib, ra)
            if configured:
                return CheckResult.SUCCESS
            else:
                self._log_when_not_quiet(
                    logging.ERROR,
                    "Fence agent %s is not configured",
                    SBDManager.SBD_RA
                )
                return CheckResult.ERROR
        if not xml_inst.is_resource_configured(SBDManager.SBD_RA):
            self._log_when_not_quiet(
                logging.ERROR,
                "Fence agent %s is not configured",
                SBDManager.SBD_RA
            )
            return CheckResult.ERROR
        elif not xml_inst.is_resource_started(SBDManager.SBD_RA) and not utils.is_cluster_in_maintenance_mode():
            self._log_when_not_quiet(
                logging.ERROR,
                "Fence agent %s is not started",
                SBDManager.SBD_RA
            )
            return CheckResult.ERROR
        return CheckResult.SUCCESS

    def _fix_fence_sbd(self):
        xml_inst = xmlutil.CrmMonXmlParser()
        shell = sh.cluster_shell()
        if not xml_inst.is_resource_configured(SBDManager.SBD_RA):
            logger.info("Configuring fence agent %s", SBDManager.SBD_RA)
            cmd = f"crm configure primitive {SBDManager.SBD_RA_ID} {SBDManager.SBD_RA}"
            shell.get_stdout_or_raise_error(cmd)
            is_2node_wo_qdevice = utils.is_2node_cluster_without_qdevice()
            bootstrap.adjust_pcmk_delay_max(is_2node_wo_qdevice)
        elif not xml_inst.is_resource_started(SBDManager.SBD_RA):
            res_id_list = xml_inst.get_resource_id_list_via_type(SBDManager.SBD_RA)
            for res_id in res_id_list:
                logger.info("Starting fence agent %s", res_id)
                cmd = f"crm resource start {res_id}"
                shell.get_stdout_or_raise_error(cmd)
        time.sleep(2)


class SBDManager:
    SYSCONFIG_SBD = "/etc/sysconfig/sbd"
    SYSCONFIG_SBD_TEMPLATE = "/usr/share/fillup-templates/sysconfig.sbd"
    SBD_SYSTEMD_DELAY_START_DIR = "/etc/systemd/system/sbd.service.d"
    SBD_SYSTEMD_DELAY_START_DISABLE_DIR = "/run/systemd/system/sbd.service.d"
    SBD_SYSTEMD_DELAY_START_DISABLE_FILE = f"{SBD_SYSTEMD_DELAY_START_DISABLE_DIR}/sbd_delay_start_disabled.conf"
    SBD_STATUS_DESCRIPTION = '''Configure SBD:
  If you have shared storage, for example a SAN or iSCSI target,
  you can use it avoid split-brain scenarios by configuring SBD.
  This requires a 1 MB partition, accessible to all nodes in the
  cluster.  The device path must be persistent and consistent
  across all nodes in the cluster, so /dev/disk/by-id/* devices
  are a good choice.  Note that all data on the partition you
  specify here will be destroyed.
'''
    NO_SBD_WARNING = "Not configuring SBD - fence will be disabled."
    DISKLESS_SBD_MIN_EXPECTED_VOTE = 3
    DISKLESS_SBD_WARNING = "Diskless SBD requires cluster with three or more nodes. If you want to use diskless SBD for 2-node cluster, should be combined with QDevice."
    SBD_NOT_INSTALLED_MSG = "Package sbd is not installed"
    FENCE_SBD_NOT_INSTALLED_MSG = "Package fence-agents-sbd is not installed"
    SBD_RA = "stonith:fence_sbd"
    SBD_RA_ID = "fencing-sbd"
    SBD_DEVICE_MAX = 3

    class NotConfigSBD(Exception):
        pass

    def __init__(
        self,
        device_list_to_init: typing.List[str] | None = None,
        timeout_dict: typing.Dict[str, int] | None = None,
        update_dict: typing.Dict[str, str] | None = None,
        diskless_sbd: bool = False,
        bootstrap_context: 'bootstrap.Context | None' = None
    ):
        '''
        Init function which can be called from crm sbd subcommand or bootstrap
        '''
        self.device_list_to_init = device_list_to_init or []
        self.timeout_dict = timeout_dict or {}
        self.update_dict = update_dict or {}
        self.diskless_sbd = diskless_sbd
        self.cluster_is_running = ServiceManager().service_is_active(constants.PCMK_SERVICE)
        self.bootstrap_context = bootstrap_context
        self.overwrite_sysconfig = False

        # From bootstrap init or join process, override the values
        if self.bootstrap_context:
            self.overwrite_sysconfig = self.bootstrap_context.type == "init"
            self.diskless_sbd = self.bootstrap_context.diskless_sbd
            self.cluster_is_running = self.bootstrap_context.cluster_is_running

    def _load_attributes_from_bootstrap(self):
        if not self.bootstrap_context or not self.overwrite_sysconfig:
            return
        if not self.timeout_dict:
            timeout_inst = SBDTimeout(self.bootstrap_context)
            self.timeout_dict["watchdog"] = timeout_inst.sbd_watchdog_timeout
            if self.diskless_sbd:
                self.update_dict["SBD_WATCHDOG_TIMEOUT"] = str(timeout_inst.sbd_watchdog_timeout)
            else:
                self.timeout_dict["msgwait"] = timeout_inst.sbd_msgwait
        self.update_dict["SBD_WATCHDOG_DEV"] = watchdog.Watchdog.get_watchdog_device(self.bootstrap_context.watchdog)

    @staticmethod
    def convert_timeout_dict_to_opt_str(timeout_dict: typing.Dict[str, int]) -> str:
        timeout_option_map = {
            "watchdog": "-1",
            "allocate": "-2",
            "loop": "-3",
            "msgwait": "-4"
        }
        return ' '.join([f"{timeout_option_map[k]} {v}" for k, v in timeout_dict.items()
                         if k in timeout_option_map])

    def update_configuration(self) -> None:
        '''
        Update and sync sbd configuration
        '''
        if not self.update_dict:
            return
        if self.overwrite_sysconfig:
            utils.copy_local_file(self.SYSCONFIG_SBD_TEMPLATE, self.SYSCONFIG_SBD)

        for key, value in self.update_dict.items():
            logger.info("Update %s in %s: %s", key, self.SYSCONFIG_SBD, value)
        utils.sysconfig_set(self.SYSCONFIG_SBD, **self.update_dict)
        if self.cluster_is_running:
            bootstrap.sync_path(self.SYSCONFIG_SBD)

    @classmethod
    def update_sbd_configuration(cls, update_dict: typing.Dict[str, str]) -> None:
        inst = cls(update_dict=update_dict)
        inst.update_configuration()

    def initialize_sbd(self):
        if self.diskless_sbd:
            logger.info("Configuring diskless SBD")
            return
        elif self.device_list_to_init:
            logger.info("Configuring disk-based SBD")
        else:
            return

        opt_str = SBDManager.convert_timeout_dict_to_opt_str(self.timeout_dict)
        shell = sh.cluster_shell()
        for dev in self.device_list_to_init:
            logger.info("Initializing SBD device %s", dev)
            cmd = f"sbd {opt_str} -d {dev} create"
            logger.debug("Running command: %s", cmd)
            shell.get_stdout_or_raise_error(cmd)

    def enable_sbd_service(self):
        if self.cluster_is_running:
            cluster_nodes = utils.list_cluster_nodes()
        else:
            cluster_nodes = [utils.this_node()]
        service_manager = ServiceManager()

        for node in cluster_nodes:
            if not service_manager.service_is_enabled(constants.SBD_SERVICE, node):
                logger.info("Enable %s on node %s", constants.SBD_SERVICE, node)
                service_manager.enable_service(constants.SBD_SERVICE, node)

    @staticmethod
    def warn_diskless_sbd():
        '''
        Give warning when configuring diskless sbd
        '''
        if SBDUtils.is_using_diskless_sbd():
            vote_dict = utils.get_quorum_votes_dict()
            expected_vote = int(vote_dict.get('Expected', 0))
            if expected_vote < SBDManager.DISKLESS_SBD_MIN_EXPECTED_VOTE:
                logger.warning('%s', SBDManager.DISKLESS_SBD_WARNING)

    def _warn_and_raise_no_sbd(self):
        logger.warning('%s', self.NO_SBD_WARNING)
        raise self.NotConfigSBD

    def _wants_to_overwrite(self, configured_devices):
        wants_to_overwrite_msg = f"SBD_DEVICE in {self.SYSCONFIG_SBD} is already configured to use '{';'.join(configured_devices)}' - overwrite?"
        if not bootstrap.confirm(wants_to_overwrite_msg):
            if not SBDUtils.check_devices_metadata_consistent(configured_devices):
                raise utils.TerminateSubCommand
            self.overwrite_sysconfig = False
            return False
        return True

    def _prompt_for_sbd_device(self) -> list[str]:
        '''
        Prompt for sbd device and verify
        '''
        dev_list = []
        dev_looks_sane = False
        while not dev_looks_sane:
            dev = bootstrap.prompt_for_string('Path to storage device (e.g. /dev/disk/by-id/...), or "none" for diskless sbd, use ";" as separator for multi path', r'none|\/.*')
            if dev == "none":
                self.diskless_sbd = True
                return []

            dev_list = utils.re_split_string("[; ]", dev)
            try:
                SBDUtils.verify_sbd_device(dev_list)
            except ValueError as e:
                logger.error('%s', e)
                continue
            for dev in dev_list:
                if SBDUtils.has_sbd_device_already_initialized(dev):
                    dev_looks_sane = True
                    continue
                else:
                    logger.warning("All data on %s will be destroyed", dev)
                    if bootstrap.confirm('Are you sure you wish to use this device?'):
                        dev_looks_sane = True
                    else:
                        dev_looks_sane = False
                        break
        return dev_list

    def get_sbd_device_interactive(self) -> list[str]:
        '''
        Get sbd device on interactive mode
        '''
        if self.bootstrap_context.yes_to_all:
            self._warn_and_raise_no_sbd()
        logger.info(self.SBD_STATUS_DESCRIPTION)
        if not bootstrap.confirm("Do you wish to use SBD?"):
            self._warn_and_raise_no_sbd()
        if not utils.package_is_installed("sbd"):
            utils.fatal(self.SBD_NOT_INSTALLED_MSG)

        configured_devices = SBDUtils.get_sbd_device_from_config()
        # return empty list if already configured and user doesn't want to overwrite
        if configured_devices and not self._wants_to_overwrite(configured_devices):
            return_devices = []
        else:
            return_devices = self._prompt_for_sbd_device()

        if not self.diskless_sbd and not utils.package_is_installed("fence-agents-sbd"):
            utils.fatal(self.FENCE_SBD_NOT_INSTALLED_MSG)

        return return_devices

    def get_sbd_device_from_bootstrap(self):
        '''
        Handle sbd device input from 'crm cluster init' with -s or -S option
        -s is for disk-based sbd
        -S is for diskless sbd
        '''
        # if specified sbd device with -s option
        device_list = self.bootstrap_context.sbd_devices
        # else if not use -S option, get sbd device interactively
        if not device_list and not self.bootstrap_context.diskless_sbd:
            device_list = self.get_sbd_device_interactive()
        if not device_list:
            return

        # get two lists of devices, one for overwrite, one for no overwrite with consistent metadata
        overwrite_list, no_overwrite_list = SBDUtils.handle_input_sbd_devices(device_list)
        self.device_list_to_init = overwrite_list
        # if no_overwrite_list is not empty, get timeout metadata from the first device
        if no_overwrite_list:
            self.timeout_dict = SBDUtils.get_sbd_device_metadata(no_overwrite_list[0], timeout_only=True)
        self.update_dict["SBD_DEVICE"] = ';'.join(device_list)

    def init_and_deploy_sbd(self, restart_first=False):
        '''
        The process of deploying sbd includes:
        1. Initialize sbd device
        2. Write config file /etc/sysconfig/sbd
        3. Enable sbd.service
        4. Restart cluster service if possible
        5. Configure fencing-sbd resource and related properties
        '''
        if self.bootstrap_context:
            try:
                self.get_sbd_device_from_bootstrap()
            except self.NotConfigSBD:
                ServiceManager().disable_service(constants.SBD_SERVICE)
                return
            self._load_attributes_from_bootstrap()

        with utils.leverage_maintenance_mode() as enabled:
            if not utils.able_to_restart_cluster(enabled):
                return

            self.initialize_sbd()
            self.update_configuration()
            self.enable_sbd_service()

            if self.cluster_is_running:

                # If diskless SBD is being added and sbd.service is not running, like running:
                #     crm cluster init sbd -S -y
                # the cluster must be restarted first to activate sbd.service on all nodes.
                # Only then should additional properties be configured,
                # because the fencing-watchdog-timeout property requires sbd.service to be active.
                restart_cluster_first = restart_first or \
                        not self.diskless_sbd or \
                        not ServiceManager().service_is_active(constants.SBD_SERVICE)
                if restart_cluster_first:
                    bootstrap.restart_cluster()

                bootstrap.adjust_properties()

                # In other cases, it is better to restart the cluster
                # after modifying SBD-related configurations.
                # This helps prevent unexpected issues, such as nodes being fenced
                # due to large SBD_WATCHDOG_TIMEOUT values combined with smaller timeouts.
                if not restart_cluster_first:
                    bootstrap.restart_cluster()

    def join_sbd(self, remote_user, peer_host):
        '''
        Function join_sbd running on join process only
        On joining process, check whether peer node has enabled sbd.service
        If so, check prerequisites of SBD and verify sbd device on join node
        '''
        service_manager = ServiceManager()
        if not os.path.exists(self.SYSCONFIG_SBD) or not service_manager.service_is_enabled(constants.SBD_SERVICE, peer_host):
            service_manager.disable_service(constants.SBD_SERVICE)
            return

        if not utils.package_is_installed("sbd"):
            utils.fatal(self.SBD_NOT_INSTALLED_MSG)
        dev_list = SBDUtils.get_sbd_device_from_config()
        if dev_list and not utils.package_is_installed("fence-agents-sbd"):
            utils.fatal(self.FENCE_SBD_NOT_INSTALLED_MSG)

        self._watchdog_inst = watchdog.Watchdog(remote_user=remote_user, peer_host=peer_host)
        self._watchdog_inst.join_watchdog()

        if dev_list:
            SBDUtils.verify_sbd_device(dev_list, [peer_host])

        logger.info("Got {}SBD configuration".format("" if dev_list else "diskless "))
        self.enable_sbd_service()

    @staticmethod
    def unset_sbd_delay_start(node_list: list[str] | None = None):
        if ServiceManager().service_is_enabled(constants.SBD_SERVICE) and SBDTimeout.is_sbd_delay_start():
            cmd = f"mkdir -p {SBDManager.SBD_SYSTEMD_DELAY_START_DISABLE_DIR} && " \
                  f"echo -e '[Service]\\nUnsetEnvironment=SBD_DELAY_START' > {SBDManager.SBD_SYSTEMD_DELAY_START_DISABLE_FILE} && " \
                  "systemctl daemon-reload"
            utils.cluster_run_cmd(cmd, node_list)


def cleanup_existing_sbd_resource():
    if xmlutil.CrmMonXmlParser().is_resource_configured(SBDManager.SBD_RA):
        sbd_id_list = xmlutil.CrmMonXmlParser().get_resource_id_list_via_type(SBDManager.SBD_RA)
        if xmlutil.CrmMonXmlParser().is_resource_started(SBDManager.SBD_RA):
            for sbd_id in sbd_id_list:
                logger.info("Stop sbd resource '%s'(%s)", sbd_id, SBDManager.SBD_RA)
                utils.ext_cmd("crm resource stop {}".format(sbd_id))
        logger.info("Remove sbd resource '%s'", ';' .join(sbd_id_list))
        utils.ext_cmd("crm configure delete {}".format(' '.join(sbd_id_list)))


def cleanup_sbd_configurations(remote=None):
    shell = sh.cluster_shell()
    sysconfig_sbd_bak = f"{SBDManager.SYSCONFIG_SBD}.bak"
    logger.info("Rename %s to %s on node %s",
                SBDManager.SYSCONFIG_SBD, sysconfig_sbd_bak, remote or utils.this_node())
    cmd = f"test -f {SBDManager.SYSCONFIG_SBD} && mv {SBDManager.SYSCONFIG_SBD} {sysconfig_sbd_bak} || exit 0"
    shell.get_stdout_or_raise_error(cmd, host=remote)

    for _dir in [SBDManager.SBD_SYSTEMD_DELAY_START_DIR, SBDManager.SBD_SYSTEMD_DELAY_START_DISABLE_DIR]:
        cmd = f"test -d {_dir} && rm -rf {_dir} && systemctl daemon-reload || exit 0"
        shell.get_stdout_or_raise_error(cmd, host=remote)


def purge_sbd_from_cluster():
    '''
    Purge SBD from cluster, the process includes:
    - stop and remove sbd agent
    - disable sbd.service
    - move /etc/sysconfig/sbd to /etc/sysconfig/sbd.bak
    - adjust cluster attributes
    - adjust related timeout values
    '''
    cleanup_existing_sbd_resource()

    cluster_nodes = utils.list_cluster_nodes()
    service_manager = ServiceManager()
    for node in cluster_nodes:
        if service_manager.service_is_enabled(constants.SBD_SERVICE, node):
            logger.info("Disable %s on node %s", constants.SBD_SERVICE, node)
            service_manager.disable_service(constants.SBD_SERVICE, node)
        cleanup_sbd_configurations(node)

    out = sh.cluster_shell().get_stdout_or_raise_error("stonith_admin -L")
    res = re.search("([0-9]+) fence device[s]* found", out)
    # after disable sbd.service, check if sbd is the last fence device
    if res and int(res.group(1)) <= 1:
        utils.cleanup_fencing_related_properties()
