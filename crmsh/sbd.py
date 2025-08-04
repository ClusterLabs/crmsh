import os
import re
import typing
import shutil
from . import utils, sh
from . import bootstrap
from . import log
from . import constants
from . import corosync
from . import xmlutil
from . import watchdog
from . import parallax
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
        try:
            out = sh.cluster_shell().get_stdout_or_raise_error(f"sbd -d {dev} dump", remote)
        except Exception:
            return sbd_info

        pattern = r"UUID\s+:\s+(\S+)|Timeout\s+\((\w+)\)\s+:\s+(\d+)"
        matches = re.findall(pattern, out)
        for uuid, timeout_type, timeout_value in matches:
            if uuid and not timeout_only:
                sbd_info["uuid"] = uuid
            elif timeout_type and timeout_value:
                sbd_info[timeout_type] = int(timeout_value)
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
    def check_devices_metadata_consistent(dev_list) -> bool:
        '''
        Check if all devices have the same metadata
        '''
        consistent = True
        if len(dev_list) < 2:
            return consistent
        first_dev_metadata = SBDUtils.get_sbd_device_metadata(dev_list[0], timeout_only=True)
        if not first_dev_metadata:
            logger.warning(f"Cannot get metadata for {dev_list[0]}")
            return False
        for dev in dev_list[1:]:
            this_dev_metadata = SBDUtils.get_sbd_device_metadata(dev, timeout_only=True)
            if not this_dev_metadata:
                logger.warning(f"Cannot get metadata for {dev}")
                return False
            if this_dev_metadata != first_dev_metadata:
                logger.warning(f"Device {dev} doesn't have the same metadata as {dev_list[0]}")
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


class SBDTimeout(object):
    '''
    Consolidate sbd related timeout methods and constants
    '''
    SBD_WATCHDOG_TIMEOUT_DEFAULT = 5
    SBD_WATCHDOG_TIMEOUT_DEFAULT_S390 = 15
    SBD_WATCHDOG_TIMEOUT_DEFAULT_WITH_QDEVICE = 35
    QDEVICE_SYNC_TIMEOUT_MARGIN = 5
    SHOW_SBD_START_TIMEOUT_CMD = "systemctl show -p TimeoutStartUSec sbd.service --value"

    def __init__(self, context=None):
        '''
        Init function
        '''
        self.context = context
        self.sbd_msgwait = None
        self.stonith_timeout = None
        self.sbd_watchdog_timeout = self.SBD_WATCHDOG_TIMEOUT_DEFAULT
        self.stonith_watchdog_timeout = None
        self.two_node_without_qdevice = False

    def initialize_timeout(self):
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
            logger.warning("sbd_watchdog_timeout is set to %d for s390, it was %d", self.SBD_WATCHDOG_TIMEOUT_DEFAULT_S390, self.sbd_watchdog_timeout)
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
                logger.warning("sbd msgwait is set to %d, it was %d", sbd_msgwait_default, sbd_msgwait)
                sbd_msgwait = sbd_msgwait_default
        self.sbd_msgwait = sbd_msgwait

    @classmethod
    def get_advised_sbd_timeout(cls, diskless=False) -> typing.Tuple[int, int]:
        '''
        Get suitable sbd_watchdog_timeout and sbd_msgwait
        '''
        ctx = bootstrap.Context()
        ctx.diskless_sbd = diskless
        ctx.load_profiles()
        time_inst = cls(ctx)
        time_inst.initialize_timeout()

        sbd_watchdog_timeout = time_inst.sbd_watchdog_timeout
        sbd_msgwait = None if diskless else time_inst.sbd_msgwait
        return sbd_watchdog_timeout, sbd_msgwait

    def _adjust_sbd_watchdog_timeout_with_diskless_and_qdevice(self):
        '''
        When using diskless SBD with Qdevice, adjust value of sbd_watchdog_timeout
        '''
        # add sbd after qdevice started
        if corosync.is_qdevice_configured() and ServiceManager().service_is_active("corosync-qdevice.service"):
            qdevice_sync_timeout = utils.get_qdevice_sync_timeout()
            if self.sbd_watchdog_timeout <= qdevice_sync_timeout:
                watchdog_timeout_with_qdevice = qdevice_sync_timeout + self.QDEVICE_SYNC_TIMEOUT_MARGIN
                logger.warning("sbd_watchdog_timeout is set to {} for qdevice, it was {}".format(watchdog_timeout_with_qdevice, self.sbd_watchdog_timeout))
                self.sbd_watchdog_timeout = watchdog_timeout_with_qdevice
        # add sbd and qdevice together from beginning
        elif self.context.qdevice_inst:
            if self.sbd_watchdog_timeout < self.SBD_WATCHDOG_TIMEOUT_DEFAULT_WITH_QDEVICE:
                logger.warning("sbd_watchdog_timeout is set to {} for qdevice, it was {}".format(self.SBD_WATCHDOG_TIMEOUT_DEFAULT_WITH_QDEVICE, self.sbd_watchdog_timeout))
                self.sbd_watchdog_timeout = self.SBD_WATCHDOG_TIMEOUT_DEFAULT_WITH_QDEVICE

    @staticmethod
    def get_sbd_msgwait(dev):
        '''
        Get msgwait for sbd device
        '''
        res = SBDUtils.get_sbd_device_metadata(dev).get("msgwait")
        if not res:
            raise ValueError(f"Cannot get sbd msgwait for {dev}")
        return res

    @staticmethod
    def get_sbd_watchdog_timeout():
        '''
        Get SBD_WATCHDOG_TIMEOUT from /etc/sysconfig/sbd
        '''
        res = SBDUtils.get_sbd_value_from_config("SBD_WATCHDOG_TIMEOUT")
        if not res:
            raise ValueError("Cannot get the value of SBD_WATCHDOG_TIMEOUT")
        return int(res)

    @staticmethod
    def get_stonith_watchdog_timeout_expected():
        '''
        Returns the value of the stonith-watchdog-timeout cluster property.

        If the Pacemaker service is inactive, returns the default value (2 * SBD_WATCHDOG_TIMEOUT).
        If the property is set and its value is equal to or greater than the default, returns the property value.
        Otherwise, returns the default value.
        '''
        default = 2 * SBDTimeout.get_sbd_watchdog_timeout()
        if not ServiceManager().service_is_active(constants.PCMK_SERVICE):
            return default
        value = utils.get_property("stonith-watchdog-timeout", get_default=False)
        return_value = value if utils.crm_msec(value) >= utils.crm_msec(default) else default
        return int(utils.crm_msec(return_value)/1000)  # convert msec to sec

    def _load_configurations(self):
        '''
        Load necessary configurations for both disk-based/disk-less sbd
        '''
        self.two_node_without_qdevice = utils.is_2node_cluster_without_qdevice()

        dev_list = SBDUtils.get_sbd_device_from_config()
        if dev_list:  # disk-based
            self.disk_based = True
            self.msgwait = SBDTimeout.get_sbd_msgwait(dev_list[0])
            self.pcmk_delay_max = utils.get_pcmk_delay_max(self.two_node_without_qdevice)
        else:  # disk-less
            self.disk_based = False
            self.sbd_watchdog_timeout = SBDTimeout.get_sbd_watchdog_timeout()
            self.stonith_watchdog_timeout = SBDTimeout.get_stonith_watchdog_timeout_expected()
        self.sbd_delay_start_value_expected = self.get_sbd_delay_start_expected() if utils.detect_virt() else "no"
        self.sbd_delay_start_value_from_config = SBDUtils.get_sbd_value_from_config("SBD_DELAY_START")

        logger.debug("Inspect SBDTimeout: %s", vars(self))

    def get_stonith_timeout_expected(self):
        '''
        Get stonith-timeout value for sbd cases, formulas are:

        value_from_sbd = 1.2 * msgwait # for disk-based sbd
        value_from_sbd = 1.2 * max (stonith_watchdog_timeout, 2*SBD_WATCHDOG_TIMEOUT) # for disk-less sbd

        stonith_timeout = max(value_from_sbd, constants.STONITH_TIMEOUT_DEFAULT) + token + consensus
        '''
        if self.disk_based:
            value_from_sbd = int(1.2*self.msgwait)
        else:
            value_from_sbd = int(1.2*max(self.stonith_watchdog_timeout, 2*self.sbd_watchdog_timeout))

        value = max(value_from_sbd, constants.STONITH_TIMEOUT_DEFAULT) + corosync.token_and_consensus_timeout()
        logger.debug("Result of SBDTimeout.get_stonith_timeout_expected %d", value)
        return value

    @classmethod
    def get_stonith_timeout(cls):
        cls_inst = cls()
        cls_inst._load_configurations()
        return cls_inst.get_stonith_timeout_expected()

    def get_sbd_delay_start_expected(self):
        '''
        Get the value for SBD_DELAY_START, formulas are:

        SBD_DELAY_START = (token + consensus + pcmk_delay_max + msgwait)  # for disk-based sbd
        SBD_DELAY_START = (token + consensus + 2*SBD_WATCHDOG_TIMEOUT) # for disk-less sbd
        '''
        token_and_consensus_timeout = corosync.token_and_consensus_timeout()
        if self.disk_based:
            value = token_and_consensus_timeout + self.pcmk_delay_max + self.msgwait
        else:
            value = token_and_consensus_timeout + 2*self.sbd_watchdog_timeout
        return value

    @staticmethod
    def get_sbd_delay_start_sec_from_sysconfig():
        '''
        Get suitable systemd start timeout for sbd.service
        '''
        # TODO 5ms, 5us, 5s, 5m, 5h are also valid for sbd sysconfig
        value = SBDUtils.get_sbd_value_from_config("SBD_DELAY_START")
        if utils.is_boolean_true(value):
            return 2*SBDTimeout.get_sbd_watchdog_timeout()
        return int(value)

    @staticmethod
    def is_sbd_delay_start():
        '''
        Check if SBD_DELAY_START is not no or not set
        '''
        res = SBDUtils.get_sbd_value_from_config("SBD_DELAY_START")
        return res and res != "no"

    @staticmethod
    def get_sbd_systemd_start_timeout() -> int:
        out = sh.cluster_shell().get_stdout_or_raise_error(SBDTimeout.SHOW_SBD_START_TIMEOUT_CMD)
        return utils.get_systemd_timeout_start_in_sec(out)

    def adjust_systemd_start_timeout(self):
        '''
        Adjust start timeout for sbd when set SBD_DELAY_START
        '''
        sbd_delay_start_value = SBDUtils.get_sbd_value_from_config("SBD_DELAY_START")
        if sbd_delay_start_value == "no":
            return

        start_timeout = SBDTimeout.get_sbd_systemd_start_timeout()
        if start_timeout > int(sbd_delay_start_value):
            return

        utils.mkdirp(SBDManager.SBD_SYSTEMD_DELAY_START_DIR)
        sbd_delay_start_file = "{}/sbd_delay_start.conf".format(SBDManager.SBD_SYSTEMD_DELAY_START_DIR)
        utils.str2file("[Service]\nTimeoutSec={}".format(int(1.2*int(sbd_delay_start_value))), sbd_delay_start_file)
        bootstrap.sync_file(SBDManager.SBD_SYSTEMD_DELAY_START_DIR)
        utils.cluster_run_cmd("systemctl daemon-reload")

    def adjust_stonith_timeout(self):
        '''
        Adjust stonith-timeout property
        '''
        utils.set_property("stonith-timeout", self.get_stonith_timeout_expected(), conditional=True)

    def adjust_sbd_delay_start(self):
        '''
        Adjust SBD_DELAY_START in /etc/sysconfig/sbd
        '''
        expected_value = str(self.sbd_delay_start_value_expected)
        config_value = self.sbd_delay_start_value_from_config
        if expected_value == config_value:
            return
        if expected_value == "no" \
                or (not re.search(r'\d+', config_value)) \
                or (int(expected_value) > int(config_value)):
            SBDManager.update_sbd_configuration({"SBD_DELAY_START": expected_value})

    @classmethod
    def adjust_sbd_timeout_related_cluster_configuration(cls):
        '''
        Adjust sbd timeout related configurations
        '''
        cls_inst = cls()
        cls_inst._load_configurations()
        cls_inst.adjust_sbd_delay_start()
        cls_inst.adjust_stonith_timeout()
        cls_inst.adjust_systemd_start_timeout()


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
    NO_SBD_WARNING = "Not configuring SBD - STONITH will be disabled."
    DISKLESS_SBD_MIN_EXPECTED_VOTE = 3
    DISKLESS_SBD_WARNING = "Diskless SBD requires cluster with three or more nodes. If you want to use diskless SBD for 2-node cluster, should be combined with QDevice."
    SBD_NOT_INSTALLED_MSG = "Package sbd is not installed"
    FENCE_SBD_NOT_EXISTED_MSG = "fence_sbd command does not exist."
    SBD_RA = "stonith:fence_sbd"
    SBD_RA_ID = "stonith-sbd"
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
            timeout_inst.initialize_timeout()
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
        bootstrap.sync_file(self.SYSCONFIG_SBD)
        logger.info("Already synced %s to all nodes", self.SYSCONFIG_SBD)

    @classmethod
    def update_sbd_configuration(cls, update_dict: typing.Dict[str, str]) -> None:
        inst = cls(update_dict=update_dict)
        inst.update_configuration()

    def initialize_sbd(self):
        if self.diskless_sbd:
            logger.info("Configuring diskless SBD")
            self._warn_diskless_sbd()
            return
        elif self.device_list_to_init:
            logger.info("Configuring disk-based SBD")
        else:
            return

        if not shutil.which("fence_sbd"):
            utils.fatal(self.FENCE_SBD_NOT_EXISTED_MSG)

        opt_str = SBDManager.convert_timeout_dict_to_opt_str(self.timeout_dict)
        shell = sh.cluster_shell()
        for dev in self.device_list_to_init:
            logger.info("Initializing SBD device %s", dev)
            cmd = f"sbd {opt_str} -d {dev} create"
            logger.debug("Running command: %s", cmd)
            shell.get_stdout_or_raise_error(cmd)

    @staticmethod
    def enable_sbd_service():
        cluster_nodes = utils.list_cluster_nodes() or [utils.this_node()]
        service_manager = ServiceManager()

        for node in cluster_nodes:
            if not service_manager.service_is_enabled(constants.SBD_SERVICE, node):
                logger.info("Enable %s on node %s", constants.SBD_SERVICE, node)
                service_manager.enable_service(constants.SBD_SERVICE, node)

    @staticmethod
    def restart_cluster_if_possible(with_maintenance_mode=False):
        if not ServiceManager().service_is_active(constants.PCMK_SERVICE):
            return
        if not xmlutil.CrmMonXmlParser().is_non_stonith_resource_running():
            bootstrap.restart_cluster()
        elif with_maintenance_mode:
            if not utils.is_dlm_running():
                bootstrap.restart_cluster()
            else:
                logger.warning("Resource is running, need to restart cluster service manually on each node")
        else:
            logger.warning("Resource is running, need to restart cluster service manually on each node")
            logger.warning("Or, run with `crm -F` or `--force` option, the `sbd` subcommand will leverage maintenance mode for any changes that require restarting sbd.service")
            logger.warning("Understand risks that running RA has no cluster protection while the cluster is in maintenance mode and restarting")

    def configure_sbd(self):
        '''
        Configure fence_sbd resource and related properties
        '''
        if self.diskless_sbd:
            swt_value = self.timeout_dict.get("stonith-watchdog", SBDTimeout.get_stonith_watchdog_timeout_expected())
            utils.set_property("stonith-watchdog-timeout", swt_value)
        else:
            if utils.get_property("stonith-watchdog-timeout", get_default=False):
                utils.delete_property("stonith-watchdog-timeout")
            if not xmlutil.CrmMonXmlParser().is_resource_configured(self.SBD_RA):
                cmd = f"crm configure primitive {self.SBD_RA_ID} {self.SBD_RA}"
                sh.cluster_shell().get_stdout_or_raise_error(cmd)
        utils.set_property("stonith-enabled", "true")

    def _warn_diskless_sbd(self, peer=None):
        '''
        Give warning when configuring diskless sbd
        '''
        # When in sbd stage or join process
        if (self.diskless_sbd and self.cluster_is_running) or peer:
            vote_dict = utils.get_quorum_votes_dict(peer)
            expected_vote = int(vote_dict.get('Expected', 0))
            if expected_vote < self.DISKLESS_SBD_MIN_EXPECTED_VOTE:
                logger.warning('%s', self.DISKLESS_SBD_WARNING)
        # When in init process
        elif self.diskless_sbd:
            logger.warning('%s', self.DISKLESS_SBD_WARNING)

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
            return []

        return self._prompt_for_sbd_device()

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

    def init_and_deploy_sbd(self):
        '''
        The process of deploying sbd includes:
        1. Initialize sbd device
        2. Write config file /etc/sysconfig/sbd
        3. Enable sbd.service
        4. Restart cluster service if possible
        5. Configure stonith-sbd resource and related properties
        '''
        if self.bootstrap_context:
            try:
                self.get_sbd_device_from_bootstrap()
            except self.NotConfigSBD:
                ServiceManager().disable_service(constants.SBD_SERVICE)
                return
            self._load_attributes_from_bootstrap()

        with utils.leverage_maintenance_mode() as enabled:
            self.initialize_sbd()
            self.update_configuration()
            SBDManager.enable_sbd_service()

            if self.cluster_is_running:
                self.configure_sbd()
                bootstrap.adjust_properties()
                SBDManager.restart_cluster_if_possible(with_maintenance_mode=enabled)

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

        from .watchdog import Watchdog
        self._watchdog_inst = Watchdog(remote_user=remote_user, peer_host=peer_host)
        self._watchdog_inst.join_watchdog()

        dev_list = SBDUtils.get_sbd_device_from_config()
        if dev_list:
            SBDUtils.verify_sbd_device(dev_list, [peer_host])
        else:
            self._warn_diskless_sbd(peer_host)

        logger.info("Got {}SBD configuration".format("" if dev_list else "diskless "))
        service_manager.enable_service(constants.SBD_SERVICE)


def cleanup_existing_sbd_resource():
    if xmlutil.CrmMonXmlParser().is_resource_configured(SBDManager.SBD_RA):
        sbd_id_list = xmlutil.CrmMonXmlParser().get_resource_id_list_via_type(SBDManager.SBD_RA)
        if xmlutil.CrmMonXmlParser().is_resource_started(SBDManager.SBD_RA):
            for sbd_id in sbd_id_list:
                logger.info("Stop sbd resource '%s'(%s)", sbd_id, SBDManager.SBD_RA)
                utils.ext_cmd("crm resource stop {}".format(sbd_id))
        logger.info("Remove sbd resource '%s'", ';' .join(sbd_id_list))
        utils.ext_cmd("crm configure delete {}".format(' '.join(sbd_id_list)))


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

    config_bak = f"{SBDManager.SYSCONFIG_SBD}.bak"
    logger.info("Move %s to %s on all nodes", SBDManager.SYSCONFIG_SBD, config_bak)
    utils.cluster_run_cmd(f"mv {SBDManager.SYSCONFIG_SBD} {config_bak}")

    out = sh.cluster_shell().get_stdout_or_raise_error("stonith_admin -L")
    res = re.search("([0-9]+) fence device[s]* found", out)
    # after disable sbd.service, check if sbd is the last stonith device
    if res and int(res.group(1)) <= 1:
        utils.cleanup_stonith_related_properties()

    for _dir in [SBDManager.SBD_SYSTEMD_DELAY_START_DIR, SBDManager.SBD_SYSTEMD_DELAY_START_DISABLE_DIR]:
        cmd = f"test -d {_dir} && rm -rf {_dir} || exit 0"
        parallax.parallax_call(cluster_nodes, cmd)
