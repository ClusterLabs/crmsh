import os
import re
import shutil
from . import utils, sh
from . import bootstrap
from .bootstrap import SYSCONFIG_SBD, SBD_SYSTEMD_DELAY_START_DIR
from . import log
from . import constants
from . import corosync
from . import xmlutil
from .service_manager import ServiceManager
from .sh import ShellUtils

logger = log.setup_logger(__name__)
logger_utils = log.LoggerUtils(logger)


class SBDTimeout(object):
    """
    Consolidate sbd related timeout methods and constants
    """
    STONITH_WATCHDOG_TIMEOUT_DEFAULT = -1
    SBD_WATCHDOG_TIMEOUT_DEFAULT = 5
    SBD_WATCHDOG_TIMEOUT_DEFAULT_S390 = 15
    SBD_WATCHDOG_TIMEOUT_DEFAULT_WITH_QDEVICE = 35
    QDEVICE_SYNC_TIMEOUT_MARGIN = 5

    def __init__(self, context=None):
        """
        Init function
        """
        self.context = context
        self.sbd_msgwait = None
        self.stonith_timeout = None
        self.sbd_watchdog_timeout = self.SBD_WATCHDOG_TIMEOUT_DEFAULT
        self.stonith_watchdog_timeout = self.STONITH_WATCHDOG_TIMEOUT_DEFAULT
        self.sbd_delay_start = None
        self.two_node_without_qdevice = False

    def initialize_timeout(self):
        self._set_sbd_watchdog_timeout()
        if self.context.diskless_sbd:
            self._adjust_sbd_watchdog_timeout_with_diskless_and_qdevice()
        else:
            self._set_sbd_msgwait()

    def _set_sbd_watchdog_timeout(self):
        """
        Set sbd_watchdog_timeout from profiles.yml if exists
        Then adjust it if in s390 environment
        """
        if "sbd.watchdog_timeout" in self.context.profiles_dict:
            self.sbd_watchdog_timeout = int(self.context.profiles_dict["sbd.watchdog_timeout"])
        if self.context.is_s390 and self.sbd_watchdog_timeout < self.SBD_WATCHDOG_TIMEOUT_DEFAULT_S390:
            logger.warning("sbd_watchdog_timeout is set to %d for s390, it was %d", self.SBD_WATCHDOG_TIMEOUT_DEFAULT_S390, self.sbd_watchdog_timeout)
            self.sbd_watchdog_timeout = self.SBD_WATCHDOG_TIMEOUT_DEFAULT_S390

    def _set_sbd_msgwait(self):
        """
        Set sbd msgwait from profiles.yml if exists
        Default is 2 * sbd_watchdog_timeout
        """
        sbd_msgwait_default = 2 * self.sbd_watchdog_timeout
        sbd_msgwait = sbd_msgwait_default
        if "sbd.msgwait" in self.context.profiles_dict:
            sbd_msgwait = int(self.context.profiles_dict["sbd.msgwait"])
            if sbd_msgwait < sbd_msgwait_default:
                logger.warning("sbd msgwait is set to %d, it was %d", sbd_msgwait_default, sbd_msgwait)
                sbd_msgwait = sbd_msgwait_default
        self.sbd_msgwait = sbd_msgwait

    def _adjust_sbd_watchdog_timeout_with_diskless_and_qdevice(self):
        """
        When using diskless SBD with Qdevice, adjust value of sbd_watchdog_timeout
        """
        # add sbd after qdevice started
        if utils.is_qdevice_configured() and ServiceManager().service_is_active("corosync-qdevice.service"):
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
        """
        Get msgwait for sbd device
        """
        out = sh.cluster_shell().get_stdout_or_raise_error("sbd -d {} dump".format(dev))
        # Format like "Timeout (msgwait)  : 30"
        res = re.search("\(msgwait\)\s+:\s+(\d+)", out)
        if not res:
            raise ValueError("Cannot get sbd msgwait for {}".format(dev))
        return int(res.group(1))

    @staticmethod
    def get_sbd_watchdog_timeout():
        """
        Get SBD_WATCHDOG_TIMEOUT from /etc/sysconfig/sbd
        """
        res = SBDManager.get_sbd_value_from_config("SBD_WATCHDOG_TIMEOUT")
        if not res:
            raise ValueError("Cannot get the value of SBD_WATCHDOG_TIMEOUT")
        return int(res)

    @staticmethod
    def get_stonith_watchdog_timeout():
        """
        For non-bootstrap case, get stonith-watchdog-timeout value from cluster property
        """
        default = SBDTimeout.STONITH_WATCHDOG_TIMEOUT_DEFAULT
        if not ServiceManager().service_is_active("pacemaker.service"):
            return default
        value = utils.get_property("stonith-watchdog-timeout")
        return int(value.strip('s')) if value else default

    def _load_configurations(self):
        """
        Load necessary configurations for both disk-based/disk-less sbd
        """
        self.two_node_without_qdevice = utils.is_2node_cluster_without_qdevice()

        dev_list = SBDManager.get_sbd_device_from_config()
        if dev_list:  # disk-based
            self.disk_based = True
            self.msgwait = SBDTimeout.get_sbd_msgwait(dev_list[0])
        else:  # disk-less
            self.disk_based = False
            self.sbd_watchdog_timeout = SBDTimeout.get_sbd_watchdog_timeout()
            self.stonith_watchdog_timeout = SBDTimeout.get_stonith_watchdog_timeout()
        self.sbd_delay_start_value_expected = self.get_sbd_delay_start_expected() if utils.detect_virt() else "no"
        self.sbd_delay_start_value_from_config = SBDManager.get_sbd_value_from_config("SBD_DELAY_START")

        logger.debug("Inspect SBDTimeout: %s", vars(self))

    def get_stonith_timeout_expected(self):
        """
        Get stonith-timeout value for sbd cases, formulas are:

        value_from_sbd = 1.2 * msgwait # for disk-based sbd
        value_from_sbd = 1.2 * max (stonith_watchdog_timeout, 2*SBD_WATCHDOG_TIMEOUT) # for disk-less sbd

        stonith_timeout = max(value_from_sbd, constants.STONITH_TIMEOUT_DEFAULT) + token + consensus
        """
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
        """
        Get the value for SBD_DELAY_START, formulas are:

        SBD_DELAY_START = (token + consensus + msgwait)  # for disk-based sbd
        SBD_DELAY_START = (token + consensus + 2*SBD_WATCHDOG_TIMEOUT) # for disk-less sbd
        """
        token_and_consensus_timeout = corosync.token_and_consensus_timeout()
        if self.disk_based:
            value = token_and_consensus_timeout + self.msgwait
        else:
            value = token_and_consensus_timeout + 2*self.sbd_watchdog_timeout
        return value

    @staticmethod
    def get_sbd_delay_start_sec_from_sysconfig():
        """
        Get suitable systemd start timeout for sbd.service
        """
        # TODO 5ms, 5us, 5s, 5m, 5h are also valid for sbd sysconfig
        value = SBDManager.get_sbd_value_from_config("SBD_DELAY_START")
        if utils.is_boolean_true(value):
            return 2*SBDTimeout.get_sbd_watchdog_timeout()
        return int(value)

    @staticmethod
    def is_sbd_delay_start():
        """
        Check if SBD_DELAY_START is not no or not set
        """
        res = SBDManager.get_sbd_value_from_config("SBD_DELAY_START")
        return res and res != "no"

    def adjust_systemd_start_timeout(self):
        """
        Adjust start timeout for sbd when set SBD_DELAY_START
        """
        sbd_delay_start_value = SBDManager.get_sbd_value_from_config("SBD_DELAY_START")
        if sbd_delay_start_value == "no":
            return

        cmd = "systemctl show -p TimeoutStartUSec sbd --value"
        out = sh.cluster_shell().get_stdout_or_raise_error(cmd)
        start_timeout = utils.get_systemd_timeout_start_in_sec(out)
        if start_timeout > int(sbd_delay_start_value):
            return

        utils.mkdirp(SBD_SYSTEMD_DELAY_START_DIR)
        sbd_delay_start_file = "{}/sbd_delay_start.conf".format(SBD_SYSTEMD_DELAY_START_DIR)
        utils.str2file("[Service]\nTimeoutSec={}".format(int(1.2*int(sbd_delay_start_value))), sbd_delay_start_file)
        bootstrap.sync_file(SBD_SYSTEMD_DELAY_START_DIR)
        utils.cluster_run_cmd("systemctl daemon-reload")

    def adjust_stonith_timeout(self):
        """
        Adjust stonith-timeout property
        """
        utils.set_property("stonith-timeout", self.get_stonith_timeout_expected(), conditional=True)

    def adjust_sbd_delay_start(self):
        """
        Adjust SBD_DELAY_START in /etc/sysconfig/sbd
        """
        expected_value = str(self.sbd_delay_start_value_expected)
        config_value = self.sbd_delay_start_value_from_config
        if expected_value == config_value:
            return
        if expected_value == "no" \
                or (not re.search(r'\d+', config_value)) \
                or (int(expected_value) > int(config_value)):
            SBDManager.update_configuration({"SBD_DELAY_START": expected_value})

    @classmethod
    def adjust_sbd_timeout_related_cluster_configuration(cls):
        """
        Adjust sbd timeout related configurations
        """
        cls_inst = cls()
        cls_inst._load_configurations()

        message = "Adjusting sbd related timeout values"
        with logger_utils.status_long(message):
            cls_inst.adjust_sbd_delay_start()
            cls_inst.adjust_stonith_timeout()
            cls_inst.adjust_systemd_start_timeout()


class SBDManager(object):
    """
    Class to manage sbd configuration and services
    """
    SYSCONFIG_SBD_TEMPLATE = "/usr/share/fillup-templates/sysconfig.sbd"
    SBD_STATUS_DESCRIPTION = """Configure SBD:
  If you have shared storage, for example a SAN or iSCSI target,
  you can use it avoid split-brain scenarios by configuring SBD.
  This requires a 1 MB partition, accessible to all nodes in the
  cluster.  The device path must be persistent and consistent
  across all nodes in the cluster, so /dev/disk/by-id/* devices
  are a good choice.  Note that all data on the partition you
  specify here will be destroyed.
"""
    SBD_WARNING = "Not configuring SBD - STONITH will be disabled."
    DISKLESS_SBD_WARNING = "Diskless SBD requires cluster with three or more nodes. If you want to use diskless SBD for 2-node cluster, should be combined with QDevice."
    PARSE_RE = "[; ]"
    DISKLESS_CRM_CMD = "crm configure property stonith-enabled=true stonith-watchdog-timeout={} stonith-timeout={}"
    SBD_RA = "stonith:external/sbd"
    SBD_RA_ID = "stonith-sbd"

    def __init__(self, context):
        """
        Init function

        sbd_devices is provided by '-s' option on init process
        diskless_sbd is provided by '-S' option on init process
        """
        self.sbd_devices_input = context.sbd_devices
        self.diskless_sbd = context.diskless_sbd
        self._sbd_devices = None
        self._watchdog_inst = None
        self._context = context
        self._delay_start = False
        self.timeout_inst = None
        self.no_overwrite_map = {}
        self.no_update_config = False

    @staticmethod
    def _get_device_uuid(dev, node=None):
        """
        Get UUID for specific device and node
        """
        out = sh.cluster_shell().get_stdout_or_raise_error("sbd -d {} dump".format(dev), node)
        res = re.search("UUID\s*:\s*(.*)\n", out)
        if not res:
            raise ValueError("Cannot find sbd device UUID for {}".format(dev))
        return res.group(1)

    def _compare_device_uuid(self, dev, node_list):
        """
        Compare local sbd device UUID with other node's sbd device UUID
        """
        if not node_list:
            return
        local_uuid = self._get_device_uuid(dev)
        for node in node_list:
            remote_uuid = self._get_device_uuid(dev, node)
            if local_uuid != remote_uuid:
                raise ValueError("Device {} doesn't have the same UUID with {}".format(dev, node))

    def _verify_sbd_device(self, dev_list, compare_node_list=[]):
        """
        Verify sbd device
        """
        if len(dev_list) > 3:
            raise ValueError("Maximum number of SBD device is 3")
        for dev in dev_list:
            if not utils.is_block_device(dev):
                raise ValueError("{} doesn't look like a block device".format(dev))
            self._compare_device_uuid(dev, compare_node_list)
        utils.detect_duplicate_device_path(dev_list)

    def _no_overwrite_check(self, dev):
        """
        Check if device already initialized and if need to overwrite
        """
        return SBDManager.has_sbd_device_already_initialized(dev) and not bootstrap.confirm("SBD is already configured to use {} - overwrite?".format(dev))

    def _get_sbd_device_interactive(self):
        """
        Get sbd device on interactive mode
        """
        if self._context.yes_to_all:
            logger.warning(self.SBD_WARNING)
            return

        logger.info(self.SBD_STATUS_DESCRIPTION)

        if not bootstrap.confirm("Do you wish to use SBD?"):
            logger.warning(self.SBD_WARNING)
            return

        configured_dev_list = self._get_sbd_device_from_config()
        for dev in configured_dev_list:
            self.no_overwrite_map[dev] = self._no_overwrite_check(dev)
        if self.no_overwrite_map and all(self.no_overwrite_map.values()):
            self.no_update_config = True
            return configured_dev_list

        dev_list = []
        dev_looks_sane = False
        while not dev_looks_sane:
            dev = bootstrap.prompt_for_string('Path to storage device (e.g. /dev/disk/by-id/...), or "none" for diskless sbd, use ";" as separator for multi path', r'none|\/.*')
            if dev == "none":
                self.diskless_sbd = True
                return

            dev_list = utils.re_split_string(self.PARSE_RE, dev)
            try:
                self._verify_sbd_device(dev_list)
            except ValueError as err_msg:
                logger.error(str(err_msg))
                continue

            for dev in dev_list:
                if dev not in self.no_overwrite_map:
                    self.no_overwrite_map[dev] = self._no_overwrite_check(dev)
                if self.no_overwrite_map[dev]:
                    if dev == dev_list[-1]:
                        return dev_list
                    continue
                logger.warning("All data on {} will be destroyed!".format(dev))
                if bootstrap.confirm('Are you sure you wish to use this device?'):
                    dev_looks_sane = True
                else:
                    dev_looks_sane = False
                    break

        return dev_list

    def _get_sbd_device(self):
        """
        Get sbd device from options or interactive mode
        """
        dev_list = []
        if self.sbd_devices_input:
            dev_list = self.sbd_devices_input
            self._verify_sbd_device(dev_list)
            for dev in dev_list:
                self.no_overwrite_map[dev] = self._no_overwrite_check(dev)
            if all(self.no_overwrite_map.values()) and dev_list == self._get_sbd_device_from_config():
                self.no_update_config = True
        elif not self.diskless_sbd:
            dev_list = self._get_sbd_device_interactive()
        self._sbd_devices = dev_list

    def _initialize_sbd(self):
        """
        Initialize SBD parameters according to profiles.yml, or the crmsh defined defaulst as the last resort.
        This covers both disk-based-sbd, and diskless-sbd scenarios.
        For diskless-sbd, set sbd_watchdog_timeout then return;
        For disk-based-sbd, also calculate the msgwait value, then initialize the SBD device.
        """
        msg = ""
        if self.diskless_sbd:
            msg = "Configuring diskless SBD"
        elif not all(self.no_overwrite_map.values()):
            msg = "Initializing SBD"
        if msg:
            logger.info(msg)
        self.timeout_inst = SBDTimeout(self._context)
        self.timeout_inst.initialize_timeout()
        if self.diskless_sbd:
            return

        opt = "-4 {} -1 {}".format(self.timeout_inst.sbd_msgwait, self.timeout_inst.sbd_watchdog_timeout)

        for dev in self._sbd_devices:
            if dev in self.no_overwrite_map and self.no_overwrite_map[dev]:
                continue
            rc, _, err = bootstrap.invoke("sbd {} -d {} create".format(opt, dev))
            if not rc:
                utils.fatal("Failed to initialize SBD device {}: {}".format(dev, err))

    def _update_sbd_configuration(self):
        """
        Update /etc/sysconfig/sbd
        """
        if self.no_update_config:
            bootstrap.sync_file(SYSCONFIG_SBD)
            return

        utils.copy_local_file(self.SYSCONFIG_SBD_TEMPLATE, SYSCONFIG_SBD)
        sbd_config_dict = {
                "SBD_WATCHDOG_DEV": self._watchdog_inst.watchdog_device_name,
                "SBD_WATCHDOG_TIMEOUT": str(self.timeout_inst.sbd_watchdog_timeout)
                }
        if self._sbd_devices:
            sbd_config_dict["SBD_DEVICE"] = ';'.join(self._sbd_devices)
        utils.sysconfig_set(SYSCONFIG_SBD, **sbd_config_dict)
        bootstrap.sync_file(SYSCONFIG_SBD)

    def _get_sbd_device_from_config(self):
        """
        Gets currently configured SBD device, i.e. what's in /etc/sysconfig/sbd
        """
        res = SBDManager.get_sbd_value_from_config("SBD_DEVICE")
        if res:
            return utils.re_split_string(self.PARSE_RE, res)
        else:
            return []

    def _restart_cluster_and_configure_sbd_ra(self):
        """
        Try to configure sbd resource, restart cluster on needed
        """
        if not xmlutil.CrmMonXmlParser().is_any_resource_running():
            bootstrap.restart_cluster()
            self.configure_sbd_resource_and_properties()
        else:
            logger.warning("To start sbd.service, need to restart cluster service manually on each node")
            if self.diskless_sbd:
                cmd = self.DISKLESS_CRM_CMD.format(self.timeout_inst.stonith_watchdog_timeout, SBDTimeout.get_stonith_timeout())
                logger.warning("Then run \"{}\" on any node".format(cmd))
            else:
                self.configure_sbd_resource_and_properties()

    def _enable_sbd_service(self):
        """
        Try to enable sbd service
        """
        if self._context.cluster_is_running:
            # in sbd stage, enable sbd.service on cluster wide
            utils.cluster_run_cmd("systemctl enable sbd.service")
            self._restart_cluster_and_configure_sbd_ra()
        else:
            # in init process
            bootstrap.invoke("systemctl enable sbd.service")

    def _warn_diskless_sbd(self, peer=None):
        """
        Give warning when configuring diskless sbd
        """
        # When in sbd stage or join process
        if (self.diskless_sbd and self._context.cluster_is_running) or peer:
            vote_dict = utils.get_quorum_votes_dict(peer)
            expected_vote = int(vote_dict['Expected'])
            if (expected_vote < 2 and peer) or (expected_vote < 3 and not peer):
                logger.warning(self.DISKLESS_SBD_WARNING)
        # When in init process
        elif self.diskless_sbd:
            logger.warning(self.DISKLESS_SBD_WARNING)

    def sbd_init(self):
        """
        Function sbd_init includes these steps:
        1. Get sbd device from options or interactive mode
        2. Initialize sbd device
        3. Write config file /etc/sysconfig/sbd
        """
        from .watchdog import Watchdog

        if not utils.package_is_installed("sbd"):
            return
        self._watchdog_inst = Watchdog(_input=self._context.watchdog)
        self._watchdog_inst.init_watchdog()
        self._get_sbd_device()
        if not self._sbd_devices and not self.diskless_sbd:
            bootstrap.invoke("systemctl disable sbd.service")
            return
        self._warn_diskless_sbd()
        self._initialize_sbd()
        self._update_sbd_configuration()
        self._enable_sbd_service()

    def configure_sbd_resource_and_properties(self):
        """
        Configure stonith-sbd resource and related properties
        """
        if not utils.package_is_installed("sbd") or \
                not ServiceManager().service_is_enabled("sbd.service") or \
                xmlutil.CrmMonXmlParser().is_resource_configured(self.SBD_RA):
            return
        shell = sh.cluster_shell()

        # disk-based sbd
        if self._get_sbd_device_from_config():
            shell.get_stdout_or_raise_error("crm configure primitive {} {}".format(self.SBD_RA_ID, self.SBD_RA))
            utils.set_property("stonith-enabled", "true")
        # disk-less sbd
        else:
            if self.timeout_inst is None:
                self.timeout_inst = SBDTimeout(self._context)
                self.timeout_inst.initialize_timeout()
            cmd = self.DISKLESS_CRM_CMD.format(self.timeout_inst.stonith_watchdog_timeout, constants.STONITH_TIMEOUT_DEFAULT)
            shell.get_stdout_or_raise_error(cmd)

        # in sbd stage
        if self._context.cluster_is_running:
            bootstrap.adjust_properties()

    def join_sbd(self, remote_user, peer_host):
        """
        Function join_sbd running on join process only
        On joining process, check whether peer node has enabled sbd.service
        If so, check prerequisites of SBD and verify sbd device on join node
        """
        from .watchdog import Watchdog

        if not utils.package_is_installed("sbd"):
            return
        if not os.path.exists(SYSCONFIG_SBD) or not ServiceManager().service_is_enabled("sbd.service", peer_host):
            bootstrap.invoke("systemctl disable sbd.service")
            return
        self._watchdog_inst = Watchdog(remote_user=remote_user, peer_host=peer_host)
        self._watchdog_inst.join_watchdog()
        dev_list = self._get_sbd_device_from_config()
        if dev_list:
            self._verify_sbd_device(dev_list, [peer_host])
        else:
            self._warn_diskless_sbd(peer_host)
        logger.info("Got {}SBD configuration".format("" if dev_list else "diskless "))
        bootstrap.invoke("systemctl enable sbd.service")

    @classmethod
    def verify_sbd_device(cls):
        """
        This classmethod is for verifying sbd device on a running cluster
        Raise ValueError for exceptions
        """
        inst = cls(bootstrap.Context())
        dev_list = inst._get_sbd_device_from_config()
        if not dev_list:
            raise ValueError("No sbd device configured")
        inst._verify_sbd_device(dev_list, utils.list_cluster_nodes_except_me())

    @classmethod
    def get_sbd_device_from_config(cls):
        """
        Get sbd device list from config
        """
        inst = cls(bootstrap.Context())
        return inst._get_sbd_device_from_config()

    @classmethod
    def is_using_diskless_sbd(cls):
        """
        Check if using diskless SBD
        """
        inst = cls(bootstrap.Context())
        dev_list = inst._get_sbd_device_from_config()
        if not dev_list and ServiceManager().service_is_active("sbd.service"):
            return True
        return False

    @staticmethod
    def update_configuration(sbd_config_dict):
        """
        Update and sync sbd configuration
        """
        utils.sysconfig_set(SYSCONFIG_SBD, **sbd_config_dict)
        bootstrap.sync_file(SYSCONFIG_SBD)

    @staticmethod
    def get_sbd_value_from_config(key):
        """
        Get value from /etc/sysconfig/sbd
        """
        conf = utils.parse_sysconfig(SYSCONFIG_SBD)
        res = conf.get(key)
        return res

    @staticmethod
    def has_sbd_device_already_initialized(dev):
        """
        Check if sbd device already initialized
        """
        cmd = "sbd -d {} dump".format(dev)
        rc, _, _ = ShellUtils().get_stdout_stderr(cmd)
        return rc == 0


def clean_up_existing_sbd_resource():
    if xmlutil.CrmMonXmlParser().is_resource_configured(SBDManager.SBD_RA):
        sbd_id_list = xmlutil.CrmMonXmlParser().get_resource_id_list_via_type(SBDManager.SBD_RA)
        if xmlutil.CrmMonXmlParser().is_resource_started(SBDManager.SBD_RA):
            for sbd_id in sbd_id_list:
                utils.ext_cmd("crm resource stop {}".format(sbd_id))
        utils.ext_cmd("crm configure delete {}".format(' '.join(sbd_id_list)))
