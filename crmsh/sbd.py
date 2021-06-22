import os
import re
import shutil
from . import utils
from . import bootstrap
from .bootstrap import SYSCONFIG_SBD
from .constants import SSH_OPTION


class SBDManager(object):
    """
    Class to manage sbd configuration and services
    """
    SYSCONFIG_SBD_TEMPLATE = "/usr/share/fillup-templates/sysconfig.sbd"
    SBD_STATUS_DESCRIPTION = """
Configure SBD:
  If you have shared storage, for example a SAN or iSCSI target,
  you can use it avoid split-brain scenarios by configuring SBD.
  This requires a 1 MB partition, accessible to all nodes in the
  cluster.  The device path must be persistent and consistent
  across all nodes in the cluster, so /dev/disk/by-id/* devices
  are a good choice.  Note that all data on the partition you
  specify here will be destroyed.
"""
    SBD_WARNING = "Not configuring SBD - STONITH will be disabled."
    DISKLESS_SBD_WARNING = """Diskless SBD requires cluster with three or more nodes.
If you want to use diskless SBD for two-nodes cluster, should be combined with QDevice."""
    PARSE_RE = "[; ]"
    DISKLESS_CRM_CMD = "crm configure property stonith-enabled=true stonith-watchdog-timeout={} stonith-timeout={}"
    SBD_WATCHDOG_TIMEOUT_DEFAULT_WITH_QDEVICE = 35
    STONITH_WATCHDOG_TIMEOUT_DEFAULT = "10s"
    STONITH_WATCHDOG_TIMEOUT_DEFAULT_S390 = "30s"

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
        self._stonith_watchdog_timeout = self.STONITH_WATCHDOG_TIMEOUT_DEFAULT
        self._stonith_timeout = 60
        self._sbd_watchdog_timeout = 0
        self._is_s390 = "390" in os.uname().machine
        self._context = context

    @staticmethod
    def _get_device_uuid(dev, node=None):
        """
        Get UUID for specific device and node
        """
        cmd = "sbd -d {} dump".format(dev)
        if node:
            cmd = "ssh {} root@{} '{}'".format(SSH_OPTION, node, cmd)

        rc, out, err = utils.get_stdout_stderr(cmd)
        if rc != 0 and err:
            raise ValueError("Cannot dump sbd meta-data: {}".format(err))
        if rc == 0 and out:
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

    def _get_sbd_device_interactive(self):
        """
        Get sbd device on interactive mode
        """
        if self._context.yes_to_all:
            bootstrap.warn(self.SBD_WARNING)
            return

        bootstrap.status(self.SBD_STATUS_DESCRIPTION)

        if not bootstrap.confirm("Do you wish to use SBD?"):
            bootstrap.warn(self.SBD_WARNING)
            return

        configured_dev_list = self._get_sbd_device_from_config()
        if configured_dev_list and not bootstrap.confirm("SBD is already configured to use {} - overwrite?".format(';'.join(configured_dev_list))):
            return configured_dev_list

        dev_list = []
        dev_looks_sane = False
        while not dev_looks_sane:
            dev = bootstrap.prompt_for_string('Path to storage device (e.g. /dev/disk/by-id/...), or "none" for diskless sbd, use ";" as separator for multi path', r'none|\/.*')
            if not dev:
                continue
            if dev == "none":
                self.diskless_sbd = True
                return
            dev_list = utils.re_split_string(self.PARSE_RE, dev)
            try:
                self._verify_sbd_device(dev_list)
            except ValueError as err_msg:
                bootstrap.print_error_msg(str(err_msg))
                continue
            for dev_item in dev_list:
                bootstrap.warn("All data on {} will be destroyed!".format(dev_item))
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
            dev_list = utils.parse_append_action_argument(self.sbd_devices_input)
            self._verify_sbd_device(dev_list)
        elif not self.diskless_sbd:
            dev_list = self._get_sbd_device_interactive()
        self._sbd_devices = dev_list

    def _initialize_sbd(self):
        """
        Initialize SBD device
        """
        if self.diskless_sbd:
            return
        for dev in self._sbd_devices:
            rc, _, err = bootstrap.invoke("sbd -d {} create".format(dev))
            if not rc:
                bootstrap.error("Failed to initialize SBD device {}: {}".format(dev, err))

    def _update_configuration(self):
        """
        Update /etc/sysconfig/sbd
        """
        shutil.copyfile(self.SYSCONFIG_SBD_TEMPLATE, SYSCONFIG_SBD)
        self._determine_sbd_watchdog_timeout()
        sbd_config_dict = {
                "SBD_PACEMAKER": "yes",
                "SBD_STARTMODE": "always",
                "SBD_DELAY_START": "no",
                "SBD_WATCHDOG_DEV": self._watchdog_inst.watchdog_device_name
                }
        if self._sbd_watchdog_timeout > 0:
            sbd_config_dict["SBD_WATCHDOG_TIMEOUT"] = str(self._sbd_watchdog_timeout)
        if self._sbd_devices:
            sbd_config_dict["SBD_DEVICE"] = ';'.join(self._sbd_devices)
        utils.sysconfig_set(SYSCONFIG_SBD, **sbd_config_dict)
        bootstrap.csync2_update(SYSCONFIG_SBD)

    def _determine_sbd_watchdog_timeout(self):
        """
        When using diskless SBD, determine value of SBD_WATCHDOG_TIMEOUT
        """
        if not self.diskless_sbd:
            return
        # add sbd after qdevice started
        if utils.is_qdevice_configured() and utils.service_is_active("corosync-qdevice.service"):
            qdevice_sync_timeout = utils.get_qdevice_sync_timeout()
            self._sbd_watchdog_timeout = qdevice_sync_timeout + 5
            if self._is_s390 and self._sbd_watchdog_timeout < 15:
                self._sbd_watchdog_timeout = 15
            self._stonith_timeout = self.calculate_stonith_timeout(self._sbd_watchdog_timeout)
        # add sbd and qdevice together from beginning
        elif self._context.qdevice_inst:
            self._sbd_watchdog_timeout = self.SBD_WATCHDOG_TIMEOUT_DEFAULT_WITH_QDEVICE
            self._stonith_timeout = self.calculate_stonith_timeout(self._sbd_watchdog_timeout)

    def _determine_stonith_watchdog_timeout(self):
        """
        Determine value of stonith-watchdog-timeout
        """
        res = SBDManager.get_sbd_value_from_config("SBD_WATCHDOG_TIMEOUT")
        if res:
            self._stonith_watchdog_timeout = -1
        elif self._is_s390:
            self._stonith_watchdog_timeout = self.STONITH_WATCHDOG_TIMEOUT_DEFAULT_S390

    def _get_sbd_device_from_config(self):
        """
        Gets currently configured SBD device, i.e. what's in /etc/sysconfig/sbd
        """
        res = SBDManager.get_sbd_value_from_config("SBD_DEVICE")
        if res:
            return utils.re_split_string(self.PARSE_RE, res)
        else:
            return None

    def _restart_cluster_and_configure_sbd_ra(self):
        """
        Try to configure sbd resource, restart cluster on needed
        """
        if not utils.has_resource_running():
            bootstrap.status("Restarting cluster service")
            utils.cluster_run_cmd("crm cluster restart")
            bootstrap.wait_for_cluster()
            self.configure_sbd_resource()
        else:
            bootstrap.warn("To start sbd.service, need to restart cluster service manually on each node")
            if self.diskless_sbd:
                cmd = self.DISKLESS_CRM_CMD.format(self._stonith_watchdog_timeout, str(self._stonith_timeout)+"s")
                bootstrap.warn("Then run \"{}\" on any node".format(cmd))
            else:
                self.configure_sbd_resource()

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
                bootstrap.warn(self.DISKLESS_SBD_WARNING)
        # When in init process
        elif self.diskless_sbd:
            bootstrap.warn(self.DISKLESS_SBD_WARNING)

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
        with bootstrap.status_long("Initializing {}SBD...".format("diskless " if self.diskless_sbd else "")):
            self._initialize_sbd()
            self._update_configuration()
        self._determine_stonith_watchdog_timeout()
        self._enable_sbd_service()

    def configure_sbd_resource(self):
        """
        Configure stonith-sbd resource and stonith-enabled property
        """
        if not utils.package_is_installed("sbd") or \
                not utils.service_is_enabled("sbd.service") or \
                utils.has_resource_configured("stonith:external/sbd"):
            return

        if self._get_sbd_device_from_config():
            if not bootstrap.invokerc("crm configure primitive stonith-sbd stonith:external/sbd pcmk_delay_max=30s"):
                bootstrap.error("Can't create stonith-sbd primitive")
            if not bootstrap.invokerc("crm configure property stonith-enabled=true"):
                bootstrap.error("Can't enable STONITH for SBD")
        else:
            cmd = self.DISKLESS_CRM_CMD.format(self._stonith_watchdog_timeout, str(self._stonith_timeout)+"s")
            if not bootstrap.invokerc(cmd):
                bootstrap.error("Can't enable STONITH for diskless SBD")

    def join_sbd(self, peer_host):
        """
        Function join_sbd running on join process only
        On joining process, check whether peer node has enabled sbd.service
        If so, check prerequisites of SBD and verify sbd device on join node
        """
        from .watchdog import Watchdog

        if not utils.package_is_installed("sbd"):
            return
        if not os.path.exists(SYSCONFIG_SBD) or not utils.service_is_enabled("sbd.service", peer_host):
            bootstrap.invoke("systemctl disable sbd.service")
            return
        self._watchdog_inst = Watchdog(peer_host=peer_host)
        self._watchdog_inst.join_watchdog()
        dev_list = self._get_sbd_device_from_config()
        if dev_list:
            self._verify_sbd_device(dev_list, [peer_host])
        else:
            self._warn_diskless_sbd(peer_host)
        bootstrap.status("Got {}SBD configuration".format("" if dev_list else "diskless "))
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
        if not dev_list and utils.service_is_active("sbd.service"):
            return True
        return False

    @staticmethod
    def update_configuration(sbd_config_dict):
        """
        Update and sync sbd configuration
        """
        utils.sysconfig_set(SYSCONFIG_SBD, **sbd_config_dict)
        bootstrap.csync2_update(SYSCONFIG_SBD)

    @staticmethod
    def calculate_stonith_timeout(sbd_watchdog_timeout):
        """
        Calculate stonith timeout
        """
        return int(sbd_watchdog_timeout * 2 * 1.2)

    @staticmethod
    def get_sbd_value_from_config(key):
        """
        Get value from /etc/sysconfig/sbd
        """
        conf = utils.parse_sysconfig(SYSCONFIG_SBD)
        res = conf.get(key)
        return res
