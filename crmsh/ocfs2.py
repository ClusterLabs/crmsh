import re
from contextlib import contextmanager
from . import utils
from . import bootstrap
from . import ra
from . import corosync
from . import log
from . import xmlutil
from . import constants


logger = log.setup_logger(__name__)
logger_utils = log.LoggerUtils(logger)


class OCFS2Manager(object):
    """
    Class to manage OCFS2 and configure related resources
    """
    RA_ID_PREFIX = "ocfs2-"
    DLM_RA_ID = "{}dlm".format(RA_ID_PREFIX)
    FS_RA_ID = "{}clusterfs".format(RA_ID_PREFIX)
    LVMLOCKD_RA_ID = "{}lvmlockd".format(RA_ID_PREFIX)
    LVMACTIVATE_RA_ID = "{}lvmactivate".format(RA_ID_PREFIX)
    GROUP_ID = "{}group".format(RA_ID_PREFIX)
    CLONE_ID = "{}clone".format(RA_ID_PREFIX)
    VG_ID = "{}vg".format(RA_ID_PREFIX)
    LV_ID = "{}lv".format(RA_ID_PREFIX)

    MAX_CLONE_NUM = 8
    # Note: using undocumented '-x' switch to avoid prompting if overwriting
    MKFS_CMD = "mkfs.ocfs2 --cluster-stack pcmk --cluster-name {} -N {} -x {}"
    HINTS_WHEN_RUNNING = """
The cluster service has already been initialized, but the prerequisites are missing
to configure OCFS2. Please fix it and use the stage procedure to configure OCFS2 separately,
e.g. crm cluster init ocfs2 -o <ocfs2_device>
    """

    def __init__(self, context):
        """
        Init function
        """
        self.ocfs2_devices = context.ocfs2_devices
        self.use_cluster_lvm2 = context.use_cluster_lvm2
        self.mount_point = context.mount_point
        self.use_stage = context.stage == "ocfs2"
        self.yes_to_all = context.yes_to_all
        self.cluster_name = None
        self.exist_ra_id_list = []
        self.vg_id = None
        self.group_id = None
        self.target_device = None

    def _verify_packages(self, use_cluster_lvm2=False):
        """
        Find if missing required package
        """
        required_packages = ["ocfs2-tools"]
        if use_cluster_lvm2:
            required_packages.append("lvm2-lockd")
        for pkg in required_packages:
            if not utils.package_is_installed(pkg):
                raise ValueError("Missing required package for configuring OCFS2: {}".format(pkg))

    def _verify_options(self):
        """
        Verify options related with OCFS2
        """
        if self.use_stage and not self.ocfs2_devices:
            raise ValueError("ocfs2 stage require -o option")
        if len(self.ocfs2_devices) > 1 and not self.use_cluster_lvm2:
            raise ValueError("Without Cluster LVM2 (-C option), -o option only support one device")
        if self.use_cluster_lvm2 and not self.ocfs2_devices:
            raise ValueError("-C option only valid together with -o option")
        if self.mount_point and utils.has_mount_point_used(self.mount_point):
            raise ValueError("Mount point {} already mounted".format(self.mount_point))

    def _verify_devices(self):
        """
        Verify ocfs2 devices
        """
        for dev in self.ocfs2_devices:
            if not utils.is_block_device(dev):
                raise ValueError("{} doesn't look like a block device".format(dev))
            if utils.is_dev_used_for_lvm(dev) and self.use_cluster_lvm2:
                raise ValueError("{} is a Logical Volume, cannot be used with the -C option".format(dev))
            if utils.has_disk_mounted(dev):
                raise ValueError("{} already mounted".format(dev))

    def _check_if_already_configured(self):
        """
        Check if ocfs2 related resource already configured
        """
        if not self.use_stage:
            return
        out = utils.get_stdout_or_raise_error("crm configure show")
        if "fstype=ocfs2" in out:
            logger.info("Already configured OCFS2 related resources")
            raise utils.TerminateSubCommand

    def _static_verify(self):
        """
        Verify before configuring on init process
        """
        self._verify_packages(self.use_cluster_lvm2)
        self._check_if_already_configured()
        self._verify_options()
        self._verify_devices()

    def _dynamic_raise_error(self, error_msg):
        """
        Customize error message after cluster running
        """
        raise ValueError(error_msg + ("" if self.use_stage else self.HINTS_WHEN_RUNNING))

    def _check_sbd_and_ocfs2_dev(self):
        """
        Raise error when ocfs2 device is the same with sbd device
        """
        from . import sbd
        if utils.service_is_enabled("sbd.service"):
            sbd_device_list = sbd.SBDManager.get_sbd_device_from_config()
            for dev in self.ocfs2_devices:
                if dev in sbd_device_list:
                    self._dynamic_raise_error("{} cannot be the same with SBD device".format(dev))

    def _confirm_to_overwrite_ocfs2_dev(self):
        """
        Confirm to overwrit ocfs2 device on interactive mode
        """
        for dev in self.ocfs2_devices:
            msg = ""
            if utils.has_dev_partitioned(dev):
                msg = "Found a partition table in {}".format(dev)
            else:
                fs_type = utils.get_dev_fs_type(dev)
                if fs_type:
                    msg = "{} contains a {} file system".format(dev, fs_type)
            if msg and not bootstrap.confirm("{} - Proceed anyway?".format(msg)):
                raise utils.TerminateSubCommand

        for dev in self.ocfs2_devices:
            utils.get_stdout_or_raise_error("wipefs -a {}".format(dev))

    def _dynamic_verify(self):
        """
        Verify after cluster running
        """
        if not utils.has_stonith_running():
            self._dynamic_raise_error("OCFS2 requires stonith device configured and running")

        self._check_sbd_and_ocfs2_dev()
        self._confirm_to_overwrite_ocfs2_dev()

    def _gen_ra_scripts(self, ra_type, kv):
        """
        Generate ra scripts
        Return id and scripts
        """
        config_scripts = ""
        kv["id"] = utils.gen_unused_id(self.exist_ra_id_list, kv["id"])
        config_scripts = ra.CONFIGURE_RA_TEMPLATE_DICT[ra_type].format(**kv)
        return kv["id"], config_scripts

    def _mkfs(self, target):
        """
        Creating OCFS2 filesystem for the target device
        """
        with logger_utils.status_long("  Creating OCFS2 filesystem for {}".format(target)):
            self.cluster_name = corosync.get_value('totem.cluster_name')
            utils.get_stdout_or_raise_error(self.MKFS_CMD.format(self.cluster_name, self.MAX_CLONE_NUM, target))

    @contextmanager
    def _vg_change(self):
        """
        vgchange process using contextmanager
        """
        utils.get_stdout_or_raise_error("vgchange -ay {}".format(self.vg_id))
        try:
            yield
        finally:
            utils.get_stdout_or_raise_error("vgchange -an {}".format(self.vg_id))

    def _create_lv(self):
        """
        Create PV, VG, LV and return LV path
        """
        disks_string = ' '.join(self.ocfs2_devices)

        # Create PV
        with logger_utils.status_long("  Creating PV for {}".format(disks_string)):
            utils.get_stdout_or_raise_error("pvcreate {} -y".format(disks_string))

        # Create VG
        self.vg_id = utils.gen_unused_id(utils.get_all_vg_name(), self.VG_ID)
        with logger_utils.status_long("  Creating VG {}".format(self.vg_id)):
            utils.get_stdout_or_raise_error("vgcreate --shared {} {} -y".format(self.vg_id, disks_string))

        # Create LV
        with logger_utils.status_long("  Creating LV {} on VG {}".format(self.LV_ID, self.vg_id)):
            pe_number = utils.get_pe_number(self.vg_id)
            utils.get_stdout_or_raise_error("lvcreate -l {} {} -n {} -y".format(pe_number, self.vg_id, self.LV_ID))
 
        return "/dev/{}/{}".format(self.vg_id, self.LV_ID)

    def _gen_group_and_clone_scripts(self, ra_list):
        """
        Generate group and clone scripts
        """
        # Group
        group_kv = {"id":self.GROUP_ID, "ra_string":' '.join(ra_list)}
        self.group_id, group_scripts = self._gen_ra_scripts("GROUP", group_kv)
        # Clone
        clone_kv = {"id":self.CLONE_ID, "group_id":self.group_id}
        _, clone_scripts = self._gen_ra_scripts("CLONE", clone_kv)
        return group_scripts + clone_scripts

    def _gen_fs_scripts(self):
        """
        Generate Filesystem scripts
        """
        fs_kv = {
                "id": self.FS_RA_ID,
                "mnt_point": self.mount_point,
                "fs_type": "ocfs2",
                "device": self.target_device
                }
        return self._gen_ra_scripts("Filesystem", fs_kv)

    def _load_append_and_wait(self, scripts, res_id, msg, need_append=True):
        """
        Load scripts, append to exist group and wait resource started
        """
        bootstrap.crm_configure_load("update", scripts)
        if need_append:
            utils.append_res_to_group(self.group_id, res_id)
        bootstrap.wait_for_resource(msg, res_id)

    def _config_dlm(self):
        """
        Configure DLM resource
        """
        config_scripts = ""
        dlm_id, dlm_scripts = self._gen_ra_scripts("DLM", {"id":self.DLM_RA_ID})
        group_clone_scripts = self._gen_group_and_clone_scripts([dlm_id])
        config_scripts = dlm_scripts + group_clone_scripts
        self._load_append_and_wait(config_scripts, dlm_id, "  Wait for DLM({}) start".format(dlm_id), need_append=False)

    def _config_lvmlockd(self):
        """
        Configure LVMLockd resource
        """
        _id, _scripts = self._gen_ra_scripts("LVMLockd", {"id":self.LVMLOCKD_RA_ID})
        self._load_append_and_wait(_scripts, _id, "  Wait for LVMLockd({}) start".format(_id))

    def _config_lvmactivate(self):
        """
        Configure LVMActivate resource
        """
        _id, _scripts = self._gen_ra_scripts("LVMActivate", {"id": self.LVMACTIVATE_RA_ID, "vgname": self.vg_id})
        self._load_append_and_wait(_scripts, _id, "  Wait for LVMActivate({}) start".format(_id))

    def _config_fs(self):
        """
        Configure Filesystem resource
        """
        utils.mkdirp(self.mount_point)
        _id, _scripts = self._gen_fs_scripts()
        self._load_append_and_wait(_scripts, _id, "  Wait for Filesystem({}) start".format(_id))

    def _config_resource_stack_lvm2(self):
        """
        Configure dlm + lvmlockd + lvm-activate + Filesystem
        """
        self._config_dlm()
        self._config_lvmlockd()
        self.target_device = self._create_lv()
        with self._vg_change():
            self._mkfs(self.target_device)
        self._config_lvmactivate()
        self._config_fs()

    def _config_resource_stack_ocfs2_along(self):
        """
        Configure dlm + Filesystem
        """
        self._config_dlm()
        self.target_device = self.ocfs2_devices[0]
        self._mkfs(self.target_device)
        self._config_fs()

    def init_ocfs2(self):
        """
        OCFS2 configure process on init node
        """
        logger.info("Configuring OCFS2")
        self._dynamic_verify()
        self.exist_ra_id_list = utils.all_exist_id()

        no_quorum_policy_value = utils.get_property("no-quorum-policy")
        if not no_quorum_policy_value or no_quorum_policy_value != "freeze":
            utils.set_property("no-quorum-policy", "freeze")
            logger.info("  'no-quorum-policy' is changed to \"freeze\"")

        if self.use_cluster_lvm2:
            self._config_resource_stack_lvm2()
        else:
            self._config_resource_stack_ocfs2_along()
        logger.info("  OCFS2 device %s mounted on %s", self.target_device, self.mount_point)

    def _find_target_on_join(self, peer):
        """
        Find device name from OCF Filesystem param on peer node
        """
        out = utils.get_stdout_or_raise_error("crm configure show", remote=peer)
        for line in out.splitlines():
            if "fstype=ocfs2" in line:
                res = re.search("device=\"(.*?)\"", line)
                if res:
                    return res.group(1)
                else:
                    raise ValueError("Filesystem require configure device")
        return None

    def join_ocfs2(self, peer):
        """
        Called on join process, to verify ocfs2 environment
        """
        target = self._find_target_on_join(peer)
        if not target:
            return
        with logger_utils.status_long("Verify OCFS2 environment"):
            use_cluster_lvm2 = xmlutil.CrmMonXmlParser(peer).is_resource_configured(constants.LVMLOCKD_RA)
            self._verify_packages(use_cluster_lvm2)
            if utils.is_dev_a_plain_raw_disk_or_partition(target, peer):
                utils.compare_uuid_with_peer_dev([target], peer)

    @classmethod
    def verify_ocfs2(cls, ctx):
        """
        Verify OCFS2 related packages and environment
        """
        inst = cls(ctx)
        inst._static_verify()
