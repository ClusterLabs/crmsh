import re
from contextlib import contextmanager
from . import utils, sh
from . import bootstrap
from . import ra
from . import corosync
from . import log
from . import xmlutil
from . import constants
from . import sbd
from .service_manager import ServiceManager

logger = log.setup_logger(__name__)
logger_utils = log.LoggerUtils(logger)


class Error(ValueError):
    def __init__(self, msg: str):
        super().__init__(msg)


class ClusterFSManager(object):
    """
    Class to manage cluster filesystem (OCFS2 or GFS2)
    and configure related resources
    """
    def __init__(self, context):
        """
        Init function
        """
        self.ocfs2_devices = context.ocfs2_devices
        self.gfs2_devices = context.gfs2_devices
        self.stage = context.stage
        self.use_cluster_lvm2 = context.use_cluster_lvm2
        self.mount_point = context.mount_point
        self.use_stage = context.stage in ("ocfs2", "gfs2")
        self.yes_to_all = context.yes_to_all
        self.exist_ra_id_list = []
        self.vg_id = None
        self.group_id = None
        # device that finally mounted
        self.target_device = None
        self.type = None
        self.devices = []

        self._verify_options()

        if self.ocfs2_devices:
            self.type = "OCFS2"
            self.devices = self.ocfs2_devices
        elif self.gfs2_devices:
            self.type = "GFS2"
            self.devices = self.gfs2_devices
        if self.type:
            prefix = self.type.lower()
            self.fstype = prefix

            # Consider such issue might not be fixed in the local pacemaker version
            # https://github.com/ClusterLabs/pacemaker/pull/3766
            # DLM RA's id shouldn avoid using 'gfs' as prefix
            self.DLM_RA_ID = "dlm"
            self.FS_RA_ID = f"{prefix}-clusterfs"
            self.LVMLOCKD_RA_ID = f"{prefix}-lvmlockd"
            self.LVMACTIVATE_RA_ID = f"{prefix}-lvmactivate"
            self.GROUP_ID = f"{prefix}-group"
            self.CLONE_ID = f"{prefix}-clone"
            self.VG_ID = f"{prefix}-vg"
            self.LV_ID = f"{prefix}-lv"

    def _verify_packages(self, fs_type=None, use_cluster_lvm2=None):
        """
        Find if missing required package
        """
        _type = fs_type or self.type
        _use_cluster_lvm2 = use_cluster_lvm2 or self.use_cluster_lvm2
        cluster_nodes = utils.list_cluster_nodes() if self.use_stage else []

        package_requirements = {
            "GFS2": ["gfs2-utils"],
            "OCFS2": ["ocfs2-tools"]
        }
        required_packages = package_requirements.get(_type, [])
        if _use_cluster_lvm2:
            required_packages.append("lvm2-lockd")

        def check_packages(node=None):
            for pkg in required_packages:
                if not utils.package_is_installed(pkg, node):
                    node_info = f" on {node}" if node else ""
                    raise Error(f"Missing required package for configuring {_type}{node_info}: {pkg}")

        for node in cluster_nodes:
            check_packages(node)
        else:
            check_packages()

    def _verify_options(self):
        """
        Verify options related with OCFS2 and GFS2
        """
        if self.gfs2_devices and self.ocfs2_devices:
            raise Error("Can't use -g and -o options together")
        if self.stage == "ocfs2" and not self.ocfs2_devices:
            raise Error("ocfs2 stage require -o option")
        if self.stage == "gfs2" and not self.gfs2_devices:
            raise Error("gfs2 stage require -g option")
        if self.use_cluster_lvm2:
            if not self.ocfs2_devices and not self.gfs2_devices:
                raise Error("-C option only valid together with -o or -g option")
        else:
            if len(self.ocfs2_devices) > 1:
                raise Error("Without Cluster LVM2 (-C option), -o option only support one device")
            elif len(self.gfs2_devices) > 1:
                raise Error("Without Cluster LVM2 (-C option), -g option only support one device")
        if self.mount_point and utils.has_mount_point_used(self.mount_point):
            raise Error(f"Mount point {self.mount_point} already mounted")

    def _verify_devices(self):
        """
        Verify OCFS2/GFS2 devices
        """
        for dev in self.devices:
            if not utils.is_block_device(dev):
                raise Error(f"{dev} doesn't look like a block device")
            if utils.is_dev_used_for_lvm(dev) and self.use_cluster_lvm2:
                raise Error(f"{dev} is a Logical Volume, cannot be used with the -C option")
            if utils.has_disk_mounted(dev):
                raise Error(f"{dev} is already mounted")

    def _check_if_already_configured(self):
        """
        Check if OCFS2/GFS2 related resource already configured
        """
        if not self.use_stage:
            return
        out = sh.cluster_shell().get_stdout_or_raise_error("crm configure show")
        if f"fstype={self.fstype}" in out:
            logger.warning("Already configured %s related resources", self.type)
            raise utils.TerminateSubCommand

    def _pre_verify(self):
        """
        Verify before configuring on init process
        """
        self._verify_packages()
        self._check_if_already_configured()
        self._verify_devices()

    @property
    def error_hints_for_stage(self):
        hints = f"""
The cluster service has already been initialized, but the prerequisites are missing
to configure {self.type}. Please fix it and use the stage procedure to configure {self.type} separately,
e.g. crm cluster init {self.type.lower()} -o <device>
        """
        return "" if self.use_stage else hints

    def _check_device_with_sbd_device(self):
        """
        Raise error when OCFS2/GFS2 device is the same with sbd device
        """
        if ServiceManager().service_is_enabled(constants.SBD_SERVICE):
            sbd_device_list = sbd.SBDUtils.get_sbd_device_from_config()
            for dev in self.devices:
                if dev in sbd_device_list:
                    msg = f"{dev} cannot be the same with SBD device" + self.error_hints_for_stage
                    raise Error(msg)

    def _confirm_to_overwrite_device(self):
        """
        Confirm to overwrit OCFS2/GFS2 device on interactive mode
        """
        for dev in self.devices:
            msg = ""
            if utils.has_dev_partitioned(dev):
                msg = f"Found a partition table in {dev}"
            else:
                fs_type = utils.get_dev_fs_type(dev)
                if fs_type:
                    msg = f"{dev} contains a {fs_type} file system"
            if msg and not bootstrap.confirm(f"{msg} - overwrite?"):
                raise utils.TerminateSubCommand

        shell = sh.cluster_shell()
        for dev in self.devices:
            shell.get_stdout_or_raise_error(f"wipefs -a {dev}")

    def init_verify(self):
        """
        Verify after cluster running on init node
        """
        if not utils.has_stonith_running():
            msg = f"{self.type} requires stonith device configured and running." + self.error_hints_for_stage
            raise Error(msg)

        self._check_device_with_sbd_device()
        self._confirm_to_overwrite_device()

    def _gen_ra_scripts(self, ra_type: str, kv: dict) -> tuple[str, str]:
        """
        Generate ra scripts
        Return id and scripts
        """
        if ra_type not in ra.CONFIGURE_RA_TEMPLATE_DICT:
            raise Error(f"Unsupported RA type: {ra_type}")
        config_scripts = ""
        kv["id"] = utils.gen_unused_id(self.exist_ra_id_list, kv["id"])
        config_scripts = ra.CONFIGURE_RA_TEMPLATE_DICT[ra_type].format(**kv)
        return kv["id"], config_scripts

    def _mkfs(self):
        """
        Creating OCFS2/GFS2 filesystem for the target device
        """
        cluster_name = corosync.get_value('totem.cluster_name')
        mkfs_cmd = ""
        if self.type == "OCFS2":
            # TODO now -N value is fixed to 8, need to be configurable in the future if needed
            mkfs_cmd = f"mkfs.ocfs2 --cluster-stack pcmk --cluster-name {cluster_name} -N 8 -x {self.target_device}"
        elif self.type == "GFS2":
            # TODO make sure the lock table name is real unique in the future if needed
            lock_table_name = f"{cluster_name}:FS_{utils.randomword(12)}"
            # TODO now -j value is fixed to 8, need to be configurable in the future if needed
            mkfs_cmd = f"mkfs.gfs2 -t {lock_table_name} -p lock_dlm -j 8 {self.target_device} -O"
        logger.debug("mkfs command: %s", mkfs_cmd)
        with logger_utils.status_long(f"Creating {self.fstype} filesystem on {self.target_device}"):
            sh.cluster_shell().get_stdout_or_raise_error(mkfs_cmd)

    @contextmanager
    def _vg_change(self):
        """
        vgchange process using contextmanager
        """
        shell = sh.cluster_shell()
        shell.get_stdout_or_raise_error(f"vgchange -ay {self.vg_id}")
        try:
            yield
        finally:
            shell.get_stdout_or_raise_error(f"vgchange -an {self.vg_id}")

    def _create_lv(self):
        """
        Create PV, VG, LV and return LV path
        """
        disks_string = ' '.join(self.devices)
        shell = sh.cluster_shell()

        # Create PV
        with logger_utils.status_long(f"Creating PV for {disks_string}"):
            shell.get_stdout_or_raise_error(f"pvcreate {disks_string} -y")

        # Create VG
        self.vg_id = utils.gen_unused_id(utils.get_all_vg_name(), self.VG_ID)
        with logger_utils.status_long(f"Creating VG {self.vg_id}"):
            shell.get_stdout_or_raise_error(f"vgcreate --shared {self.vg_id} {disks_string} -y")

        # Create LV
        with logger_utils.status_long(f"Creating LV {self.LV_ID} on VG {self.vg_id}"):
            pe_number = utils.get_pe_number(self.vg_id)
            shell.get_stdout_or_raise_error(f"lvcreate -l {pe_number} {self.vg_id} -n {self.LV_ID} -y")
 
        return f"/dev/{self.vg_id}/{self.LV_ID}"

    def _gen_group_and_clone_scripts(self, ra_list: list) -> str:
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
                "fs_type": self.fstype,
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
        msg = f"Wait for DLM ({dlm_id}) start"
        self._load_append_and_wait(config_scripts, dlm_id, msg, need_append=False)

    def _config_lvmlockd(self):
        """
        Configure LVMLockd resource
        """
        _id, _scripts = self._gen_ra_scripts("LVMLockd", {"id":self.LVMLOCKD_RA_ID})
        msg = f"Wait for LVMLockd ({_id}) start"
        self._load_append_and_wait(_scripts, _id, msg)

    def _config_lvmactivate(self):
        """
        Configure LVMActivate resource
        """
        _id, _scripts = self._gen_ra_scripts("LVMActivate", {"id": self.LVMACTIVATE_RA_ID, "vgname": self.vg_id})
        msg = f"Wait for LVMActivate ({_id}) start"
        self._load_append_and_wait(_scripts, _id, msg)

    def _config_fs(self):
        """
        Configure Filesystem resource
        """
        utils.mkdirp(self.mount_point)
        _id, _scripts = self._gen_fs_scripts()
        msg = f"Wait for Filesystem ({_id}) start"
        self._load_append_and_wait(_scripts, _id, msg)

    def _configure_resource_stack(self):
        self._config_dlm()

        if self.use_cluster_lvm2:
            # Configure dlm + lvmlockd + lvm-activate + Filesystem
            self._config_lvmlockd()
            self.target_device = self._create_lv()
            with self._vg_change():
                self._mkfs()
            self._config_lvmactivate()
        else:
            # Configure dlm + Filesystem
            self.target_device = self.devices[0]
            self._mkfs()

        self._config_fs()

        logger.info("%s device %s mounted on %s", self.type, self.target_device, self.mount_point)

    def init(self):
        """
        OCFS2/GFS2 configure process on init node
        """
        logger.info("Configuring %s", self.type)

        self.init_verify()

        self.exist_ra_id_list = utils.all_exist_id()

        no_quorum_policy_value = utils.get_property("no-quorum-policy")
        if not no_quorum_policy_value or no_quorum_policy_value != "freeze":
            utils.set_property("no-quorum-policy", "freeze")

        self._configure_resource_stack()

    def _find_target_on_join(self, peer) -> dict:
        """
        Find device name from OCF2/GFS2 Filesystem param on peer node
        Return (cluster_fs_type, device)
        """
        fstype_pattern = r'fstype=(ocfs2|gfs2)'
        device_pattern = r'device="([^"]+)"'
        pattern = rf'{fstype_pattern}.*{device_pattern}|{device_pattern}.*{fstype_pattern}'
        out = sh.cluster_shell().get_stdout_or_raise_error("crm configure show", peer)
        res = re.search(pattern, out)
        if res:
            cluster_fs_type = res.group(1) or res.group(4)
            device = res.group(2) or res.group(3)
            return {"cluster_fs_type": cluster_fs_type, "device": device}
        return None

    def join(self, peer):
        """
        Called on join process, to verify OCFS2/GFS2 environment
        """
        target_dict = self._find_target_on_join(peer)
        if not target_dict:
            return
        cluster_fs_type, device = target_dict["cluster_fs_type"], target_dict["device"]
        with logger_utils.status_long(f"Verify {cluster_fs_type.upper()} environment on {device}"):
            use_cluster_lvm2 = xmlutil.CrmMonXmlParser(peer).is_resource_configured(constants.LVMLOCKD_RA)
            self._verify_packages(cluster_fs_type.upper(), use_cluster_lvm2)
            if utils.is_dev_a_plain_raw_disk_or_partition(device, peer):
                utils.compare_uuid_with_peer_dev([device], peer)

    @classmethod
    def pre_verify(cls, ctx):
        inst = cls(ctx)
        inst._pre_verify()
