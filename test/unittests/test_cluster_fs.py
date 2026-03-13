import unittest
from unittest import mock

from crmsh import cluster_fs, utils, ra


class TestClusterFSManager(unittest.TestCase):

    @mock.patch("crmsh.cluster_fs.ClusterFSManager._verify_options")
    def setUp(self, mock_verify_options):
        ocfs2_context_one_device = mock.Mock(ocfs2_devices=["/dev/sda1"], gfs2_devices=[], use_cluster_lvm2=False, stage=None)
        gfs2_context_one_device_clvm2 = mock.Mock(ocfs2_devices=[], gfs2_devices=["/dev/sda1"], use_cluster_lvm2=True)
        self.ocfs2_instance_one_device = cluster_fs.ClusterFSManager(ocfs2_context_one_device)
        self.gfs2_instance_one_device_clvm2 = cluster_fs.ClusterFSManager(gfs2_context_one_device_clvm2)

        ocfs2_gfs2_both_context = mock.Mock(ocfs2_devices=["/dev/sda1"], gfs2_devices=["/dev/sda2"])
        self.instance_both = cluster_fs.ClusterFSManager(ocfs2_gfs2_both_context)

        ocfs2_stage_without_device_context = mock.Mock(ocfs2_devices=[], gfs2_devices=[], stage="ocfs2")
        self.instance_ocfs2_stage_without_device = cluster_fs.ClusterFSManager(ocfs2_stage_without_device_context)

        gfs2_stage_without_device_context = mock.Mock(ocfs2_devices=[], gfs2_devices=[], stage="gfs2")
        self.instance_gfs2_stage_without_device = cluster_fs.ClusterFSManager(gfs2_stage_without_device_context)

        ocfs2_stage_with_device_context = mock.Mock(ocfs2_devices=["/dev/sda1"], gfs2_devices=[], stage="ocfs2", use_cluster_lvm2=False)
        self.instance_ocfs2_stage_with_device = cluster_fs.ClusterFSManager(ocfs2_stage_with_device_context)

        ocfs2_stage_with_device_clvm2_context = mock.Mock(ocfs2_devices=["/dev/sda1"], gfs2_devices=[], stage="ocfs2", use_cluster_lvm2=True)
        self.instance_ocfs2_stage_with_device_clvm2 = cluster_fs.ClusterFSManager(ocfs2_stage_with_device_clvm2_context)

        clvm2_without_device_context = mock.Mock(ocfs2_devices=[], gfs2_devices=[], use_cluster_lvm2=True)
        self.instance_clvm2_without_device = cluster_fs.ClusterFSManager(clvm2_without_device_context)

        multi_ocfs2_devices_without_clvm2_context = mock.Mock(ocfs2_devices=["/dev/sda1", "/dev/sda2"], gfs2_devices=[], use_cluster_lvm2=False)
        self.multi_ocfs2_devices_without_clvm2 = cluster_fs.ClusterFSManager(multi_ocfs2_devices_without_clvm2_context)

        multi_gfs2_devices_without_clvm2_context = mock.Mock(ocfs2_devices=[], gfs2_devices=["/dev/sda1", "/dev/sda2"], use_cluster_lvm2=False)
        self.multi_gfs2_devices_without_clvm2 = cluster_fs.ClusterFSManager(multi_gfs2_devices_without_clvm2_context)

        gfs2_context_one_device_with_mount_point = mock.Mock(ocfs2_devices=[], gfs2_devices=["/dev/sda1"], use_cluster_lvm2=False, mount_point="/mnt/gfs2")
        self.gfs2_instance_one_device_with_mount_point = cluster_fs.ClusterFSManager(gfs2_context_one_device_with_mount_point)

    @mock.patch("crmsh.utils.package_is_installed")
    @mock.patch("crmsh.utils.list_cluster_nodes")
    def test_verify_packages_local(self, mock_list_cluster_nodes, mock_package_is_installed):
        mock_package_is_installed.return_value = True
        self.ocfs2_instance_one_device._verify_packages()
        mock_list_cluster_nodes.assert_not_called()
        mock_package_is_installed.assert_called_once_with("ocfs2-tools", None)

    @mock.patch("crmsh.utils.package_is_installed")
    @mock.patch("crmsh.utils.list_cluster_nodes")
    def test_verify_packages_remote(self, mock_list_cluster_nodes, mock_package_is_installed):
        mock_list_cluster_nodes.return_value = ["node1", "node2"]
        mock_package_is_installed.return_value = False
        with self.assertRaises(cluster_fs.Error) as context:
            self.instance_ocfs2_stage_with_device_clvm2._verify_packages()
        self.assertIn("Missing required package for configuring OCFS2 on node1: ocfs2-tools", str(context.exception))

    def test_verify_options(self):
        with self.assertRaises(cluster_fs.Error) as context:
            self.instance_both._verify_options()
        self.assertIn("Can't use -g and -o options together", str(context.exception))

        with self.assertRaises(cluster_fs.Error) as context:
            self.instance_ocfs2_stage_without_device._verify_options()
        self.assertIn("ocfs2 stage require -o option", str(context.exception))

        with self.assertRaises(cluster_fs.Error) as context:
            self.instance_gfs2_stage_without_device._verify_options()
        self.assertIn("gfs2 stage require -g option", str(context.exception))

        with self.assertRaises(cluster_fs.Error) as context:
            self.instance_clvm2_without_device._verify_options()
        self.assertIn("-C option only valid together with -o or -g option", str(context.exception))
        with self.assertRaises(cluster_fs.Error) as context:
            self.multi_ocfs2_devices_without_clvm2._verify_options()
        self.assertIn("Without Cluster LVM2 (-C option), -o option only support one device", str(context.exception))

        with self.assertRaises(cluster_fs.Error) as context:
            self.multi_gfs2_devices_without_clvm2._verify_options()
        self.assertIn("Without Cluster LVM2 (-C option), -g option only support one device", str(context.exception))

    @mock.patch("crmsh.utils.has_mount_point_used")
    def test_verify_options_mount_point(self, mock_has_mount_point_used):
        mock_has_mount_point_used.return_value = True
        with self.assertRaises(cluster_fs.Error) as context:
            self.gfs2_instance_one_device_with_mount_point._verify_options()
        self.assertIn("Mount point /mnt/gfs2 already mounted", str(context.exception))

    @mock.patch("crmsh.utils.is_block_device")
    def test_verify_devices_not_block_device(self, mock_is_block_device):
        mock_is_block_device.return_value = False
        with self.assertRaises(cluster_fs.Error) as context:
            self.ocfs2_instance_one_device._verify_devices()
        self.assertIn("/dev/sda1 doesn't look like a block device", str(context.exception))

    @mock.patch("crmsh.utils.is_dev_used_for_lvm")
    @mock.patch("crmsh.utils.is_block_device")
    def test_verify_devices_clvm2_with_lv(self, mock_is_block_device, mock_is_dev_used_for_lvm):
        mock_is_block_device.return_value = True
        mock_is_dev_used_for_lvm.return_value = True
        with self.assertRaises(cluster_fs.Error) as context:
            self.gfs2_instance_one_device_clvm2._verify_devices()
        self.assertIn("/dev/sda1 is a Logical Volume, cannot be used with the -C option", str(context.exception))

    @mock.patch("crmsh.utils.has_disk_mounted")
    @mock.patch("crmsh.utils.is_dev_used_for_lvm")
    @mock.patch("crmsh.utils.is_block_device")
    def test_verify_devices_already_mounted(self, mock_is_block_device, mock_is_dev_used_for_lvm, mock_has_disk_mounted):
        mock_is_block_device.return_value = True
        mock_is_dev_used_for_lvm.return_value = False
        mock_has_disk_mounted.return_value = True
        with self.assertRaises(cluster_fs.Error) as context:
            self.ocfs2_instance_one_device._verify_devices()
        self.assertIn("/dev/sda1 is already mounted", str(context.exception))

    @mock.patch("crmsh.sh.cluster_shell")
    def test_check_if_already_configured_return(self, mock_cluster_shell):
        self.ocfs2_instance_one_device._check_if_already_configured()
        mock_cluster_shell.assert_not_called()

    @mock.patch("logging.Logger.warning")
    @mock.patch("crmsh.sh.cluster_shell")
    def test_check_if_already_configured(self, mock_cluster_shell, mock_warning):
        mock_cluster_shell_inst = mock.Mock()
        mock_cluster_shell.return_value = mock_cluster_shell_inst
        mock_cluster_shell_inst.get_stdout_or_raise_error.return_value = """
        fstype=ocfs2
        data
        """
        with self.assertRaises(utils.TerminateSubCommand):
            self.instance_ocfs2_stage_with_device._check_if_already_configured()
        mock_warning.assert_called_once_with("Already configured %s related resources", "OCFS2")

    def test_pre_verify(self):
        self.ocfs2_instance_one_device._verify_packages = mock.Mock()
        self.ocfs2_instance_one_device._check_if_already_configured = mock.Mock()
        self.ocfs2_instance_one_device._verify_devices = mock.Mock()
        self.ocfs2_instance_one_device._pre_verify()
        self.ocfs2_instance_one_device._verify_packages.assert_called_once()
        self.ocfs2_instance_one_device._check_if_already_configured.assert_called_once()
        self.ocfs2_instance_one_device._verify_devices.assert_called_once()

    @mock.patch("crmsh.sbd.SBDUtils.get_sbd_device_from_config")
    @mock.patch("crmsh.cluster_fs.ServiceManager")
    def test_check_device_with_sbd_device(self, mock_service_manager, mock_get_sbd_device_from_config):
        mock_service_manager_inst = mock.Mock()
        mock_service_manager.return_value = mock_service_manager_inst
        mock_service_manager_inst.service_is_enabled.return_value = True
        mock_get_sbd_device_from_config.return_value = "/dev/sda1"
        with self.assertRaises(cluster_fs.Error) as context:
            self.instance_ocfs2_stage_with_device._check_device_with_sbd_device()
        self.assertEqual(str(context.exception), '/dev/sda1 cannot be the same with SBD device')

    @mock.patch("crmsh.bootstrap.confirm")
    @mock.patch("crmsh.utils.has_dev_partitioned")
    def test_confirm_to_overwrite_device_no_overwrite(self, mock_has_dev_partitioned, mock_confirm):
        mock_has_dev_partitioned.return_value = True
        mock_confirm.return_value = False
        with self.assertRaises(utils.TerminateSubCommand):
            self.ocfs2_instance_one_device._confirm_to_overwrite_device()
        mock_confirm.assert_called_once_with("Found a partition table in /dev/sda1 - overwrite?")

    @mock.patch("crmsh.sh.cluster_shell")
    @mock.patch("crmsh.bootstrap.confirm")
    @mock.patch("crmsh.utils.get_dev_fs_type")
    @mock.patch("crmsh.utils.has_dev_partitioned")
    def test_confirm_to_overwrite_device(self, mock_has_dev_partitioned, mock_get_dev_fs_type, mock_confirm, mock_cluster_shell):
        mock_has_dev_partitioned.return_value = False
        mock_get_dev_fs_type.return_value = "ext4"
        mock_confirm.return_value = True
        mock_cluster_shell_inst = mock.Mock()
        mock_cluster_shell.return_value = mock_cluster_shell_inst
        mock_cluster_shell_inst.get_stdout_or_raise_error.return_value = None
        self.ocfs2_instance_one_device._confirm_to_overwrite_device()
        mock_confirm.assert_called_once_with("/dev/sda1 contains a ext4 file system - overwrite?")
        mock_cluster_shell_inst.get_stdout_or_raise_error.assert_called_once_with("wipefs -a /dev/sda1")

    @mock.patch("crmsh.utils.has_fence_device_registered")
    def test_init_verify_no_fence_device(self, mock_has_fence_device_registered):
        mock_has_fence_device_registered.return_value = False
        with self.assertRaises(cluster_fs.Error) as context:
            self.instance_ocfs2_stage_with_device.init_verify()
        self.assertIn("OCFS2 requires fence device configured and running", str(context.exception))

    def test_gen_ra_scripts_unsupport_type(self):
        with self.assertRaises(cluster_fs.Error) as context:
            self.ocfs2_instance_one_device._gen_ra_scripts("unsupport", {})
        self.assertIn("Unsupported RA type: unsupport", str(context.exception))

    @mock.patch("crmsh.utils.gen_unused_id")
    def test_gen_ra_scripts(self, mock_gen_unused_id):
        mock_gen_unused_id.return_value = "dlm"
        _id, scripts = self.ocfs2_instance_one_device._gen_ra_scripts("DLM", {"id": "dlm"})
        self.assertEqual(_id, "dlm")
        self.assertEqual(scripts, ra.DLM_RA_SCRIPTS.format(id="dlm"))

    @mock.patch("crmsh.sh.cluster_shell")
    @mock.patch("crmsh.log.LoggerUtils.status_long")
    @mock.patch("logging.Logger.debug")
    @mock.patch("crmsh.corosync.get_value")
    def test_mkfs_ocfs2(self, mock_get_value, mock_debug, mock_status_long, mock_cluster_shell):
        mock_get_value.return_value = "hacluster"
        mock_status_long.return_value.__enter__ = mock.Mock()
        mock_status_long.return_value.__exit__ = mock.Mock()
        mock_cluster_shell_inst = mock.Mock()
        mock_cluster_shell.return_value = mock_cluster_shell_inst
        mock_cluster_shell_inst.get_stdout_or_raise_error.return_value = ""
        self.ocfs2_instance_one_device.target_device = "/dev/sda1"
        self.ocfs2_instance_one_device._mkfs()
        mock_debug.assert_called_once_with("mkfs command: %s", "mkfs.ocfs2 --cluster-stack pcmk --cluster-name hacluster -N 8 -x /dev/sda1")
        mock_status_long.assert_called_once_with("Creating ocfs2 filesystem on /dev/sda1")

    @mock.patch("crmsh.utils.randomword")
    @mock.patch("crmsh.sh.cluster_shell")
    @mock.patch("crmsh.log.LoggerUtils.status_long")
    @mock.patch("logging.Logger.debug")
    @mock.patch("crmsh.corosync.get_value")
    def test_mkfs_gfs2(self, mock_get_value, mock_debug, mock_status_long, mock_cluster_shell, mock_randomword):
        mock_randomword.return_value = "exezoy"
        mock_get_value.return_value = "hacluster"
        mock_status_long.return_value.__enter__ = mock.Mock()
        mock_status_long.return_value.__exit__ = mock.Mock()
        mock_cluster_shell_inst = mock.Mock()
        mock_cluster_shell.return_value = mock_cluster_shell_inst
        mock_cluster_shell_inst.get_stdout_or_raise_error.return_value = ""
        self.gfs2_instance_one_device_clvm2.target_device = "/dev/sda1"
        self.gfs2_instance_one_device_clvm2._mkfs()
        mock_debug.assert_called_once_with("mkfs command: %s", "mkfs.gfs2 -t hacluster:FS_exezoy -p lock_dlm -j 8 /dev/sda1 -O")
        mock_status_long.assert_called_once_with("Creating gfs2 filesystem on /dev/sda1")

    @mock.patch("crmsh.utils.set_property")
    @mock.patch("crmsh.utils.get_property")
    @mock.patch("crmsh.utils.all_exist_id")
    @mock.patch("logging.Logger.info")
    def test_init(self, mock_info, mock_all_exist_id, mock_get_property, mock_set_property):
        mock_all_exist_id.return_value = ["ocfs2"]
        mock_get_property.return_value = "good"
        self.ocfs2_instance_one_device.init_verify = mock.Mock()
        self.ocfs2_instance_one_device._configure_resource_stack = mock.Mock()
        self.ocfs2_instance_one_device.init()
        mock_info.assert_called_once_with("Configuring %s", "OCFS2")
        mock_set_property.assert_called_once_with("no-quorum-policy", "freeze")

    @mock.patch("logging.Logger.info")
    def test_configure_resource_stack_lvm2(self, mock_info):
        self.gfs2_instance_one_device_clvm2._config_dlm = mock.Mock()
        self.gfs2_instance_one_device_clvm2._config_lvmlockd = mock.Mock()
        self.gfs2_instance_one_device_clvm2._create_lv = mock.Mock(return_value="/dev/vg/lv")
        self.gfs2_instance_one_device_clvm2._vg_change = mock.Mock()
        self.gfs2_instance_one_device_clvm2._vg_change.return_value.__enter__ = mock.Mock()
        self.gfs2_instance_one_device_clvm2._vg_change.return_value.__exit__ = mock.Mock()
        self.gfs2_instance_one_device_clvm2._mkfs = mock.Mock()
        self.gfs2_instance_one_device_clvm2._config_lvmactivate = mock.Mock()
        self.gfs2_instance_one_device_clvm2._config_fs = mock.Mock()
        self.gfs2_instance_one_device_clvm2.mount_point = "/mnt/gfs2"
        self.gfs2_instance_one_device_clvm2._configure_resource_stack()
        mock_info.assert_called_once_with('%s device %s mounted on %s', 'GFS2', '/dev/vg/lv', '/mnt/gfs2')

    @mock.patch("logging.Logger.info")
    def test_configure_resource_stack(self, mock_info):
        self.ocfs2_instance_one_device._config_dlm = mock.Mock()
        self.ocfs2_instance_one_device._mkfs = mock.Mock()
        self.ocfs2_instance_one_device._config_fs = mock.Mock()
        self.ocfs2_instance_one_device.mount_point = "/mnt/ocfs2"
        self.ocfs2_instance_one_device._configure_resource_stack()
        mock_info.assert_called_once_with('%s device %s mounted on %s', 'OCFS2', '/dev/sda1', '/mnt/ocfs2')

    @mock.patch("crmsh.sh.cluster_shell")
    def test_find_target_on_join_none(self, mock_cluster_shell):
        mock_cluster_shell_inst = mock.Mock()
        mock_cluster_shell.return_value = mock_cluster_shell_inst
        mock_cluster_shell_inst.get_stdout_or_raise_error.return_value = "data"
        self.assertIsNone(self.ocfs2_instance_one_device._find_target_on_join("node1"))
        mock_cluster_shell_inst.get_stdout_or_raise_error.assert_called_once_with("crm configure show", "node1")

    @mock.patch("crmsh.sh.cluster_shell")
    def test_find_target_on_join(self, mock_cluster_shell):
        mock_cluster_shell_inst = mock.Mock()
        mock_cluster_shell.return_value = mock_cluster_shell_inst
        mock_cluster_shell_inst.get_stdout_or_raise_error.return_value = """
        primitive gfs2-clusterfs Filesystem \
        params directory="/srv/clusterfs" fstype=gfs2 device="/dev/sda6" \
        op monitor interval=20 timeout=40 \
        """
        expected_dict = {"cluster_fs_type": "gfs2", "device": "/dev/sda6"}
        self.assertDictEqual(self.ocfs2_instance_one_device._find_target_on_join("node1"), expected_dict)
        mock_cluster_shell_inst.get_stdout_or_raise_error.assert_called_once_with("crm configure show", "node1")

    @mock.patch("crmsh.log.LoggerUtils.status_long")
    def test_join_return(self, mock_status_long):
        self.ocfs2_instance_one_device._find_target_on_join = mock.Mock(return_value=None)
        self.ocfs2_instance_one_device.join("node1")
        mock_status_long.assert_not_called()

    @mock.patch("crmsh.utils.compare_uuid_with_peer_dev")
    @mock.patch("crmsh.utils.is_dev_a_plain_raw_disk_or_partition")
    @mock.patch("crmsh.xmlutil.CrmMonXmlParser")
    @mock.patch("crmsh.log.LoggerUtils.status_long")
    def test_join(self, mock_status_long, mock_crmmonxmlparser, mock_is_dev_a_plain_raw_disk_or_partition, mock_compare_uuid_with_peer_dev):
        mock_crmmonxmlparser_inst = mock.Mock()
        mock_crmmonxmlparser.return_value = mock_crmmonxmlparser_inst
        mock_crmmonxmlparser_inst.is_resource_configured = mock.Mock(return_value=True)
        self.ocfs2_instance_one_device._find_target_on_join = mock.Mock(return_value={"cluster_fs_type": "ocfs2", "device": "/dev/sda1"})
        self.ocfs2_instance_one_device._verify_packages = mock.Mock()
        mock_status_long.return_value.__enter__ = mock.Mock()
        mock_status_long.return_value.__exit__ = mock.Mock()
        mock_is_dev_a_plain_raw_disk_or_partition.return_value = True
        self.ocfs2_instance_one_device.join("node1")
        mock_status_long.assert_called_once_with("Verify OCFS2 environment on /dev/sda1")
