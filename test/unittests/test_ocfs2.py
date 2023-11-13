import logging
import unittest
try:
    from unittest import mock
except ImportError:
    import mock
from crmsh import ocfs2, utils, ra, constants

logging.basicConfig(level=logging.INFO)

class TestOCFS2Manager(unittest.TestCase):
    """
    Unitary tests for crmsh.bootstrap.SBDManager
    """

    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

    def setUp(self):
        """
        Test setUp.
        """
        context1 = mock.Mock(ocfs2_devices=[])
        self.ocfs2_inst1 = ocfs2.OCFS2Manager(context1)

        context2 = mock.Mock(ocfs2_devices=[],
                stage="ocfs2",
                yes_to_all=True)
        self.ocfs2_inst2 = ocfs2.OCFS2Manager(context2)

        context3 = mock.Mock(ocfs2_devices=["/dev/sdb2", "/dev/sdc2"],
                use_cluster_lvm2=False)
        self.ocfs2_inst3 = ocfs2.OCFS2Manager(context3)

        context4 = mock.Mock(ocfs2_devices=[],
                use_cluster_lvm2=True)
        self.ocfs2_inst4 = ocfs2.OCFS2Manager(context4)

        context5 = mock.Mock(ocfs2_devices=["/dev/sda2", "/dev/sda2"])
        self.ocfs2_inst5 = ocfs2.OCFS2Manager(context5)

        context6 = mock.Mock(ocfs2_devices=["/dev/sda2"],
                mount_point="/data")
        self.ocfs2_inst6 = ocfs2.OCFS2Manager(context6)

        context7 = mock.Mock(ocfs2_devices=["/dev/sdb2"],
                use_cluster_lvm2=True)
        self.ocfs2_inst7 = ocfs2.OCFS2Manager(context7)

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    @mock.patch('crmsh.utils.package_is_installed')
    def test_verify_packages(self, mock_installed):
        mock_installed.side_effect = [True, False]
        with self.assertRaises(ValueError) as err:
            self.ocfs2_inst1._verify_packages(use_cluster_lvm2=True)
        self.assertEqual("Missing required package for configuring OCFS2: lvm2-lockd", str(err.exception))
        mock_installed.assert_has_calls([
            mock.call("ocfs2-tools"),
            mock.call("lvm2-lockd")
            ])

    def test_verify_options_stage_miss_option(self):
        with self.assertRaises(ValueError) as err:
            self.ocfs2_inst2._verify_options()
        self.assertEqual("ocfs2 stage require -o option", str(err.exception))

    def test_verify_options_two_devices(self):
        with self.assertRaises(ValueError) as err:
            self.ocfs2_inst3._verify_options()
        self.assertEqual("Without Cluster LVM2 (-C option), -o option only support one device", str(err.exception))

    def test_verify_options_only_C(self):
        with self.assertRaises(ValueError) as err:
            self.ocfs2_inst4._verify_options()
        self.assertEqual("-C option only valid together with -o option", str(err.exception))

    @mock.patch('crmsh.utils.has_mount_point_used')
    def test_verify_options_mount(self, mock_mount):
        mock_mount.return_value = True
        with self.assertRaises(ValueError) as err:
            self.ocfs2_inst6._verify_options()
        self.assertEqual("Mount point /data already mounted", str(err.exception))
        mock_mount.assert_called_once_with("/data")

    @mock.patch('crmsh.utils.is_block_device')
    def test_verify_devices_not_block(self, mock_is_block):
        mock_is_block.return_value = False
        with self.assertRaises(ValueError) as err:
            self.ocfs2_inst3._verify_devices()
        self.assertEqual("/dev/sdb2 doesn't look like a block device", str(err.exception))
        mock_is_block.assert_called_once_with("/dev/sdb2")

    @mock.patch('crmsh.utils.is_dev_used_for_lvm')
    @mock.patch('crmsh.utils.is_block_device')
    def test_verify_devices_lvm(self, mock_is_block, mock_lvm):
        mock_lvm.return_value = True
        mock_is_block.return_value = True
        with self.assertRaises(ValueError) as err:
            self.ocfs2_inst7._verify_devices()
        self.assertEqual("/dev/sdb2 is a Logical Volume, cannot be used with the -C option", str(err.exception))
        mock_is_block.assert_called_once_with("/dev/sdb2")
        mock_lvm.assert_called_once_with("/dev/sdb2")

    @mock.patch('crmsh.utils.has_disk_mounted')
    @mock.patch('crmsh.utils.is_dev_used_for_lvm')
    @mock.patch('crmsh.utils.is_block_device')
    def test_verify_devices_mounted(self, mock_is_block, mock_lvm, mock_mounted):
        mock_lvm.return_value = False
        mock_is_block.return_value = True
        mock_mounted.return_value = True
        with self.assertRaises(ValueError) as err:
            self.ocfs2_inst7._verify_devices()
        self.assertEqual("/dev/sdb2 already mounted", str(err.exception))
        mock_is_block.assert_called_once_with("/dev/sdb2")
        mock_lvm.assert_called_once_with("/dev/sdb2")
        mock_mounted.assert_called_once_with("/dev/sdb2")

    def test_check_if_already_configured_return(self):
        self.ocfs2_inst3._check_if_already_configured()

    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
    def test_check_if_already_configured(self, mock_run, mock_info):
        mock_run.return_value = "data xxx fstype=ocfs2  sss"
        with self.assertRaises(utils.TerminateSubCommand):
            self.ocfs2_inst2._check_if_already_configured()
        mock_run.assert_called_once_with("crm configure show")
        mock_info.assert_called_once_with("Already configured OCFS2 related resources")

    @mock.patch('crmsh.ocfs2.OCFS2Manager._verify_devices')
    @mock.patch('crmsh.ocfs2.OCFS2Manager._check_if_already_configured')
    @mock.patch('crmsh.ocfs2.OCFS2Manager._verify_options')
    @mock.patch('crmsh.ocfs2.OCFS2Manager._verify_packages')
    def test_static_verify(self, mock_verify_packages, mock_verify_options, mock_configured, mock_verify_devices):
        self.ocfs2_inst3._static_verify()
        mock_verify_packages.assert_called_once_with(False)
        mock_verify_options.assert_called_once_with()
        mock_configured.assert_called_once_with()
        mock_verify_devices.assert_called_once_with()

    def test_dynamic_raise_error(self):
        with self.assertRaises(ValueError) as err:
            self.ocfs2_inst2._dynamic_raise_error("error messages")
        self.assertEqual("error messages", str(err.exception))

    @mock.patch('crmsh.ocfs2.OCFS2Manager._dynamic_raise_error')
    @mock.patch('crmsh.sbd.SBDManager.get_sbd_device_from_config')
    @mock.patch('crmsh.service_manager.ServiceManager.service_is_enabled')
    def test_check_sbd_and_ocfs2_dev(self, mock_enabled, mock_get_device, mock_error):
        mock_enabled.return_value = True
        mock_get_device.return_value = ["/dev/sdb2"]
        self.ocfs2_inst3._check_sbd_and_ocfs2_dev()
        mock_enabled.assert_called_once_with("sbd.service")
        mock_get_device.assert_called_once_with()
        mock_error.assert_called_once_with("/dev/sdb2 cannot be the same with SBD device")

    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('crmsh.utils.get_dev_fs_type')
    @mock.patch('crmsh.utils.has_dev_partitioned')
    def test_confirm_to_overwrite_ocfs2_dev(self, mock_has_parted, mock_fstype, mock_confirm):
        mock_has_parted.side_effect = [True, False]
        mock_fstype.return_value = "ext4"
        mock_confirm.side_effect = [True, False]
        with self.assertRaises(utils.TerminateSubCommand) as err:
            self.ocfs2_inst3._confirm_to_overwrite_ocfs2_dev()
        mock_has_parted.assert_has_calls([
            mock.call("/dev/sdb2"),
            mock.call("/dev/sdc2")
            ])
        mock_fstype.assert_called_once_with("/dev/sdc2")
        mock_confirm.assert_has_calls([
            mock.call("Found a partition table in /dev/sdb2 - Proceed anyway?"),
            mock.call("/dev/sdc2 contains a ext4 file system - Proceed anyway?")
            ])

    @mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('crmsh.utils.get_dev_fs_type')
    @mock.patch('crmsh.utils.has_dev_partitioned')
    def test_confirm_to_overwrite_ocfs2_dev_confirmed(self, mock_has_parted, mock_fstype, mock_confirm, mock_run):
        mock_has_parted.side_effect = [True, False]
        mock_fstype.return_value = "ext4"
        mock_confirm.side_effect = [True, True]
        self.ocfs2_inst3._confirm_to_overwrite_ocfs2_dev()
        mock_has_parted.assert_has_calls([
            mock.call("/dev/sdb2"),
            mock.call("/dev/sdc2")
            ])
        mock_fstype.assert_called_once_with("/dev/sdc2")
        mock_confirm.assert_has_calls([
            mock.call("Found a partition table in /dev/sdb2 - Proceed anyway?"),
            mock.call("/dev/sdc2 contains a ext4 file system - Proceed anyway?")
            ])
        mock_run.assert_has_calls([
            mock.call("wipefs -a /dev/sdb2"),
            mock.call("wipefs -a /dev/sdc2")
            ])

    @mock.patch('crmsh.ocfs2.OCFS2Manager._dynamic_raise_error')
    @mock.patch('crmsh.utils.has_stonith_running')
    def test_dynamic_verify_error(self, mock_has_stonith, mock_error):
        mock_has_stonith.return_value = False
        mock_error.side_effect = SystemExit
        with self.assertRaises(SystemExit):
            self.ocfs2_inst3._dynamic_verify()
        mock_has_stonith.assert_called_once_with()
        mock_error.assert_called_once_with("OCFS2 requires stonith device configured and running")

    @mock.patch('crmsh.ocfs2.OCFS2Manager._confirm_to_overwrite_ocfs2_dev')
    @mock.patch('crmsh.ocfs2.OCFS2Manager._check_sbd_and_ocfs2_dev')
    @mock.patch('crmsh.utils.has_stonith_running')
    def test_dynamic_verify(self, mock_has_stonith, mock_check_dev, mock_confirm):
        mock_has_stonith.return_value = True
        self.ocfs2_inst3._dynamic_verify()
        mock_has_stonith.assert_called_once_with()
        mock_check_dev.assert_called_once_with()
        mock_confirm.assert_called_once_with()

    @mock.patch('crmsh.utils.gen_unused_id')
    def test_gen_ra_scripts(self, mock_gen_unused):
        self.ocfs2_inst3.exist_ra_id_list = []
        mock_gen_unused.return_value = "g1"
        res = self.ocfs2_inst3._gen_ra_scripts("GROUP", {"id": "g1", "ra_string": "d vip"})
        assert res == ("g1", "\ngroup g1 d vip")
        mock_gen_unused.assert_called_once_with([], "g1")

    @mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
    @mock.patch('crmsh.corosync.get_value')
    @mock.patch('crmsh.log.LoggerUtils.status_long')
    def test_mkfs(self, mock_long, mock_get_value, mock_run):
        mock_get_value.return_value = "hacluster"
        self.ocfs2_inst3._mkfs("/dev/sdb2")
        mock_long.assert_called_once_with("  Creating OCFS2 filesystem for /dev/sdb2")
        mock_get_value.assert_called_once_with("totem.cluster_name")
        mock_run.assert_called_once_with("mkfs.ocfs2 --cluster-stack pcmk --cluster-name hacluster -N 8 -x /dev/sdb2")

    @mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
    def test_vg_change(self, mock_run):
        self.ocfs2_inst3.vg_id = "vg1"
        with self.ocfs2_inst3._vg_change():
            pass
        mock_run.assert_has_calls([
            mock.call("vgchange -ay vg1"),
            mock.call("vgchange -an vg1")
            ])

    @mock.patch('crmsh.utils.get_pe_number')
    @mock.patch('crmsh.utils.gen_unused_id')
    @mock.patch('crmsh.utils.get_all_vg_name')
    @mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
    @mock.patch('crmsh.log.LoggerUtils.status_long')
    def test_create_lv(self, mock_long, mock_run, mock_all_vg, mock_unused, mock_pe_num):
        mock_all_vg.return_value = []
        mock_unused.return_value = "vg1"
        mock_pe_num.return_value = 1234
        res = self.ocfs2_inst3._create_lv()
        self.assertEqual(res, "/dev/vg1/ocfs2-lv")
        mock_run.assert_has_calls([
            mock.call("pvcreate /dev/sdb2 /dev/sdc2 -y"),
            mock.call("vgcreate --shared vg1 /dev/sdb2 /dev/sdc2 -y"),
            mock.call("lvcreate -l 1234 vg1 -n ocfs2-lv -y")
            ])

    @mock.patch('crmsh.ocfs2.OCFS2Manager._gen_ra_scripts')
    def test_gen_group_and_clone_scripts(self, mock_gen):
        mock_gen.side_effect = [("id1", "group_script\n"), ("id2", "clone_script\n")]
        res = self.ocfs2_inst3._gen_group_and_clone_scripts(["ra1", "ra2"])
        self.assertEqual(res, "group_script\nclone_script\n")
        mock_gen.assert_has_calls([
            mock.call('GROUP', {'id': 'ocfs2-group', 'ra_string': 'ra1 ra2'}),
            mock.call('CLONE', {'id': 'ocfs2-clone', 'group_id': 'id1'})
            ])

    @mock.patch('crmsh.ocfs2.OCFS2Manager._gen_ra_scripts')
    def test_gen_fs_scripts(self, mock_gen):
        mock_gen.return_value = "scripts"
        self.ocfs2_inst3.mount_point = "/data"
        self.ocfs2_inst3.target_device = "/dev/sda1"
        res = self.ocfs2_inst3._gen_fs_scripts()
        self.assertEqual(res, "scripts")
        mock_gen.assert_called_once_with("Filesystem", {'id': 'ocfs2-clusterfs', 'mnt_point': '/data', 'fs_type': 'ocfs2', 'device': '/dev/sda1'})

    @mock.patch('crmsh.bootstrap.wait_for_resource')
    @mock.patch('crmsh.utils.append_res_to_group')
    @mock.patch('crmsh.bootstrap.crm_configure_load')
    def test_load_append_and_wait(self, mock_load, mock_append, mock_wait):
        self.ocfs2_inst3.group_id = "g1"
        self.ocfs2_inst3._load_append_and_wait("scripts", "res_id", "messages data")
        mock_load.assert_called_once_with("update", "scripts")
        mock_append.assert_called_once_with("g1", "res_id")
        mock_wait.assert_called_once_with("messages data", "res_id")

    @mock.patch('crmsh.ocfs2.OCFS2Manager._load_append_and_wait')
    @mock.patch('crmsh.ocfs2.OCFS2Manager._gen_group_and_clone_scripts')
    @mock.patch('crmsh.ocfs2.OCFS2Manager._gen_ra_scripts')
    def test_config_dlm(self, mock_gen_ra, mock_gen_group, mock_load_wait):
        mock_gen_ra.return_value = ("dlm_id", "dlm_scripts\n")
        mock_gen_group.return_value = "group_scripts\n"
        self.ocfs2_inst3._config_dlm()
        mock_gen_ra.assert_called_once_with("DLM", {"id": "ocfs2-dlm"})
        mock_gen_group.assert_called_once_with(["dlm_id"])
        mock_load_wait.assert_called_once_with("dlm_scripts\ngroup_scripts\n", "dlm_id", "  Wait for DLM(dlm_id) start", need_append=False)

    @mock.patch('crmsh.ocfs2.OCFS2Manager._load_append_and_wait')
    @mock.patch('crmsh.ocfs2.OCFS2Manager._gen_ra_scripts')
    def test_config_lvmlockd(self, mock_gen_ra, mock_load_wait):
        mock_gen_ra.return_value = ("ra_id", "ra_scripts\n")
        self.ocfs2_inst3._config_lvmlockd()
        mock_gen_ra.assert_called_once_with("LVMLockd", {"id": "ocfs2-lvmlockd"})
        mock_load_wait.assert_called_once_with("ra_scripts\n", "ra_id", "  Wait for LVMLockd(ra_id) start")

    @mock.patch('crmsh.ocfs2.OCFS2Manager._load_append_and_wait')
    @mock.patch('crmsh.ocfs2.OCFS2Manager._gen_ra_scripts')
    def test_config_lvmactivate(self, mock_gen_ra, mock_load_wait):
        mock_gen_ra.return_value = ("ra_id", "ra_scripts\n")
        self.ocfs2_inst3.vg_id = "vg1"
        self.ocfs2_inst3._config_lvmactivate()
        mock_gen_ra.assert_called_once_with("LVMActivate", {"id": "ocfs2-lvmactivate", "vgname": "vg1"})
        mock_load_wait.assert_called_once_with("ra_scripts\n", "ra_id", "  Wait for LVMActivate(ra_id) start")

    @mock.patch('crmsh.ocfs2.OCFS2Manager._load_append_and_wait')
    @mock.patch('crmsh.ocfs2.OCFS2Manager._gen_fs_scripts')
    @mock.patch('crmsh.utils.mkdirp')
    def test_config_fs(self, mock_mkdir, mock_gen_fs, mock_load_wait):
        mock_gen_fs.return_value = ("ra_id", "ra_scripts\n")
        self.ocfs2_inst3.mount_point = "/data"
        self.ocfs2_inst3._config_fs()
        mock_mkdir.assert_called_once_with("/data")
        mock_gen_fs.assert_called_once_with()
        mock_load_wait.assert_called_once_with("ra_scripts\n", "ra_id", "  Wait for Filesystem(ra_id) start")

    @mock.patch('crmsh.ocfs2.OCFS2Manager._config_fs')
    @mock.patch('crmsh.ocfs2.OCFS2Manager._config_lvmactivate')
    @mock.patch('crmsh.ocfs2.OCFS2Manager._mkfs')
    @mock.patch('crmsh.ocfs2.OCFS2Manager._vg_change')
    @mock.patch('crmsh.ocfs2.OCFS2Manager._create_lv')
    @mock.patch('crmsh.ocfs2.OCFS2Manager._config_lvmlockd')
    @mock.patch('crmsh.ocfs2.OCFS2Manager._config_dlm')
    def test_config_resource_stack_lvm2(self, mock_dlm, mock_lvmlockd, mock_lv, mock_vg, mock_mkfs, mock_lvmactivate, mock_fs):
        mock_lv.return_value = "/dev/sda1"
        self.ocfs2_inst3._config_resource_stack_lvm2()
        mock_dlm.assert_called_once_with()
        mock_lvmlockd.assert_called_once_with()
        mock_lv.assert_called_once_with()
        mock_mkfs.assert_called_once_with("/dev/sda1")
        mock_lvmactivate.assert_called_once_with()
        mock_fs.assert_called_once_with()

    @mock.patch('crmsh.ocfs2.OCFS2Manager._config_fs')
    @mock.patch('crmsh.ocfs2.OCFS2Manager._mkfs')
    @mock.patch('crmsh.ocfs2.OCFS2Manager._config_dlm')
    def test_config_resource_stack_ocfs2_along(self, mock_dlm, mock_mkfs, mock_fs):
        self.ocfs2_inst3._config_resource_stack_ocfs2_along()
        mock_dlm.assert_called_once_with()
        mock_mkfs.assert_called_once_with("/dev/sdb2")
        mock_fs.assert_called_once_with()

    @mock.patch('crmsh.ocfs2.OCFS2Manager._config_resource_stack_lvm2')
    @mock.patch('crmsh.utils.set_property')
    @mock.patch('crmsh.utils.get_property')
    @mock.patch('crmsh.utils.all_exist_id')
    @mock.patch('crmsh.ocfs2.OCFS2Manager._dynamic_verify')
    @mock.patch('logging.Logger.info')
    def test_init_ocfs2_lvm2(self, mock_status, mock_dynamic_verify, mock_all_id, mock_get, mock_set, mock_lvm2):
        mock_all_id.return_value = []
        mock_get.return_value = None
        self.ocfs2_inst7.mount_point = "/data"
        self.ocfs2_inst7.target_device = "/dev/vg1/lv1"
        self.ocfs2_inst7.init_ocfs2()
        mock_status.assert_has_calls([
            mock.call("Configuring OCFS2"),
            mock.call('  \'no-quorum-policy\' is changed to "freeze"'),
            mock.call('  OCFS2 device %s mounted on %s', '/dev/vg1/lv1', '/data')
            ])
        mock_dynamic_verify.assert_called_once_with()
        mock_all_id.assert_called_once_with()
        mock_lvm2.assert_called_once_with()

    @mock.patch('crmsh.ocfs2.OCFS2Manager._config_resource_stack_ocfs2_along')
    @mock.patch('crmsh.utils.set_property')
    @mock.patch('crmsh.utils.get_property')
    @mock.patch('crmsh.utils.all_exist_id')
    @mock.patch('crmsh.ocfs2.OCFS2Manager._dynamic_verify')
    @mock.patch('logging.Logger.info')
    def test_init_ocfs2(self, mock_status, mock_dynamic_verify, mock_all_id, mock_get, mock_set, mock_ocfs2):
        mock_all_id.return_value = []
        mock_get.return_value = None
        self.ocfs2_inst3.mount_point = "/data"
        self.ocfs2_inst3.target_device = "/dev/sda1"
        self.ocfs2_inst3.init_ocfs2()
        mock_status.assert_has_calls([
            mock.call("Configuring OCFS2"),
            mock.call('  \'no-quorum-policy\' is changed to "freeze"'),
            mock.call('  OCFS2 device %s mounted on %s', '/dev/sda1', '/data')
            ])
        mock_dynamic_verify.assert_called_once_with()
        mock_all_id.assert_called_once_with()
        mock_ocfs2.assert_called_once_with()

    @mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
    def test_find_target_on_join_none(self, mock_run):
        mock_run.return_value = "data"
        res = self.ocfs2_inst3._find_target_on_join("node1")
        assert res is None
        mock_run.assert_called_once_with("crm configure show", "node1")

    @mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
    def test_find_target_on_join_exception(self, mock_run):
        mock_run.return_value = """
params directory="/srv/clusterfs" fstype=ocfs2
        """
        with self.assertRaises(ValueError) as err:
            self.ocfs2_inst3._find_target_on_join("node1")
        self.assertEqual("Filesystem require configure device", str(err.exception))
        mock_run.assert_called_once_with("crm configure show", "node1")

    @mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
    def test_find_target_on_join(self, mock_run):
        mock_run.return_value = """
params directory="/srv/clusterfs" fstype=ocfs2 device="/dev/sda2"
        """
        res = self.ocfs2_inst3._find_target_on_join("node1")
        self.assertEqual(res, "/dev/sda2")
        mock_run.assert_called_once_with("crm configure show", "node1")

    @mock.patch('crmsh.ocfs2.OCFS2Manager._find_target_on_join')
    def test_join_ocfs2_return(self, mock_find):
        mock_find.return_value = None
        self.ocfs2_inst3.join_ocfs2("node1")
        mock_find.assert_called_once_with("node1")

    @mock.patch('crmsh.utils.compare_uuid_with_peer_dev')
    @mock.patch('crmsh.utils.is_dev_a_plain_raw_disk_or_partition')
    @mock.patch('crmsh.ocfs2.OCFS2Manager._verify_packages')
    @mock.patch('crmsh.xmlutil.CrmMonXmlParser')
    @mock.patch('crmsh.log.LoggerUtils.status_long')
    @mock.patch('crmsh.ocfs2.OCFS2Manager._find_target_on_join')
    def test_join_ocfs2(self, mock_find, mock_long, mock_parser, mock_verify_packages, mock_is_mapper, mock_compare):
        mock_find.return_value = "/dev/sda2"
        mock_parser("node1").is_resource_configured.return_value = False
        mock_is_mapper.return_value = True
        self.ocfs2_inst3.join_ocfs2("node1")
        mock_find.assert_called_once_with("node1")
        mock_verify_packages.assert_called_once_with(False)
        mock_is_mapper.assert_called_once_with("/dev/sda2", "node1")
        mock_compare.assert_called_once_with(["/dev/sda2"], "node1")

    @mock.patch('crmsh.ocfs2.OCFS2Manager._static_verify')
    def test_verify_ocfs2(self, mock_static_verify):
        context1 = mock.Mock(ocfs2_devices=[])
        ocfs2.OCFS2Manager.verify_ocfs2(context1)
        mock_static_verify.assert_called_once_with()
