import logging
import unittest
from unittest.mock import patch, MagicMock, call, Mock
from crmsh.sbd import SBDUtils, SBDManager
from crmsh import utils
from crmsh import sbd
from crmsh import constants


class TestSBDUtils(unittest.TestCase):

    TEST_DATA = """
    UUID : 1234-5678
    Timeout (watchdog) : 5
    Timeout (msgwait) : 10
    """

    @patch('crmsh.sh.cluster_shell')
    def test_get_sbd_device_metadata_success(self, mock_cluster_shell):
        mock_cluster_shell.return_value.get_stdout_or_raise_error.return_value = self.TEST_DATA
        result = SBDUtils.get_sbd_device_metadata("/dev/sbd_device")
        expected = {'uuid': '1234-5678', 'watchdog': 5, 'msgwait': 10}
        self.assertEqual(result, expected)

    @patch('crmsh.sh.cluster_shell')
    def test_get_sbd_device_metadata_timeout_only(self, mock_cluster_shell):
        mock_cluster_shell.return_value.get_stdout_or_raise_error.return_value = self.TEST_DATA
        result = SBDUtils.get_sbd_device_metadata("/dev/sbd_device", timeout_only=True)
        expected = {'watchdog': 5, 'msgwait': 10}
        self.assertNotIn('uuid', result)
        self.assertEqual(result, expected)

    @patch('crmsh.sbd.SBDUtils.get_sbd_device_metadata')
    def test_get_device_uuid_success(self, mock_get_sbd_device_metadata):
        mock_get_sbd_device_metadata.return_value = {'uuid': '1234-5678'}
        result = SBDUtils.get_device_uuid("/dev/sbd_device")
        self.assertEqual(result, '1234-5678')

    @patch('crmsh.sbd.SBDUtils.get_sbd_device_metadata')
    def test_get_device_uuid_no_uuid_found(self, mock_get_sbd_device_metadata):
        mock_get_sbd_device_metadata.return_value = {}
        with self.assertRaises(ValueError) as context:
            SBDUtils.get_device_uuid("/dev/sbd_device")
        self.assertTrue("Cannot find sbd device UUID for /dev/sbd_device" in str(context.exception))

    @patch('crmsh.sbd.SBDUtils.get_device_uuid')
    def test_compare_device_uuid_empty_node_list(self, mock_get_device_uuid):
        result = SBDUtils.compare_device_uuid("/dev/sbd_device", [])
        self.assertIsNone(result)

    @patch('crmsh.sbd.SBDUtils.get_device_uuid')
    def test_compare_device_uuid_same_uuid(self, mock_get_device_uuid):
        mock_get_device_uuid.return_value = '1234-5678'
        SBDUtils.compare_device_uuid("/dev/sbd_device", ["node1", "node2"])

    @patch('crmsh.sbd.SBDUtils.get_device_uuid')
    def test_compare_device_uuid_different_uuid(self, mock_get_device_uuid):
        mock_get_device_uuid.side_effect = lambda dev, node=None: '1234-5678' if node is None else '8765-4321'
        with self.assertRaises(ValueError):
            SBDUtils.compare_device_uuid("/dev/sbd_device", ["node1"])

    @patch('crmsh.utils.is_block_device')
    @patch('crmsh.sbd.SBDUtils.compare_device_uuid')
    def test_verify_sbd_device_exceeds_max(self, mock_compare_device_uuid, mock_is_block_device):
        dev_list = [f"/dev/sbd_device_{i}" for i in range(SBDManager.SBD_DEVICE_MAX + 1)]
        with self.assertRaises(ValueError):
            SBDUtils.verify_sbd_device(dev_list)

    @patch('crmsh.utils.is_block_device')
    @patch('crmsh.sbd.SBDUtils.compare_device_uuid')
    def test_verify_sbd_device_non_block(self, mock_compare_device_uuid, mock_is_block_device):
        mock_is_block_device.return_value = False
        with self.assertRaises(ValueError):
            SBDUtils.verify_sbd_device(["/dev/not_a_block_device"])

    @patch('crmsh.utils.is_block_device')
    @patch('crmsh.sbd.SBDUtils.compare_device_uuid')
    def test_verify_sbd_device_valid(self, mock_compare_device_uuid, mock_is_block_device):
        mock_is_block_device.return_value = True
        SBDUtils.verify_sbd_device(["/dev/sbd_device"], ["node1", "node2"])

    @patch('crmsh.utils.parse_sysconfig')
    def test_get_sbd_value_from_config(self, mock_parse_sysconfig):
        mock_parse_sysconfig.return_value = {'SBD_DEVICE': '/dev/sbd_device'}
        result = SBDUtils.get_sbd_value_from_config("SBD_DEVICE")
        self.assertEqual(result, '/dev/sbd_device')

    @patch('crmsh.sbd.SBDUtils.get_sbd_value_from_config')
    def test_get_sbd_device_from_config(self, mock_get_sbd_value_from_config):
        mock_get_sbd_value_from_config.return_value = '/dev/sbd_device;/dev/another_sbd_device'
        result = SBDUtils.get_sbd_device_from_config()
        self.assertEqual(result, ['/dev/sbd_device', '/dev/another_sbd_device'])

    @patch('crmsh.sbd.SBDUtils.get_sbd_value_from_config')
    def test_get_crashdump_watchdog_timeout_none(self, mock_get_sbd_value_from_config):
        mock_get_sbd_value_from_config.return_value = None
        result = SBDUtils.get_crashdump_watchdog_timeout()
        self.assertIsNone(result)

    @patch('crmsh.sbd.SBDUtils.get_sbd_value_from_config')
    def test_get_crashdump_watchdog_timeout(self, mock_get_sbd_value_from_config):
        mock_get_sbd_value_from_config.return_value = "-C 60 -Z"
        result = SBDUtils.get_crashdump_watchdog_timeout()
        self.assertEqual(result, 60)

    @patch('crmsh.sbd.SBDUtils.get_sbd_device_from_config')
    @patch('crmsh.service_manager.ServiceManager.service_is_active')
    def test_is_using_diskless_sbd(self, mock_service_is_active, mock_get_sbd_device_from_config):
        mock_get_sbd_device_from_config.return_value = []
        mock_service_is_active.return_value = True
        result = SBDUtils.is_using_diskless_sbd()
        self.assertTrue(result)

    @patch('crmsh.sbd.SBDUtils.get_sbd_device_from_config')
    @patch('crmsh.service_manager.ServiceManager.service_is_active')
    def test_is_using_disk_based_sbd(self, mock_service_is_active, mock_get_sbd_device_from_config):
        mock_get_sbd_device_from_config.return_value = ['/dev/sbd_device']
        mock_service_is_active.return_value = True
        result = SBDUtils.is_using_disk_based_sbd()
        self.assertTrue(result)

    @patch('crmsh.sbd.ShellUtils.get_stdout_stderr')
    def test_has_sbd_device_already_initialized(self, mock_get_stdout_stderr):
        mock_get_stdout_stderr.return_value = (0, '', '')
        result = SBDUtils.has_sbd_device_already_initialized('/dev/sbd_device')
        self.assertTrue(result)

    @patch('crmsh.bootstrap.confirm')
    @patch('crmsh.sbd.SBDUtils.has_sbd_device_already_initialized')
    def test_no_overwrite_device_check(self, mock_has_sbd_device_already_initialized, mock_confirm):
        mock_has_sbd_device_already_initialized.return_value = True
        mock_confirm.return_value = False
        result = SBDUtils.no_overwrite_device_check('/dev/sbd_device')
        self.assertTrue(result)

    @patch('crmsh.sbd.SBDUtils.get_sbd_device_metadata')
    def test_check_devices_metadata_consistent_single_device(self, mock_get_sbd_device_metadata):
        dev_list = ['/dev/sbd_device']
        result = SBDUtils.check_devices_metadata_consistent(dev_list)
        self.assertTrue(result)

    @patch('crmsh.sbd.SBDUtils.get_sbd_device_metadata')
    def test_check_devices_metadata_consistent_multiple_devices_consistent(self, mock_get_sbd_device_metadata):
        dev_list = ['/dev/sbd_device1', '/dev/sbd_device2']
        mock_get_sbd_device_metadata.side_effect = ['metadata1', 'metadata1']
        result = SBDUtils.check_devices_metadata_consistent(dev_list)
        self.assertTrue(result)

    @patch('crmsh.sbd.SBDUtils.get_sbd_device_metadata')
    @patch('logging.Logger.error')
    def test_check_devices_metadata_consistent_multiple_devices_inconsistent(self, mock_logger_error, mock_get_sbd_device_metadata):
        dev_list = ['/dev/sbd_device1', '/dev/sbd_device2']
        mock_get_sbd_device_metadata.side_effect = ['metadata1', 'metadata2']
        result = SBDUtils.check_devices_metadata_consistent(dev_list)
        self.assertFalse(result)
        mock_logger_error.assert_called_once_with("Device %s doesn't have the same metadata as %s", '/dev/sbd_device2', '/dev/sbd_device1')

    @patch('crmsh.sbd.SBDUtils.check_devices_metadata_consistent')
    @patch('crmsh.sbd.SBDUtils.no_overwrite_device_check')
    def test_handle_input_sbd_devices_exception(self, mock_no_overwrite_device_check, mock_check_devices_metadata_consistent):
        mock_no_overwrite_device_check.return_value = True
        mock_check_devices_metadata_consistent.return_value = False
        with self.assertRaises(utils.TerminateSubCommand):
            SBDUtils.handle_input_sbd_devices(['/dev/sbd1'], dev_list_from_config=['/dev/sbd2'])
        mock_no_overwrite_device_check.assert_called_once_with('/dev/sbd1')
        mock_check_devices_metadata_consistent.assert_called_once_with(['/dev/sbd2', '/dev/sbd1'])

    @patch('crmsh.sbd.SBDUtils.check_devices_metadata_consistent')
    @patch('crmsh.sbd.SBDUtils.no_overwrite_device_check')
    def test_handle_input_sbd_devices(self, mock_no_overwrite_device_check, mock_check_devices_metadata_consistent):
        mock_no_overwrite_device_check.return_value = False
        _list1, _list2 = SBDUtils.handle_input_sbd_devices(['/dev/sbd1'])
        self.assertEqual(_list1, ['/dev/sbd1'])
        self.assertEqual(_list2, [])
        mock_no_overwrite_device_check.assert_called_once_with('/dev/sbd1')
        mock_check_devices_metadata_consistent.assert_not_called()

    @patch('crmsh.sbd.SBDUtils.get_sbd_device_from_config')
    def test_diskbased_sbd_configured(self, mock_get_sbd_device_from_config):
        mock_get_sbd_device_from_config.return_value = ['/dev/sbd_device']
        self.assertTrue(SBDUtils.diskbased_sbd_configured())

    @patch('crmsh.utils.get_property')
    def test_diskless_sbd_configured(self, mock_get_property):
        mock_get_property.return_value = 100
        self.assertTrue(SBDUtils.diskless_sbd_configured())


class TestSBDTimeout(unittest.TestCase):
    """
    Unitary tests for crmsh.sbd.SBDTimeout
    """
    @patch('crmsh.sbd.SBDUtils.get_sbd_value_from_config')
    def test_get_sbd_watchdog_timeout_exception(self, mock_get_sbd_value_from_config):
        mock_get_sbd_value_from_config.return_value = None
        with self.assertRaises(ValueError) as context:
            sbd.SBDTimeout.get_sbd_watchdog_timeout()
            self.assertTrue("Cannot get the value of SBD_WATCHDOG_TIMEOUT" in str(context.exception))

    @patch('crmsh.sbd.SBDUtils.get_sbd_value_from_config')
    def test_get_sbd_watchdog_timeout(self, mock_get_sbd_value_from_config):
        mock_get_sbd_value_from_config.return_value = 5
        result = sbd.SBDTimeout.get_sbd_watchdog_timeout()
        self.assertEqual(result, 5)

    @patch('crmsh.sbd.SBDUtils.get_sbd_value_from_config')
    def test_is_sbd_delay_start(self, mock_get_sbd_value_from_config):
        mock_get_sbd_value_from_config.return_value = "yes"
        result = sbd.SBDTimeout.is_sbd_delay_start()
        self.assertTrue(result)

    @patch('crmsh.utils.get_systemd_timeout_start_in_sec')
    @patch('crmsh.sh.cluster_shell')
    def test_get_sbd_systemd_start_timeout(self, mock_cluster_shell, mock_get_systemd_timeout_start_in_sec):
        mock_cluster_shell.return_value.get_stdout_or_raise_error = MagicMock(return_value="1min 30s")
        mock_get_systemd_timeout_start_in_sec.return_value = 90
        result = sbd.SBDTimeout.get_sbd_systemd_start_timeout()
        self.assertEqual(result, 90)
        mock_cluster_shell.return_value.get_stdout_or_raise_error.assert_called_once_with(sbd.SBDTimeout.SHOW_SBD_START_TIMEOUT_CMD, None)
        mock_get_systemd_timeout_start_in_sec.assert_called_once_with("1min 30s")

    @patch('crmsh.corosync.token_and_consensus_timeout')
    def test_get_sbd_delay_start_expected_diskbased(self, mock_token_and_consensus_timeout):
        inst = sbd.SBDTimeout()
        inst.disk_based = True
        inst.pcmk_delay_max = 10
        inst.sbd_msgwait = 5
        mock_token_and_consensus_timeout.return_value = 10
        self.assertEqual(inst.get_sbd_delay_start_expected(), 25)

    @patch('crmsh.corosync.token_and_consensus_timeout')
    def test_get_sbd_delay_start_expected_diskless(self, mock_token_and_consensus_timeout):
        inst = sbd.SBDTimeout()
        inst.disk_based = False
        inst.sbd_watchdog_timeout = 5
        mock_token_and_consensus_timeout.return_value = 10
        self.assertEqual(inst.get_sbd_delay_start_expected(), 20)

    @patch('crmsh.sbd.SBDTimeout.get_fencing_timeout_expected')
    @patch('crmsh.sbd.SBDTimeout._load_configurations_from_runtime')
    def test_get_fencing_timeout(self, mock_load_configurations_from_runtime, mock_get_sbd_delay_start_expected):
        mock_get_sbd_delay_start_expected.return_value = 10
        res = sbd.SBDTimeout.get_fencing_timeout()
        self.assertEqual(res, 10)
        mock_load_configurations_from_runtime.assert_called_once()
        mock_get_sbd_delay_start_expected.assert_called_once()

    @patch('logging.Logger.debug')
    @patch('crmsh.corosync.token_and_consensus_timeout')
    def test_get_fencing_timeout_expected_diskbased(self, mock_token_and_consensus_timeout, mock_logger_debug):
        inst = sbd.SBDTimeout()
        inst.disk_based = True
        inst.sbd_msgwait = 5
        mock_token_and_consensus_timeout.return_value = 10
        result = inst.get_fencing_timeout_expected()
        self.assertEqual(result, 70)

    @patch('logging.Logger.debug')
    @patch('crmsh.corosync.token_and_consensus_timeout')
    def test_get_fencing_timeout_expected_diskless(self, mock_token_and_consensus_timeout, mock_logger_debug):
        inst = sbd.SBDTimeout()
        inst.disk_based = False
        inst.sbd_watchdog_timeout = 5
        inst.fencing_watchdog_timeout = 20
        mock_token_and_consensus_timeout.return_value = 20
        result = inst.get_fencing_timeout_expected()
        self.assertEqual(result, 80)


class TestSBDConfigChecker(unittest.TestCase):

    def setUp(self):
        self.instance_check = sbd.SBDConfigChecker(fix=False)
        self.instance_fix = sbd.SBDConfigChecker(fix=True)

    @patch('logging.Logger.info')
    def test_log_and_return_success(self, mock_logger_info):
        self.assertTrue(self.instance_check.log_and_return(sbd.CheckResult.SUCCESS))
        mock_logger_info.assert_called_once_with("SBD: Check sbd timeout configuration: OK.")

    @patch('logging.Logger.info')
    @patch('logging.Logger.error')
    def test_log_and_return_error(self, mock_logger_error, mock_logger_info):
        self.assertFalse(self.instance_check.log_and_return(sbd.CheckResult.ERROR))
        mock_logger_info.assert_called_once_with("Please run \"crm cluster health sbd --fix\" to fix the above error on the running cluster")
        mock_logger_error.assert_called_once_with("SBD: Check sbd timeout configuration: FAIL.")

    @patch('logging.Logger.info')
    def test_log_and_return_warning(self, mock_logger_info):
        self.assertTrue(self.instance_check.log_and_return(sbd.CheckResult.WARNING, fix_flag=True))
        mock_logger_info.assert_called_once_with("SBD: Check sbd timeout configuration: OK.")

    @patch('crmsh.sbd.ServiceManager')
    def test_check_and_fix_sbd_not_active(self, mock_service_manager):
        self.instance_check.fix = True
        mock_service_manager_inst = Mock()
        mock_service_manager.return_value = mock_service_manager_inst
        mock_service_manager_inst.service_is_active = Mock(return_value=False)
        with self.assertRaises(sbd.FixAborted) as context: 
            self.instance_check.check_and_fix()
        self.assertTrue("sbd.service is not active" in str(context.exception))
        mock_service_manager_inst.service_is_active.assert_called_once_with(constants.SBD_SERVICE)

    @patch('crmsh.sbd.SBDUtils.diskless_sbd_configured')
    @patch('crmsh.sbd.SBDUtils.diskbased_sbd_configured')
    @patch('crmsh.sbd.ServiceManager')
    def test_check_and_fix_sbd_not_configured(self, mock_service_manager, mock_diskbased_sbd_configured, mock_diskless_sbd_configured):
        self.instance_check.fix = False
        mock_service_manager_inst = Mock()
        mock_service_manager.return_value = mock_service_manager_inst
        mock_service_manager_inst.service_is_active = Mock(return_value=False)
        mock_diskbased_sbd_configured.return_value = False
        mock_diskless_sbd_configured.return_value = False
        with self.assertRaises(sbd.FixAborted) as context:
            self.instance_check.check_and_fix()
        self.assertTrue("Neither disk-based nor disk-less SBD is configured" in str(context.exception))

    @patch('crmsh.utils.list_cluster_nodes_except_me')
    @patch('crmsh.utils.check_all_nodes_reachable')
    @patch('crmsh.sbd.ServiceManager')
    def test_check_and_fix_sbd_inconsistent(self, mock_service_manager, mock_check_all_nodes_reachable, mock_list_cluster_nodes_except_me):
        mock_service_manager_inst = Mock()
        mock_service_manager.return_value = mock_service_manager_inst
        mock_service_manager_inst.service_is_active = Mock(return_value=True)
        self.instance_check._check_config_consistency = Mock(return_value=False)
        with self.assertRaises(sbd.FixAborted):
            self.instance_check.check_and_fix()
        mock_service_manager_inst.service_is_active.assert_called_once_with(constants.SBD_SERVICE)
        self.instance_check._check_config_consistency.assert_called_once()

    @patch('crmsh.utils.list_cluster_nodes_except_me')
    @patch('crmsh.utils.check_all_nodes_reachable')
    @patch('crmsh.sbd.ServiceManager')
    def test_check_and_fix_not_fix(self, mock_service_manager, mock_check_all_nodes_reachable, mock_list_cluster_nodes_except_me):
        mock_service_manager_inst = Mock()
        mock_service_manager.return_value = mock_service_manager_inst
        mock_service_manager_inst.service_is_active = Mock(return_value=True)
        self.instance_check._check_config_consistency = Mock(return_value=True)
        self.instance_check._load_configurations_from_runtime = Mock()
        self.instance_check._check_sbd_disk_metadata = Mock(return_value=sbd.CheckResult.SUCCESS)
        self.instance_check._check_sbd_device_metadata_consistency = Mock(return_value=sbd.CheckResult.SUCCESS)
        self.instance_check._check_sbd_watchdog_timeout = Mock(return_value=sbd.CheckResult.SUCCESS)
        self.instance_check._check_sbd_delay_start = Mock(return_value=sbd.CheckResult.SUCCESS)
        self.instance_check._check_sbd_systemd_start_timeout = Mock(return_value=sbd.CheckResult.ERROR)
        self.instance_check._check_fencing_watchdog_timeout = Mock(return_value=sbd.CheckResult.SUCCESS)
        self.instance_check._check_fencing_timeout = Mock(return_value=sbd.CheckResult.SUCCESS)
        self.instance_check._check_sbd_delay_start_unset_dropin = Mock(return_value=sbd.CheckResult.SUCCESS)

        res = self.instance_check.check_and_fix()
        self.assertEqual(res, sbd.CheckResult.ERROR)

        mock_service_manager_inst.service_is_active.assert_called_once_with(constants.SBD_SERVICE)
        self.instance_check._check_config_consistency.assert_called_once()
        self.instance_check._load_configurations_from_runtime.assert_called_once()
        self.instance_check._check_sbd_disk_metadata.assert_called_once()

    @patch('crmsh.utils.list_cluster_nodes_except_me')
    @patch('crmsh.utils.check_all_nodes_reachable')
    @patch('crmsh.sbd.ServiceManager')
    def test_check_and_fix_fix_failure(self, mock_service_manager, mock_check_all_nodes_reachable, mock_list_cluster_nodes_except_me):
        mock_service_manager_inst = Mock()
        mock_service_manager.return_value = mock_service_manager_inst
        mock_service_manager_inst.service_is_active = Mock(return_value=True)
        self.instance_fix._check_config_consistency = Mock(return_value=True)
        self.instance_fix._load_configurations_from_runtime = Mock()
        self.instance_fix._check_sbd_device_metadata_consistency = Mock(return_value=sbd.CheckResult.SUCCESS)
        self.instance_fix._check_sbd_disk_metadata = Mock(side_effect=[sbd.CheckResult.ERROR, sbd.CheckResult.ERROR])
        self.instance_fix._fix_sbd_disk_metadata = Mock()

        with self.assertRaises(sbd.FixFailure) as context:
            self.instance_fix.check_and_fix()
        self.assertTrue("Failed to fix SBD disk metadata" in str(context.exception))

    @patch('crmsh.utils.list_cluster_nodes_except_me')
    @patch('crmsh.utils.check_all_nodes_reachable')
    @patch('crmsh.sbd.ServiceManager')
    def test_check_and_fix_fix_success(self, mock_service_manager, mock_check_all_nodes_reachable, mock_list_cluster_nodes_except_me):
        mock_service_manager_inst = Mock()
        mock_service_manager.return_value = mock_service_manager_inst
        mock_service_manager_inst.service_is_active = Mock(return_value=True)
        self.instance_fix._check_config_consistency = Mock(return_value=True)
        self.instance_fix._load_configurations_from_runtime = Mock()
        self.instance_fix._check_sbd_device_metadata_consistency = Mock(return_value=sbd.CheckResult.SUCCESS)
        self.instance_fix._check_sbd_disk_metadata = Mock(return_value=sbd.CheckResult.SUCCESS)
        self.instance_fix._check_sbd_watchdog_timeout = Mock(return_value=sbd.CheckResult.SUCCESS)
        self.instance_fix._check_sbd_delay_start = Mock(return_value=sbd.CheckResult.SUCCESS)
        self.instance_fix._check_sbd_systemd_start_timeout = Mock(return_value=sbd.CheckResult.SUCCESS)
        self.instance_fix._check_fencing_watchdog_timeout = Mock(return_value=sbd.CheckResult.SUCCESS)
        self.instance_fix._check_fencing_timeout = Mock(return_value=sbd.CheckResult.SUCCESS)
        self.instance_fix._check_sbd_delay_start_unset_dropin = Mock(return_value=sbd.CheckResult.SUCCESS)
        self.instance_fix._check_fencing_enabled = Mock(return_value=sbd.CheckResult.SUCCESS)

        res = self.instance_fix.check_and_fix()
        self.assertEqual(res, sbd.CheckResult.SUCCESS)

        mock_service_manager_inst.service_is_active.assert_called_once_with(constants.SBD_SERVICE)
        self.instance_fix._check_config_consistency.assert_called_once()
        self.instance_fix._load_configurations_from_runtime.assert_called_once()
        self.instance_fix._check_sbd_disk_metadata.assert_called_once()
        self.instance_fix._check_sbd_watchdog_timeout.assert_called_once()
        self.instance_fix._check_sbd_delay_start.assert_called_once()
        self.instance_fix._check_sbd_systemd_start_timeout.assert_called_once()
        self.instance_fix._check_fencing_watchdog_timeout.assert_called_once()
        self.instance_fix._check_fencing_timeout.assert_called_once()
        self.instance_fix._check_sbd_delay_start_unset_dropin.assert_called_once()

    @patch('logging.Logger.error')
    @patch('logging.Logger.warning')
    @patch('crmsh.utils.remote_diff_this')
    @patch('crmsh.corosync.conf')
    @patch('crmsh.utils.this_node')
    def test_check_config_consistency(self, mock_this_node, mock_corosync_conf, mock_remote_diff_this, mock_logger_warning, mock_logger_error):
        mock_this_node.return_value = 'node1'
        mock_corosync_conf.return_value = "corosync.conf"
        mock_remote_diff_this.side_effect = ["diff data1", "diff data2"]
        self.instance_check.peer_node_list = ["node2", "node3"]

        self.assertFalse(self.instance_check._check_config_consistency())

        mock_logger_error.assert_has_calls([
            call('%s is not consistent across cluster nodes', "corosync.conf"),
            call('%s is not consistent across cluster nodes', sbd.SBDManager.SYSCONFIG_SBD),
        ])

    @patch('logging.Logger.warning')
    def test_check_config_consistency_skip(self, mock_logger_warning):
        self.instance_check.peer_node_list = []
        self.assertTrue(self.instance_check._check_config_consistency("no peer nodes"))
        mock_logger_warning.assert_called_once_with("Skipping configuration consistency check: %s", "no peer nodes")

    @patch('crmsh.sbd.SBDTimeout.get_sbd_metadata_expected')
    def test_check_sbd_disk_metadata_failure(self, mock_get_sbd_metadata_expected):
        self.instance_check.disk_based = True
        self.instance_check._log_when_not_quiet = Mock()
        mock_get_sbd_metadata_expected.return_value = (15, 30)
        self.instance_check.sbd_watchdog_timeout = 10
        self.assertEqual(self.instance_check._check_sbd_disk_metadata(), sbd.CheckResult.ERROR)
        self.instance_check._log_when_not_quiet.assert_called_once_with(logging.ERROR, "It's required that SBD watchdog timeout(now %d) >= %d", 10, 15)    

    @patch('crmsh.sbd.SBDTimeout.get_sbd_metadata_expected')
    def test_check_sbd_disk_metadata_failure_msgwait(self, mock_get_sbd_metadata_expected):
        self.instance_check.disk_based = True
        self.instance_check._log_when_not_quiet = Mock()
        mock_get_sbd_metadata_expected.return_value = (10, 25)
        self.instance_check.sbd_watchdog_timeout = 10
        self.instance_check.sbd_msgwait = 20
        self.assertEqual(self.instance_check._check_sbd_disk_metadata(), sbd.CheckResult.ERROR)
        self.instance_check._log_when_not_quiet.assert_called_once_with(logging.ERROR, "It's required that SBD msgwait(now %d) >= %d", 20, 25)

    @patch('crmsh.sbd.SBDTimeout.get_sbd_metadata_expected')
    def test_check_sbd_disk_metadata_success(self, mock_get_sbd_metadata_expected):
        self.instance_check.disk_based = True
        mock_get_sbd_metadata_expected.return_value = (10, 20)
        self.instance_check.sbd_watchdog_timeout = 10
        self.instance_check.sbd_msgwait = 20
        self.assertEqual(self.instance_check._check_sbd_disk_metadata(), sbd.CheckResult.SUCCESS)

    @patch('crmsh.sh.cluster_shell')
    @patch('logging.Logger.info')
    def test_fix_sbd_disk_metadata(self, mock_logger_info, mock_cluster_shell):
        self.instance_fix.sbd_msgwait_expected = 10
        self.instance_fix.sbd_watchdog_timeout_expected = 5
        mock_cluster_shell_inst = Mock()
        mock_cluster_shell.return_value = mock_cluster_shell_inst
        mock_cluster_shell_inst.get_stdout_or_raise_error.return_value = "data"
        self.instance_fix._fix_sbd_disk_metadata()
        mock_logger_info.assert_called_once_with("Adjusting sbd msgwait to %d, watchdog timeout to %d", 10, 5)

    @patch('crmsh.sbd.SBDTimeout.get_sbd_watchdog_timeout_expected')
    def test_check_sbd_watchdog_timeout_failure(self, mock_get_sbd_watchdog_timeout_expected):
        self.instance_check.disk_based = False
        self.instance_check._log_when_not_quiet = Mock()
        mock_get_sbd_watchdog_timeout_expected.return_value = 10
        self.instance_check.sbd_watchdog_timeout = 3
        self.assertEqual(self.instance_check._check_sbd_watchdog_timeout(), sbd.CheckResult.ERROR)
        self.instance_check._log_when_not_quiet.assert_called_once_with(logging.ERROR, "It's required that SBD_WATCHDOG_TIMEOUT(now %d) >= %d", 3, 10)

    @patch('crmsh.sbd.SBDTimeout.get_sbd_watchdog_timeout_expected')
    def test_check_sbd_watchdog_timeout_success(self, mock_get_sbd_watchdog_timeout_expected):
        self.instance_check.disk_based = False
        mock_get_sbd_watchdog_timeout_expected.return_value = 10
        self.instance_check.sbd_watchdog_timeout = 10
        self.assertEqual(self.instance_check._check_sbd_watchdog_timeout(), sbd.CheckResult.SUCCESS)

    @patch('crmsh.sbd.SBDManager.update_sbd_configuration')
    def test_fix_sbd_watchdog_timeout(self, mock_update_sbd_configuration):
        self.instance_fix.sbd_watchdog_timeout_expected = 10
        self.instance_fix._fix_sbd_watchdog_timeout()
        mock_update_sbd_configuration.assert_called_once_with({"SBD_WATCHDOG_TIMEOUT": "10"})

    def test_check_sbd_delay_start_failure(self):
        self.instance_check.sbd_delay_start_value_expected = "100"
        self.instance_check.sbd_delay_start_value_from_config = "30"
        self.instance_check._log_when_not_quiet = Mock()
        self.assertEqual(self.instance_check._check_sbd_delay_start(), sbd.CheckResult.ERROR)
        self.instance_check._log_when_not_quiet.assert_called_once_with(logging.ERROR, "It's required that SBD_DELAY_START is set to %s, now is %s", "100", "30")

    def test_check_sbd_delay_start_success(self):
        self.instance_check.sbd_delay_start_value_expected = "50"
        self.instance_check.sbd_delay_start_value_from_config = "50"
        self.assertTrue(self.instance_check._check_sbd_delay_start())

    def test_check_sbd_delay_start_warning(self):
        self.instance_check.sbd_delay_start_value_expected = "70"
        self.instance_check.sbd_delay_start_value_from_config = "80"
        self.instance_check._log_when_not_quiet = Mock()
        self.assertEqual(self.instance_check._check_sbd_delay_start(), sbd.CheckResult.WARNING)
        self.instance_check._log_when_not_quiet.assert_called_once_with(logging.WARNING, "It's recommended that SBD_DELAY_START is set to %s, now is %s", "70", "80")

    @patch('crmsh.sbd.SBDManager.update_sbd_configuration')
    def test_fix_sbd_delay_start(self, mock_update_sbd_configuration):
        self.instance_fix.sbd_delay_start_value_expected = "80"
        self.instance_fix._fix_sbd_delay_start()
        mock_update_sbd_configuration.assert_called_once_with({"SBD_DELAY_START": "80"})

    @patch('crmsh.sbd.SBDConfigChecker._return_helper')
    @patch('crmsh.sbd.SBDTimeout.get_sbd_systemd_start_timeout')
    @patch('crmsh.utils.this_node')
    def test_check_sbd_systemd_start_timeout(self, mock_this_node, mock_get_sbd_systemd_start_timeout, mock_return_helper):
        mock_this_node.return_value = 'node1'
        self.instance_check.sbd_systemd_start_timeout_expected = 60
        self.instance_check.peer_node_list = ['node2', 'node3']
        self.instance_check.quiet = False
        self.instance_check._log_when_not_quiet = Mock()
        mock_get_sbd_systemd_start_timeout.side_effect = [60, 50, 70]
        mock_return_helper.return_value = sbd.CheckResult.ERROR

        self.assertEqual(self.instance_check._check_sbd_systemd_start_timeout(), sbd.CheckResult.ERROR)

        self.instance_check._log_when_not_quiet.assert_has_calls([
            call(logging.ERROR, "It's required that systemd start timeout for sbd.service is set to %ds, now is %ds on node %s", 60, 50, 'node2'),
            call(logging.WARNING, "It's recommended that systemd start timeout for sbd.service is set to %ds, now is %ds on node %s", 60, 70, 'node3')
        ])

    @patch('crmsh.utils.cluster_run_cmd')
    @patch('crmsh.bootstrap.sync_path')
    @patch('crmsh.utils.str2file')
    @patch('os.path.join')
    @patch('crmsh.utils.mkdirp')
    @patch('logging.Logger.info')
    def test_fix_sbd_systemd_start_timeout(self, mock_logger_info, mock_mkdirp, mock_os_path_join, mock_str2file, mock_sync_path, mock_cluster_run_cmd):
        mock_os_path_join.return_value = f"{sbd.SBDManager.SBD_SYSTEMD_DELAY_START_DIR}/sbd_delay_start.conf"
        self.instance_fix.sbd_systemd_start_timeout_expected = 120
        self.instance_fix._fix_sbd_systemd_start_timeout()
        mock_logger_info.assert_called_once_with("Adjusting systemd start timeout for sbd.service to %ds", 120)

    @patch('crmsh.utils.get_property')
    def test_check_fencing_watchdog_timeout_disk_based_failure(self, mock_get_property):
        self.instance_check.disk_based = True
        mock_get_property.return_value = 5
        self.instance_check._log_when_not_quiet = Mock()
        self.assertEqual(self.instance_check._check_fencing_watchdog_timeout(), sbd.CheckResult.WARNING)
        self.instance_check._log_when_not_quiet.assert_called_once_with(logging.WARNING, "It's recommended that fencing-watchdog-timeout is not set when using disk-based SBD")

    @patch('crmsh.utils.get_property')
    def test_check_fencing_watchdog_timeout_disk_less_failure(self, mock_get_property):
        self.instance_check.disk_based = False
        self.instance_check.fencing_watchdog_timeout = 15
        mock_get_property.return_value = ""
        self.instance_check._log_when_not_quiet = Mock()
        self.assertEqual(self.instance_check._check_fencing_watchdog_timeout(), sbd.CheckResult.ERROR)
        self.instance_check._log_when_not_quiet.assert_called_once_with(logging.ERROR, "It's required that fencing-watchdog-timeout is set to %d, now is not set", 15)

    @patch('crmsh.utils.get_property')
    def test_check_fencing_watchdog_timeout_success(self, mock_get_property):
        self.instance_check.disk_based = False
        self.instance_check.fencing_watchdog_timeout = 20
        mock_get_property.return_value = 25
        self.assertTrue(self.instance_check._check_fencing_watchdog_timeout())

    @patch('crmsh.utils.delete_property')
    @patch('logging.Logger.info')
    def test_fix_fencing_watchdog_timeout_disk_based_success(self, mock_logger_info, mock_delete_property):
        self.instance_fix.disk_based = True
        self.instance_fix._fix_fencing_watchdog_timeout()
        mock_logger_info.assert_called_once_with("Removing fencing-watchdog-timeout property")
        mock_delete_property.assert_called_once_with('fencing-watchdog-timeout')

    @patch('crmsh.utils.set_property')
    @patch('logging.Logger.info')
    def test_fix_fencing_watchdog_timeout_disk_less_success(self, mock_logger_info, mock_set_property):
        self.instance_fix.disk_based = False
        self.instance_fix.fencing_watchdog_timeout = 15
        self.instance_fix._fix_fencing_watchdog_timeout()
        mock_logger_info.assert_called_once_with("Adjusting fencing-watchdog-timeout to %d", 15)
        mock_set_property.assert_called_once_with('fencing-watchdog-timeout', 15)

    @patch('crmsh.utils.get_property')
    def test_check_fencing_timeout_failure(self, mock_get_property):
        self.instance_check.get_fencing_timeout_expected = Mock(return_value=60)
        mock_get_property.return_value = 30
        self.instance_check._log_when_not_quiet = Mock()
        self.assertEqual(self.instance_check._check_fencing_timeout(), sbd.CheckResult.ERROR)
        self.instance_check._log_when_not_quiet.assert_called_once_with(logging.ERROR, "It's required that fencing-timeout is set to %d, now is %d", 60, 30)

    @patch('crmsh.utils.get_property')
    def test_check_fencing_timeout_warning(self, mock_get_property):
        self.instance_check.get_fencing_timeout_expected = Mock(return_value=80)
        mock_get_property.return_value = 90
        self.instance_check._log_when_not_quiet = Mock()
        self.assertEqual(self.instance_check._check_fencing_timeout(), sbd.CheckResult.WARNING)
        self.instance_check._log_when_not_quiet.assert_called_once_with(logging.WARNING, "It's recommended that fencing-timeout is set to %d, now is %d", 80, 90)

    @patch('crmsh.utils.get_property')
    def test_check_fencing_timeout_success(self, mock_get_property):
        self.instance_check.get_fencing_timeout_expected = Mock(return_value=50)
        mock_get_property.return_value = 50
        self.assertTrue(self.instance_check._check_fencing_timeout())

    @patch('crmsh.utils.set_property')
    @patch('logging.Logger.info')
    def test_fix_fencing_timeout(self, mock_logger_info, mock_set_property):
        self.instance_fix.get_fencing_timeout_expected = Mock(return_value=70)
        self.instance_fix._fix_fencing_timeout()
        mock_logger_info.assert_called_once_with("Adjusting fencing-timeout to %d", 70)
        mock_set_property.assert_called_once_with('fencing-timeout', 70)

    @patch('crmsh.sbd.SBDTimeout.is_sbd_delay_start')
    def test_check_sbd_delay_start_unset_dropin_not_set_delay_start(self, mock_is_sbd_delay_start):
        mock_is_sbd_delay_start.return_value = False
        self.assertEqual(self.instance_check._check_sbd_delay_start_unset_dropin(), sbd.CheckResult.SUCCESS)

    @patch('crmsh.sbd.SBDConfigChecker._return_helper')
    @patch('crmsh.utils.this_node')
    @patch('crmsh.sh.cluster_shell')
    @patch('crmsh.sbd.SBDTimeout.is_sbd_delay_start')
    def test_check_sbd_delay_start_unset_dropin(self, mock_is_sbd_delay_start, mock_cluster_shell, mock_this_node, mock_return_helper):
        mock_is_sbd_delay_start.return_value = True
        mock_this_node.return_value = 'node1'
        mock_cluster_shell_inst = Mock()
        mock_cluster_shell.return_value = mock_cluster_shell_inst
        self.instance_check.peer_node_list = ['node2']
        self.instance_check.quiet = False
        self.instance_check._log_when_not_quiet = Mock()
        mock_cluster_shell_inst.get_rc_and_error.side_effect = [(0, None), (1, None)]
        mock_return_helper.return_value = sbd.CheckResult.WARNING

        self.assertEqual(self.instance_check._check_sbd_delay_start_unset_dropin(), sbd.CheckResult.WARNING)

        self.instance_check._log_when_not_quiet.assert_called_once_with(logging.WARNING, "Runtime drop-in file %s to unset SBD_DELAY_START is missing on node %s", sbd.SBDManager.SBD_SYSTEMD_DELAY_START_DISABLE_FILE, 'node2')

    @patch('crmsh.sbd.SBDManager.unset_sbd_delay_start')
    @patch('logging.Logger.info')
    def test_fix_sbd_delay_start_unset_dropin(self, mock_logger_info, mock_unset_sbd_delay_start):
        self.instance_check._fix_sbd_delay_start_unset_dropin()
        mock_logger_info.assert_called_once_with("Createing runtime drop-in file %s to unset SBD_DELAY_START", sbd.SBDManager.SBD_SYSTEMD_DELAY_START_DISABLE_FILE)

    def test_check_fence_sbd_diskless(self):
        self.instance_check.disk_based = False
        self.assertEqual(self.instance_check._check_fence_sbd(), sbd.CheckResult.SUCCESS)

    @patch('crmsh.sbd.SBDConfigChecker._return_helper')
    @patch('crmsh.utils.this_node')
    @patch('crmsh.sbd.ServiceManager')
    def test_check_sbd_service_is_enabled(self, mock_ServiceManager, mock_this_node, mock_return_helper):
        mock_this_node.return_value = 'node1'
        mock_service_manager_inst = Mock()
        mock_ServiceManager.return_value = mock_service_manager_inst
        self.instance_check.peer_node_list = ['node2']
        self.instance_check.quiet = False
        self.instance_check._log_when_not_quiet = Mock()
        mock_service_manager_inst.service_is_enabled.side_effect = [True, False]
        mock_return_helper.return_value = sbd.CheckResult.ERROR
        self.assertEqual(self.instance_check._check_sbd_service_is_enabled(), sbd.CheckResult.ERROR)
        self.instance_check._log_when_not_quiet.assert_called_once_with(logging.ERROR, "%s is not enabled on node %s", constants.SBD_SERVICE, 'node2')

    @patch('logging.Logger.info')
    @patch('crmsh.sbd.ServiceManager')
    def test_fix_sbd_service_is_enabled(self, mock_ServiceManager, mock_logger_info):
        mock_service_manager_inst = Mock()
        mock_ServiceManager.return_value = mock_service_manager_inst
        self.instance_fix.service_disabled_node_list = ['node2']
        mock_service_manager_inst.enable_service = Mock()
        self.instance_fix._fix_sbd_service_is_enabled()
        mock_logger_info.assert_called_once_with("Enabling %s on node %s", constants.SBD_SERVICE, 'node2')

    @patch('crmsh.xmlutil.CrmMonXmlParser')
    def test_check_fence_sbd_not_configured(self, mock_CrmMonXmlParser):
        self.instance_check.disk_based = True
        self.instance_check.quiet = False
        self.instance_check._log_when_not_quiet = Mock()
        mock_parser_instance = Mock()
        mock_CrmMonXmlParser.return_value = mock_parser_instance
        mock_parser_instance.not_connected.return_value = False
        mock_parser_instance.is_resource_configured.return_value = False
        self.assertEqual(self.instance_check._check_fence_sbd(), sbd.CheckResult.ERROR)
        self.instance_check._log_when_not_quiet.assert_called_once_with(logging.ERROR, "Fence agent %s is not configured", sbd.SBDManager.SBD_RA)

    @patch('crmsh.cibquery.get_primitives_with_ra')
    @patch('crmsh.cibquery.ResourceAgent')
    @patch('crmsh.xmlutil.text2elem')
    @patch('crmsh.sh.cluster_shell')
    @patch('crmsh.xmlutil.CrmMonXmlParser')
    def test_check_fence_sbd_not_configured_cluster_offline(self, mock_CrmMonXmlParser, mock_cluster_shell, mock_text2elem, mock_ResourceAgent, mock_get_primitives_with_ra):
        self.instance_check.disk_based = True
        self.instance_check.quiet = False
        self.instance_check._log_when_not_quiet = Mock()
        mock_parser_instance = Mock()
        mock_CrmMonXmlParser.return_value = mock_parser_instance
        mock_parser_instance.not_connected.return_value = True
        mock_cluster_shell_inst = Mock()
        mock_cluster_shell.return_value = mock_cluster_shell_inst
        mock_cluster_shell_inst.get_stdout_or_raise_error.return_value = "<cib></cib>"
        mock_text2elem.return_value = "cib_elem"
        mock_resource_agent_instance = Mock()
        mock_ResourceAgent.return_value = mock_resource_agent_instance
        mock_get_primitives_with_ra.return_value = []
        self.assertEqual(self.instance_check._check_fence_sbd(), sbd.CheckResult.ERROR)
        self.instance_check._log_when_not_quiet.assert_called_once_with(logging.ERROR, "Fence agent %s is not configured", sbd.SBDManager.SBD_RA)

    @patch('crmsh.cibquery.get_primitives_with_ra')
    @patch('crmsh.cibquery.ResourceAgent')
    @patch('crmsh.xmlutil.text2elem')
    @patch('crmsh.sh.cluster_shell')
    @patch('crmsh.xmlutil.CrmMonXmlParser')
    def test_check_fence_sbd_success_cluster_offline(self, mock_CrmMonXmlParser, mock_cluster_shell, mock_text2elem, mock_ResourceAgent, mock_get_primitives_with_ra):
        self.instance_check.disk_based = True
        mock_parser_instance = Mock()
        mock_CrmMonXmlParser.return_value = mock_parser_instance
        mock_parser_instance.not_connected.return_value = True
        mock_cluster_shell_inst = Mock()
        mock_cluster_shell.return_value = mock_cluster_shell_inst
        mock_cluster_shell_inst.get_stdout_or_raise_error.return_value = "<cib></cib>"
        mock_text2elem.return_value = "cib_elem"
        mock_resource_agent_instance = Mock()
        mock_ResourceAgent.return_value = mock_resource_agent_instance
        mock_get_primitives_with_ra.return_value = ['fence_sbd_0']
        self.assertEqual(self.instance_check._check_fence_sbd(), sbd.CheckResult.SUCCESS)

    @patch('crmsh.xmlutil.CrmMonXmlParser')
    def test_check_fence_sbd_not_started(self, mock_CrmMonXmlParser):
        self.instance_check.disk_based = True
        self.instance_check.quiet = False
        self.instance_check._log_when_not_quiet = Mock()
        mock_parser_instance = Mock()
        mock_CrmMonXmlParser.return_value = mock_parser_instance
        mock_parser_instance.not_connected.return_value = False
        mock_parser_instance.is_resource_configured.return_value = True
        mock_parser_instance.is_resource_started.return_value = False
        self.assertEqual(self.instance_check._check_fence_sbd(), sbd.CheckResult.ERROR)
        self.instance_check._log_when_not_quiet.assert_called_once_with(logging.ERROR, "Fence agent %s is not started", sbd.SBDManager.SBD_RA)

    @patch('crmsh.xmlutil.CrmMonXmlParser')
    def test_check_fence_sbd_success(self, mock_CrmMonXmlParser):
        self.instance_check.disk_based = True
        mock_parser_instance = Mock()
        mock_CrmMonXmlParser.return_value = mock_parser_instance
        mock_parser_instance.not_connected.return_value = False
        mock_parser_instance.is_resource_configured.return_value = True
        mock_parser_instance.is_resource_started.return_value = True
        self.assertEqual(self.instance_check._check_fence_sbd(), sbd.CheckResult.SUCCESS)

    @patch('crmsh.bootstrap.adjust_pcmk_delay_max')
    @patch('crmsh.utils.is_2node_cluster_without_qdevice')
    @patch('logging.Logger.info')
    @patch('crmsh.sh.cluster_shell')
    @patch('crmsh.xmlutil.CrmMonXmlParser')
    def test_fix_fence_sbd_not_configured(self, mock_CrmMonXmlParser, mock_cluster_shell, mock_logger_info, mock_is_2node_cluster_without_qdevice, mock_adjust_pcmk_delay_max):
        mock_parser_instance = Mock()
        mock_CrmMonXmlParser.return_value = mock_parser_instance
        mock_parser_instance.is_resource_configured.return_value = False
        mock_cluster_shell_inst = Mock()
        mock_cluster_shell.return_value = mock_cluster_shell_inst
        mock_cluster_shell_inst.get_stdout_or_raise_error = Mock()
        mock_is_2node_cluster_without_qdevice.return_value = True
        self.instance_fix._fix_fence_sbd()
        mock_logger_info.assert_called_once_with("Configuring fence agent %s", sbd.SBDManager.SBD_RA)

    @patch('logging.Logger.info')
    @patch('crmsh.sh.cluster_shell')
    @patch('crmsh.xmlutil.CrmMonXmlParser')
    def test_fix_fence_sbd_not_started(self, mock_CrmMonXmlParser, mock_cluster_shell, mock_logger_info):
        mock_parser_instance = Mock()
        mock_CrmMonXmlParser.return_value = mock_parser_instance
        mock_parser_instance.is_resource_configured.return_value = True
        mock_parser_instance.is_resource_started.return_value = False
        mock_parser_instance.get_resource_id_list_via_type.return_value = ['fence_sbd_0']
        mock_cluster_shell_inst = Mock()
        mock_cluster_shell.return_value = mock_cluster_shell_inst
        mock_cluster_shell_inst.get_stdout_or_raise_error = Mock()
        self.instance_fix._fix_fence_sbd()
        mock_logger_info.assert_called_once_with("Starting fence agent %s", 'fence_sbd_0')

    @patch('crmsh.utils.is_boolean_false')
    @patch('crmsh.utils.get_property')
    def test_check_fencing_enabled_success(self, mock_get_property, mock_is_boolean_false):
        mock_get_property.return_value = "true"
        mock_is_boolean_false.return_value = False
        self.assertEqual(self.instance_check._check_fencing_enabled(), sbd.CheckResult.SUCCESS)

    @patch('crmsh.utils.is_boolean_false')
    @patch('crmsh.utils.get_property')
    def test_check_fencing_enabled_failure(self, mock_get_property, mock_is_boolean_false):
        mock_get_property.return_value = "false"
        mock_is_boolean_false.return_value = True
        self.instance_check._log_when_not_quiet = Mock()
        self.assertEqual(self.instance_check._check_fencing_enabled(), sbd.CheckResult.ERROR)
        self.instance_check._log_when_not_quiet.assert_called_once_with(logging.ERROR, "It's required that fencing-enabled is set to true, now is false")

    @patch('logging.Logger.info')
    @patch('crmsh.utils.set_property')
    def test_fix_fencing_enabled(self, mock_set_property, mock_logger_info):
        self.instance_fix._fix_fencing_enabled()
        mock_logger_info.assert_called_once_with("Setting fencing-enabled to true")
        mock_set_property.assert_called_once_with('fencing-enabled', 'true')


class TestSBDManager(unittest.TestCase):

    def test_convert_timeout_dict_to_opt_str(self):
        timeout_dict = {'watchdog': 5, 'msgwait': 10}
        result = SBDManager.convert_timeout_dict_to_opt_str(timeout_dict)
        self.assertEqual(result, '-1 5 -4 10')

    @patch('logging.Logger.info')
    @patch('crmsh.sbd.ServiceManager')
    @patch('crmsh.utils.list_cluster_nodes')
    def test_enable_sbd_service(self, mock_list_cluster_nodes, mock_ServiceManager, mock_logger_info):
        mock_bootstrap_ctx = Mock(cluster_is_running=True)
        sbdmanager_instance = SBDManager(bootstrap_context=mock_bootstrap_ctx)
        mock_list_cluster_nodes.return_value = ['node1', 'node2']
        mock_ServiceManager.return_value.service_is_enabled.side_effect = [False, False]
        sbdmanager_instance.enable_sbd_service()
        mock_logger_info.assert_has_calls([
            call("Enable %s on node %s", constants.SBD_SERVICE, 'node1'),
            call("Enable %s on node %s", constants.SBD_SERVICE, 'node2')
        ])

    @patch('crmsh.bootstrap.prompt_for_string')
    def test_prompt_for_sbd_device_diskless(self, mock_prompt_for_string):
        mock_prompt_for_string.return_value = "none"
        sbdmanager_instance = SBDManager()
        result = sbdmanager_instance._prompt_for_sbd_device()
        self.assertEqual(result, [])

    @patch('crmsh.bootstrap.confirm')
    @patch('logging.Logger.warning')
    @patch('crmsh.sbd.SBDUtils.has_sbd_device_already_initialized')
    @patch('logging.Logger.error')
    @patch('crmsh.sbd.SBDUtils.verify_sbd_device')
    @patch('crmsh.utils.re_split_string')
    @patch('crmsh.bootstrap.prompt_for_string')
    def test_prompt_for_sbd_device(self, mock_prompt_for_string, mock_re_split_string, mock_verify_sbd_device, mock_logger_error, mock_has_sbd_device_already_initialized, mock_logger_warning, mock_confirm):
        mock_prompt_for_string.side_effect = ["/dev/dev1", "/dev/dev2", "/dev/dev3;/dev/dev4"]
        mock_re_split_string.side_effect = [["/dev/dev1"], ["/dev/dev2"], ["/dev/dev3", "/dev/dev4"]]
        mock_verify_sbd_device.side_effect = [ValueError("Not a block device"), None, None]
        mock_has_sbd_device_already_initialized.side_effect = [False, True, False]
        mock_confirm.side_effect = [False, True]
        sbdmanager_instance = SBDManager()
        result = sbdmanager_instance._prompt_for_sbd_device()
        self.assertEqual(result, ["/dev/dev3", "/dev/dev4"])

    @patch('crmsh.sbd.ServiceManager')
    def test_get_sbd_device_interactive_yes_to_all(self, mock_ServiceManager):
        mock_bootstrap_ctx = Mock(yes_to_all=True)
        sbdmanager_instance = SBDManager(bootstrap_context=mock_bootstrap_ctx)
        sbdmanager_instance._warn_and_raise_no_sbd = Mock()
        sbdmanager_instance._warn_and_raise_no_sbd.side_effect = SBDManager.NotConfigSBD
        with self.assertRaises(SBDManager.NotConfigSBD):
            sbdmanager_instance.get_sbd_device_interactive()
        sbdmanager_instance._warn_and_raise_no_sbd.assert_called_once()

    @patch('crmsh.bootstrap.confirm')
    @patch('logging.Logger.info')
    @patch('crmsh.sbd.ServiceManager')
    def test_get_sbd_device_interactive_not_wish(self, mock_ServiceManager, mock_logger_info, mock_confirm):
        mock_bootstrap_ctx = Mock(yes_to_all=False)
        mock_confirm.return_value = False
        sbdmanager_instance = SBDManager(bootstrap_context=mock_bootstrap_ctx)
        sbdmanager_instance._warn_and_raise_no_sbd = Mock()
        sbdmanager_instance._warn_and_raise_no_sbd.side_effect = SBDManager.NotConfigSBD
        with self.assertRaises(SBDManager.NotConfigSBD):
            sbdmanager_instance.get_sbd_device_interactive()
        mock_logger_info.assert_called_once_with(SBDManager.SBD_STATUS_DESCRIPTION)
        sbdmanager_instance._warn_and_raise_no_sbd.assert_called_once()

    @patch('crmsh.utils.fatal')
    @patch('crmsh.utils.package_is_installed')
    @patch('crmsh.bootstrap.confirm')
    @patch('logging.Logger.info')
    @patch('crmsh.sbd.ServiceManager')
    def test_get_sbd_device_interactive_not_installed(self, mock_ServiceManager, mock_logger_info, mock_confirm, mock_package_is_installed, mock_fatal):
        mock_bootstrap_ctx = Mock(yes_to_all=False)
        mock_confirm.return_value = True
        mock_package_is_installed.return_value = False
        mock_fatal.side_effect = ValueError("SBD is not installed")
        sbdmanager_instance = SBDManager(bootstrap_context=mock_bootstrap_ctx)
        with self.assertRaises(ValueError):
            sbdmanager_instance.get_sbd_device_interactive()
        mock_logger_info.assert_called_once_with(SBDManager.SBD_STATUS_DESCRIPTION)
        mock_fatal.assert_called_once_with(SBDManager.SBD_NOT_INSTALLED_MSG)

    @patch('crmsh.sbd.SBDUtils.get_sbd_device_from_config')
    @patch('crmsh.utils.package_is_installed')
    @patch('crmsh.bootstrap.confirm')
    @patch('logging.Logger.info')
    @patch('crmsh.sbd.ServiceManager')
    def test_get_sbd_device_interactive_not_overwrite(self, mock_ServiceManager, mock_logger_info, mock_confirm, mock_package_is_installed, mock_get_sbd_device_from_config):
        mock_bootstrap_ctx = Mock(yes_to_all=False)
        mock_confirm.return_value = True
        mock_package_is_installed.return_value = True
        mock_get_sbd_device_from_config.return_value = ['/dev/sbd_device']
        sbdmanager_instance = SBDManager(bootstrap_context=mock_bootstrap_ctx)
        sbdmanager_instance._wants_to_overwrite = Mock()
        sbdmanager_instance._wants_to_overwrite.return_value = False
        self.assertEqual(sbdmanager_instance.get_sbd_device_interactive(), [])
        mock_logger_info.assert_called_once_with(SBDManager.SBD_STATUS_DESCRIPTION)
        sbdmanager_instance._wants_to_overwrite.assert_called_once_with(['/dev/sbd_device'])

    @patch('crmsh.sbd.SBDUtils.get_sbd_device_from_config')
    @patch('crmsh.utils.package_is_installed')
    @patch('crmsh.bootstrap.confirm')
    @patch('logging.Logger.info')
    @patch('crmsh.sbd.ServiceManager')
    def test_get_sbd_device_interactive(self, mock_ServiceManager, mock_logger_info, mock_confirm, mock_package_is_installed, mock_get_sbd_device_from_config):
        mock_bootstrap_ctx = Mock(yes_to_all=False)
        mock_confirm.return_value = True
        mock_package_is_installed.return_value = True
        mock_get_sbd_device_from_config.return_value = []
        sbdmanager_instance = SBDManager(bootstrap_context=mock_bootstrap_ctx)
        sbdmanager_instance._wants_to_overwrite = Mock()
        sbdmanager_instance._prompt_for_sbd_device = Mock()
        sbdmanager_instance._prompt_for_sbd_device.return_value = ['/dev/sbd_device']
        self.assertEqual(sbdmanager_instance.get_sbd_device_interactive(), ['/dev/sbd_device'])
        mock_logger_info.assert_called_once_with(SBDManager.SBD_STATUS_DESCRIPTION)
        sbdmanager_instance._wants_to_overwrite.assert_not_called()
        sbdmanager_instance._prompt_for_sbd_device.assert_called_once()

    @patch('crmsh.sbd.SBDUtils.check_devices_metadata_consistent')
    @patch('crmsh.bootstrap.confirm')
    @patch('crmsh.sbd.ServiceManager')
    def test_wants_to_overwrite_exception(self, mock_ServiceManager, mock_confirm, mock_check_devices_metadata_consistent):
        sbdmanager_instance = SBDManager()
        mock_confirm.return_value = False
        mock_check_devices_metadata_consistent.return_value = False
        with self.assertRaises(utils.TerminateSubCommand):
            sbdmanager_instance._wants_to_overwrite(['/dev/sbd_device'])

    @patch('logging.Logger.warning')
    def test_warn_and_raise_no_sbd(self, mock_logger_warning):
        sbdmanager_instance = SBDManager()
        with self.assertRaises(SBDManager.NotConfigSBD):
            sbdmanager_instance._warn_and_raise_no_sbd()
        mock_logger_warning.assert_called_once_with('%s', SBDManager.NO_SBD_WARNING)

    @patch('crmsh.utils.get_quorum_votes_dict')
    @patch('logging.Logger.warning')
    @patch('crmsh.sbd.SBDUtils.is_using_diskless_sbd')
    def test_warn_diskless_sbd(self, mock_is_using_sbd, mock_logger_warning, mock_get_quorum_votes_dict):
        mock_is_using_sbd.return_value = True
        mock_get_quorum_votes_dict.return_value = {'Expected': '2', 'Total': '2'}
        sbd.SBDManager.warn_diskless_sbd()
        mock_logger_warning.assert_called_once_with('%s', SBDManager.DISKLESS_SBD_WARNING)

    @patch('crmsh.sbd.SBDUtils.check_devices_metadata_consistent')
    @patch('crmsh.bootstrap.confirm')
    @patch('crmsh.sbd.ServiceManager')
    def test_wants_to_overwrite_return_false(self, mock_ServiceManager, mock_confirm, mock_check_devices_metadata_consistent):
        sbdmanager_instance = SBDManager()
        mock_confirm.return_value = False
        mock_check_devices_metadata_consistent.return_value = True
        result = sbdmanager_instance._wants_to_overwrite(['/dev/sbd_device'])
        self.assertFalse(result)

    @patch('crmsh.sbd.SBDUtils.check_devices_metadata_consistent')
    @patch('crmsh.bootstrap.confirm')
    @patch('crmsh.sbd.ServiceManager')
    def test_wants_to_overwrite_return_true(self, mock_ServiceManager, mock_confirm, mock_check_devices_metadata_consistent):
        mock_confirm.return_value = True
        sbdmanager_instance = SBDManager()
        result = sbdmanager_instance._wants_to_overwrite(['/dev/sbd_device'])
        self.assertTrue(result)

    @patch('crmsh.sbd.SBDUtils.handle_input_sbd_devices')
    @patch('crmsh.sbd.ServiceManager')
    def test_get_sbd_device_from_bootstrap_return(self, mock_ServiceManager, mock_handle_input_sbd_devices):
        mock_bootstrap_ctx = Mock(sbd_devices=[], diskless_sbd=False)
        sbdmanager_instance = SBDManager(bootstrap_context=mock_bootstrap_ctx)
        sbdmanager_instance.get_sbd_device_interactive = Mock()
        sbdmanager_instance.get_sbd_device_interactive.return_value = []
        sbdmanager_instance.get_sbd_device_from_bootstrap()
        mock_handle_input_sbd_devices.assert_not_called()

    @patch('crmsh.sbd.SBDUtils.get_sbd_device_metadata')
    @patch('crmsh.sbd.SBDUtils.handle_input_sbd_devices')
    @patch('crmsh.sbd.ServiceManager')
    def test_get_sbd_device_from_bootstrap(self, mock_ServiceManager, mock_handle_input_sbd_devices, mock_get_sbd_device_metadata):
        mock_bootstrap_ctx = Mock(sbd_devices=['/dev/sda1', '/dev/sda2'], diskless_sbd=False)
        mock_handle_input_sbd_devices.return_value = (['/dev/sda1'], ['/dev/sda2'])
        mock_get_sbd_device_metadata.return_value = {'uuid': '1234-5678'}
        sbdmanager_instance = SBDManager(bootstrap_context=mock_bootstrap_ctx)
        sbdmanager_instance.get_sbd_device_from_bootstrap()
        mock_handle_input_sbd_devices.assert_called_once_with(['/dev/sda1', '/dev/sda2'])
        mock_get_sbd_device_metadata.assert_called_once_with('/dev/sda2', timeout_only=True)

    @patch('crmsh.sbd.ServiceManager')
    def test_init_and_deploy_sbd_not_config_sbd(self, mock_ServiceManager):
        mock_bootstrap_ctx = Mock()
        sbdmanager_instance = SBDManager(bootstrap_context=mock_bootstrap_ctx)
        sbdmanager_instance.get_sbd_device_from_bootstrap = Mock(side_effect=SBDManager.NotConfigSBD)
        sbdmanager_instance._load_attributes_from_bootstrap = Mock()
        sbdmanager_instance.init_and_deploy_sbd()
        mock_ServiceManager.return_value.disable_service.assert_called_once_with(constants.SBD_SERVICE)
        sbdmanager_instance._load_attributes_from_bootstrap.assert_not_called()

    @patch('crmsh.bootstrap.adjust_properties')
    @patch('crmsh.bootstrap.restart_cluster')
    @patch('crmsh.sbd.SBDManager.enable_sbd_service')
    @patch('crmsh.sbd.ServiceManager')
    def test_init_and_deploy_sbd(self, mock_ServiceManager, mock_enable_sbd_service, mock_restart_cluster, mock_adjust_properties):
        mock_bootstrap_ctx = Mock(cluster_is_running=True)
        sbdmanager_instance = SBDManager(bootstrap_context=mock_bootstrap_ctx)
        sbdmanager_instance.get_sbd_device_from_bootstrap = Mock()
        sbdmanager_instance._load_attributes_from_bootstrap = Mock()
        sbdmanager_instance.initialize_sbd = Mock()
        sbdmanager_instance.update_configuration = Mock()
        sbdmanager_instance.configure_sbd = Mock()
        sbdmanager_instance.init_and_deploy_sbd()
        mock_ServiceManager.return_value.disable_service.assert_not_called()
        mock_adjust_properties.assert_called_once()

    @patch('os.path.exists')
    @patch('crmsh.sbd.ServiceManager')
    def test_join_sbd_return(self, mock_ServiceManager, mock_exists):
        mock_exists.return_value = False
        mock_ServiceManager.return_value.disable_service = Mock()
        sbdmanager_instance = SBDManager()
        sbdmanager_instance.join_sbd("remote_user", "peer_host")
        mock_exists.assert_called_once_with(sbd.SBDManager.SYSCONFIG_SBD)
        mock_ServiceManager.return_value.disable_service.assert_called_once_with(constants.SBD_SERVICE)

    @patch('crmsh.utils.package_is_installed')
    @patch('logging.Logger.info')
    @patch('crmsh.sbd.SBDUtils.verify_sbd_device')
    @patch('crmsh.sbd.SBDUtils.get_sbd_device_from_config')
    @patch('crmsh.watchdog.Watchdog')
    @patch('os.path.exists')
    @patch('crmsh.sbd.ServiceManager')
    def test_join_sbd_diskbased(self, mock_ServiceManager, mock_exists, mock_Watchdog, mock_get_sbd_device_from_config, mock_verify_sbd_device, mock_logger_info, mock_package_is_installed):
        mock_package_is_installed.side_effect = [True, True]
        mock_exists.return_value = True
        mock_ServiceManager.return_value.service_is_enabled.return_value = True
        mock_Watchdog.return_value.join_watchdog = Mock()
        mock_get_sbd_device_from_config.return_value = ['/dev/sbd_device']

        sbdmanager_instance = SBDManager()
        sbdmanager_instance.enable_sbd_service = Mock()
        sbdmanager_instance.join_sbd("remote_user", "peer_host")

        mock_logger_info.assert_called_once_with("Got SBD configuration")

    @patch('crmsh.utils.package_is_installed')
    @patch('logging.Logger.info')
    @patch('crmsh.sbd.SBDUtils.get_sbd_device_from_config')
    @patch('crmsh.watchdog.Watchdog')
    @patch('os.path.exists')
    @patch('crmsh.sbd.ServiceManager')
    def test_join_sbd_diskless(self, mock_ServiceManager, mock_exists, mock_Watchdog, mock_get_sbd_device_from_config, mock_logger_info, mock_package_is_installed):
        mock_exists.return_value = True
        mock_package_is_installed.return_value = True
        mock_ServiceManager.return_value.service_is_enabled.return_value = True
        mock_Watchdog.return_value.join_watchdog = Mock()
        mock_get_sbd_device_from_config.return_value = []

        sbdmanager_instance = SBDManager()
        sbdmanager_instance._warn_diskless_sbd = Mock()
        sbdmanager_instance.enable_sbd_service = Mock()
        sbdmanager_instance.join_sbd("remote_user", "peer_host")

        mock_logger_info.assert_called_once_with("Got diskless SBD configuration")

    @patch('crmsh.sbd.SBDManager.update_configuration')
    def test_update_sbd_configuration(self, mock_update_configuration):
        SBDManager.update_sbd_configuration({'key': 'value'})
        mock_update_configuration.assert_called_once()

    @patch('crmsh.utils.sysconfig_set')
    @patch('crmsh.sbd.ServiceManager')
    def test_update_configuration_return(self, mock_ServiceManager, mock_sysconfig_set):
        sbdmanager_instance = SBDManager()
        sbdmanager_instance.update_configuration()
        mock_sysconfig_set.assert_not_called()

    @patch('crmsh.bootstrap.sync_path')
    @patch('crmsh.utils.sysconfig_set')
    @patch('logging.Logger.info')
    @patch('crmsh.utils.copy_local_file')
    @patch('crmsh.sbd.ServiceManager')
    def test_update_configuration(self, mock_ServiceManager, mock_copy_local_file, mock_logger_info, mock_sysconfig_set, mock_sync_file):
        sbdmanager_instance = SBDManager(update_dict={'key': 'value'})
        sbdmanager_instance.overwrite_sysconfig = True
        sbdmanager_instance.update_configuration()
        mock_logger_info.assert_has_calls([
            call("Update %s in %s: %s", 'key', sbd.SBDManager.SYSCONFIG_SBD, 'value'),
        ])

    @patch('logging.Logger.info')
    def test_initialize_sbd_diskless(self, mock_logger_info):
        sbdmanager_instance = SBDManager(diskless_sbd=True)
        sbdmanager_instance._warn_diskless_sbd = Mock()
        sbdmanager_instance.initialize_sbd()
        mock_logger_info.assert_called_once_with("Configuring diskless SBD")

    @patch('crmsh.sbd.ServiceManager')
    @patch('logging.Logger.debug')
    @patch('crmsh.sbd.sh.cluster_shell')
    @patch('crmsh.sbd.SBDManager.convert_timeout_dict_to_opt_str')
    @patch('shutil.which')
    @patch('logging.Logger.info')
    def test_initialize_sbd_diskbased(self, mock_logger_info, mock_which, mock_convert_timeout_dict_to_opt_str, mock_cluster_shell, mock_logger_debug, mock_ServiceManager):
        mock_which.return_value = "/sbin/fence_sbd"
        sbdmanager_instance = SBDManager(device_list_to_init=['/dev/sbd_device'], timeout_dict={'watchdog': 5, 'msgwait': 10})
        sbdmanager_instance.initialize_sbd()
        mock_logger_info.assert_has_calls([
            call("Configuring disk-based SBD"),
            call("Initializing SBD device %s", '/dev/sbd_device')
        ])

    @patch('crmsh.sbd.SBDManager.convert_timeout_dict_to_opt_str')
    def test_initialize_sbd_return(self, mock_convert_timeout_dict_to_opt_str):
        sbdmanager_instance = SBDManager()
        sbdmanager_instance.initialize_sbd()
        mock_convert_timeout_dict_to_opt_str.assert_not_called()

    @patch('crmsh.utils.cluster_run_cmd')
    @patch('crmsh.sbd.SBDTimeout.is_sbd_delay_start')
    @patch('crmsh.sbd.ServiceManager')
    def test_unset_sbd_delay_start(self, mock_ServiceManager, mock_is_sbd_delay_start, mock_cluster_run_cmd):
        mock_is_sbd_delay_start.return_value = True
        mock_ServiceManager_inst = Mock()
        mock_ServiceManager.return_value = mock_ServiceManager_inst
        mock_ServiceManager_inst.service_is_enabled.return_value = True
        sbdmanager_instance = SBDManager()
        sbdmanager_instance.unset_sbd_delay_start(['node1', 'node2'])
        cmd = f"mkdir -p {sbd.SBDManager.SBD_SYSTEMD_DELAY_START_DISABLE_DIR} && " \
                f"echo -e '[Service]\\nUnsetEnvironment=SBD_DELAY_START' > {sbd.SBDManager.SBD_SYSTEMD_DELAY_START_DISABLE_FILE} && " \
                "systemctl daemon-reload"
        mock_cluster_run_cmd.assert_called_once_with(cmd, ['node1', 'node2'])


class TestOutterFunctions(unittest.TestCase):
    """
    Unitary tests for crmsh.sbd outter functions
    """
    @patch('crmsh.utils.ext_cmd')
    @patch('logging.Logger.info')
    @patch('crmsh.sbd.xmlutil.CrmMonXmlParser')
    def test_cleanup_existing_sbd_resource(self, mock_CrmMonXmlParser, mock_logger_info, mock_ext_cmd):
        mock_CrmMonXmlParser.return_value.is_resource_configured.return_value = True
        mock_CrmMonXmlParser.return_value.get_resource_id_list_via_type.return_value = ['sbd_resource']
        mock_CrmMonXmlParser.return_value.is_resource_started.return_value = True
        sbd.cleanup_existing_sbd_resource()
        mock_logger_info.assert_has_calls([
            call("Stop sbd resource '%s'(%s)", 'sbd_resource', sbd.SBDManager.SBD_RA),
            call("Remove sbd resource '%s'", 'sbd_resource')
        ])

    @patch('logging.Logger.info')
    @patch('crmsh.sh.cluster_shell')
    def test_cleanup_sbd_configurations(self, mock_cluster_shell, mock_logger_info):
        mock_cluster_shell_inst = Mock()
        mock_cluster_shell.return_value = mock_cluster_shell_inst
        mock_cluster_shell_inst.get_stdout_or_raise_error = Mock()
        sbd.cleanup_sbd_configurations()
        mock_cluster_shell_inst.get_stdout_or_raise_error.assert_has_calls([
            call(f"test -f {sbd.SBDManager.SYSCONFIG_SBD} && mv {sbd.SBDManager.SYSCONFIG_SBD} {sbd.SBDManager.SYSCONFIG_SBD}.bak || exit 0", host=None),
            call(f"test -d {sbd.SBDManager.SBD_SYSTEMD_DELAY_START_DIR} && rm -rf {sbd.SBDManager.SBD_SYSTEMD_DELAY_START_DIR} && systemctl daemon-reload || exit 0", host=None),
            call(f"test -d {sbd.SBDManager.SBD_SYSTEMD_DELAY_START_DISABLE_DIR} && rm -rf {sbd.SBDManager.SBD_SYSTEMD_DELAY_START_DISABLE_DIR} && systemctl daemon-reload || exit 0", host=None),
        ])

    @patch('crmsh.sbd.cleanup_sbd_configurations')
    @patch('crmsh.utils.cleanup_fencing_related_properties')
    @patch('crmsh.sbd.sh.cluster_shell')
    @patch('logging.Logger.info')
    @patch('crmsh.sbd.ServiceManager')
    @patch('crmsh.utils.list_cluster_nodes')
    @patch('crmsh.sbd.cleanup_existing_sbd_resource')
    def test_purge_sbd_from_cluster(self, mock_cleanup_existing_sbd_resource, mock_list_cluster_nodes, mock_ServiceManager, mock_logger_info, mock_cluster_shell, mock_cleanup_fencing_related_properties, mock_rm_sbd_configuration_files):
        mock_list_cluster_nodes.return_value = ['node1', 'node2']
        mock_ServiceManager.return_value.service_is_enabled.side_effect = [True, True]
        fencing_data = """fencing-sbd
1 fence device found
        """
        mock_cluster_shell.return_value.get_stdout_or_raise_error.return_value = fencing_data
        sbd.purge_sbd_from_cluster()
        mock_logger_info.assert_has_calls([
            call("Disable %s on node %s", constants.SBD_SERVICE, 'node1'),
            call("Disable %s on node %s", constants.SBD_SERVICE, 'node2'),
        ])
        mock_cleanup_fencing_related_properties.assert_called_once()
        mock_rm_sbd_configuration_files.assert_has_calls([call("node1"), call("node2")])
