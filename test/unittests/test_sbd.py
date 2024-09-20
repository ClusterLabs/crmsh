import logging
import unittest
from unittest.mock import patch, MagicMock
from crmsh.sbd import SBDUtils, SBDManager


class TestSBDUtils(unittest.TestCase):

    @patch('crmsh.sh.cluster_shell')
    def test_get_sbd_device_metadata_success(self, mock_cluster_shell):
        mock_cluster_shell.return_value.get_stdout_or_raise_error.return_value = """
        UUID : 1234-5678
        Timeout (watchdog) : 5
        Timeout (msgwait) : 10
        """
        result = SBDUtils.get_sbd_device_metadata("/dev/sbd_device")
        expected = {'uuid': '1234-5678', 'watchdog': 5, 'msgwait': 10}
        self.assertEqual(result, expected)

    @patch('crmsh.sh.cluster_shell')
    def test_get_sbd_device_metadata_exception(self, mock_cluster_shell):
        mock_cluster_shell.return_value.get_stdout_or_raise_error.side_effect = Exception
        result = SBDUtils.get_sbd_device_metadata("/dev/sbd_device")
        self.assertEqual(result, {})

    @patch('crmsh.sh.cluster_shell')
    def test_get_sbd_device_metadata_timeout_only(self, mock_cluster_shell):
        mock_cluster_shell.return_value.get_stdout_or_raise_error.return_value = """
        UUID : 1234-5678
        Timeout (watchdog) : 5
        Timeout (msgwait) : 10
        """
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

    @patch('crmsh.sbd.SBDUtils.get_sbd_device_from_config')
    @patch('crmsh.service_manager.ServiceManager.service_is_active')
    def test_is_using_diskless_sbd(self, mock_service_is_active, mock_get_sbd_device_from_config):
        mock_get_sbd_device_from_config.return_value = []
        mock_service_is_active.return_value = True
        result = SBDUtils.is_using_diskless_sbd()
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
    @patch('logging.Logger.warning')
    def test_check_devices_metadata_consistent_multiple_devices_inconsistent(self, mock_logger_warning, mock_get_sbd_device_metadata):
        dev_list = ['/dev/sbd_device1', '/dev/sbd_device2']
        mock_get_sbd_device_metadata.side_effect = ['metadata1', 'metadata2']
        result = SBDUtils.check_devices_metadata_consistent(dev_list)
        self.assertFalse(result)
        mock_logger_warning.assert_called()


class TestSBDTimeout(unittest.TestCase):
    """
    Unitary tests for crmsh.sbd.SBDTimeout
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

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """
