import unittest

try:
    from unittest import mock
except ImportError:
    import mock

from crmsh import sbd
from crmsh import watchdog
from crmsh import bootstrap
from crmsh import constants


class TestWatchdog(unittest.TestCase):
    """
    Unitary tests for crmsh.watchdog.Watchdog
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
        self.watchdog_inst = watchdog.Watchdog()
        self.watchdog_join_inst = watchdog.Watchdog(remote_user="alice", peer_host="node1")

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    def test_watchdog_device_name(self):
        res = self.watchdog_inst.watchdog_device_name
        assert res is None

    @mock.patch('crmsh.sh.ShellUtils.get_stdout_stderr')
    def test_verify_watchdog_device_ignore_error(self, mock_run):
        mock_run.return_value = (1, None, "error")
        res = self.watchdog_inst.verify_watchdog_device("/dev/watchdog", True)
        self.assertEqual(res, False)
        mock_run.assert_called_once_with("wdctl /dev/watchdog")

    @mock.patch('crmsh.utils.fatal')
    @mock.patch('crmsh.sh.ShellUtils.get_stdout_stderr')
    def test_verify_watchdog_device_error(self, mock_run, mock_error):
        mock_run.return_value = (1, None, "error")
        mock_error.side_effect = ValueError
        with self.assertRaises(ValueError) as err:
            self.watchdog_inst.verify_watchdog_device("/dev/watchdog")
        mock_error.assert_called_once_with("Invalid watchdog device /dev/watchdog: error")
        mock_run.assert_called_once_with("wdctl /dev/watchdog")

    @mock.patch('crmsh.sh.ShellUtils.get_stdout_stderr')
    def test_verify_watchdog_device(self, mock_run):
        mock_run.return_value = (0, None, None)
        res = self.watchdog_inst.verify_watchdog_device("/dev/watchdog")
        self.assertEqual(res, True)

    @mock.patch('crmsh.sh.ShellUtils.get_stdout_stderr')
    def test_load_watchdog_driver(self, mock_run):
        self.watchdog_inst._load_watchdog_driver("softdog")
        mock_run.assert_has_calls([
            mock.call(f"echo softdog > {watchdog.Watchdog.WATCHDOG_CFG}"),
            mock.call("systemctl restart systemd-modules-load")
            ])

    @mock.patch('crmsh.utils.parse_sysconfig')
    def test_get_watchdog_device_from_sbd_config(self, mock_parse):
        mock_parse_inst = mock.Mock()
        mock_parse.return_value = mock_parse_inst
        mock_parse_inst.get.return_value = "/dev/watchdog"
        res = self.watchdog_inst.get_watchdog_device_from_sbd_config()
        self.assertEqual(res, "/dev/watchdog")
        mock_parse.assert_called_once_with(sbd.SBDManager.SYSCONFIG_SBD)

    @mock.patch('crmsh.sh.ShellUtils.get_stdout_stderr')
    def test_driver_is_loaded(self, mock_run):
        output = """
button                 24576  0
softdog                16384  2
btrfs                1474560  1
        """
        mock_run.return_value = (0, output, None)
        res = self.watchdog_inst._driver_is_loaded("softdog")
        assert res is not None
        mock_run.assert_called_once_with("lsmod")

    @mock.patch('crmsh.utils.fatal')
    @mock.patch('crmsh.sh.ShellUtils.get_stdout_stderr')
    def test_set_watchdog_info_error(self, mock_run, mock_error):
        mock_run.return_value = (1, None, "error")
        mock_error.side_effect = ValueError
        with self.assertRaises(ValueError):
            self.watchdog_inst._set_watchdog_info()
        mock_run.assert_called_once_with(watchdog.Watchdog.QUERY_CMD)
        mock_error.assert_called_once_with("Failed to run {}: error".format(watchdog.Watchdog.QUERY_CMD))

    @mock.patch('crmsh.sh.ShellUtils.get_stdout_stderr')
    def test_set_watchdog_info(self, mock_run):
        output = """
Discovered 3 watchdog devices:

[1] /dev/watchdog
Identity: Software Watchdog
Driver: softdog
CAUTION: Not recommended for use with sbd.

[2] /dev/watchdog0
Identity: Software Watchdog
Driver: softdog
CAUTION: Not recommended for use with sbd.

[3] /dev/watchdog1
Identity: iTCO_wdt
Driver: iTCO_wdt
        """
        mock_run.return_value = (0, output, None)
        self.watchdog_inst._set_watchdog_info()
        self.assertEqual(self.watchdog_inst._watchdog_info_dict, {'/dev/watchdog': 'softdog', '/dev/watchdog0': 'softdog', '/dev/watchdog1': 'iTCO_wdt'})

    @mock.patch('crmsh.watchdog.Watchdog.verify_watchdog_device')
    def test_get_device_through_driver_none(self, mock_verify):
        self.watchdog_inst._watchdog_info_dict = {'/dev/watchdog': 'softdog', '/dev/watchdog0': 'softdog', '/dev/watchdog1': 'iTCO_wdt'}
        mock_verify.return_value = False
        res = self.watchdog_inst._get_device_through_driver("iTCO_wdt")
        self.assertEqual(res, None)
        mock_verify.assert_called_once_with("/dev/watchdog1")

    @mock.patch('crmsh.watchdog.Watchdog.verify_watchdog_device')
    def test_get_device_through_driver(self, mock_verify):
        self.watchdog_inst._watchdog_info_dict = {'/dev/watchdog': 'softdog', '/dev/watchdog0': 'softdog', '/dev/watchdog1': 'iTCO_wdt'}
        mock_verify.return_value = True
        res = self.watchdog_inst._get_device_through_driver("iTCO_wdt")
        self.assertEqual(res, "/dev/watchdog1")
        mock_verify.assert_called_once_with("/dev/watchdog1")

    @mock.patch('crmsh.utils.fatal')
    @mock.patch('crmsh.sh.ShellUtils.get_stdout_stderr')
    def test_get_driver_through_device_remotely_error(self, mock_run, mock_error):
        mock_run.return_value = (1, None, "error")
        self.watchdog_join_inst._get_driver_through_device_remotely("test")
        mock_run.assert_called_once_with("ssh {} alice@node1 sudo sbd query-watchdog".format(constants.SSH_OPTION))
        mock_error.assert_called_once_with("Failed to run sudo sbd query-watchdog remotely: error")

    @mock.patch('crmsh.sh.ShellUtils.get_stdout_stderr')
    def test_get_driver_through_device_remotely_none(self, mock_run):
        mock_run.return_value = (0, "data", None)
        res = self.watchdog_join_inst._get_driver_through_device_remotely("/dev/watchdog")
        self.assertEqual(res, None)
        mock_run.assert_called_once_with("ssh {} alice@node1 sudo sbd query-watchdog".format(constants.SSH_OPTION))

    @mock.patch('crmsh.sh.ShellUtils.get_stdout_stderr')
    def test_get_driver_through_device_remotely(self, mock_run):
        output = """
Discovered 3 watchdog devices:

[1] /dev/watchdog
Identity: Software Watchdog
Driver: softdog
CAUTION: Not recommended for use with sbd.

[2] /dev/watchdog0
Identity: Software Watchdog
Driver: softdog
CAUTION: Not recommended for use with sbd.

[3] /dev/watchdog1
Identity: iTCO_wdt
Driver: iTCO_wdt
        """
        mock_run.return_value = (0, output, None)
        res = self.watchdog_join_inst._get_driver_through_device_remotely("/dev/watchdog")
        self.assertEqual(res, "softdog")
        mock_run.assert_called_once_with("ssh {} alice@node1 sudo sbd query-watchdog".format(constants.SSH_OPTION))

    def test_get_first_unused_device_none(self):
        res = self.watchdog_inst._get_first_unused_device()
        self.assertEqual(res, None)

    @mock.patch('crmsh.watchdog.Watchdog.verify_watchdog_device')
    def test_get_first_unused_device(self, mock_verify):
        mock_verify.return_value = True
        self.watchdog_inst._watchdog_info_dict = {'/dev/watchdog': 'softdog', '/dev/watchdog0': 'softdog', '/dev/watchdog1': 'iTCO_wdt'}
        res = self.watchdog_inst._get_first_unused_device()
        self.assertEqual(res, "/dev/watchdog")
        mock_verify.assert_called_once_with("/dev/watchdog", ignore_error=True)

    @mock.patch('crmsh.watchdog.Watchdog._get_first_unused_device')
    @mock.patch('crmsh.watchdog.Watchdog.verify_watchdog_device')
    @mock.patch('crmsh.watchdog.Watchdog.get_watchdog_device_from_sbd_config')
    def test_set_input_from_config(self, mock_from_config, mock_verify, mock_first):
        mock_from_config.return_value = "/dev/watchdog"
        mock_verify.return_value = True
        self.watchdog_inst._set_input()
        mock_first.assert_not_called()
        mock_from_config.assert_called_once_with()

    @mock.patch('crmsh.watchdog.Watchdog._get_first_unused_device')
    @mock.patch('crmsh.watchdog.Watchdog.verify_watchdog_device')
    @mock.patch('crmsh.watchdog.Watchdog.get_watchdog_device_from_sbd_config')
    def test_set_input(self, mock_from_config, mock_verify, mock_first):
        mock_from_config.return_value = None
        mock_first.return_value = None
        self.watchdog_inst._set_input()
        self.assertEqual(self.watchdog_inst._input, "softdog")
        mock_from_config.assert_called_once_with()
        mock_verify.assert_not_called()
        mock_first.assert_called_once_with()

    def test_valid_device_false(self):
        res = self.watchdog_inst._valid_device("test")
        self.assertEqual(res, False)

    @mock.patch('crmsh.watchdog.Watchdog.verify_watchdog_device')
    def test_valid_device(self, mock_verify):
        mock_verify.return_value = True
        self.watchdog_inst._watchdog_info_dict = {'/dev/watchdog': 'softdog', '/dev/watchdog0': 'softdog', '/dev/watchdog1': 'iTCO_wdt'}
        res = self.watchdog_inst._valid_device("/dev/watchdog")
        self.assertEqual(res, True)

    @mock.patch('crmsh.utils.fatal')
    @mock.patch('crmsh.watchdog.Watchdog.get_watchdog_device_from_sbd_config')
    @mock.patch('crmsh.watchdog.Watchdog._set_watchdog_info')
    def test_join_watchdog_error(self, mock_set_info, mock_from_config, mock_error):
        mock_from_config.return_value = None
        mock_error.side_effect = SystemExit
        with self.assertRaises(SystemExit):
            self.watchdog_join_inst.join_watchdog()
        mock_set_info.assert_called_once_with()
        mock_from_config.assert_called_once_with()
        mock_error.assert_called_once_with("Failed to get watchdog device from {}".format(sbd.SBDManager.SYSCONFIG_SBD))

    @mock.patch('crmsh.watchdog.Watchdog._load_watchdog_driver')
    @mock.patch('crmsh.watchdog.Watchdog._get_driver_through_device_remotely')
    @mock.patch('crmsh.watchdog.Watchdog._valid_device')
    @mock.patch('crmsh.watchdog.Watchdog.get_watchdog_device_from_sbd_config')
    @mock.patch('crmsh.watchdog.Watchdog._set_watchdog_info')
    def test_join_watchdog(self, mock_set_info, mock_from_config, mock_valid, mock_get_driver_remotely, mock_load):
        mock_from_config.return_value = "/dev/watchdog"
        mock_valid.return_value = False
        mock_get_driver_remotely.return_value = "softdog"

        self.watchdog_join_inst.join_watchdog()

        mock_set_info.assert_called_once_with()
        mock_from_config.assert_called_once_with()
        mock_valid.assert_called_once_with("/dev/watchdog")
        mock_get_driver_remotely.assert_called_once_with("/dev/watchdog")
        mock_load.assert_called_once_with("softdog")

    @mock.patch('crmsh.sh.ShellUtils.get_stdout_stderr')
    @mock.patch('crmsh.watchdog.Watchdog._valid_device')
    @mock.patch('crmsh.watchdog.Watchdog._set_input')
    @mock.patch('crmsh.watchdog.Watchdog._set_watchdog_info')
    def test_init_watchdog_valid(self, mock_set_info, mock_set_input, mock_valid, mock_run):
        mock_valid.return_value = True
        mock_run.return_value = (0, None, None)
        self.watchdog_inst._input = "/dev/watchdog"
        self.watchdog_inst.init_watchdog()
        mock_run.assert_not_called()
        mock_valid.assert_called_once_with("/dev/watchdog")

    @mock.patch('crmsh.utils.fatal')
    @mock.patch('crmsh.sh.ShellUtils.get_stdout_stderr')
    @mock.patch('crmsh.watchdog.Watchdog._valid_device')
    @mock.patch('crmsh.watchdog.Watchdog._set_input')
    @mock.patch('crmsh.watchdog.Watchdog._set_watchdog_info')
    def test_init_watchdog_error(self, mock_set_info, mock_set_input, mock_valid, mock_run, mock_error):
        mock_valid.return_value = False
        mock_run.return_value = (1, None, None)
        self.watchdog_inst._input = "test"
        mock_error.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            self.watchdog_inst.init_watchdog()

        mock_valid.assert_called_once_with("test")
        mock_run.assert_called_once_with("modinfo test")
        mock_error.assert_called_once_with("Should provide valid watchdog device or driver name by -w option")

    @mock.patch('crmsh.watchdog.Watchdog._get_device_through_driver')
    @mock.patch('crmsh.watchdog.Watchdog._load_watchdog_driver')
    @mock.patch('crmsh.watchdog.Watchdog._driver_is_loaded')
    @mock.patch('crmsh.sh.ShellUtils.get_stdout_stderr')
    @mock.patch('crmsh.watchdog.Watchdog._valid_device')
    @mock.patch('crmsh.watchdog.Watchdog._set_input')
    @mock.patch('crmsh.watchdog.Watchdog._set_watchdog_info')
    def test_init_watchdog(self, mock_set_info, mock_set_input, mock_valid, mock_run, mock_is_loaded, mock_load, mock_get_device):
        mock_valid.return_value = False
        self.watchdog_inst._input = "softdog"
        mock_run.return_value = (0, None, None)
        mock_is_loaded.return_value = False
        mock_get_device.return_value = "/dev/watchdog"

        self.watchdog_inst.init_watchdog()

        mock_valid.assert_called_once_with("softdog")
        mock_run.assert_called_once_with("modinfo softdog")
        mock_is_loaded.assert_called_once_with("softdog")
        mock_load.assert_called_once_with("softdog")
        mock_set_info.assert_has_calls([mock.call(), mock.call()])
        mock_get_device.assert_called_once_with("softdog")
