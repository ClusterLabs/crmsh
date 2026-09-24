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

    @mock.patch('crmsh.utils.cluster_run_cmd')
    def test_write_watchdog_config_cluster_wide(self, mock_run):
        # node_list=None lets cluster_run_cmd discover the node list itself
        # from the running CIB.
        watchdog.Watchdog._write_watchdog_config("softdog", node_list=None)
        mock_run.assert_called_once_with(
            f"echo softdog > {watchdog.Watchdog.WATCHDOG_CFG}", None)

    @mock.patch('crmsh.utils.cluster_run_cmd')
    def test_write_watchdog_config_specific_nodes(self, mock_run):
        watchdog.Watchdog._write_watchdog_config("softdog", node_list=["node1"])
        mock_run.assert_called_once_with(
            f"echo softdog > {watchdog.Watchdog.WATCHDOG_CFG}", ["node1"])

    @mock.patch('crmsh.utils.cluster_run_cmd')
    def test_reload_driver(self, mock_run):
        watchdog.Watchdog._reload_driver(["node1"])
        mock_run.assert_called_once_with("systemctl restart systemd-modules-load", ["node1"])

    @mock.patch('crmsh.utils.parse_sysconfig')
    def test_get_watchdog_device_from_sbd_config(self, mock_parse):
        mock_parse_inst = mock.Mock()
        mock_parse.return_value = mock_parse_inst
        mock_parse_inst.get.return_value = "/dev/watchdog"
        res = self.watchdog_inst.get_watchdog_device_from_sbd_config()
        self.assertEqual(res, "/dev/watchdog")
        mock_parse.assert_called_once_with(sbd.SBDManager.SYSCONFIG_SBD)

    @mock.patch('crmsh.utils.cluster_run_cmd')
    def test_driver_is_loaded_single_node(self, mock_run):
        mock_run.return_value = [("node1", (0, b"\nsoftdog 16384 2", b""))]
        assert self.watchdog_inst._driver_is_loaded("softdog", node_list=["node1"]) is True
        mock_run.assert_called_once_with("lsmod", ["node1"])

    @mock.patch('crmsh.utils.cluster_run_cmd')
    def test_driver_is_not_loaded_single_node(self, mock_run):
        mock_run.return_value = [("node1", (0, b"\nbutton 24576 0", b""))]
        assert self.watchdog_inst._driver_is_loaded("softdog", node_list=["node1"]) is False

    @mock.patch('crmsh.utils.cluster_run_cmd')
    def test_driver_is_loaded_cluster_wide_all(self, mock_run):
        output = "\nsoftdog 16384 2"
        mock_run.return_value = [("node1", (0, output.encode(), b"")), ("node2", (0, output.encode(), b""))]
        assert self.watchdog_inst._driver_is_loaded("softdog", node_list=["node1", "node2"]) is True
        mock_run.assert_called_once_with("lsmod", ["node1", "node2"])

    @mock.patch('crmsh.utils.cluster_run_cmd')
    def test_driver_is_loaded_cluster_wide_not_all(self, mock_run):
        loaded = "\nsoftdog 16384 2"
        mock_run.return_value = [("node1", (0, loaded.encode(), b"")), ("node2", (0, b"\nbutton 24576 0", b""))]
        assert self.watchdog_inst._driver_is_loaded("softdog", node_list=["node1", "node2"]) is False

    @mock.patch("crmsh.watchdog.Watchdog._driver_is_loaded")
    def test_get_watchdog_info(self, mock_driver_is_loaded):
        output = """
Discovered 2 watchdog devices:

[1] /dev/watchdog
Identity: Busy: PID 3120 (sbd)
Driver: softdog
CAUTION: Not recommended for use with sbd.

[2] /dev/watchdog1
Identity: iTCO_wdt
Driver: iTCO_wdt
        """
        res = watchdog.Watchdog.get_watchdog_info(output)
        self.assertEqual(res, {"/dev/watchdog": "softdog", "/dev/watchdog1": "iTCO_wdt"})
        mock_driver_is_loaded.assert_not_called()

    def test_get_watchdog_info_sbd_only(self):
        output = """
[1] /dev/watchdog
Identity: Busy: PID 3120 (sbd)
Driver: softdog

[2] /dev/watchdog1
Identity: iTCO_wdt
Driver: iTCO_wdt
        """
        res = watchdog.Watchdog.get_watchdog_info(output, sbd_only=True)
        self.assertEqual(res, {"/dev/watchdog": "softdog"})

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

    def test_set_input_keep_existing(self):
        self.watchdog_inst._input = "/dev/watchdog"
        self.watchdog_inst._set_input()
        self.assertEqual(self.watchdog_inst._input, "/dev/watchdog")

    def test_set_input_softdog_when_no_device(self):
        self.watchdog_inst._set_input()
        self.assertEqual(self.watchdog_inst._input, "softdog")

    def test_set_input_softdog_when_only_softdog(self):
        self.watchdog_inst._watchdog_info_dict = {'/dev/watchdog': 'softdog', '/dev/watchdog0': 'softdog'}
        self.watchdog_inst._set_input()
        self.assertEqual(self.watchdog_inst._input, "softdog")

    def test_set_input_prefer_non_softdog(self):
        self.watchdog_inst._watchdog_info_dict = {'/dev/watchdog': 'softdog', '/dev/watchdog1': 'iTCO_wdt'}
        self.watchdog_inst._set_input()
        self.assertEqual(self.watchdog_inst._input, "/dev/watchdog1")

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
            self.watchdog_inst.join_watchdog()
        mock_set_info.assert_called_once_with()
        mock_from_config.assert_called_once_with()
        mock_error.assert_called_once_with("Failed to get watchdog device from {}".format(sbd.SBDManager.SYSCONFIG_SBD))

    @mock.patch('crmsh.utils.this_node')
    @mock.patch('crmsh.watchdog.Watchdog._reload_driver')
    @mock.patch('crmsh.watchdog.Watchdog._valid_device')
    @mock.patch('crmsh.watchdog.Watchdog.get_watchdog_device_from_sbd_config')
    @mock.patch('crmsh.watchdog.Watchdog._set_watchdog_info')
    def test_join_watchdog(self, mock_set_info, mock_from_config, mock_valid, mock_reload, mock_this_node):
        mock_from_config.return_value = "/dev/watchdog"
        mock_valid.return_value = False
        mock_this_node.return_value = "node1"

        self.watchdog_inst.join_watchdog()

        mock_set_info.assert_called_once_with()
        mock_from_config.assert_called_once_with()
        mock_valid.assert_called_once_with("/dev/watchdog")
        mock_reload.assert_called_once_with(["node1"])

    @mock.patch('crmsh.watchdog.Watchdog._reload_driver')
    @mock.patch('crmsh.watchdog.Watchdog._valid_device')
    @mock.patch('crmsh.watchdog.Watchdog.get_watchdog_device_from_sbd_config')
    @mock.patch('crmsh.watchdog.Watchdog._set_watchdog_info')
    def test_join_watchdog_already_valid(self, mock_set_info, mock_from_config, mock_valid, mock_reload):
        mock_from_config.return_value = "/dev/watchdog"
        mock_valid.return_value = True

        self.watchdog_inst.join_watchdog()

        mock_set_info.assert_called_once_with()
        mock_from_config.assert_called_once_with()
        mock_valid.assert_called_once_with("/dev/watchdog")
        mock_reload.assert_not_called()

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
        mock_error.assert_called_once_with("Should provide valid watchdog device or driver name")

    @mock.patch('crmsh.watchdog.Watchdog._get_device_through_driver')
    @mock.patch('crmsh.watchdog.Watchdog._reload_driver')
    @mock.patch('crmsh.watchdog.Watchdog._write_watchdog_config')
    @mock.patch('crmsh.watchdog.Watchdog._driver_is_loaded')
    @mock.patch('crmsh.sh.ShellUtils.get_stdout_stderr')
    @mock.patch('crmsh.watchdog.Watchdog._valid_device')
    @mock.patch('crmsh.watchdog.Watchdog._set_input')
    @mock.patch('crmsh.watchdog.Watchdog._set_watchdog_info')
    def test_init_watchdog_cluster_running(self, mock_set_info, mock_set_input, mock_valid, mock_run, mock_is_loaded, mock_write, mock_reload, mock_get_device):
        # cluster_is_running=True (default): cluster_run_cmd discovers the node
        # list itself from the running CIB, so no explicit node_list is passed.
        mock_valid.return_value = False
        self.watchdog_inst._input = "softdog"
        mock_run.return_value = (0, None, None)
        mock_is_loaded.return_value = False
        mock_get_device.return_value = "/dev/watchdog"

        self.watchdog_inst.init_watchdog()

        mock_valid.assert_called_once_with("softdog")
        mock_run.assert_called_once_with("modinfo softdog")
        mock_is_loaded.assert_called_once_with("softdog", node_list=None)
        mock_write.assert_called_once_with("softdog", node_list=None)
        mock_reload.assert_called_once_with(None)
        mock_set_info.assert_has_calls([mock.call(), mock.call()])
        mock_get_device.assert_called_once_with("softdog")

    @mock.patch('crmsh.watchdog.Watchdog._get_device_through_driver')
    @mock.patch('crmsh.watchdog.Watchdog._reload_driver')
    @mock.patch('crmsh.watchdog.Watchdog._write_watchdog_config')
    @mock.patch('crmsh.watchdog.Watchdog._driver_is_loaded')
    @mock.patch('crmsh.sh.ShellUtils.get_stdout_stderr')
    @mock.patch('crmsh.watchdog.Watchdog._valid_device')
    @mock.patch('crmsh.watchdog.Watchdog._set_input')
    @mock.patch('crmsh.watchdog.Watchdog._set_watchdog_info')
    @mock.patch('crmsh.utils.this_node')
    def test_init_watchdog_cluster_not_running(self, mock_this_node, mock_set_info, mock_set_input, mock_valid, mock_run, mock_is_loaded, mock_write, mock_reload, mock_get_device):
        # cluster_is_running=False (e.g. 'crm cluster init' before the cluster
        # exists): the driver can only be loaded on the local node.
        mock_this_node.return_value = "node1"
        watchdog_inst = watchdog.Watchdog(cluster_is_running=False)
        mock_valid.return_value = False
        watchdog_inst._input = "softdog"
        mock_run.return_value = (0, None, None)
        mock_is_loaded.return_value = False
        mock_get_device.return_value = "/dev/watchdog"

        watchdog_inst.init_watchdog()

        mock_valid.assert_called_once_with("softdog")
        mock_run.assert_called_once_with("modinfo softdog")
        mock_is_loaded.assert_called_once_with("softdog", node_list=["node1"])
        mock_write.assert_called_once_with("softdog", node_list=["node1"])
        mock_reload.assert_called_once_with(["node1"])
        mock_set_info.assert_has_calls([mock.call(), mock.call()])
        mock_get_device.assert_called_once_with("softdog")

    @mock.patch('crmsh.watchdog.Watchdog._get_device_through_driver')
    @mock.patch('crmsh.watchdog.Watchdog._reload_driver')
    @mock.patch('crmsh.watchdog.Watchdog._write_watchdog_config')
    @mock.patch('crmsh.watchdog.Watchdog._driver_is_loaded')
    @mock.patch('crmsh.sh.ShellUtils.get_stdout_stderr')
    @mock.patch('crmsh.watchdog.Watchdog._valid_device')
    @mock.patch('crmsh.watchdog.Watchdog._set_input')
    @mock.patch('crmsh.watchdog.Watchdog._set_watchdog_info')
    def test_init_watchdog_driver_already_loaded(self, mock_set_info, mock_set_input, mock_valid, mock_run, mock_is_loaded, mock_write, mock_reload, mock_get_device):
        # The critical fix: even when the driver is already loaded in the
        # kernel, WATCHDOG_CFG must still be written so it survives reboot and
        # is synced to joining nodes. Only the reload is skipped.
        mock_valid.return_value = False
        self.watchdog_inst._input = "softdog"
        mock_run.return_value = (0, None, None)
        mock_is_loaded.return_value = True
        mock_get_device.return_value = "/dev/watchdog"

        self.watchdog_inst.init_watchdog()

        mock_valid.assert_called_once_with("softdog")
        mock_run.assert_called_once_with("modinfo softdog")
        mock_is_loaded.assert_called_once_with("softdog", node_list=None)
        mock_write.assert_called_once_with("softdog", node_list=None)
        mock_reload.assert_not_called()
        mock_set_info.assert_called_once_with()
        mock_get_device.assert_called_once_with("softdog")

    @mock.patch('crmsh.watchdog.Watchdog.init_watchdog')
    def test_get_watchdog_device(self, mock_init):
        original_init = watchdog.Watchdog.__init__

        def _fake_init(self, *args, **kwargs):
            return original_init(self, *args, **kwargs)

        with mock.patch('crmsh.watchdog.Watchdog.__init__', side_effect=_fake_init, autospec=True) as mock_wd_init:
            watchdog.Watchdog.get_watchdog_device("softdog", cluster_is_running=False)
            mock_wd_init.assert_called_once_with(mock.ANY, _input="softdog", cluster_is_running=False)

    @mock.patch('crmsh.watchdog.Watchdog.init_watchdog')
    def test_get_watchdog_device_defaults(self, mock_init):
        original_init = watchdog.Watchdog.__init__

        def _fake_init(self, *args, **kwargs):
            return original_init(self, *args, **kwargs)

        with mock.patch('crmsh.watchdog.Watchdog.__init__', side_effect=_fake_init, autospec=True) as mock_wd_init:
            watchdog.Watchdog.get_watchdog_device()
            mock_wd_init.assert_called_once_with(mock.ANY, _input=None, cluster_is_running=True)
