import io
import unittest
from unittest import mock

from crmsh import ui_sbd
from crmsh import constants
from crmsh import sbd
from crmsh import utils


class TestOutterFunctions(unittest.TestCase):
    @mock.patch('crmsh.sbd.SBDUtils.is_using_disk_based_sbd')
    def test_sbd_device_completer_return_no_diskbased_sbd(self, mock_is_using_disk_based_sbd):
        mock_is_using_disk_based_sbd.return_value = False
        self.assertEqual(ui_sbd.sbd_device_completer([]), [])
        mock_is_using_disk_based_sbd.assert_called_once()

    @mock.patch('crmsh.sbd.SBDUtils.is_using_disk_based_sbd')
    def test_sbd_device_completer_return_options(self, mock_is_using_disk_based_sbd):
        mock_is_using_disk_based_sbd.return_value = True
        self.assertEqual(ui_sbd.sbd_device_completer(["device", ""]), ["add", "remove"])
        mock_is_using_disk_based_sbd.assert_called_once()

    @mock.patch('crmsh.sbd.SBDUtils.is_using_disk_based_sbd')
    def test_sbd_device_completer_return_no_options(self, mock_is_using_disk_based_sbd):
        mock_is_using_disk_based_sbd.return_value = True
        self.assertEqual(ui_sbd.sbd_device_completer(["device", "add", "/dev/sda1"]), [])
        mock_is_using_disk_based_sbd.assert_called_once()

    @mock.patch('crmsh.sbd.SBDUtils.get_sbd_device_from_config')
    @mock.patch('crmsh.sbd.SBDUtils.is_using_disk_based_sbd')
    def test_sbd_device_completer_return_no_last_dev(self, mock_is_using_disk_based_sbd, mock_get_sbd_device_from_config):
        mock_is_using_disk_based_sbd.return_value = True
        mock_get_sbd_device_from_config.return_value = ["/dev/sda1", "/dev/sda2"]
        self.assertEqual(ui_sbd.sbd_device_completer(["device", "remove", "/dev/sda1"]), [])
        mock_is_using_disk_based_sbd.assert_called_once()
        mock_get_sbd_device_from_config.assert_called_once()

    @mock.patch('crmsh.sbd.SBDUtils.get_sbd_device_from_config')
    @mock.patch('crmsh.sbd.SBDUtils.is_using_disk_based_sbd')
    def test_sbd_device_completer(self, mock_is_using_disk_based_sbd, mock_get_sbd_device_from_config):
        mock_is_using_disk_based_sbd.return_value = True
        mock_get_sbd_device_from_config.return_value = ["/dev/sda1", "/dev/sda2"]
        self.assertEqual(ui_sbd.sbd_device_completer(["device", "remove", "/dev"]), mock_get_sbd_device_from_config.return_value)
        mock_is_using_disk_based_sbd.assert_called_once()
        mock_get_sbd_device_from_config.assert_called_once()

    @mock.patch('crmsh.ui_sbd.ServiceManager')
    def test_sbd_configure_completer_return(self, mock_ServiceManager):
        mock_ServiceManager.return_value.service_is_active.side_effect = [True, False]
        self.assertEqual(ui_sbd.sbd_configure_completer([]), [])
        mock_ServiceManager.return_value.service_is_active.assert_has_calls([
            mock.call(constants.PCMK_SERVICE),
            mock.call(constants.SBD_SERVICE)
        ])

    @mock.patch('crmsh.sbd.SBDUtils.is_using_diskless_sbd')
    @mock.patch('crmsh.sbd.SBDUtils.is_using_disk_based_sbd')
    @mock.patch('crmsh.ui_sbd.ServiceManager')
    def test_sbd_configure_completer_show_return(self, mock_ServiceManager, mock_is_using_disk_based_sbd, mock_is_using_diskless_sbd):
        mock_ServiceManager.return_value.service_is_active.side_effect = [True, True]
        mock_is_using_disk_based_sbd.return_value = True
        mock_is_using_diskless_sbd.return_value = False
        self.assertEqual(ui_sbd.sbd_configure_completer(["configure", "show", ""]), list(ui_sbd.SBD.SHOW_TYPES))
        mock_ServiceManager.return_value.service_is_active.assert_has_calls([
            mock.call(constants.PCMK_SERVICE),
            mock.call(constants.SBD_SERVICE)
        ])
        mock_is_using_disk_based_sbd.assert_called_once()
        mock_is_using_diskless_sbd.assert_called_once()

    @mock.patch('crmsh.sbd.SBDUtils.is_using_diskless_sbd')
    @mock.patch('crmsh.sbd.SBDUtils.is_using_disk_based_sbd')
    @mock.patch('crmsh.ui_sbd.ServiceManager')
    def test_sbd_configure_completer_show_return_empty(self, mock_ServiceManager, mock_is_using_disk_based_sbd, mock_is_using_diskless_sbd):
        mock_ServiceManager.return_value.service_is_active.side_effect = [True, True]
        mock_is_using_disk_based_sbd.return_value = True
        mock_is_using_diskless_sbd.return_value = False
        self.assertEqual(ui_sbd.sbd_configure_completer(["configure", "show", "xx", ""]), [])
        mock_ServiceManager.return_value.service_is_active.assert_has_calls([
            mock.call(constants.PCMK_SERVICE),
            mock.call(constants.SBD_SERVICE)
        ])
        mock_is_using_disk_based_sbd.assert_called_once()
        mock_is_using_diskless_sbd.assert_called_once()

    @mock.patch('crmsh.sbd.SBDUtils.is_using_diskless_sbd')
    @mock.patch('crmsh.sbd.SBDUtils.is_using_disk_based_sbd')
    @mock.patch('crmsh.ui_sbd.ServiceManager')
    def test_sbd_configure_completer_success(self, mock_ServiceManager, mock_is_using_disk_based_sbd, mock_is_using_diskless_sbd):
        mock_ServiceManager.return_value.service_is_active.side_effect = [True, True]
        mock_is_using_disk_based_sbd.return_value = False
        mock_is_using_diskless_sbd.return_value = True
        self.assertEqual(ui_sbd.sbd_configure_completer(["configure", ""]), ["show", "watchdog-timeout=", "crashdump-watchdog-timeout=", "watchdog-device="])
        mock_ServiceManager.return_value.service_is_active.assert_has_calls([
            mock.call(constants.PCMK_SERVICE),
            mock.call(constants.SBD_SERVICE)
        ])
        mock_is_using_disk_based_sbd.assert_called_once()
        mock_is_using_diskless_sbd.assert_called_once()


class TestSBD(unittest.TestCase):

    def setUp(self):
        self.sbd_instance_diskbased = ui_sbd.SBD()
        self.sbd_instance_diskbased.cluster_nodes = ["node1", "node2"]
        self.sbd_instance_diskbased.device_list_from_config = ["/dev/sda1"]
        self.sbd_instance_diskbased.watchdog_device_from_config = "/dev/watchdog0"
        self.sbd_instance_diskbased.device_meta_dict_runtime = {"watchdog": 10, "allocate": 5, "loop": 5, "msgwait": 20}
        self.sbd_instance_diskbased.cluster_shell = mock.Mock()
        self.sbd_instance_diskbased.service_manager = mock.Mock()

        self.sbd_instance_diskless = ui_sbd.SBD()
        self.sbd_instance_diskless.cluster_nodes = ["node1", "node2"]
        self.sbd_instance_diskless.watchdog_device_from_config = "/dev/watchdog0"
        self.sbd_instance_diskless.watchdog_timeout_from_config = 10
        self.sbd_instance_diskless.cluster_shell = mock.Mock()
        self.sbd_instance_diskless.service_manager = mock.Mock()

    @mock.patch('logging.Logger.error')
    @mock.patch('crmsh.utils.package_is_installed')
    def test_requires(self, mock_package_is_installed, mock_logger_error):
        mock_package_is_installed.return_value = False
        self.assertFalse(self.sbd_instance_diskbased.requires())
        mock_package_is_installed.assert_called_with("sbd")
        mock_package_is_installed.return_value = True
        self.assertTrue(self.sbd_instance_diskbased.requires())
        mock_package_is_installed.assert_called_with("sbd")

    @mock.patch('logging.Logger.error')
    def test_service_is_active_false(self, mock_logger_error):
        self.sbd_instance_diskbased.service_manager.service_is_active = mock.Mock(return_value=False)
        self.assertFalse(self.sbd_instance_diskbased._service_is_active(constants.PCMK_SERVICE))
        mock_logger_error.assert_called_once_with("%s is not active", constants.PCMK_SERVICE)

    @mock.patch('logging.Logger.error')
    def test_service_is_active_true(self, mock_logger_error):
        self.sbd_instance_diskbased.service_manager.service_is_active = mock.Mock(return_value=True)
        self.assertTrue(self.sbd_instance_diskbased._service_is_active(constants.PCMK_SERVICE))
        mock_logger_error.assert_not_called()

    @mock.patch('crmsh.sbd.SBDUtils.is_using_diskless_sbd')
    @mock.patch('crmsh.sbd.SBDUtils.is_using_disk_based_sbd')
    def test_configure_usage_none(self, mock_is_using_disk_based_sbd, mock_is_using_diskless_sbd):
        mock_is_using_disk_based_sbd.return_value = False
        mock_is_using_diskless_sbd.return_value = False
        self.assertEqual(self.sbd_instance_diskbased.configure_usage, "")
        mock_is_using_disk_based_sbd.assert_called_once()
        mock_is_using_diskless_sbd.assert_called_once()

    @mock.patch('crmsh.sbd.SBDUtils.is_using_diskless_sbd')
    @mock.patch('crmsh.sbd.SBDUtils.is_using_disk_based_sbd')
    def test_configure_usage_disk_diskbased(self, mock_is_using_disk_based_sbd, mock_is_using_diskless_sbd):
        mock_is_using_disk_based_sbd.return_value = True
        timeout_usage_str = " ".join([f"[{t}-timeout=<integer>]" for t in ui_sbd.SBD.TIMEOUT_TYPE_MINIMUMS])
        show_usage = f"crm sbd configure show [{'|'.join(ui_sbd.SBD.SHOW_TYPES)}]"
        expected = f"Usage:\n{show_usage}\ncrm sbd configure {timeout_usage_str} [watchdog-device=<device>]\n"
        self.assertEqual(self.sbd_instance_diskbased.configure_usage, expected)
        mock_is_using_disk_based_sbd.assert_called_once()
        mock_is_using_diskless_sbd.assert_not_called()

    @mock.patch('crmsh.sbd.SBDUtils.is_using_diskless_sbd')
    @mock.patch('crmsh.sbd.SBDUtils.is_using_disk_based_sbd')
    def test_configure_usage_disk_diskless(self, mock_is_using_disk_based_sbd, mock_is_using_diskless_sbd):
        mock_is_using_disk_based_sbd.return_value = False
        mock_is_using_diskless_sbd.return_value = True
        timeout_usage_str = " ".join([f"[{t}-timeout=<integer>]" for t in ui_sbd.SBD.DISKLESS_TIMEOUT_TYPE_MINIMUMS])
        show_usage = f"crm sbd configure show [{'|'.join(ui_sbd.SBD.DISKLESS_SHOW_TYPES)}]"
        expected = f"Usage:\n{show_usage}\ncrm sbd configure {timeout_usage_str} [watchdog-device=<device>]\n"
        self.assertEqual(self.sbd_instance_diskless.configure_usage, expected)
        mock_is_using_disk_based_sbd.assert_called_once()
        mock_is_using_diskless_sbd.assert_called_once()

    @mock.patch('logging.Logger.info')
    @mock.patch('builtins.open', new_callable=mock.mock_open, read_data="# Comment line\nKEY1=value1\nKEY2=value2\n")
    def test_show_sysconfig(self, mock_open, mock_logger_info):
        with mock.patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            self.sbd_instance_diskbased._show_sysconfig()
            self.assertTrue(mock_logger_info.called)
            mock_logger_info.assert_called_with("crm sbd configure show sysconfig")
            self.assertEqual(mock_stdout.getvalue(), "KEY1=value1\nKEY2=value2\n")

    @mock.patch('logging.Logger.info')
    def test_show_disk_metadata(self, mock_logger_info):
        self.sbd_instance_diskbased.cluster_shell.get_stdout_or_raise_error.return_value = "disk metadata: data"
        with mock.patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            self.sbd_instance_diskbased._show_disk_metadata()
            self.assertTrue(mock_logger_info.called)
            mock_logger_info.assert_called_with("crm sbd configure show disk_metadata")
            self.assertEqual(mock_stdout.getvalue(), "disk metadata: data\n\n")
        self.sbd_instance_diskbased.cluster_shell.get_stdout_or_raise_error.assert_called_with("sbd -d /dev/sda1 dump")

    def test_do_configure_no_service(self):
        self.sbd_instance_diskbased._load_attributes = mock.Mock()
        self.sbd_instance_diskbased._service_is_active = mock.Mock(return_value=False)
        res = self.sbd_instance_diskbased.do_configure(mock.Mock(), "test")
        self.assertFalse(res)

    @mock.patch('crmsh.sbd.SBDTimeout.get_sbd_systemd_start_timeout')
    @mock.patch('logging.Logger.info')
    @mock.patch('builtins.print')
    def test_show_property(self, mock_print, mock_logger_info, mock_get_sbd_systemd_start_timeout):
        data1 = """property cib-bootstrap-options: \
        have-watchdog=true \
        dc-version="2.1.7+20240711.239cba384-1.1-2.1.7+20240711.239cba384" \
        cluster-infrastructure=corosync \
        cluster-name=hacluster \
        stonith-enabled=true \
        stonith-timeout=83 \
        priority-fencing-delay=60
        """
        data2 = "fence_sbd parameters"
        self.sbd_instance_diskbased.cluster_shell.get_stdout_or_raise_error = mock.Mock(side_effect=[data1, data2])
        mock_get_sbd_systemd_start_timeout.return_value = 10
        self.sbd_instance_diskbased._show_property()
        mock_logger_info.assert_has_calls([
            mock.call("crm sbd configure show property"),
            mock.call("%s", "crm configure show related:fence_sbd"),
            mock.call("%s", sbd.SBDTimeout.SHOW_SBD_START_TIMEOUT_CMD)
        ])
        mock_print.assert_has_calls([
            mock.call("have-watchdog=true"),
            mock.call("stonith-enabled=true"),
            mock.call("stonith-timeout=83"),
            mock.call(),
            mock.call("fence_sbd parameters"),
            mock.call(),
            mock.call(f"TimeoutStartUSec=10")
        ])

    def test_configure_show_invalid_arg(self):
        with self.assertRaises(ui_sbd.SBD.SyntaxError) as e:
            res = self.sbd_instance_diskbased._configure_show(["arg1", "arg2", "arg3"])
        self.assertEqual(str(e.exception), "Invalid argument")

    def test_configure_show_unknown_arg(self):
        with self.assertRaises(ui_sbd.SBD.SyntaxError) as e:
            res = self.sbd_instance_diskbased._configure_show(["xxx1", "xxx2"])
        self.assertEqual(str(e.exception), f"Unknown argument: xxx2")

    @mock.patch('crmsh.sbd.SBDTimeoutChecker')
    def test_configure_show_disk_metadata(self, mock_sbd_timeout_checker):
        mock_sbd_timeout_checker_instance = mock.Mock()
        mock_sbd_timeout_checker.return_value = mock_sbd_timeout_checker_instance
        mock_sbd_timeout_checker_instance.check_and_fix = mock.Mock()
        self.sbd_instance_diskbased._show_disk_metadata = mock.Mock()
        self.sbd_instance_diskbased._configure_show(["show", "disk_metadata"])
        self.sbd_instance_diskbased._show_disk_metadata.assert_called_once()
        mock_sbd_timeout_checker.assert_called_once_with()
        mock_sbd_timeout_checker_instance.check_and_fix.assert_called_once()

    @mock.patch('crmsh.sbd.SBDTimeoutChecker')
    @mock.patch('crmsh.ui_sbd.SBD._show_sysconfig')
    def test_configure_show_sysconfig(self, mock_show_sysconfig, mock_sbd_timeout_checker):
        mock_sbd_timeout_checker_instance = mock.Mock()
        mock_sbd_timeout_checker.return_value = mock_sbd_timeout_checker_instance
        mock_sbd_timeout_checker_instance.check_and_fix = mock.Mock()
        self.sbd_instance_diskbased._configure_show(["show", "sysconfig"])
        mock_show_sysconfig.assert_called_once()
        mock_sbd_timeout_checker.assert_called_once_with()
        mock_sbd_timeout_checker_instance.check_and_fix.assert_called_once()

    @mock.patch('crmsh.sbd.SBDTimeoutChecker')
    def test_configure_show_property(self, mock_sbd_timeout_checker):
        mock_sbd_timeout_checker_instance = mock.Mock()
        mock_sbd_timeout_checker.return_value = mock_sbd_timeout_checker_instance
        mock_sbd_timeout_checker_instance.check_and_fix = mock.Mock()
        self.sbd_instance_diskbased._show_property = mock.Mock()
        self.sbd_instance_diskbased._configure_show(["show", "property"])
        self.sbd_instance_diskbased._show_property.assert_called_once()
        mock_sbd_timeout_checker.assert_called_once_with()
        mock_sbd_timeout_checker_instance.check_and_fix.assert_called_once()

    def test_parse_re(self):
        test_data = [
            ("watchdog-timeout=30", ("watchdog", "timeout", "30")),
            ("crashdump-watchdog-timeout=120", ("crashdump-watchdog", "timeout", "120")),
            ("watchdog-device=/dev/watchdog", ("watchdog", "device", "/dev/watchdog")),
            ("loop-timeout=5", ("loop", "timeout", "5")),
            ("msgwait-timeout=10", ("msgwait", "timeout", "10")),
        ]
        for input_str, expected in test_data:
            match = ui_sbd.SBD.PARSE_RE.match(input_str)
            self.assertIsNotNone(match)
            self.assertEqual(match.groups(), expected)

    @mock.patch('crmsh.sbd.SBDTimeoutChecker')
    @mock.patch('crmsh.ui_sbd.SBD._show_sysconfig')
    @mock.patch('builtins.print')
    def test_configure_show(self, mock_print, mock_show_sysconfig, mock_sbd_timeout_checker):
        mock_sbd_timeout_checker_instance = mock.Mock()
        mock_sbd_timeout_checker.return_value = mock_sbd_timeout_checker_instance
        mock_sbd_timeout_checker_instance.check_and_fix = mock.Mock()
        self.sbd_instance_diskbased._show_disk_metadata = mock.Mock()
        self.sbd_instance_diskbased._show_property = mock.Mock()
        self.sbd_instance_diskbased._configure_show(["show"])
        mock_print.assert_has_calls([mock.call(), mock.call()])
        mock_sbd_timeout_checker_instance.check_and_fix.assert_called_once()

    def test_parse_args_invalid_args(self):
        with self.assertRaises(ui_sbd.SBD.SyntaxError) as e:
            self.sbd_instance_diskbased._parse_args(["arg1"])
        self.assertEqual(str(e.exception), "Invalid argument: arg1")

    def test_parse_args_invalid_timeout_value(self):
        with self.assertRaises(ui_sbd.SBD.SyntaxError) as e:
            self.sbd_instance_diskbased._parse_args(["watchdog-timeout=xxx"])
        self.assertEqual(str(e.exception), "Invalid timeout value: xxx")

    @mock.patch('logging.Logger.debug')
    @mock.patch('crmsh.watchdog.Watchdog.get_watchdog_device')
    def test_parse_args(self, mock_get_watchdog_device, mock_logger_debug):
        mock_get_watchdog_device.return_value = "/dev/watchdog0"
        args = self.sbd_instance_diskbased._parse_args(["watchdog-timeout=10", "watchdog-device=/dev/watchdog0"])
        self.assertEqual(args, {"watchdog": 10, "watchdog-device": "/dev/watchdog0"})

    @mock.patch('logging.Logger.warning')
    @mock.patch('logging.Logger.info')
    def test_adjust_timeout_dict(self, mock_logger_info, mock_logger_warning):
        timeout_dict = {"watchdog": 10, "msgwait": 10}
        res = ui_sbd.SBD._adjust_timeout_dict(timeout_dict)
        self.assertEqual(res, timeout_dict)
        mock_logger_warning.assert_called_once_with("It's recommended to set msgwait timeout >= 2*watchdog timeout")
        timeout_dict = {"watchdog": 10}
        res = ui_sbd.SBD._adjust_timeout_dict(timeout_dict)
        self.assertEqual(res, {"watchdog": 10, "msgwait": 20})
        timeout_dict = {"msgwait": 10}
        res = ui_sbd.SBD._adjust_timeout_dict(timeout_dict)
        self.assertEqual(res, {"watchdog": 5, "msgwait": 10})

    @mock.patch('logging.Logger.error')
    @mock.patch('crmsh.cibquery.get_primitives_with_ra')
    @mock.patch('crmsh.cibquery.ResourceAgent')
    @mock.patch('crmsh.xmlutil.text2elem')
    def test_set_crashdump_option_exception(self, mock_text2elem, mock_ResourceAgent, mock_get_primitives_with_ra, mock_logger_error):
        self.sbd_instance_diskbased.cluster_shell.get_stdout_or_raise_error = mock.Mock(return_value="<dummy></dummy>")
        mock_text2elem.return_value = "dummy"
        mock_ra_instance = mock.Mock()
        mock_ResourceAgent.return_value = mock_ra_instance
        mock_get_primitives_with_ra.return_value = []

        with self.assertRaises(utils.TerminateSubCommand):
            self.sbd_instance_diskbased._set_crashdump_option()

        self.sbd_instance_diskbased.cluster_shell.get_stdout_or_raise_error.assert_called_once_with("crm configure show xml")
        mock_logger_error.assert_called_once_with("No fence_sbd resource found")

    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.utils.is_boolean_false')
    @mock.patch('crmsh.cibquery.get_parameter_value')
    @mock.patch('crmsh.cibquery.get_primitives_with_ra')
    @mock.patch('crmsh.cibquery.ResourceAgent')
    @mock.patch('crmsh.xmlutil.text2elem')
    def test_set_crashdump_option(self, mock_text2elem, mock_ResourceAgent, mock_get_primitives_with_ra, mock_get_parameter_value, mock_is_boolean_false, mock_logger_info):
        self.sbd_instance_diskbased.cluster_shell.get_stdout_or_raise_error = mock.Mock(side_effect=["<dummy></dummy>", ""])
        mock_text2elem.return_value = "dummy"
        mock_ra_instance = mock.Mock()
        mock_ResourceAgent.return_value = mock_ra_instance
        mock_get_primitives_with_ra.return_value = ["fence_sbd"]
        mock_get_parameter_value.return_value = None
        mock_is_boolean_false.return_value = True

        self.sbd_instance_diskbased._set_crashdump_option()
        mock_logger_info.assert_called_once_with("Set crashdump option for fence_sbd resource")

    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.utils.is_boolean_false')
    @mock.patch('crmsh.cibquery.get_parameter_value')
    @mock.patch('crmsh.cibquery.get_primitives_with_ra')
    @mock.patch('crmsh.cibquery.ResourceAgent')
    @mock.patch('crmsh.xmlutil.text2elem')
    def test_set_crashdump_option_delete(self, mock_text2elem, mock_ResourceAgent, mock_get_primitives_with_ra, mock_get_parameter_value, mock_is_boolean_false, mock_logger_info):
        self.sbd_instance_diskbased.cluster_shell.get_stdout_or_raise_error = mock.Mock(side_effect=["<dummy></dummy>", ""])
        mock_text2elem.return_value = "dummy"
        mock_ra_instance = mock.Mock()
        mock_ResourceAgent.return_value = mock_ra_instance
        mock_get_primitives_with_ra.return_value = ["fence_sbd"]
        mock_get_parameter_value.return_value = None
        mock_is_boolean_false.return_value = False

        self.sbd_instance_diskbased._set_crashdump_option(delete=True)
        mock_logger_info.assert_called_once_with("Delete crashdump option for fence_sbd resource")

    @mock.patch('logging.Logger.warning')
    def test_check_kdump_service(self, mock_logger_warning):
        self.sbd_instance_diskbased.service_manager.service_is_active = mock.Mock(side_effect=[True, False])
        self.sbd_instance_diskbased._check_kdump_service()
        mock_logger_warning.assert_has_calls([
            mock.call("Kdump service is not active on %s", "node2"),
            mock.call("Kdump service is required for crashdump")
        ])

    def test_should_configure_crashdump_no_set(self):
        self.sbd_instance_diskbased.crashdump_watchdog_timeout_from_config = None
        res = self.sbd_instance_diskbased._should_configure_crashdump(None, None)
        self.assertFalse(res)

    def test_should_configure_crashdump(self):
        self.sbd_instance_diskbased.crashdump_watchdog_timeout_from_config = 1
        res = self.sbd_instance_diskbased._should_configure_crashdump(10, None)
        self.assertTrue(res)

    @mock.patch("crmsh.ui_sbd.SBD.configure_usage", new_callable=mock.PropertyMock)
    @mock.patch('builtins.print')
    @mock.patch('logging.Logger.error')
    def test_do_configure_no_args(self, mock_logger_error, mock_print, mock_configure_usage):
        self.sbd_instance_diskbased._load_attributes = mock.Mock()
        mock_configure_usage.return_value = "usage data"
        res = self.sbd_instance_diskbased.do_configure(mock.Mock())
        self.assertFalse(res)
        mock_logger_error.assert_called_once_with('%s', "No argument")
        mock_print.assert_called_once_with("usage data")

    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.sbd.SBDManager')
    def test_configure_diskbase(self, mock_SBDManager, mock_logger_info):
        parameter_dict = {"watchdog": 12, "watchdog-device": "/dev/watchdog100", "crashdump-watchdog": 12}
        self.sbd_instance_diskbased._should_configure_crashdump = mock.Mock(return_value=True)
        self.sbd_instance_diskbased._check_kdump_service = mock.Mock()
        self.sbd_instance_diskbased._set_crashdump_option = mock.Mock()
        self.sbd_instance_diskbased._set_crashdump_in_sysconfig = mock.Mock(return_value={"SBD_TIMEOUT_ACTION": "flush,crashdump", "SBD_OPTS": "-C 12"})
        mock_SBDManager.return_value.init_and_deploy_sbd = mock.Mock()
        self.sbd_instance_diskbased._configure_diskbase(parameter_dict)
        mock_SBDManager.assert_called_once_with(
            device_list_to_init=self.sbd_instance_diskbased.device_list_from_config,
            timeout_dict={'watchdog': 12, 'allocate': 5, 'loop': 5, 'msgwait': 36},
            update_dict={'SBD_TIMEOUT_ACTION': 'flush,crashdump', 'SBD_OPTS': '-C 12', 'SBD_WATCHDOG_DEV': '/dev/watchdog100'}
        )
        mock_SBDManager.return_value.init_and_deploy_sbd.assert_called_once()
        self.sbd_instance_diskbased._check_kdump_service.assert_called_once()
        self.sbd_instance_diskbased._set_crashdump_option.assert_called_once()

    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.sbd.SBDManager')
    def test_configure_diskbase_no_change(self, mock_SBDManager, mock_logger_info):
        parameter_dict = {"msgwait": 20, "watchdog": 10, "watchdog-device": "/dev/watchdog0"}
        self.sbd_instance_diskbased._should_configure_crashdump = mock.Mock(return_value=False)
        self.sbd_instance_diskbased._configure_diskbase(parameter_dict)
        mock_logger_info.assert_called_once_with("No change in SBD configuration")

    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.sbd.SBDManager')
    def test_configure_diskless(self, mock_SBDManager, mock_logger_info):
        parameter_dict = {"watchdog": 12, "watchdog-device": "/dev/watchdog100", "crashdump-watchdog": 12}
        self.sbd_instance_diskless._should_configure_crashdump = mock.Mock(return_value=True)
        self.sbd_instance_diskless._check_kdump_service = mock.Mock()
        self.sbd_instance_diskless._check_kdump_service = mock.Mock()
        self.sbd_instance_diskless._set_crashdump_in_sysconfig = mock.Mock(return_value={"SBD_TIMEOUT_ACTION": "flush,crashdump", "SBD_OPTS": "-C 12 -Z"})
        mock_SBDManager.return_value.init_and_deploy_sbd = mock.Mock()
        self.sbd_instance_diskless._configure_diskless(parameter_dict)
        mock_SBDManager.assert_called_once_with(
            timeout_dict={'stonith-watchdog': 24},
            update_dict={'SBD_WATCHDOG_TIMEOUT': '12', 'SBD_WATCHDOG_DEV': '/dev/watchdog100', 'SBD_TIMEOUT_ACTION': 'flush,crashdump', 'SBD_OPTS': '-C 12 -Z'},
            diskless_sbd=True
        )
        mock_SBDManager.return_value.init_and_deploy_sbd.assert_called_once()
        self.sbd_instance_diskless._check_kdump_service.assert_called_once()

    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.sbd.SBDManager')
    def test_configure_diskless_no_change(self, mock_SBDManager, mock_logger_info):
        parameter_dict = {"watchdog": 10, "watchdog-device": "/dev/watchdog0"}
        self.sbd_instance_diskless._should_configure_crashdump = mock.Mock(return_value=False)
        self.sbd_instance_diskless._configure_diskless(parameter_dict)
        mock_logger_info.assert_called_once_with("No change in SBD configuration")

    @mock.patch('crmsh.sbd.SBDManager')
    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.sbd.SBDUtils.handle_input_sbd_devices')
    @mock.patch('crmsh.sbd.SBDUtils.verify_sbd_device')
    def test_device_add(self, mock_verify_sbd_device, mock_handle_input_sbd_devices, mock_logger_info, mock_SBDManager):
        mock_handle_input_sbd_devices.return_value = [["/dev/sda2"], ["/dev/sda1"]]
        mock_SBDManager.return_value.init_and_deploy_sbd = mock.Mock()
        self.sbd_instance_diskbased._device_add(["/dev/sda2"])
        mock_verify_sbd_device.assert_called_once_with(["/dev/sda1", "/dev/sda2"])
        mock_handle_input_sbd_devices.assert_called_once_with(["/dev/sda2"], ["/dev/sda1"])
        mock_SBDManager.assert_called_once_with(
            device_list_to_init=["/dev/sda2"],
            update_dict={"SBD_DEVICE": "/dev/sda1;/dev/sda2"},
            timeout_dict=self.sbd_instance_diskbased.device_meta_dict_runtime
        )
        mock_logger_info.assert_called_once_with("Append devices: %s", "/dev/sda2")

    def test_device_remove_dev_not_in_config(self):
        with self.assertRaises(ui_sbd.SBD.SyntaxError) as e:
            self.sbd_instance_diskbased._device_remove(["/dev/sda2"])
        self.assertEqual(str(e.exception), "Device /dev/sda2 is not in config")

    def test_device_remove_last_dev(self):
        with self.assertRaises(ui_sbd.SBD.SyntaxError) as e:
            self.sbd_instance_diskbased._device_remove(["/dev/sda1"])
        self.assertEqual(str(e.exception), "Not allowed to remove all devices")

    @mock.patch('crmsh.bootstrap.restart_cluster')
    @mock.patch('crmsh.sbd.SBDManager.update_sbd_configuration')
    @mock.patch('logging.Logger.info')
    def test_device_remove(self, mock_logger_info, mock_update_sbd_configuration, mock_restart_cluster):
        self.sbd_instance_diskbased.device_list_from_config = ["/dev/sda1", "/dev/sda2"]
        self.sbd_instance_diskbased._device_remove(["/dev/sda1"])
        mock_update_sbd_configuration.assert_called_once_with({"SBD_DEVICE": "/dev/sda2"})
        mock_restart_cluster.assert_called_once()
        mock_logger_info.assert_called_once_with("Remove devices: %s", "/dev/sda1")

    def test_do_device_no_service(self):
        self.sbd_instance_diskbased._load_attributes = mock.Mock()
        self.sbd_instance_diskbased._service_is_active = mock.Mock(return_value=False)
        res = self.sbd_instance_diskbased.do_device(mock.Mock())
        self.assertFalse(res)
        self.sbd_instance_diskbased._load_attributes.assert_called_once()
        self.sbd_instance_diskbased._service_is_active.assert_called_once_with(constants.PCMK_SERVICE)

    @mock.patch('logging.Logger.info')
    @mock.patch('logging.Logger.error')
    @mock.patch('crmsh.sbd.SBDUtils.is_using_disk_based_sbd')
    def test_do_device_no_diskbase(self, mock_is_using_disk_based_sbd, mock_logger_error, mock_logger_info):
        self.sbd_instance_diskbased._load_attributes = mock.Mock()
        mock_is_using_disk_based_sbd.return_value = False
        self.sbd_instance_diskbased._service_is_active = mock.Mock(return_value=True)
        res = self.sbd_instance_diskbased.do_device(mock.Mock())
        self.assertFalse(res)
        mock_logger_error.assert_called_once_with("Only works for disk-based SBD")
        mock_logger_info.assert_called_once_with("Please use 'crm cluster init sbd -s <dev1> [-s <dev2> [-s <dev3>]]' to configure the disk-based SBD first")

    @mock.patch('logging.Logger.error')
    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.sbd.SBDUtils.is_using_disk_based_sbd')
    def test_do_device_no_args(self, mock_is_using_disk_based_sbd, mock_logger_info, mock_logger_error):
        self.sbd_instance_diskbased._load_attributes = mock.Mock()
        mock_is_using_disk_based_sbd.return_value = True
        self.sbd_instance_diskbased._service_is_active = mock.Mock(return_value=True)
        res = self.sbd_instance_diskbased.do_device(mock.Mock())
        self.assertFalse(res)
        mock_logger_error.assert_called_once_with('%s', "No argument")
        mock_logger_info.assert_called_once_with("Usage: crm sbd device <add|remove> <device>...")

    @mock.patch('logging.Logger.error')
    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.sbd.SBDUtils.is_using_disk_based_sbd')
    def test_do_device_invalid_args(self, mock_is_using_disk_based_sbd, mock_logger_info, mock_logger_error):
        self.sbd_instance_diskbased._load_attributes = mock.Mock()
        mock_is_using_disk_based_sbd.return_value = True
        self.sbd_instance_diskbased._service_is_active = mock.Mock(return_value=True)
        res = self.sbd_instance_diskbased.do_device(mock.Mock(), "arg1")
        self.assertFalse(res)
        mock_logger_error.assert_called_once_with('%s', "Invalid argument: arg1")
        mock_logger_info.assert_called_once_with("Usage: crm sbd device <add|remove> <device>...")

    @mock.patch('logging.Logger.error')
    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.sbd.SBDUtils.is_using_disk_based_sbd')
    def test_do_device_no_device(self, mock_is_using_disk_based_sbd, mock_logger_info, mock_logger_error):
        self.sbd_instance_diskbased._load_attributes = mock.Mock()
        mock_is_using_disk_based_sbd.return_value = True
        self.sbd_instance_diskbased._service_is_active = mock.Mock(return_value=True)
        res = self.sbd_instance_diskbased.do_device(mock.Mock(), "add")
        self.assertFalse(res)
        mock_logger_error.assert_called_once_with('%s', "No device specified")
        mock_logger_info.assert_called_once_with("Usage: crm sbd device <add|remove> <device>...")

    @mock.patch('crmsh.utils.check_all_nodes_reachable')
    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.sbd.SBDUtils.is_using_disk_based_sbd')
    def test_do_device_add(self, mock_is_using_disk_based_sbd, mock_logger_info, mock_check_all_nodes_reachable):
        mock_is_using_disk_based_sbd.return_value = True
        self.sbd_instance_diskbased.service_is_active = mock.Mock(return_value=True)
        self.sbd_instance_diskbased._load_attributes = mock.Mock()
        self.sbd_instance_diskbased._device_add = mock.Mock()
        res = self.sbd_instance_diskbased.do_device(mock.Mock(), "add", "/dev/sda2;/dev/sda3")
        self.assertTrue(res)
        self.sbd_instance_diskbased._device_add.assert_called_once_with(["/dev/sda2", "/dev/sda3"])
        mock_logger_info.assert_called_once_with("Configured sbd devices: %s", "/dev/sda1")
        mock_check_all_nodes_reachable.assert_called_once_with("configuring SBD device")

    @mock.patch('crmsh.utils.check_all_nodes_reachable')
    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.sbd.SBDUtils.is_using_disk_based_sbd')
    def test_do_device_remove(self, mock_is_using_disk_based_sbd, mock_logger_info, mock_check_all_nodes_reachable):
        mock_is_using_disk_based_sbd.return_value = True
        self.sbd_instance_diskbased.service_is_active = mock.Mock(return_value=True)
        self.sbd_instance_diskbased._load_attributes = mock.Mock()
        self.sbd_instance_diskbased._device_remove = mock.Mock()
        res = self.sbd_instance_diskbased.do_device(mock.Mock(), "remove", "/dev/sda1")
        self.assertTrue(res)
        self.sbd_instance_diskbased._device_remove.assert_called_once_with(["/dev/sda1"])
        mock_logger_info.assert_called_once_with("Configured sbd devices: %s", "/dev/sda1")
        mock_check_all_nodes_reachable.assert_called_once_with("configuring SBD device")

    @mock.patch('crmsh.sbd.purge_sbd_from_cluster')
    def test_do_purge_no_service(self, mock_purge_sbd_from_cluster):
        self.sbd_instance_diskbased._load_attributes = mock.Mock()
        self.sbd_instance_diskbased._service_is_active = mock.Mock(return_value=False)
        res = self.sbd_instance_diskbased.do_purge(mock.Mock())
        self.assertFalse(res)
        mock_purge_sbd_from_cluster.assert_not_called()

    @mock.patch('crmsh.bootstrap.restart_cluster')
    @mock.patch('crmsh.utils.check_all_nodes_reachable')
    @mock.patch('crmsh.sbd.purge_sbd_from_cluster')
    def test_do_purge(self, mock_purge_sbd_from_cluster, mock_check_all_nodes_reachable, mock_restart_cluster):
        self.sbd_instance_diskbased._load_attributes = mock.Mock()
        self.sbd_instance_diskbased._service_is_active = mock.Mock(return_value=True)
        res = self.sbd_instance_diskbased.do_purge(mock.Mock())
        self.assertTrue(res)
        mock_purge_sbd_from_cluster.assert_called_once()
        self.sbd_instance_diskbased._load_attributes.assert_called_once()
        self.sbd_instance_diskbased._service_is_active.assert_called_once_with(constants.SBD_SERVICE)
        mock_purge_sbd_from_cluster.assert_called_once_with()
        mock_check_all_nodes_reachable.assert_called_once_with("purging SBD")

    @mock.patch('crmsh.xmlutil.CrmMonXmlParser')
    def test_print_sbd_agent_status(self, mock_CrmMonXmlParser):
        mock_CrmMonXmlParser.return_value.is_resource_configured.return_value = True
        mock_CrmMonXmlParser.return_value.get_resource_id_list_via_type.return_value = ["sbd"]
        self.sbd_instance_diskbased.cluster_shell.get_rc_output_without_input.return_value = (0, "active")
        with mock.patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            self.sbd_instance_diskbased._print_sbd_agent_status()
            self.assertEqual(mock_stdout.getvalue(), "# Status of fence_sbd:\nactive\n")

    @mock.patch('builtins.print')
    def test_print_sbd_type_no_sbd(self, mock_print):
        self.sbd_instance_diskbased.service_manager.service_is_active = mock.Mock(return_value=False)
        self.sbd_instance_diskbased._print_sbd_type()
        mock_print.assert_not_called()

    @mock.patch('builtins.print')
    def test_print_sbd_type(self, mock_print):
        self.sbd_instance_diskbased.service_manager.service_is_active = mock.Mock(return_value=True)
        self.sbd_instance_diskbased._print_sbd_type()
        mock_print.assert_has_calls([
            mock.call('# Type of SBD:'),
            mock.call('Disk-based SBD configured'),
            mock.call()
        ])

    @mock.patch('builtins.print')
    def test_print_sbd_type_diskless(self, mock_print):
        self.sbd_instance_diskless.service_manager.service_is_active = mock.Mock(return_value=True)
        self.sbd_instance_diskless._print_sbd_type()
        mock_print.assert_has_calls([
            mock.call('# Type of SBD:'),
            mock.call('Diskless SBD configured'),
            mock.call()
        ])

    @mock.patch('builtins.print')
    def test_print_sbd_status(self, mock_print):
        self.sbd_instance_diskbased.service_manager.service_is_active = mock.Mock(side_effect=[True, False])
        self.sbd_instance_diskbased.service_manager.service_is_enabled = mock.Mock(side_effect=[True, False])
        self.sbd_instance_diskbased.cluster_shell.get_stdout_or_raise_error = mock.Mock(side_effect=["10min", "10sec"])
        self.sbd_instance_diskbased._print_sbd_status()
        mock_print.assert_has_calls([
            mock.call('# Status of sbd.service:'),
            mock.call('Node   |Active  |Enabled |Since'),
            mock.call('node1  |YES     |YES     |active since: 10min'),
            mock.call('node2  |NO      |NO      |disactive since: 10sec'),
            mock.call()
        ])

    @mock.patch('builtins.print')
    def test_print_watchdog_info_no_cluster_nodes(self, mock_print):
        data_node1 = """Discovered 1 watchdog devices:

        [1] /dev/watchdog0
        Identity: iTCO_wdt
        Driver: iTCO_wdt
        """
        data_node2 = """Discovered 1 watchdog devices:

        [1] /dev/watchdog0
        Identity: iTCO_wdt
        Driver: iTCO_wdt
        """
        self.sbd_instance_diskbased.cluster_shell.get_stdout_or_raise_error.side_effect = [data_node1, data_node2]
        self.sbd_instance_diskbased._print_watchdog_info()
        mock_print.assert_has_calls([
            mock.call("# Watchdog info:"),
            mock.call('Node   |Device  |Driver  |Kernel Timeout'),
            mock.call('node1  |N/A     |N/A     |N/A'),
            mock.call('node2  |N/A     |N/A     |N/A'),
            mock.call()
        ])

    @mock.patch('builtins.print')
    def test_print_watchdog_info(self, mock_print):
        data_node1 = """Discovered 1 watchdog devices:

[1] /dev/watchdog0
Identity: Busy: PID 3120 (sbd)
Driver: iTCO_wdt
        """
        data_node2 = """Discovered 1 watchdog devices:

[1] /dev/watchdog0
Identity: Busy: PID 3120 (sbd)
Driver: iTCO_wdt
        """
        self.sbd_instance_diskbased.cluster_shell.get_stdout_or_raise_error.side_effect = [data_node1, "10", data_node2, "10"]
        self.sbd_instance_diskbased._print_watchdog_info()

    def test_do_status(self):
        self.sbd_instance_diskbased._load_attributes = mock.Mock()
        self.sbd_instance_diskbased._print_sbd_type = mock.Mock()
        self.sbd_instance_diskbased._print_sbd_status = mock.Mock()
        self.sbd_instance_diskbased._print_watchdog_info = mock.Mock()
        self.sbd_instance_diskbased._print_sbd_agent_status = mock.Mock()
        self.sbd_instance_diskbased._print_sbd_cgroup_status = mock.Mock()
        mock_context = mock.Mock()
        self.sbd_instance_diskbased.do_status(mock_context)
        self.sbd_instance_diskbased._load_attributes.assert_called_once()
        self.sbd_instance_diskbased._print_sbd_type.assert_called_once()
        self.sbd_instance_diskbased._print_sbd_status.assert_called_once()
        self.sbd_instance_diskbased._print_watchdog_info.assert_called_once()
        self.sbd_instance_diskbased._print_sbd_agent_status.assert_called_once()
        self.sbd_instance_diskbased._print_sbd_cgroup_status.assert_called_once()
