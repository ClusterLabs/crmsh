import io
import unittest
from unittest import mock

from crmsh import ui_sbd
from crmsh import constants
from crmsh import sbd


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
        self.assertEqual(ui_sbd.sbd_configure_completer(["configure", ""]), ["show", "watchdog-timeout=", "watchdog-device="])
        mock_ServiceManager.return_value.service_is_active.assert_has_calls([
            mock.call(constants.PCMK_SERVICE),
            mock.call(constants.SBD_SERVICE)
        ])
        mock_is_using_disk_based_sbd.assert_called_once()
        mock_is_using_diskless_sbd.assert_called_once()


class TestSBD(unittest.TestCase):

    @mock.patch('crmsh.utils.node_reachable_check')
    @mock.patch('crmsh.utils.list_cluster_nodes')
    @mock.patch('crmsh.ui_sbd.sh.cluster_shell')
    @mock.patch('crmsh.ui_sbd.ServiceManager')
    @mock.patch('crmsh.watchdog.Watchdog.get_watchdog_device_from_sbd_config')
    @mock.patch('crmsh.sbd.SBDTimeout.get_sbd_watchdog_timeout')
    @mock.patch('crmsh.sbd.SBDUtils.get_sbd_device_metadata')
    @mock.patch('crmsh.sbd.SBDUtils.get_sbd_device_from_config')
    def setUp(self, mock_get_sbd_device_from_config, mock_get_sbd_device_metadata, mock_get_sbd_watchdog_timeout, mock_get_watchdog_device_from_sbd_config, mock_ServiceManager, mock_cluster_shell, mock_list_cluster_nodes, mock_node_reachable_check):

        mock_list_cluster_nodes.return_value = ["node1", "node2"]
        mock_get_sbd_device_from_config.return_value = ["/dev/sda1"]
        mock_get_watchdog_device_from_sbd_config.return_value = "/dev/watchdog0"
        mock_get_sbd_watchdog_timeout.return_value = 10
        mock_get_sbd_device_metadata.return_value = {"watchdog": 10, "msgwait": 20}
        self.sbd_instance_diskbased = ui_sbd.SBD()
        self.sbd_instance_diskbased._load_attributes()

        mock_get_sbd_device_from_config.return_value = []
        self.sbd_instance_diskless = ui_sbd.SBD()
        self.sbd_instance_diskless._load_attributes()

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
        self.assertFalse(self.sbd_instance_diskbased.service_is_active(constants.PCMK_SERVICE))
        mock_logger_error.assert_called_once_with("%s is not active", constants.PCMK_SERVICE)

    @mock.patch('logging.Logger.error')
    def test_service_is_active_true(self, mock_logger_error):
        self.sbd_instance_diskbased.service_manager.service_is_active = mock.Mock(return_value=True)
        self.assertTrue(self.sbd_instance_diskbased.service_is_active(constants.PCMK_SERVICE))
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
        timeout_usage_str = " ".join([f"[{t}-timeout=<integer>]" for t in ui_sbd.SBD.TIMEOUT_TYPES])
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
        timeout_usage_str = " ".join([f"[{t}-timeout=<integer>]" for t in ui_sbd.SBD.DISKLESS_TIMEOUT_TYPES])
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
        self.sbd_instance_diskbased.service_is_active = mock.Mock(return_value=False)
        res = self.sbd_instance_diskbased.do_configure(mock.Mock())
        self.assertFalse(res)

    @mock.patch('crmsh.sbd.SBDTimeout.get_sbd_systemd_start_timeout')
    @mock.patch('logging.Logger.info')
    @mock.patch('builtins.print')
    def test_show_property(self, mock_print, mock_logger_info, mock_get_sbd_systemd_start_timeout):
        data = """property cib-bootstrap-options: \
        have-watchdog=true \
        dc-version="2.1.7+20240711.239cba384-1.1-2.1.7+20240711.239cba384" \
        cluster-infrastructure=corosync \
        cluster-name=hacluster \
        stonith-enabled=true \
        stonith-timeout=83 \
        priority-fencing-delay=60
        """
        self.sbd_instance_diskbased.cluster_shell.get_stdout_or_raise_error = mock.Mock(return_value=data)
        mock_get_sbd_systemd_start_timeout.return_value = 10
        self.sbd_instance_diskbased._show_property()
        mock_logger_info.assert_has_calls([
            mock.call("crm sbd configure show property"),
            mock.call("%s", sbd.SBDTimeout.SHOW_SBD_START_TIMEOUT_CMD)
        ])
        mock_print.assert_has_calls([
            mock.call("have-watchdog=true"),
            mock.call("stonith-enabled=true"),
            mock.call("stonith-timeout=83"),
            mock.call("priority-fencing-delay=60"),
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

    def test_configure_show_disk_metadata(self):
        self.sbd_instance_diskbased._show_disk_metadata = mock.Mock()
        self.sbd_instance_diskbased._configure_show(["show", "disk_metadata"])
        self.sbd_instance_diskbased._show_disk_metadata.assert_called_once()

    @mock.patch('crmsh.ui_sbd.SBD._show_sysconfig')
    def test_configure_show_sysconfig(self, mock_show_sysconfig):
        self.sbd_instance_diskbased._configure_show(["show", "sysconfig"])
        mock_show_sysconfig.assert_called_once()

    def test_configure_show_property(self):
        self.sbd_instance_diskbased._show_property = mock.Mock()
        self.sbd_instance_diskbased._configure_show(["show", "property"])
        self.sbd_instance_diskbased._show_property.assert_called_once()

    @mock.patch('crmsh.ui_sbd.SBD._show_sysconfig')
    @mock.patch('builtins.print')
    def test_configure_show(self, mock_print, mock_show_sysconfig):
        self.sbd_instance_diskbased._show_disk_metadata = mock.Mock()
        self.sbd_instance_diskbased._show_property = mock.Mock()
        self.sbd_instance_diskbased._configure_show(["show"])
        mock_print.assert_has_calls([mock.call(), mock.call()])

    def test_parse_args_invalid_args(self):
        with self.assertRaises(ui_sbd.SBD.SyntaxError) as e:
            self.sbd_instance_diskbased._parse_args(["arg1"])
        self.assertEqual(str(e.exception), "Invalid argument: arg1")

    def test_parse_args_invalid_timeout_value(self):
        with self.assertRaises(ui_sbd.SBD.SyntaxError) as e:
            self.sbd_instance_diskbased._parse_args(["watchdog-timeout=xxx"])
        self.assertEqual(str(e.exception), "Invalid timeout value: xxx")

    def test_parse_args_unknown_arg(self):
        with self.assertRaises(ui_sbd.SBD.SyntaxError) as e:
            self.sbd_instance_diskbased._parse_args(["name=xin"])
        self.assertEqual(str(e.exception), "Unknown argument: name=xin")

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

    @mock.patch("crmsh.ui_sbd.SBD.configure_usage", new_callable=mock.PropertyMock)
    @mock.patch('builtins.print')
    @mock.patch('logging.Logger.error')
    def test_do_configure_no_args(self, mock_logger_error, mock_print, mock_configure_usage):
        self.sbd_instance_diskbased.service_is_active = mock.Mock(side_effect=[True, True])
        mock_configure_usage.return_value = "usage data"
        res = self.sbd_instance_diskbased.do_configure(mock.Mock())
        self.assertFalse(res)
        mock_logger_error.assert_called_once_with('%s', "No argument")
        mock_print.assert_called_once_with("usage data")

    @mock.patch('crmsh.sbd.SBDManager')
    def test_configure_diskbase(self, mock_SBDManager):
        parameter_dict = {"watchdog": 12, "watchdog-device": "/dev/watchdog100"}
        self.sbd_instance_diskbased._adjust_timeout_dict = mock.Mock(return_value=parameter_dict)
        mock_SBDManager.return_value.init_and_deploy_sbd = mock.Mock()
        self.sbd_instance_diskbased._configure_diskbase(parameter_dict)
        mock_SBDManager.assert_called_once_with(
            device_list_to_init=self.sbd_instance_diskbased.device_list_from_config,
            timeout_dict={"watchdog": 12, "msgwait": 20, "watchdog-device": "/dev/watchdog100"},
            update_dict={
                "SBD_WATCHDOG_DEV": "/dev/watchdog100"
            }
        )
        mock_SBDManager.return_value.init_and_deploy_sbd.assert_called_once()

    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.utils.is_subdict')
    @mock.patch('crmsh.sbd.SBDManager')
    def test_configure_diskbase_no_change(self, mock_SBDManager, mock_is_subdict, mock_logger_info):
        parameter_dict = {"watchdog": 10, "watchdog-device": "/dev/watchdog0"}
        mock_is_subdict.return_value = True
        self.sbd_instance_diskbased._configure_diskbase(parameter_dict)
        mock_logger_info.assert_called_once_with("No change in SBD configuration")

    @mock.patch('crmsh.sbd.SBDManager')
    def test_configure_diskless(self, mock_SBDManager):
        parameter_dict = {"watchdog": 12, "watchdog-device": "/dev/watchdog100"}
        self.sbd_instance_diskless._adjust_timeout_dict = mock.Mock(return_value=parameter_dict)
        mock_SBDManager.return_value.init_and_deploy_sbd = mock.Mock()
        self.sbd_instance_diskless._configure_diskless(parameter_dict)
        mock_SBDManager.assert_called_once_with(
            update_dict={
                "SBD_WATCHDOG_DEV": "/dev/watchdog100",
                "SBD_WATCHDOG_TIMEOUT": "12"
            },
            diskless_sbd=True
        )
        mock_SBDManager.return_value.init_and_deploy_sbd.assert_called_once()

    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.sbd.SBDManager')
    def test_configure_diskless_no_change(self, mock_SBDManager, mock_logger_info):
        parameter_dict = {"watchdog": 10, "watchdog-device": "/dev/watchdog0"}
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

    @mock.patch('crmsh.sbd.SBDManager.restart_cluster_if_possible')
    @mock.patch('crmsh.sbd.SBDManager.update_sbd_configuration')
    @mock.patch('logging.Logger.info')
    def test_device_remove(self, mock_logger_info, mock_update_sbd_configuration, mock_restart_cluster_if_possible):
        self.sbd_instance_diskbased.device_list_from_config = ["/dev/sda1", "/dev/sda2"]
        self.sbd_instance_diskbased._device_remove(["/dev/sda1"])
        mock_update_sbd_configuration.assert_called_once_with({"SBD_DEVICE": "/dev/sda2"})
        mock_restart_cluster_if_possible.assert_called_once()
        mock_logger_info.assert_called_once_with("Remove devices: %s", "/dev/sda1")

    def test_do_device_no_service(self):
        self.sbd_instance_diskbased.service_is_active = mock.Mock(return_value=False)
        res = self.sbd_instance_diskbased.do_device(mock.Mock())
        self.assertFalse(res)

    @mock.patch('logging.Logger.info')
    @mock.patch('logging.Logger.error')
    @mock.patch('crmsh.sbd.SBDUtils.is_using_disk_based_sbd')
    def test_do_device_no_diskbase(self, mock_is_using_disk_based_sbd, mock_logger_error, mock_logger_info):
        mock_is_using_disk_based_sbd.return_value = False
        self.sbd_instance_diskbased.service_is_active = mock.Mock(return_value=True)
        res = self.sbd_instance_diskbased.do_device(mock.Mock())
        self.assertFalse(res)
        mock_logger_error.assert_called_once_with("Only works for disk-based SBD")
        mock_logger_info.assert_called_once_with("Please use 'crm cluster init sbd -s <dev1> [-s <dev2> [-s <dev3>]]' to configure the disk-based SBD first")

    @mock.patch('logging.Logger.error')
    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.sbd.SBDUtils.is_using_disk_based_sbd')
    def test_do_device_no_args(self, mock_is_using_disk_based_sbd, mock_logger_info, mock_logger_error):
        mock_is_using_disk_based_sbd.return_value = True
        self.sbd_instance_diskbased.service_is_active = mock.Mock(return_value=True)
        res = self.sbd_instance_diskbased.do_device(mock.Mock())
        self.assertFalse(res)
        mock_logger_error.assert_called_once_with('%s', "No argument")
        mock_logger_info.assert_called_once_with("Usage: crm sbd device <add|remove> <device>...")

    @mock.patch('logging.Logger.error')
    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.sbd.SBDUtils.is_using_disk_based_sbd')
    def test_do_device_invalid_args(self, mock_is_using_disk_based_sbd, mock_logger_info, mock_logger_error):
        mock_is_using_disk_based_sbd.return_value = True
        self.sbd_instance_diskbased.service_is_active = mock.Mock(return_value=True)
        res = self.sbd_instance_diskbased.do_device(mock.Mock(), "arg1")
        self.assertFalse(res)
        mock_logger_error.assert_called_once_with('%s', "Invalid argument: arg1")
        mock_logger_info.assert_called_once_with("Usage: crm sbd device <add|remove> <device>...")

    @mock.patch('logging.Logger.error')
    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.sbd.SBDUtils.is_using_disk_based_sbd')
    def test_do_device_no_device(self, mock_is_using_disk_based_sbd, mock_logger_info, mock_logger_error):
        mock_is_using_disk_based_sbd.return_value = True
        self.sbd_instance_diskbased.service_is_active = mock.Mock(return_value=True)
        res = self.sbd_instance_diskbased.do_device(mock.Mock(), "add")
        self.assertFalse(res)
        mock_logger_error.assert_called_once_with('%s', "No device specified")
        mock_logger_info.assert_called_once_with("Usage: crm sbd device <add|remove> <device>...")

    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.sbd.SBDUtils.is_using_disk_based_sbd')
    def test_do_device_add(self, mock_is_using_disk_based_sbd, mock_logger_info):
        mock_is_using_disk_based_sbd.return_value = True
        self.sbd_instance_diskbased.service_is_active = mock.Mock(return_value=True)
        self.sbd_instance_diskbased._device_add = mock.Mock()
        res = self.sbd_instance_diskbased.do_device(mock.Mock(), "add", "/dev/sda2;/dev/sda3")
        self.assertTrue(res)
        self.sbd_instance_diskbased._device_add.assert_called_once_with(["/dev/sda2", "/dev/sda3"])
        mock_logger_info.assert_called_once_with("Configured sbd devices: %s", "/dev/sda1")

    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.sbd.SBDUtils.is_using_disk_based_sbd')
    def test_do_device_remove(self, mock_is_using_disk_based_sbd, mock_logger_info):
        mock_is_using_disk_based_sbd.return_value = True
        self.sbd_instance_diskbased.service_is_active = mock.Mock(return_value=True)
        self.sbd_instance_diskbased._device_remove = mock.Mock()
        res = self.sbd_instance_diskbased.do_device(mock.Mock(), "remove", "/dev/sda1")
        self.assertTrue(res)
        self.sbd_instance_diskbased._device_remove.assert_called_once_with(["/dev/sda1"])
        mock_logger_info.assert_called_once_with("Configured sbd devices: %s", "/dev/sda1")

    @mock.patch('crmsh.sbd.purge_sbd_from_cluster')
    def test_do_purge_no_service(self, mock_purge_sbd_from_cluster):
        self.sbd_instance_diskbased.service_is_active = mock.Mock(return_value=False)
        res = self.sbd_instance_diskbased.do_purge(mock.Mock())
        self.assertFalse(res)
        mock_purge_sbd_from_cluster.assert_not_called()

    @mock.patch('crmsh.sbd.SBDManager.restart_cluster_if_possible')
    @mock.patch('crmsh.sbd.purge_sbd_from_cluster')
    def test_do_purge(self, mock_purge_sbd_from_cluster, mock_restart_cluster_if_possible):
        self.sbd_instance_diskbased.service_is_active = mock.Mock(return_value=True)
        res = self.sbd_instance_diskbased.do_purge(mock.Mock())
        self.assertTrue(res)
        mock_purge_sbd_from_cluster.assert_called_once()
        mock_restart_cluster_if_possible.assert_called_once()

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
        self.sbd_instance_diskbased._print_sbd_type = mock.Mock()
        self.sbd_instance_diskbased._print_sbd_status = mock.Mock()
        self.sbd_instance_diskbased._print_watchdog_info = mock.Mock()
        self.sbd_instance_diskbased._print_sbd_agent_status = mock.Mock()
        self.sbd_instance_diskbased._print_sbd_cgroup_status = mock.Mock()
        mock_context = mock.Mock()
        self.sbd_instance_diskbased.do_status(mock_context)
