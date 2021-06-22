import os
import unittest

try:
    from unittest import mock
except ImportError:
    import mock

from crmsh import bootstrap
from crmsh import sbd


class TestSBDManager(unittest.TestCase):
    """
    Unitary tests for crmsh.sbd.SBDManager
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
        self.sbd_inst = sbd.SBDManager(mock.Mock(sbd_devices=["/dev/sdb1", "/dev/sdc1"], diskless_sbd=False))
        self.sbd_inst_devices_gt_3 = sbd.SBDManager(mock.Mock(sbd_devices=["/dev/sdb1", "/dev/sdc1", "/dev/sdd1", "/dev/sde1"]))
        self.sbd_inst_interactive = sbd.SBDManager(mock.Mock(sbd_devices=[], diskless_sbd=False))
        self.sbd_inst_diskless = sbd.SBDManager(mock.Mock(sbd_devices=[], diskless_sbd=True))

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    @mock.patch('crmsh.bootstrap.warn')
    def test_get_sbd_device_interactive_yes_to_all(self, mock_warn):
        self.sbd_inst._context = mock.Mock(yes_to_all=True)
        self.sbd_inst._get_sbd_device_interactive()
        mock_warn.assert_called_once_with(sbd.SBDManager.SBD_WARNING)

    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('crmsh.bootstrap.status')
    @mock.patch('crmsh.bootstrap.warn')
    def test_get_sbd_device_interactive_not_confirm(self, mock_warn, mock_status, mock_confirm):
        self.sbd_inst._context.yes_to_all = False
        mock_confirm.return_value = False
        self.sbd_inst._get_sbd_device_interactive()
        mock_status.assert_called_once_with(sbd.SBDManager.SBD_STATUS_DESCRIPTION)
        mock_warn.assert_called_once_with("Not configuring SBD - STONITH will be disabled.")

    @mock.patch('crmsh.sbd.SBDManager._get_sbd_device_from_config')
    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('crmsh.bootstrap.status')
    def test_get_sbd_device_interactive_already_configured(self, mock_status, mock_confirm, mock_from_config):
        self.sbd_inst._context = mock.Mock(yes_to_all=False)
        mock_confirm.side_effect = [True, False]
        mock_from_config.return_value = ["/dev/sda1"]

        res = self.sbd_inst._get_sbd_device_interactive()
        self.assertEqual(res, ["/dev/sda1"])

        mock_status.assert_called_once_with(sbd.SBDManager.SBD_STATUS_DESCRIPTION)
        mock_confirm.assert_has_calls([
            mock.call("Do you wish to use SBD?"),
            mock.call("SBD is already configured to use /dev/sda1 - overwrite?")
            ])
        mock_status.assert_called_once_with(sbd.SBDManager.SBD_STATUS_DESCRIPTION)
        mock_from_config.assert_called_once_with()

    @mock.patch('crmsh.bootstrap.prompt_for_string')
    @mock.patch('crmsh.sbd.SBDManager._get_sbd_device_from_config')
    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('crmsh.bootstrap.status')
    def test_get_sbd_device_interactive_diskless(self, mock_status, mock_confirm, mock_from_config, mock_prompt):
        self.sbd_inst._context = mock.Mock(yes_to_all=False)
        mock_confirm.return_value = True
        mock_from_config.return_value = None
        mock_prompt.return_value = "none"

        self.sbd_inst._get_sbd_device_interactive()

        mock_status.assert_called_once_with(sbd.SBDManager.SBD_STATUS_DESCRIPTION)
        mock_from_config.assert_called_once_with()
        mock_prompt.assert_called_once_with('Path to storage device (e.g. /dev/disk/by-id/...), or "none" for diskless sbd, use ";" as separator for multi path', 'none|\\/.*')

    @mock.patch('crmsh.bootstrap.prompt_for_string')
    @mock.patch('crmsh.sbd.SBDManager._get_sbd_device_from_config')
    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('crmsh.bootstrap.status')
    def test_get_sbd_device_interactive_null_and_diskless(self, mock_status, mock_confirm, mock_from_config, mock_prompt):
        self.sbd_inst._context = mock.Mock(yes_to_all=False)
        mock_confirm.return_value = True
        mock_from_config.return_value = None
        mock_prompt.side_effect = [None, "none"]

        self.sbd_inst._get_sbd_device_interactive()

        mock_status.assert_called_once_with(sbd.SBDManager.SBD_STATUS_DESCRIPTION)
        mock_confirm.assert_called_once_with("Do you wish to use SBD?")
        mock_from_config.assert_called_once_with()
        mock_prompt.assert_has_calls([
            mock.call('Path to storage device (e.g. /dev/disk/by-id/...), or "none" for diskless sbd, use ";" as separator for multi path', 'none|\\/.*') for x in range(2)
            ])

    @mock.patch('crmsh.utils.re_split_string')
    @mock.patch('crmsh.bootstrap.warn')
    @mock.patch('crmsh.bootstrap.print_error_msg')
    @mock.patch('crmsh.sbd.SBDManager._verify_sbd_device')
    @mock.patch('crmsh.bootstrap.prompt_for_string')
    @mock.patch('crmsh.sbd.SBDManager._get_sbd_device_from_config')
    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('crmsh.bootstrap.status')
    def test_get_sbd_device_interactive(self, mock_status, mock_confirm, mock_from_config, mock_prompt, mock_verify, mock_error_msg, mock_warn, mock_split):
        self.sbd_inst._context = mock.Mock(yes_to_all=False)
        mock_confirm.side_effect = [True, False, True]
        mock_from_config.return_value = None
        mock_prompt.side_effect = ["/dev/test1", "/dev/sda1", "/dev/sdb1"]
        mock_split.side_effect = [["/dev/test1"], ["/dev/sda1"], ["/dev/sdb1"]]
        mock_verify.side_effect = [ValueError("/dev/test1 error"), None, None]

        res = self.sbd_inst._get_sbd_device_interactive()
        self.assertEqual(res, ["/dev/sdb1"])

        mock_status.assert_called_once_with(sbd.SBDManager.SBD_STATUS_DESCRIPTION)
        mock_confirm.assert_has_calls([
            mock.call("Do you wish to use SBD?"),
            mock.call("Are you sure you wish to use this device?")
            ])
        mock_from_config.assert_called_once_with()
        mock_error_msg.assert_called_once_with("/dev/test1 error")
        mock_warn.assert_has_calls([
            mock.call("All data on /dev/sda1 will be destroyed!"),
            mock.call("All data on /dev/sdb1 will be destroyed!")
            ])
        mock_prompt.assert_has_calls([
            mock.call('Path to storage device (e.g. /dev/disk/by-id/...), or "none" for diskless sbd, use ";" as separator for multi path', 'none|\\/.*') for x in range(3)
            ])
        mock_split.assert_has_calls([
            mock.call(sbd.SBDManager.PARSE_RE, "/dev/test1"),
            mock.call(sbd.SBDManager.PARSE_RE, "/dev/sda1"),
            mock.call(sbd.SBDManager.PARSE_RE, "/dev/sdb1"),
            ])

    def test_verify_sbd_device_gt_3(self):
        assert self.sbd_inst_devices_gt_3.sbd_devices_input == ["/dev/sdb1", "/dev/sdc1", "/dev/sdd1", "/dev/sde1"]
        dev_list = self.sbd_inst_devices_gt_3.sbd_devices_input
        with self.assertRaises(ValueError) as err:
            self.sbd_inst_devices_gt_3._verify_sbd_device(dev_list)
        self.assertEqual("Maximum number of SBD device is 3", str(err.exception))

    @mock.patch('crmsh.sbd.SBDManager._compare_device_uuid')
    @mock.patch('crmsh.utils.is_block_device')
    def test_verify_sbd_device_not_block(self, mock_block_device, mock_compare):
        assert self.sbd_inst.sbd_devices_input == ["/dev/sdb1", "/dev/sdc1"]
        dev_list = self.sbd_inst.sbd_devices_input
        mock_block_device.side_effect = [True, False]

        with self.assertRaises(ValueError) as err:
            self.sbd_inst._verify_sbd_device(dev_list)
        self.assertEqual("/dev/sdc1 doesn't look like a block device", str(err.exception))

        mock_block_device.assert_has_calls([mock.call("/dev/sdb1"), mock.call("/dev/sdc1")])
        mock_compare.assert_called_once_with("/dev/sdb1", [])

    @mock.patch('crmsh.sbd.SBDManager._verify_sbd_device')
    @mock.patch('crmsh.utils.parse_append_action_argument')
    def test_get_sbd_device_from_option(self, mock_parse, mock_verify):
        mock_parse.return_value = ["/dev/sdb1", "/dev/sdc1"]
        self.sbd_inst._get_sbd_device()
        mock_parse.assert_called_once_with(mock_parse.return_value)
        mock_verify.assert_called_once_with(mock_parse.return_value)

    @mock.patch('crmsh.sbd.SBDManager._get_sbd_device_interactive')
    def test_get_sbd_device_from_interactive(self, mock_interactive):
        mock_interactive.return_value = ["/dev/sdb1", "/dev/sdc1"]
        self.sbd_inst_interactive._get_sbd_device()
        mock_interactive.assert_called_once_with()

    def test_get_sbd_device_diskless(self):
        self.sbd_inst_diskless._get_sbd_device()

    def test_initialize_sbd_return(self):
        self.sbd_inst_diskless._initialize_sbd()

    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.bootstrap.invoke')
    def test_initialize_sbd(self, mock_invoke, mock_error):
        self.sbd_inst._sbd_devices = ["/dev/sdb1", "/dev/sdc1"]
        mock_invoke.side_effect = [(True, None, None), (False, None, "error")]
        mock_error.side_effect = ValueError

        with self.assertRaises(ValueError):
            self.sbd_inst._initialize_sbd()

        mock_invoke.assert_has_calls([
            mock.call("sbd -d /dev/sdb1 create"),
            mock.call("sbd -d /dev/sdc1 create")
            ])
        mock_error.assert_called_once_with("Failed to initialize SBD device /dev/sdc1: error")

    @mock.patch('crmsh.utils.detect_virt')
    @mock.patch('crmsh.bootstrap.csync2_update')
    @mock.patch('crmsh.utils.sysconfig_set')
    @mock.patch('crmsh.sbd.SBDManager._determine_sbd_watchdog_timeout')
    @mock.patch('shutil.copyfile')
    def test_update_configuration(self, mock_copy, mock_determine, mock_sysconfig, mock_update, mock_detect):
        self.sbd_inst._sbd_devices = ["/dev/sdb1", "/dev/sdc1"]
        self.sbd_inst._watchdog_inst = mock.Mock(watchdog_device_name="/dev/watchdog")
        mock_detect.return_value = True

        self.sbd_inst._sbd_watchdog_timeout = 30
        self.sbd_inst._update_configuration()

        mock_copy.assert_called_once_with("/usr/share/fillup-templates/sysconfig.sbd", "/etc/sysconfig/sbd")
        mock_sysconfig.assert_called_once_with("/etc/sysconfig/sbd", SBD_PACEMAKER='yes', SBD_STARTMODE='always', SBD_DELAY_START='yes', SBD_WATCHDOG_DEV='/dev/watchdog', SBD_DEVICE='/dev/sdb1;/dev/sdc1', SBD_WATCHDOG_TIMEOUT="30")
        mock_update.assert_called_once_with("/etc/sysconfig/sbd")

    @mock.patch('crmsh.bootstrap.utils.parse_sysconfig')
    def test_get_sbd_device_from_config_none(self, mock_parse):
        mock_parse_inst = mock.Mock()
        mock_parse.return_value = mock_parse_inst
        mock_parse_inst.get.return_value = None

        res = self.sbd_inst._get_sbd_device_from_config()
        assert res is None

        mock_parse.assert_called_once_with("/etc/sysconfig/sbd")
        mock_parse_inst.get.assert_called_once_with("SBD_DEVICE")

    @mock.patch('crmsh.utils.re_split_string')
    @mock.patch('crmsh.bootstrap.utils.parse_sysconfig')
    def test_get_sbd_device_from_config(self, mock_parse, mock_split):
        mock_parse_inst = mock.Mock()
        mock_parse.return_value = mock_parse_inst
        mock_parse_inst.get.return_value = "/dev/sdb1;/dev/sdc1"
        mock_split.return_value = ["/dev/sdb1", "/dev/sdc1"]

        res = self.sbd_inst._get_sbd_device_from_config()
        assert res == ["/dev/sdb1", "/dev/sdc1"]

        mock_parse.assert_called_once_with("/etc/sysconfig/sbd")
        mock_parse_inst.get.assert_called_once_with("SBD_DEVICE")
        mock_split.assert_called_once_with(sbd.SBDManager.PARSE_RE, "/dev/sdb1;/dev/sdc1")

    @mock.patch('crmsh.bootstrap.warn')
    @mock.patch('crmsh.utils.get_quorum_votes_dict')
    def test_warn_diskless_sbd_diskless(self, mock_vote, mock_warn):
        self.sbd_inst_diskless._context = mock.Mock(cluster_is_running=False)
        self.sbd_inst_diskless._warn_diskless_sbd()
        mock_vote.assert_not_called()
        mock_warn.assert_called_once_with(sbd.SBDManager.DISKLESS_SBD_WARNING)

    @mock.patch('crmsh.bootstrap.warn')
    @mock.patch('crmsh.utils.get_quorum_votes_dict')
    def test_warn_diskless_sbd_peer(self, mock_vote, mock_warn):
        mock_vote.return_value = {'Expected': '1'}
        self.sbd_inst_diskless._warn_diskless_sbd("node2")
        mock_vote.assert_called_once_with("node2")
        mock_warn.assert_called_once_with(sbd.SBDManager.DISKLESS_SBD_WARNING)

    @mock.patch('crmsh.utils.package_is_installed')
    def test_sbd_init_not_installed(self, mock_package):
        mock_package.return_value = False
        self.sbd_inst.sbd_init()
        mock_package.assert_called_once_with("sbd")

    @mock.patch('crmsh.bootstrap.invoke')
    @mock.patch('crmsh.sbd.SBDManager._update_configuration')
    @mock.patch('crmsh.sbd.SBDManager._initialize_sbd')
    @mock.patch('crmsh.bootstrap.status_long')
    @mock.patch('crmsh.sbd.SBDManager._get_sbd_device')
    @mock.patch('crmsh.watchdog.Watchdog')
    @mock.patch('crmsh.utils.package_is_installed')
    def test_sbd_init_return(self, mock_package, mock_watchdog, mock_get_device, mock_status, mock_initialize, mock_update, mock_invoke):
        mock_package.return_value = True
        self.sbd_inst._sbd_devices = None
        self.sbd_inst.diskless_sbd = False
        self.sbd_inst._context = mock.Mock(watchdog=None)
        mock_watchdog_inst = mock.Mock()
        mock_watchdog.return_value = mock_watchdog_inst
        mock_watchdog_inst.init_watchdog = mock.Mock()

        self.sbd_inst.sbd_init()

        mock_package.assert_called_once_with("sbd")
        mock_get_device.assert_called_once_with()
        mock_status.assert_not_called()
        mock_initialize.assert_not_called()
        mock_update.assert_not_called()
        mock_watchdog.assert_called_once_with(_input=None)
        mock_watchdog_inst.init_watchdog.assert_called_once_with()
        mock_invoke.assert_called_once_with("systemctl disable sbd.service")
 
    @mock.patch('crmsh.sbd.SBDManager._determine_stonith_watchdog_timeout')
    @mock.patch('crmsh.sbd.SBDManager._enable_sbd_service')
    @mock.patch('crmsh.sbd.SBDManager._warn_diskless_sbd')
    @mock.patch('crmsh.sbd.SBDManager._update_configuration')
    @mock.patch('crmsh.sbd.SBDManager._initialize_sbd')
    @mock.patch('crmsh.bootstrap.status_long')
    @mock.patch('crmsh.sbd.SBDManager._get_sbd_device')
    @mock.patch('crmsh.watchdog.Watchdog')
    @mock.patch('crmsh.utils.package_is_installed')
    def test_sbd_init(self, mock_package, mock_watchdog, mock_get_device, mock_status, mock_initialize, mock_update, mock_warn, mock_enable_sbd, mock_determine):
        mock_package.return_value = True
        self.sbd_inst_diskless._context = mock.Mock(watchdog=None)
        mock_watchdog_inst = mock.Mock()
        mock_watchdog.return_value = mock_watchdog_inst
        mock_watchdog_inst.init_watchdog = mock.Mock()
        self.sbd_inst_diskless.sbd_init()

        mock_package.assert_called_once_with("sbd")
        mock_get_device.assert_called_once_with()
        mock_status.assert_called_once_with("Initializing diskless SBD...")
        mock_initialize.assert_called_once_with()
        mock_update.assert_called_once_with()
        mock_watchdog.assert_called_once_with(_input=None)
        mock_watchdog_inst.init_watchdog.assert_called_once_with()
        mock_warn.assert_called_once_with()
        mock_enable_sbd.assert_called_once_with()
        mock_determine.assert_called_once_with()

    @mock.patch('crmsh.sbd.SBDManager.configure_sbd_resource')
    @mock.patch('crmsh.bootstrap.wait_for_cluster')
    @mock.patch('crmsh.utils.cluster_run_cmd')
    @mock.patch('crmsh.bootstrap.status')
    @mock.patch('crmsh.utils.has_resource_running')
    def test_restart_cluster_on_needed_no_ra_running(self, mock_ra_running, mock_status, mock_cluster_run, mock_wait, mock_config_sbd_ra):
        mock_ra_running.return_value = False
        self.sbd_inst._restart_cluster_and_configure_sbd_ra()
        mock_status.assert_called_once_with("Restarting cluster service")
        mock_cluster_run.assert_called_once_with("crm cluster restart")
        mock_wait.assert_called_once_with()
        mock_config_sbd_ra.assert_called_once_with()

    @mock.patch('crmsh.bootstrap.warn')
    @mock.patch('crmsh.utils.has_resource_running')
    def test_restart_cluster_on_needed_diskless(self, mock_ra_running, mock_warn):
        mock_ra_running.return_value = True
        self.sbd_inst_diskless._restart_cluster_and_configure_sbd_ra()
        mock_warn.assert_has_calls([
            mock.call("To start sbd.service, need to restart cluster service manually on each node"),
            mock.call("Then run \"crm configure property stonith-enabled=true stonith-watchdog-timeout=10s stonith-timeout=60s\" on any node")
            ])

    @mock.patch('crmsh.sbd.SBDManager.configure_sbd_resource')
    @mock.patch('crmsh.bootstrap.warn')
    @mock.patch('crmsh.utils.has_resource_running')
    def test_restart_cluster_on_needed(self, mock_ra_running, mock_warn, mock_config_sbd_ra):
        mock_ra_running.return_value = True
        self.sbd_inst._restart_cluster_and_configure_sbd_ra()
        mock_warn.assert_has_calls([
            mock.call("To start sbd.service, need to restart cluster service manually on each node"),
            ])
        mock_config_sbd_ra.assert_called_once_with()

    @mock.patch('crmsh.bootstrap.invoke')
    def test_enable_sbd_service_init(self, mock_invoke):
        self.sbd_inst._context = mock.Mock(cluster_is_running=False)
        self.sbd_inst._enable_sbd_service()
        mock_invoke.assert_called_once_with("systemctl enable sbd.service")

    @mock.patch('crmsh.sbd.SBDManager._restart_cluster_and_configure_sbd_ra')
    @mock.patch('crmsh.utils.cluster_run_cmd')
    def test_enable_sbd_service_restart(self, mock_cluster_run, mock_restart):
        self.sbd_inst._context = mock.Mock(cluster_is_running=True)
        self.sbd_inst._enable_sbd_service()
        mock_cluster_run.assert_has_calls([
            mock.call("systemctl enable sbd.service"),
            ])
        mock_restart.assert_called_once_with()

    @mock.patch('crmsh.bootstrap.warn')
    @mock.patch('crmsh.sbd.SBDManager.configure_sbd_resource')
    @mock.patch('crmsh.utils.has_resource_running')
    @mock.patch('crmsh.utils.cluster_run_cmd')
    def test_enable_sbd_service(self, mock_cluster_run, mock_ra_running, mock_config_sbd_ra, mock_warn):
        self.sbd_inst._context = mock.Mock(cluster_is_running=True)
        mock_ra_running.return_value = True

        self.sbd_inst._enable_sbd_service()

        mock_cluster_run.assert_has_calls([
            mock.call("systemctl enable sbd.service"),
            ])
        mock_ra_running.assert_called_once_with()
        mock_config_sbd_ra.assert_called_once_with()
        mock_warn.assert_called_once_with("To start sbd.service, need to restart cluster service manually on each node")

    @mock.patch('crmsh.utils.package_is_installed')
    def test_configure_sbd_resource_not_installed(self, mock_package):
        mock_package.return_value = False
        self.sbd_inst.configure_sbd_resource()
        mock_package.assert_called_once_with("sbd")

    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.bootstrap.invokerc')
    @mock.patch('crmsh.sbd.SBDManager._get_sbd_device_from_config')
    @mock.patch('crmsh.utils.has_resource_configured')
    @mock.patch('crmsh.utils.service_is_enabled')
    @mock.patch('crmsh.utils.package_is_installed')
    def test_configure_sbd_resource_error_primitive(self, mock_package, mock_enabled, mock_ra_configured, mock_get_device, mock_invoke, mock_error):
        mock_package.return_value = True
        mock_enabled.return_value = True
        mock_ra_configured.return_value = False
        mock_get_device.return_value = ["/dev/sdb1"]
        mock_invoke.return_value = False
        mock_error.side_effect = ValueError

        with self.assertRaises(ValueError):
            self.sbd_inst.configure_sbd_resource()

        mock_package.assert_called_once_with("sbd")
        mock_enabled.assert_called_once_with("sbd.service")
        mock_ra_configured.assert_called_once_with("stonith:external/sbd")
        mock_get_device.assert_called_once_with()
        mock_invoke.assert_called_once_with("crm configure primitive stonith-sbd stonith:external/sbd pcmk_delay_max=30s")
        mock_error.assert_called_once_with("Can't create stonith-sbd primitive")

    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.bootstrap.invokerc')
    @mock.patch('crmsh.sbd.SBDManager._get_sbd_device_from_config')
    @mock.patch('crmsh.utils.has_resource_configured')
    @mock.patch('crmsh.utils.service_is_enabled')
    @mock.patch('crmsh.utils.package_is_installed')
    def test_configure_sbd_resource_error_property(self, mock_package, mock_enabled, mock_ra_configured, mock_get_device, mock_invoke, mock_error):
        mock_package.return_value = True
        mock_enabled.return_value = True
        mock_ra_configured.return_value = False
        mock_get_device.return_value = ["/dev/sdb1"]
        mock_invoke.side_effect = [True, False]
        mock_error.side_effect = ValueError

        with self.assertRaises(ValueError):
            self.sbd_inst.configure_sbd_resource()

        mock_package.assert_called_once_with("sbd")
        mock_enabled.assert_called_once_with("sbd.service")
        mock_ra_configured.assert_called_once_with("stonith:external/sbd")
        mock_get_device.assert_called_once_with()
        mock_invoke.assert_has_calls([
            mock.call("crm configure primitive stonith-sbd stonith:external/sbd pcmk_delay_max=30s"),
            mock.call("crm configure property stonith-enabled=true")
            ])
        mock_error.assert_called_once_with("Can't enable STONITH for SBD")

    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.bootstrap.invokerc')
    @mock.patch('crmsh.sbd.SBDManager._get_sbd_device_from_config')
    @mock.patch('crmsh.utils.has_resource_configured')
    @mock.patch('crmsh.utils.service_is_enabled')
    @mock.patch('crmsh.utils.package_is_installed')
    def test_configure_sbd_resource_diskless(self, mock_package, mock_enabled, mock_ra_configured, mock_get_device, mock_invoke, mock_error):
        mock_package.return_value = True
        mock_enabled.return_value = True
        mock_ra_configured.return_value = False
        mock_get_device.return_value = None
        mock_invoke.return_value = False
        mock_error.side_effect = ValueError

        with self.assertRaises(ValueError):
            self.sbd_inst_diskless.configure_sbd_resource()

        mock_package.assert_called_once_with("sbd")
        mock_enabled.assert_called_once_with("sbd.service")
        mock_get_device.assert_called_once_with()
        mock_invoke.assert_called_once_with("crm configure property stonith-enabled=true stonith-watchdog-timeout=10s stonith-timeout=60s")
        mock_error.assert_called_once_with("Can't enable STONITH for diskless SBD")
        mock_ra_configured.assert_called_once_with("stonith:external/sbd")

    @mock.patch('crmsh.utils.package_is_installed')
    def test_join_sbd_config_not_installed(self, mock_package):
        mock_package.return_value = False
        self.sbd_inst.join_sbd("node1")
        mock_package.assert_called_once_with("sbd")

    @mock.patch('crmsh.bootstrap.invoke')
    @mock.patch('os.path.exists')
    @mock.patch('crmsh.utils.package_is_installed')
    def test_join_sbd_config_not_exist(self, mock_package, mock_exists, mock_invoke):
        mock_package.return_value = True
        mock_exists.return_value = False
        self.sbd_inst.join_sbd("node1")
        mock_package.assert_called_once_with("sbd")
        mock_exists.assert_called_once_with("/etc/sysconfig/sbd")
        mock_invoke.assert_called_once_with("systemctl disable sbd.service")

    @mock.patch('crmsh.bootstrap.invoke')
    @mock.patch('crmsh.utils.service_is_enabled')
    @mock.patch('os.path.exists')
    @mock.patch('crmsh.utils.package_is_installed')
    def test_join_sbd_config_disabled(self, mock_package, mock_exists, mock_enabled, mock_invoke):
        mock_package.return_value = True
        mock_exists.return_value = True
        mock_enabled.return_value = False

        self.sbd_inst.join_sbd("node1")

        mock_package.assert_called_once_with("sbd")
        mock_exists.assert_called_once_with("/etc/sysconfig/sbd")
        mock_invoke.assert_called_once_with("systemctl disable sbd.service")
        mock_enabled.assert_called_once_with("sbd.service", "node1")

    @mock.patch('crmsh.bootstrap.status')
    @mock.patch('crmsh.sbd.SBDManager._verify_sbd_device')
    @mock.patch('crmsh.sbd.SBDManager._get_sbd_device_from_config')
    @mock.patch('crmsh.watchdog.Watchdog')
    @mock.patch('crmsh.bootstrap.invoke')
    @mock.patch('crmsh.utils.service_is_enabled')
    @mock.patch('os.path.exists')
    @mock.patch('crmsh.utils.package_is_installed')
    def test_join_sbd(self, mock_package, mock_exists, mock_enabled, mock_invoke, mock_watchdog, mock_get_device, mock_verify, mock_status):
        mock_package.return_value = True
        mock_exists.return_value = True
        mock_enabled.return_value = True
        mock_get_device.return_value = ["/dev/sdb1"]
        mock_watchdog_inst = mock.Mock()
        mock_watchdog.return_value = mock_watchdog_inst
        mock_watchdog_inst.join_watchdog = mock.Mock()

        self.sbd_inst.join_sbd("node1")

        mock_package.assert_called_once_with("sbd")
        mock_exists.assert_called_once_with("/etc/sysconfig/sbd")
        mock_invoke.assert_called_once_with("systemctl enable sbd.service")
        mock_get_device.assert_called_once_with()
        mock_verify.assert_called_once_with(["/dev/sdb1"], ["node1"])
        mock_enabled.assert_called_once_with("sbd.service", "node1")
        mock_status.assert_called_once_with("Got SBD configuration")
        mock_watchdog.assert_called_once_with(peer_host="node1")
        mock_watchdog_inst.join_watchdog.assert_called_once_with()

    @mock.patch('crmsh.bootstrap.status')
    @mock.patch('crmsh.sbd.SBDManager._warn_diskless_sbd')
    @mock.patch('crmsh.sbd.SBDManager._get_sbd_device_from_config')
    @mock.patch('crmsh.watchdog.Watchdog')
    @mock.patch('crmsh.bootstrap.invoke')
    @mock.patch('crmsh.utils.service_is_enabled')
    @mock.patch('os.path.exists')
    @mock.patch('crmsh.utils.package_is_installed')
    def test_join_sbd_diskless(self, mock_package, mock_exists, mock_enabled, mock_invoke, mock_watchdog, mock_get_device, mock_warn, mock_status):
        mock_package.return_value = True
        mock_exists.return_value = True
        mock_enabled.return_value = True
        mock_get_device.return_value = []
        mock_watchdog_inst = mock.Mock()
        mock_watchdog.return_value = mock_watchdog_inst
        mock_watchdog_inst.join_watchdog = mock.Mock()

        self.sbd_inst.join_sbd("node1")

        mock_package.assert_called_once_with("sbd")
        mock_exists.assert_called_once_with("/etc/sysconfig/sbd")
        mock_invoke.assert_called_once_with("systemctl enable sbd.service")
        mock_get_device.assert_called_once_with()
        mock_warn.assert_called_once_with("node1")
        mock_enabled.assert_called_once_with("sbd.service", "node1")
        mock_status.assert_called_once_with("Got diskless SBD configuration")
        mock_watchdog.assert_called_once_with(peer_host="node1")
        mock_watchdog_inst.join_watchdog.assert_called_once_with()

    @mock.patch('crmsh.sbd.SBDManager._get_sbd_device_from_config')
    def test_verify_sbd_device_classmethod_exception(self, mock_get_config):
        mock_get_config.return_value = []
        with self.assertRaises(ValueError) as err:
            sbd.SBDManager.verify_sbd_device()
        self.assertEqual("No sbd device configured", str(err.exception))
        mock_get_config.assert_called_once_with()

    @mock.patch('crmsh.sbd.SBDManager._verify_sbd_device')
    @mock.patch('crmsh.utils.list_cluster_nodes_except_me')
    @mock.patch('crmsh.sbd.SBDManager._get_sbd_device_from_config')
    def test_verify_sbd_device_classmethod(self, mock_get_config, mock_list_nodes, mock_verify):
        mock_get_config.return_value = ["/dev/sda1"]
        mock_list_nodes.return_value = ["node1"]
        sbd.SBDManager.verify_sbd_device()
        mock_get_config.assert_called_once_with()
        mock_verify.assert_called_once_with(["/dev/sda1"], ["node1"])

    @mock.patch('crmsh.sbd.SBDManager._get_device_uuid')
    def test_compare_device_uuid_return(self, mock_get_uuid):
        self.sbd_inst._compare_device_uuid("/dev/sdb1", None)
        mock_get_uuid.assert_not_called()

    @mock.patch('crmsh.sbd.SBDManager._get_device_uuid')
    def test_compare_device_uuid(self, mock_get_uuid):
        mock_get_uuid.side_effect = ["1234", "5678"]
        with self.assertRaises(ValueError) as err:
            self.sbd_inst._compare_device_uuid("/dev/sdb1", ["node1"])
        self.assertEqual("Device /dev/sdb1 doesn't have the same UUID with node1", str(err.exception))
        mock_get_uuid.assert_has_calls([mock.call("/dev/sdb1"), mock.call("/dev/sdb1", "node1")])

    @mock.patch('crmsh.utils.get_stdout_stderr')
    def test_get_device_uuid_error_dump(self, mock_run):
        mock_run.return_value = (1, None, "error data")
        with self.assertRaises(ValueError) as err:
            self.sbd_inst._get_device_uuid("/dev/sdb1")
        self.assertEqual("Cannot dump sbd meta-data: error data", str(err.exception))
        mock_run.assert_called_once_with("sbd -d /dev/sdb1 dump")

    @mock.patch('crmsh.utils.get_stdout_stderr')
    def test_get_device_uuid_not_match(self, mock_run):
        mock_run.return_value = (0, "output data", None)
        with self.assertRaises(ValueError) as err:
            self.sbd_inst._get_device_uuid("/dev/sdb1")
        self.assertEqual("Cannot find sbd device UUID for /dev/sdb1", str(err.exception))
        mock_run.assert_called_once_with("sbd -d /dev/sdb1 dump")

    @mock.patch('crmsh.utils.get_stdout_stderr')
    def test_get_device_uuid(self, mock_run):
        output = """
        ==Dumping header on disk /dev/sda1
        Header version     : 2.1
        UUID               : a2e9a92c-cc72-4ef9-ac55-ccc342f3546b
        Number of slots    : 255
        Sector size        : 512
        Timeout (watchdog) : 5
        Timeout (allocate) : 2
        Timeout (loop)     : 1
        Timeout (msgwait)  : 10
        ==Header on disk /dev/sda1 is dumped
        """
        mock_run.return_value = (0, output, None)
        res = self.sbd_inst._get_device_uuid("/dev/sda1", node="node1")
        self.assertEqual(res, "a2e9a92c-cc72-4ef9-ac55-ccc342f3546b")
        mock_run.assert_called_once_with("ssh -o StrictHostKeyChecking=no root@node1 'sbd -d /dev/sda1 dump'")

    @mock.patch('crmsh.utils.parse_sysconfig')
    def test_determine_watchdog_timeout(self, mock_parse):
        mock_parse_inst = mock.Mock()
        mock_parse.return_value = mock_parse_inst
        mock_parse_inst.get.return_value = "5"
        self.sbd_inst._determine_stonith_watchdog_timeout()
        assert self.sbd_inst._stonith_watchdog_timeout == -1
        mock_parse.assert_called_once_with(bootstrap.SYSCONFIG_SBD)
        mock_parse_inst.get.assert_called_once_with("SBD_WATCHDOG_TIMEOUT")

    @mock.patch('crmsh.utils.parse_sysconfig')
    def test_determine_watchdog_timeout_s390(self, mock_parse):
        mock_parse_inst = mock.Mock()
        mock_parse.return_value = mock_parse_inst
        mock_parse_inst.get.return_value = None
        self.sbd_inst._is_s390 = True
        self.sbd_inst._determine_stonith_watchdog_timeout()
        assert self.sbd_inst._stonith_watchdog_timeout == "30s"
        mock_parse.assert_called_once_with(bootstrap.SYSCONFIG_SBD)
        mock_parse_inst.get.assert_called_once_with("SBD_WATCHDOG_TIMEOUT")

    @mock.patch('crmsh.utils.is_qdevice_configured')
    def test_determine_sbd_watchdog_timeout_return(self, mock_qdevice_configured):
        self.sbd_inst._determine_sbd_watchdog_timeout()
        mock_qdevice_configured.assert_not_called()

    @mock.patch('crmsh.sbd.SBDManager.calculate_stonith_timeout')
    @mock.patch('crmsh.utils.get_qdevice_sync_timeout')
    @mock.patch('crmsh.utils.service_is_active')
    @mock.patch('crmsh.utils.is_qdevice_configured')
    def test_determine_sbd_watchdog_timeout_after_qdevice(self, mock_qdevice_configured, mock_active, mock_get_qsync_timeout, mock_cal_timeout):
        mock_qdevice_configured.return_value = True
        mock_active.return_value = True
        mock_get_qsync_timeout.return_value = 5
        self.sbd_inst_diskless._is_s390 = True
        mock_cal_timeout.return_value = 20

        self.sbd_inst_diskless._determine_sbd_watchdog_timeout()

        mock_qdevice_configured.assert_called_once_with()
        mock_active.assert_called_once_with("corosync-qdevice.service")
        mock_get_qsync_timeout.assert_called_once_with()
        mock_cal_timeout.assert_called_once_with(15)

    @mock.patch('crmsh.sbd.SBDManager.calculate_stonith_timeout')
    @mock.patch('crmsh.utils.is_qdevice_configured')
    def test_determine_sbd_watchdog_timeout(self, mock_qdevice_configured, mock_cal_timeout):
        self.sbd_inst_diskless._context = mock.Mock(qdevice_inst=mock.Mock())
        mock_qdevice_configured.return_value = False
        mock_cal_timeout.return_value = 20

        self.sbd_inst_diskless._determine_sbd_watchdog_timeout()

        mock_qdevice_configured.assert_called_once_with()
        mock_cal_timeout.assert_called_once_with(sbd.SBDManager.SBD_WATCHDOG_TIMEOUT_DEFAULT_WITH_QDEVICE)

    @mock.patch('crmsh.sbd.SBDManager._get_sbd_device_from_config')
    @mock.patch('crmsh.utils.service_is_active')
    @mock.patch('crmsh.bootstrap.Context')
    def test_is_using_diskless_sbd_true(self, mock_context, mock_is_active, mock_get_sbd):
        context_inst = mock.Mock()
        mock_context.return_value = context_inst
        mock_get_sbd.return_value = []
        mock_is_active.return_value = True
        assert sbd.SBDManager.is_using_diskless_sbd() is True
        mock_context.assert_called_once_with()
        mock_get_sbd.assert_called_once_with()
        mock_is_active.assert_called_once_with("sbd.service")

    @mock.patch('crmsh.sbd.SBDManager._get_sbd_device_from_config')
    @mock.patch('crmsh.bootstrap.Context')
    def test_is_using_diskless_sbd_false(self, mock_context, mock_get_sbd):
        context_inst = mock.Mock()
        mock_context.return_value = context_inst
        mock_get_sbd.return_value = ["/dev/sda1"]
        assert sbd.SBDManager.is_using_diskless_sbd() is False
        mock_context.assert_called_once_with()
        mock_get_sbd.assert_called_once_with()

    @mock.patch('crmsh.sbd.SBDManager._get_sbd_device_from_config')
    @mock.patch('crmsh.bootstrap.Context')
    def test_get_sbd_device_from_config_classmethod(self, mock_context, mock_get_sbd):
        context_inst = mock.Mock()
        mock_context.return_value = context_inst
        mock_get_sbd.return_value = ["/dev/sda1"]
        assert sbd.SBDManager.get_sbd_device_from_config() == ["/dev/sda1"]
        mock_context.assert_called_once_with()
        mock_get_sbd.assert_called_once_with()

    @mock.patch('crmsh.bootstrap.csync2_update')
    @mock.patch('crmsh.utils.sysconfig_set')
    def test_update_configuration_static(self, mock_config_set, mock_csync2):
        sbd_config_dict = {
                "SBD_PACEMAKER": "yes",
                "SBD_STARTMODE": "always",
                "SBD_DELAY_START": "no",
                }
        self.sbd_inst.update_configuration(sbd_config_dict)
        mock_config_set.assert_called_once_with(bootstrap.SYSCONFIG_SBD, **sbd_config_dict)
        mock_csync2.assert_called_once_with(bootstrap.SYSCONFIG_SBD)

    def test_calculate_stonith_timeout(self):
        res = self.sbd_inst.calculate_stonith_timeout(5)
        assert res == 12
