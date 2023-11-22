import os
import unittest
import logging

try:
    from unittest import mock
except ImportError:
    import mock

from crmsh import bootstrap
from crmsh import sbd


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
        _dict = {"sbd.watchdog_timeout": 5, "sbd.msgwait": 10}
        _inst_q = mock.Mock()
        self.sbd_timeout_inst = sbd.SBDTimeout(mock.Mock(profiles_dict=_dict, is_s390=True, qdevice_inst=_inst_q))

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    def test_initialize_timeout(self):
        self.sbd_timeout_inst._set_sbd_watchdog_timeout = mock.Mock()
        self.sbd_timeout_inst._set_sbd_msgwait = mock.Mock()
        self.sbd_timeout_inst._adjust_sbd_watchdog_timeout_with_diskless_and_qdevice = mock.Mock()
        self.sbd_timeout_inst.initialize_timeout()
        self.sbd_timeout_inst._set_sbd_watchdog_timeout.assert_called_once()
        self.sbd_timeout_inst._set_sbd_msgwait.assert_not_called()
        self.sbd_timeout_inst._adjust_sbd_watchdog_timeout_with_diskless_and_qdevice.assert_called_once()

    @mock.patch('logging.Logger.warning')
    def test_set_sbd_watchdog_timeout(self, mock_warn):
        self.sbd_timeout_inst._set_sbd_watchdog_timeout()
        mock_warn.assert_called_once_with("sbd_watchdog_timeout is set to %d for s390, it was %d", sbd.SBDTimeout.SBD_WATCHDOG_TIMEOUT_DEFAULT_S390, 5)

    @mock.patch('logging.Logger.warning')
    def test_set_sbd_msgwait(self, mock_warn):
        self.sbd_timeout_inst.sbd_watchdog_timeout = 15
        self.sbd_timeout_inst._set_sbd_msgwait()
        mock_warn.assert_called_once_with("sbd msgwait is set to %d, it was %d", 30, 10)

    @mock.patch('logging.Logger.warning')
    @mock.patch('crmsh.utils.get_qdevice_sync_timeout')
    @mock.patch('crmsh.utils.service_is_active')
    @mock.patch('crmsh.corosync.is_qdevice_configured')
    def test_adjust_sbd_watchdog_timeout_with_diskless_and_qdevice_sbd_stage(self, mock_is_configured, mock_is_active, mock_get_sync, mock_warn):
        mock_is_configured.return_value = True
        mock_is_active.return_value = True
        mock_get_sync.return_value = 15
        self.sbd_timeout_inst.sbd_watchdog_timeout = 5
        self.sbd_timeout_inst._adjust_sbd_watchdog_timeout_with_diskless_and_qdevice()
        mock_warn.assert_called_once_with("sbd_watchdog_timeout is set to 20 for qdevice, it was 5")

    @mock.patch('logging.Logger.warning')
    @mock.patch('crmsh.corosync.is_qdevice_configured')
    def test_adjust_sbd_watchdog_timeout_with_diskless_and_qdevice_all(self, mock_is_configured, mock_warn):
        mock_is_configured.return_value = False
        self.sbd_timeout_inst.sbd_watchdog_timeout = 5
        self.sbd_timeout_inst._adjust_sbd_watchdog_timeout_with_diskless_and_qdevice()
        mock_warn.assert_called_once_with("sbd_watchdog_timeout is set to 35 for qdevice, it was 5")

    @mock.patch('crmsh.utils.get_stdout_or_raise_error')
    def test_get_sbd_msgwait_exception(self, mock_run):
        mock_run.return_value = "data"
        with self.assertRaises(ValueError) as err:
            sbd.SBDTimeout.get_sbd_msgwait("/dev/sda1")
        self.assertEqual("Cannot get sbd msgwait for /dev/sda1", str(err.exception))
        mock_run.assert_called_once_with("sbd -d /dev/sda1 dump")

    @mock.patch('crmsh.utils.get_stdout_or_raise_error')
    def test_get_sbd_msgwait(self, mock_run):
        mock_run.return_value = """
        Timeout (loop)     : 1
        Timeout (msgwait)  : 10
        ==Header on disk /dev/sda1 is dumped
        """
        res = sbd.SBDTimeout.get_sbd_msgwait("/dev/sda1")
        assert res == 10
        mock_run.assert_called_once_with("sbd -d /dev/sda1 dump")

    @mock.patch('crmsh.sbd.SBDManager.get_sbd_value_from_config')
    def test_get_sbd_watchdog_timeout_exception(self, mock_get):
        mock_get.return_value = None
        with self.assertRaises(ValueError) as err:
            sbd.SBDTimeout.get_sbd_watchdog_timeout()
        self.assertEqual("Cannot get the value of SBD_WATCHDOG_TIMEOUT", str(err.exception))
        mock_get.assert_called_once_with("SBD_WATCHDOG_TIMEOUT")

    @mock.patch('crmsh.sbd.SBDManager.get_sbd_value_from_config')
    def test_get_sbd_watchdog_timeout(self, mock_get):
        mock_get.return_value = 5
        res = sbd.SBDTimeout.get_sbd_watchdog_timeout()
        assert res == 5
        mock_get.assert_called_once_with("SBD_WATCHDOG_TIMEOUT")

    @mock.patch('crmsh.utils.service_is_active')
    def test_get_stonith_watchdog_timeout_return(self, mock_active):
        mock_active.return_value = False
        res = sbd.SBDTimeout.get_stonith_watchdog_timeout()
        assert res == sbd.SBDTimeout.STONITH_WATCHDOG_TIMEOUT_DEFAULT
        mock_active.assert_called_once_with("pacemaker.service")

    @mock.patch('crmsh.utils.get_property')
    @mock.patch('crmsh.utils.service_is_active')
    def test_get_stonith_watchdog_timeout(self, mock_active, mock_get_property):
        mock_active.return_value = True
        mock_get_property.return_value = "60s"
        res = sbd.SBDTimeout.get_stonith_watchdog_timeout()
        assert res == 60
        mock_active.assert_called_once_with("pacemaker.service")

    @mock.patch('logging.Logger.debug')
    @mock.patch('crmsh.sbd.SBDManager.get_sbd_value_from_config')
    @mock.patch('crmsh.utils.detect_virt')
    @mock.patch('crmsh.sbd.SBDTimeout.get_sbd_delay_start_expected')
    @mock.patch('crmsh.utils.get_pcmk_delay_max')
    @mock.patch('crmsh.sbd.SBDTimeout.get_sbd_msgwait')
    @mock.patch('crmsh.sbd.SBDManager.get_sbd_device_from_config')
    @mock.patch('crmsh.utils.is_2node_cluster_without_qdevice')
    def test_load_configurations(self, mock_2node, mock_get_sbd_dev, mock_get_msgwait, mock_pcmk_delay, mock_delay_expected, mock_detect, mock_get_sbd_value, mock_debug):
        mock_2node.return_value = True
        mock_debug.return_value = False
        mock_get_sbd_value.return_value = "no"
        mock_get_sbd_dev.return_value = ["/dev/sda1"]
        mock_get_msgwait.return_value = 30
        mock_pcmk_delay.return_value = 30

        self.sbd_timeout_inst._load_configurations()

        mock_2node.assert_called_once_with()
        mock_get_sbd_dev.assert_called_once_with()
        mock_get_msgwait.assert_called_once_with("/dev/sda1")
        mock_pcmk_delay.assert_called_once_with(True)

    @mock.patch('logging.Logger.debug')
    @mock.patch('crmsh.sbd.SBDManager.get_sbd_value_from_config')
    @mock.patch('crmsh.utils.detect_virt')
    @mock.patch('crmsh.sbd.SBDTimeout.get_sbd_delay_start_expected')
    @mock.patch('crmsh.sbd.SBDTimeout.get_stonith_watchdog_timeout')
    @mock.patch('crmsh.sbd.SBDTimeout.get_sbd_watchdog_timeout')
    @mock.patch('crmsh.sbd.SBDManager.get_sbd_device_from_config')
    @mock.patch('crmsh.utils.is_2node_cluster_without_qdevice')
    def test_load_configurations_diskless(self, mock_2node, mock_get_sbd_dev, mock_get_watchdog_timeout, mock_get_stonith_watchdog_timeout, mock_delay_expected, mock_detect, mock_get_sbd_value, mock_debug):
        mock_2node.return_value = True
        mock_debug.return_value = False
        mock_get_sbd_value.return_value = "no"
        mock_get_sbd_dev.return_value = []
        mock_get_watchdog_timeout.return_value = 30
        mock_get_stonith_watchdog_timeout.return_value = 30

        self.sbd_timeout_inst._load_configurations()

        mock_2node.assert_called_once_with()
        mock_get_sbd_dev.assert_called_once_with()
        mock_get_watchdog_timeout.assert_called_once_with()
        mock_get_stonith_watchdog_timeout.assert_called_once_with()

    @mock.patch('crmsh.corosync.token_and_consensus_timeout')
    @mock.patch('logging.Logger.debug')
    def test_get_stonith_timeout_expected(self, mock_debug, mock_general):
        self.sbd_timeout_inst.disk_based = True
        self.sbd_timeout_inst.pcmk_delay_max = 30
        self.sbd_timeout_inst.msgwait = 30
        mock_general.return_value = 11
        res = self.sbd_timeout_inst.get_stonith_timeout_expected()
        assert res == 83

    @mock.patch('crmsh.corosync.token_and_consensus_timeout')
    @mock.patch('logging.Logger.debug')
    def test_get_stonith_timeout_expected_diskless(self, mock_debug, mock_general):
        self.sbd_timeout_inst.disk_based = False
        self.sbd_timeout_inst.stonith_watchdog_timeout = -1
        self.sbd_timeout_inst.sbd_watchdog_timeout = 15
        mock_general.return_value = 11
        res = self.sbd_timeout_inst.get_stonith_timeout_expected()
        assert res == 71

    @mock.patch('crmsh.corosync.token_and_consensus_timeout')
    def test_get_sbd_delay_start_expected(self, mock_corosync):
        mock_corosync.return_value = 30
        self.sbd_timeout_inst.disk_based = True
        self.sbd_timeout_inst.pcmk_delay_max = 30
        self.sbd_timeout_inst.msgwait = 30
        res = self.sbd_timeout_inst.get_sbd_delay_start_expected()
        assert res == 90

    @mock.patch('crmsh.corosync.token_and_consensus_timeout')
    def test_get_sbd_delay_start_expected_diskless(self, mock_corosync):
        mock_corosync.return_value = 30
        self.sbd_timeout_inst.disk_based = False
        self.sbd_timeout_inst.sbd_watchdog_timeout = 30
        res = self.sbd_timeout_inst.get_sbd_delay_start_expected()
        assert res == 90

    @mock.patch('crmsh.sbd.SBDManager.get_sbd_value_from_config')
    def test_is_sbd_delay_start(self, mock_get_sbd_value):
        mock_get_sbd_value.return_value = "100"
        assert sbd.SBDTimeout.is_sbd_delay_start() is True
        mock_get_sbd_value.assert_called_once_with("SBD_DELAY_START")

    @mock.patch('crmsh.sbd.SBDManager.update_configuration')
    def test_adjust_sbd_delay_start_return(self, mock_update):
        self.sbd_timeout_inst.sbd_delay_start_value_expected = 100
        self.sbd_timeout_inst.sbd_delay_start_value_from_config = "100"
        self.sbd_timeout_inst.adjust_sbd_delay_start()
        mock_update.assert_not_called()

    @mock.patch('crmsh.sbd.SBDManager.update_configuration')
    def test_adjust_sbd_delay_start(self, mock_update):
        self.sbd_timeout_inst.sbd_delay_start_value_expected = 100
        self.sbd_timeout_inst.sbd_delay_start_value_from_config = "no"
        self.sbd_timeout_inst.adjust_sbd_delay_start()
        mock_update.assert_called_once_with({"SBD_DELAY_START": "100"})

    @mock.patch('crmsh.utils.get_stdout_or_raise_error')
    @mock.patch('crmsh.sbd.SBDManager.get_sbd_value_from_config')
    def test_adjust_systemd_start_timeout_no_delay_start_no(self, mock_get_sbd_value, mock_run):
        mock_get_sbd_value.return_value = "no"
        self.sbd_timeout_inst.adjust_systemd_start_timeout()
        mock_run.assert_not_called()

    @mock.patch('crmsh.utils.mkdirp')
    @mock.patch('crmsh.utils.get_systemd_timeout_start_in_sec')
    @mock.patch('crmsh.utils.get_stdout_or_raise_error')
    @mock.patch('crmsh.sbd.SBDManager.get_sbd_value_from_config')
    def test_adjust_systemd_start_timeout_no_delay_start_return(self, mock_get_sbd_value, mock_run, mock_get_systemd_sec, mock_mkdirp):
        mock_get_sbd_value.return_value = "10"
        mock_run.return_value = "1min 30s"
        mock_get_systemd_sec.return_value = 90
        self.sbd_timeout_inst.adjust_systemd_start_timeout()
        mock_run.assert_called_once_with("systemctl show -p TimeoutStartUSec sbd --value")
        mock_get_systemd_sec.assert_called_once_with("1min 30s")
        mock_mkdirp.assert_not_called()

    @mock.patch('crmsh.utils.cluster_run_cmd')
    @mock.patch('crmsh.bootstrap.sync_file')
    @mock.patch('crmsh.utils.str2file')
    @mock.patch('crmsh.utils.mkdirp')
    @mock.patch('crmsh.utils.get_systemd_timeout_start_in_sec')
    @mock.patch('crmsh.utils.get_stdout_or_raise_error')
    @mock.patch('crmsh.sbd.SBDManager.get_sbd_value_from_config')
    def test_adjust_systemd_start_timeout_no_delay_start(self, mock_get_sbd_value, mock_run, mock_get_systemd_sec, mock_mkdirp, mock_str2file, mock_csync2, mock_cluster_run):
        mock_get_sbd_value.return_value = "100"
        mock_run.return_value = "1min 30s"
        mock_get_systemd_sec.return_value = 90
        self.sbd_timeout_inst.adjust_systemd_start_timeout()
        mock_run.assert_called_once_with("systemctl show -p TimeoutStartUSec sbd --value")
        mock_get_systemd_sec.assert_called_once_with("1min 30s")
        mock_mkdirp.assert_called_once_with(bootstrap.SBD_SYSTEMD_DELAY_START_DIR)
        mock_str2file.assert_called_once_with('[Service]\nTimeoutSec=120', '/etc/systemd/system/sbd.service.d/sbd_delay_start.conf')
        mock_csync2.assert_called_once_with(bootstrap.SBD_SYSTEMD_DELAY_START_DIR)
        mock_cluster_run.assert_called_once_with("systemctl daemon-reload")

    @mock.patch('crmsh.sbd.SBDTimeout.get_sbd_watchdog_timeout')
    @mock.patch('crmsh.sbd.SBDManager.get_sbd_value_from_config')
    def test_get_sbd_delay_start_sec_from_sysconfig_yes(self, mock_get_sbd_value, mock_get_sbd_timeout):
        mock_get_sbd_value.return_value = "yes"
        mock_get_sbd_timeout.return_value = 30
        assert sbd.SBDTimeout.get_sbd_delay_start_sec_from_sysconfig() == 60
        mock_get_sbd_value.assert_called_once_with("SBD_DELAY_START")

    @mock.patch('crmsh.sbd.SBDManager.get_sbd_value_from_config')
    def test_get_sbd_delay_start_sec_from_sysconfig(self, mock_get_sbd_value):
        mock_get_sbd_value.return_value = "30"
        assert sbd.SBDTimeout.get_sbd_delay_start_sec_from_sysconfig() == 30
        mock_get_sbd_value.assert_called_once_with("SBD_DELAY_START")


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

    @mock.patch('logging.Logger.warning')
    def test_get_sbd_device_interactive_yes_to_all(self, mock_warn):
        self.sbd_inst._context = mock.Mock(yes_to_all=True)
        self.sbd_inst._get_sbd_device_interactive()
        mock_warn.assert_called_once_with(sbd.SBDManager.SBD_WARNING)

    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('logging.Logger.info')
    @mock.patch('logging.Logger.warning')
    def test_get_sbd_device_interactive_not_confirm(self, mock_warn, mock_status, mock_confirm):
        self.sbd_inst._context.yes_to_all = False
        mock_confirm.return_value = False
        self.sbd_inst._get_sbd_device_interactive()
        mock_status.assert_called_once_with(sbd.SBDManager.SBD_STATUS_DESCRIPTION)
        mock_warn.assert_called_once_with("Not configuring SBD - STONITH will be disabled.")

    @mock.patch('crmsh.sbd.SBDManager._no_overwrite_check')
    @mock.patch('crmsh.sbd.SBDManager._get_sbd_device_from_config')
    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('logging.Logger.info')
    def test_get_sbd_device_interactive_already_configured(self, mock_status, mock_confirm, mock_from_config, mock_no_overwrite):
        self.sbd_inst._context = mock.Mock(yes_to_all=False)
        mock_confirm.return_value = True
        mock_from_config.return_value = ["/dev/sda1"]
        mock_no_overwrite.return_value = True

        res = self.sbd_inst._get_sbd_device_interactive()
        self.assertEqual(res, ["/dev/sda1"])

        mock_status.assert_called_once_with(sbd.SBDManager.SBD_STATUS_DESCRIPTION)
        mock_confirm.assert_has_calls([
            mock.call("Do you wish to use SBD?"),
            ])
        mock_status.assert_called_once_with(sbd.SBDManager.SBD_STATUS_DESCRIPTION)
        mock_from_config.assert_called_once_with()

    @mock.patch('crmsh.bootstrap.prompt_for_string')
    @mock.patch('crmsh.sbd.SBDManager._no_overwrite_check')
    @mock.patch('crmsh.sbd.SBDManager._get_sbd_device_from_config')
    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('logging.Logger.info')
    def test_get_sbd_device_interactive_diskless(self, mock_status, mock_confirm, mock_from_config, mock_no_overwrite, mock_prompt):
        self.sbd_inst._context = mock.Mock(yes_to_all=False)
        mock_confirm.return_value = True
        mock_no_overwrite.return_value = False
        mock_from_config.return_value = []
        mock_prompt.return_value = "none"

        self.sbd_inst._get_sbd_device_interactive()

        mock_status.assert_called_once_with(sbd.SBDManager.SBD_STATUS_DESCRIPTION)
        mock_from_config.assert_called_once_with()
        mock_prompt.assert_called_once_with('Path to storage device (e.g. /dev/disk/by-id/...), or "none" for diskless sbd, use ";" as separator for multi path', 'none|\\/.*')

    @mock.patch('crmsh.bootstrap.prompt_for_string')
    @mock.patch('crmsh.sbd.SBDManager._no_overwrite_check')
    @mock.patch('crmsh.sbd.SBDManager._get_sbd_device_from_config')
    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('logging.Logger.info')
    def test_get_sbd_device_interactive_null_and_diskless(self, mock_status, mock_confirm, mock_from_config, mock_no_overwrite, mock_prompt):
        self.sbd_inst._context = mock.Mock(yes_to_all=False)
        mock_confirm.return_value = True
        mock_no_overwrite.return_value = False
        mock_from_config.return_value = []
        mock_prompt.return_value = "none"

        self.sbd_inst._get_sbd_device_interactive()

        mock_status.assert_called_once_with(sbd.SBDManager.SBD_STATUS_DESCRIPTION)
        mock_confirm.assert_called_once_with("Do you wish to use SBD?")
        mock_from_config.assert_called_once_with()
        mock_prompt.assert_has_calls([
            mock.call('Path to storage device (e.g. /dev/disk/by-id/...), or "none" for diskless sbd, use ";" as separator for multi path', 'none|\\/.*')
            ])

    @mock.patch('crmsh.utils.re_split_string')
    @mock.patch('logging.Logger.warning')
    @mock.patch('logging.Logger.error')
    @mock.patch('crmsh.sbd.SBDManager._verify_sbd_device')
    @mock.patch('crmsh.bootstrap.prompt_for_string')
    @mock.patch('crmsh.sbd.SBDManager._no_overwrite_check')
    @mock.patch('crmsh.sbd.SBDManager._get_sbd_device_from_config')
    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('logging.Logger.info')
    def test_get_sbd_device_interactive(self, mock_status, mock_confirm, mock_from_config, mock_no_overwrite, mock_prompt, mock_verify, mock_error_msg, mock_warn, mock_split):
        self.sbd_inst._context = mock.Mock(yes_to_all=False)
        mock_confirm.side_effect = [True, False, True]
        mock_from_config.return_value = []
        mock_no_overwrite.return_value = False
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
    def test_get_sbd_device_from_option(self, mock_verify):
        self.sbd_inst._get_sbd_device()
        mock_verify.assert_called_once_with(['/dev/sdb1', '/dev/sdc1'])

    @mock.patch('crmsh.sbd.SBDManager._get_sbd_device_interactive')
    def test_get_sbd_device_from_interactive(self, mock_interactive):
        mock_interactive.return_value = ["/dev/sdb1", "/dev/sdc1"]
        self.sbd_inst_interactive._get_sbd_device()
        mock_interactive.assert_called_once_with()

    def test_get_sbd_device_diskless(self):
        self.sbd_inst_diskless._get_sbd_device()

    @mock.patch('crmsh.sbd.SBDTimeout')
    @mock.patch('logging.Logger.info')
    def test_initialize_sbd_return(self, mock_info, mock_sbd_timeout):
        mock_inst = mock.Mock()
        mock_sbd_timeout.return_value = mock_inst
        self.sbd_inst_diskless._context = mock.Mock(profiles_dict={})
        self.sbd_inst_diskless._initialize_sbd()
        mock_info.assert_called_once_with("Configuring diskless SBD")
        mock_inst.initialize_timeout.assert_called_once_with()

    @mock.patch('crmsh.utils.fatal')
    @mock.patch('crmsh.bootstrap.invoke')
    @mock.patch('crmsh.sbd.SBDTimeout')
    @mock.patch('logging.Logger.info')
    def test_initialize_sbd(self, mock_info, mock_sbd_timeout, mock_invoke, mock_error):
        mock_inst = mock.Mock(sbd_msgwait=10, sbd_watchdog_timeout=5)
        mock_sbd_timeout.return_value = mock_inst
        mock_inst.set_sbd_watchdog_timeout = mock.Mock()
        mock_inst.set_sbd_msgwait = mock.Mock()
        self.sbd_inst._sbd_devices = ["/dev/sdb1", "/dev/sdc1"]
        mock_invoke.side_effect = [(True, None, None), (False, None, "error")]
        mock_error.side_effect = ValueError

        with self.assertRaises(ValueError):
            self.sbd_inst._initialize_sbd()

        mock_invoke.assert_has_calls([
            mock.call("sbd -4 10 -1 5 -d /dev/sdb1 create"),
            mock.call("sbd -4 10 -1 5 -d /dev/sdc1 create")
            ])
        mock_error.assert_called_once_with("Failed to initialize SBD device /dev/sdc1: error")

    @mock.patch('crmsh.bootstrap.sync_file')
    @mock.patch('crmsh.utils.sysconfig_set')
    @mock.patch('shutil.copyfile')
    def test_update_configuration(self, mock_copy, mock_sysconfig, mock_update):
        self.sbd_inst._sbd_devices = ["/dev/sdb1", "/dev/sdc1"]
        self.sbd_inst._watchdog_inst = mock.Mock(watchdog_device_name="/dev/watchdog")
        self.sbd_inst.timeout_inst = mock.Mock(sbd_watchdog_timeout=15)

        self.sbd_inst._update_sbd_configuration()

        mock_copy.assert_called_once_with("/usr/share/fillup-templates/sysconfig.sbd", "/etc/sysconfig/sbd")
        mock_sysconfig.assert_called_once_with("/etc/sysconfig/sbd", SBD_WATCHDOG_DEV='/dev/watchdog', SBD_DEVICE='/dev/sdb1;/dev/sdc1', SBD_WATCHDOG_TIMEOUT="15")
        mock_update.assert_called_once_with("/etc/sysconfig/sbd")

    @mock.patch('crmsh.bootstrap.utils.parse_sysconfig')
    def test_get_sbd_device_from_config_none(self, mock_parse):
        mock_parse_inst = mock.Mock()
        mock_parse.return_value = mock_parse_inst
        mock_parse_inst.get.return_value = None

        res = self.sbd_inst._get_sbd_device_from_config()
        assert res == []

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

    @mock.patch('logging.Logger.warning')
    @mock.patch('crmsh.utils.get_quorum_votes_dict')
    def test_warn_diskless_sbd_diskless(self, mock_vote, mock_warn):
        self.sbd_inst_diskless._context = mock.Mock(cluster_is_running=False)
        self.sbd_inst_diskless._warn_diskless_sbd()
        mock_vote.assert_not_called()
        mock_warn.assert_called_once_with(sbd.SBDManager.DISKLESS_SBD_WARNING)

    @mock.patch('logging.Logger.warning')
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
    @mock.patch('crmsh.sbd.SBDManager._update_sbd_configuration')
    @mock.patch('crmsh.sbd.SBDManager._initialize_sbd')
    @mock.patch('crmsh.sbd.SBDManager._get_sbd_device')
    @mock.patch('crmsh.watchdog.Watchdog')
    @mock.patch('crmsh.utils.package_is_installed')
    def test_sbd_init_return(self, mock_package, mock_watchdog, mock_get_device, mock_initialize, mock_update, mock_invoke):
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
        mock_initialize.assert_not_called()
        mock_update.assert_not_called()
        mock_watchdog.assert_called_once_with(_input=None)
        mock_watchdog_inst.init_watchdog.assert_called_once_with()
        mock_invoke.assert_called_once_with("systemctl disable sbd.service")
 
    @mock.patch('crmsh.sbd.SBDManager._enable_sbd_service')
    @mock.patch('crmsh.sbd.SBDManager._warn_diskless_sbd')
    @mock.patch('crmsh.sbd.SBDManager._update_sbd_configuration')
    @mock.patch('crmsh.sbd.SBDManager._initialize_sbd')
    @mock.patch('crmsh.sbd.SBDManager._get_sbd_device')
    @mock.patch('crmsh.watchdog.Watchdog')
    @mock.patch('crmsh.utils.package_is_installed')
    def test_sbd_init(self, mock_package, mock_watchdog, mock_get_device, mock_initialize, mock_update, mock_warn, mock_enable_sbd):
        mock_package.return_value = True
        self.sbd_inst_diskless._context = mock.Mock(watchdog=None)
        mock_watchdog_inst = mock.Mock()
        mock_watchdog.return_value = mock_watchdog_inst
        mock_watchdog_inst.init_watchdog = mock.Mock()
        self.sbd_inst_diskless.sbd_init()

        mock_package.assert_called_once_with("sbd")
        mock_get_device.assert_called_once_with()
        mock_initialize.assert_called_once_with()
        mock_update.assert_called_once_with()
        mock_watchdog.assert_called_once_with(_input=None)
        mock_watchdog_inst.init_watchdog.assert_called_once_with()
        mock_warn.assert_called_once_with()
        mock_enable_sbd.assert_called_once_with()

    @mock.patch('crmsh.sbd.SBDManager.configure_sbd_resource_and_properties')
    @mock.patch('crmsh.bootstrap.wait_for_cluster')
    @mock.patch('crmsh.utils.cluster_run_cmd')
    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.xmlutil.CrmMonXmlParser')
    def test_restart_cluster_on_needed_no_ra_running(self, mock_parser, mock_status, mock_cluster_run, mock_wait, mock_config_sbd_ra):
        mock_parser().is_any_resource_running.return_value = False
        self.sbd_inst._restart_cluster_and_configure_sbd_ra()
        mock_status.assert_called_once_with("Restarting cluster service")
        mock_cluster_run.assert_called_once_with("crm cluster restart")
        mock_wait.assert_called_once_with()
        mock_config_sbd_ra.assert_called_once_with()

    @mock.patch('crmsh.sbd.SBDTimeout.get_stonith_timeout')
    @mock.patch('logging.Logger.warning')
    @mock.patch('crmsh.xmlutil.CrmMonXmlParser')
    def test_restart_cluster_on_needed_diskless(self, mock_parser, mock_warn, mock_get_timeout):
        mock_parser().is_any_resource_running.return_value = True
        mock_get_timeout.return_value = 60
        self.sbd_inst_diskless.timeout_inst = mock.Mock(stonith_watchdog_timeout=-1)
        self.sbd_inst_diskless._restart_cluster_and_configure_sbd_ra()
        mock_warn.assert_has_calls([
            mock.call("To start sbd.service, need to restart cluster service manually on each node"),
            mock.call("Then run \"crm configure property stonith-enabled=true stonith-watchdog-timeout=-1 stonith-timeout=60\" on any node")
            ])

    @mock.patch('crmsh.sbd.SBDManager.configure_sbd_resource_and_properties')
    @mock.patch('logging.Logger.warning')
    @mock.patch('crmsh.xmlutil.CrmMonXmlParser')
    def test_restart_cluster_on_needed(self, mock_parser, mock_warn, mock_config_sbd_ra):
        mock_parser().is_any_resource_running.return_value = True
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

    @mock.patch('crmsh.utils.package_is_installed')
    def test_configure_sbd_resource_and_properties_not_installed(self, mock_package):
        mock_package.return_value = False
        self.sbd_inst.configure_sbd_resource_and_properties()
        mock_package.assert_called_once_with("sbd")

    @mock.patch('crmsh.sbd.SBDTimeout.adjust_sbd_timeout_related_cluster_configuration')
    @mock.patch('crmsh.utils.set_property')
    @mock.patch('crmsh.utils.get_stdout_or_raise_error')
    @mock.patch('crmsh.xmlutil.CrmMonXmlParser')
    @mock.patch('crmsh.utils.service_is_enabled')
    @mock.patch('crmsh.utils.package_is_installed')
    def test_configure_sbd_resource_and_properties(self, mock_package, mock_enabled, mock_parser, mock_run, mock_set_property, sbd_adjust):
        mock_package.return_value = True
        mock_enabled.return_value = True
        mock_parser().is_resource_configured.return_value = False
        self.sbd_inst._context = mock.Mock(cluster_is_running=True)
        self.sbd_inst._get_sbd_device_from_config = mock.Mock()
        self.sbd_inst._get_sbd_device_from_config.return_value = ["/dev/sda1"]

        self.sbd_inst.configure_sbd_resource_and_properties()

        mock_package.assert_called_once_with("sbd")
        mock_enabled.assert_called_once_with("sbd.service")
        mock_parser().is_resource_configured.assert_called_once_with(sbd.SBDManager.SBD_RA)
        mock_run.assert_called_once_with("crm configure primitive {} {}".format(sbd.SBDManager.SBD_RA_ID, sbd.SBDManager.SBD_RA))
        mock_set_property.assert_called_once_with("stonith-enabled", "true")

    @mock.patch('crmsh.utils.package_is_installed')
    def test_join_sbd_config_not_installed(self, mock_package):
        mock_package.return_value = False
        self.sbd_inst.join_sbd("alice", "node1")
        mock_package.assert_called_once_with("sbd")

    @mock.patch('crmsh.bootstrap.invoke')
    @mock.patch('os.path.exists')
    @mock.patch('crmsh.utils.package_is_installed')
    def test_join_sbd_config_not_exist(self, mock_package, mock_exists, mock_invoke):
        mock_package.return_value = True
        mock_exists.return_value = False
        self.sbd_inst.join_sbd("alice", "node1")
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

        self.sbd_inst.join_sbd("alice", "node1")

        mock_package.assert_called_once_with("sbd")
        mock_exists.assert_called_once_with("/etc/sysconfig/sbd")
        mock_invoke.assert_called_once_with("systemctl disable sbd.service")
        mock_enabled.assert_called_once_with("sbd.service", "node1")

    @mock.patch('logging.Logger.info')
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

        self.sbd_inst.join_sbd("alice", "node1")

        mock_package.assert_called_once_with("sbd")
        mock_exists.assert_called_once_with("/etc/sysconfig/sbd")
        mock_invoke.assert_called_once_with("systemctl enable sbd.service")
        mock_get_device.assert_called_once_with()
        mock_verify.assert_called_once_with(["/dev/sdb1"], ["node1"])
        mock_enabled.assert_called_once_with("sbd.service", "node1")
        mock_status.assert_called_once_with("Got SBD configuration")
        mock_watchdog.assert_called_once_with(remote_user="alice", peer_host="node1")
        mock_watchdog_inst.join_watchdog.assert_called_once_with()

    @mock.patch('crmsh.utils.sysconfig_set')
    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.sbd.SBDManager._warn_diskless_sbd')
    @mock.patch('crmsh.sbd.SBDManager._get_sbd_device_from_config')
    @mock.patch('crmsh.watchdog.Watchdog')
    @mock.patch('crmsh.bootstrap.invoke')
    @mock.patch('crmsh.utils.service_is_enabled')
    @mock.patch('os.path.exists')
    @mock.patch('crmsh.utils.package_is_installed')
    def test_join_sbd_diskless(self, mock_package, mock_exists, mock_enabled, mock_invoke, mock_watchdog, mock_get_device, mock_warn, mock_status, mock_set):
        mock_package.return_value = True
        mock_exists.return_value = True
        mock_enabled.return_value = True
        mock_get_device.return_value = []
        mock_watchdog_inst = mock.Mock()
        mock_watchdog.return_value = mock_watchdog_inst
        mock_watchdog_inst.join_watchdog = mock.Mock()

        self.sbd_inst.join_sbd("alice", "node1")

        mock_package.assert_called_once_with("sbd")
        mock_exists.assert_called_once_with("/etc/sysconfig/sbd")
        mock_invoke.assert_called_once_with("systemctl enable sbd.service")
        mock_get_device.assert_called_once_with()
        mock_warn.assert_called_once_with("node1")
        mock_enabled.assert_called_once_with("sbd.service", "node1")
        mock_status.assert_called_once_with("Got diskless SBD configuration")
        mock_watchdog.assert_called_once_with(remote_user="alice", peer_host="node1")
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

    @mock.patch('crmsh.utils.get_stdout_or_raise_error')
    def test_get_device_uuid_not_match(self, mock_run):
        mock_run.return_value = "data"
        with self.assertRaises(ValueError) as err:
            self.sbd_inst._get_device_uuid("/dev/sdb1")
        self.assertEqual("Cannot find sbd device UUID for /dev/sdb1", str(err.exception))
        mock_run.assert_called_once_with("sbd -d /dev/sdb1 dump", remote=None)

    @mock.patch('crmsh.utils.get_stdout_or_raise_error')
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
        mock_run.return_value = output
        res = self.sbd_inst._get_device_uuid("/dev/sda1", node="node1")
        self.assertEqual(res, "a2e9a92c-cc72-4ef9-ac55-ccc342f3546b")
        mock_run.assert_called_once_with("sbd -d /dev/sda1 dump", remote="node1")

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

    @mock.patch('crmsh.bootstrap.sync_file')
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
