"""
Unitary tests for crmsh/bootstrap.py

:author: xinliang
:organization: SUSE Linux GmbH
:contact: XLiang@suse.de

:since: 2019-10-21
"""

# pylint:disable=C0103,C0111,W0212,W0611

import os
import unittest

try:
    from unittest import mock
except ImportError:
    import mock

from crmsh import bootstrap
from crmsh.constants import SSH_KEY_CRMSH, SSH_WITH_KEY, SCP_WITH_KEY, SSH_KEY_CRMSH_TAG


class TestSBDManager(unittest.TestCase):
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
        self.sbd_inst = bootstrap.SBDManager(sbd_devices=["/dev/sdb1", "/dev/sdc1"])
        self.sbd_inst_devices_gt_3 = bootstrap.SBDManager(sbd_devices=["/dev/sdb1", "/dev/sdc1", "/dev/sdd1", "/dev/sde1"])
        self.sbd_inst_interactive = bootstrap.SBDManager()
        self.sbd_inst_diskless = bootstrap.SBDManager(diskless_sbd=True)

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.bootstrap.check_watchdog')
    def test_check_environment_no_watchdog(self, mock_watchdog, mock_error):
        mock_watchdog.return_value = False
        mock_error.side_effect = ValueError

        with self.assertRaises(ValueError):
            self.sbd_inst._check_environment()

        mock_error.assert_called_once_with("Watchdog device must be configured in order to use SBD")
        mock_watchdog.assert_called_once_with()

    @mock.patch('crmsh.utils.is_program')
    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.bootstrap.check_watchdog')
    def test_check_environment_no_sbd(self, mock_watchdog, mock_error, mock_is_program):
        mock_watchdog.return_value = True
        mock_is_program.return_value = False
        mock_error.side_effect = ValueError

        with self.assertRaises(ValueError):
            self.sbd_inst._check_environment()

        mock_error.assert_called_once_with("sbd executable not found! Cannot configure SBD")
        mock_watchdog.assert_called_once_with()
        mock_is_program.assert_called_once_with("sbd")

    def test_parse_sbd_device(self):
        res = self.sbd_inst._parse_sbd_device()
        assert res == ["/dev/sdb1", "/dev/sdc1"]

    def test_verify_sbd_device_gt_3(self):
        assert self.sbd_inst_devices_gt_3.sbd_devices_input == ["/dev/sdb1", "/dev/sdc1", "/dev/sdd1", "/dev/sde1"]
        dev_list = self.sbd_inst_devices_gt_3.sbd_devices_input
        with self.assertRaises(ValueError) as err:
            self.sbd_inst_devices_gt_3._verify_sbd_device(dev_list)
        self.assertEqual("Maximum number of SBD device is 3", str(err.exception))

    @mock.patch('crmsh.bootstrap.is_block_device')
    def test_verify_sbd_device_not_block(self, mock_block_device):
        assert self.sbd_inst.sbd_devices_input == ["/dev/sdb1", "/dev/sdc1"]
        dev_list = self.sbd_inst.sbd_devices_input
        mock_block_device.side_effect = [True, False]

        with self.assertRaises(ValueError) as err:
            self.sbd_inst._verify_sbd_device(dev_list)
        self.assertEqual("/dev/sdc1 doesn't look like a block device", str(err.exception))

        mock_block_device.assert_has_calls([mock.call("/dev/sdb1"), mock.call("/dev/sdc1")])

    @mock.patch('crmsh.bootstrap.SBDManager._check_environment')
    @mock.patch('crmsh.bootstrap.SBDManager._verify_sbd_device')
    @mock.patch('crmsh.bootstrap.SBDManager._parse_sbd_device')
    def test_get_sbd_device_from_option(self, mock_parse, mock_verify, mock_check):
        mock_parse.return_value = ["/dev/sdb1", "/dev/sdc1"]
        self.sbd_inst._get_sbd_device()
        mock_parse.assert_called_once_with()
        mock_verify.assert_called_once_with(mock_parse.return_value)
        mock_check.assert_called_once_with()

    @mock.patch('crmsh.bootstrap.SBDManager._get_sbd_device_interactive')
    def test_get_sbd_device_from_interactive(self, mock_interactive):
        mock_interactive.return_value = ["/dev/sdb1", "/dev/sdc1"]
        self.sbd_inst_interactive._get_sbd_device()
        mock_interactive.assert_called_once_with()

    @mock.patch('crmsh.bootstrap.SBDManager._check_environment')
    def test_get_sbd_device_diskless(self, mock_check):
        self.sbd_inst_diskless._get_sbd_device()
        mock_check.assert_called_once_with()

    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.bootstrap.invoke')
    def test_initialize_sbd(self, mock_invoke, mock_error):
        self.sbd_inst._sbd_devices = ["/dev/sdb1", "/dev/sdc1"]
        mock_invoke.side_effect = [True, False]
        mock_error.side_effect = ValueError

        with self.assertRaises(ValueError):
            self.sbd_inst._initialize_sbd()

        mock_invoke.assert_has_calls([
            mock.call("sbd -d /dev/sdb1 create"),
            mock.call("sbd -d /dev/sdc1 create")
            ])
        mock_error.assert_called_once_with("Failed to initialize SBD device /dev/sdc1")

    @mock.patch('crmsh.bootstrap.csync2_update')
    @mock.patch('crmsh.utils.sysconfig_set')
    @mock.patch('crmsh.bootstrap.detect_watchdog_device')
    @mock.patch('shutil.copyfile')
    def test_update_configuration(self, mock_copy, mock_detect, mock_sysconfig, mock_update):
        self.sbd_inst._sbd_devices = ["/dev/sdb1", "/dev/sdc1"]
        mock_detect.return_value = "/dev/watchdog"

        self.sbd_inst._update_configuration()

        mock_copy.assert_called_once_with("/usr/share/fillup-templates/sysconfig.sbd", "/etc/sysconfig/sbd")
        mock_detect.assert_called_once_with()
        mock_sysconfig.assert_called_once_with("/etc/sysconfig/sbd", SBD_PACEMAKER='yes', SBD_STARTMODE='always', SBD_DELAY_START='no', SBD_WATCHDOG_DEV='/dev/watchdog', SBD_DEVICE='/dev/sdb1;/dev/sdc1')
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

    @mock.patch('crmsh.bootstrap.utils.parse_sysconfig')
    def test_get_sbd_device_from_config(self, mock_parse):
        mock_parse_inst = mock.Mock()
        mock_parse.return_value = mock_parse_inst
        mock_parse_inst.get.return_value = "/dev/sdb1;/dev/sdc1"

        res = self.sbd_inst._get_sbd_device_from_config()
        assert res == ["/dev/sdb1", "/dev/sdc1"]

        mock_parse.assert_called_once_with("/etc/sysconfig/sbd")
        mock_parse_inst.get.assert_called_once_with("SBD_DEVICE")

    @mock.patch('crmsh.bootstrap.status_done')
    @mock.patch('crmsh.bootstrap.SBDManager._update_configuration')
    @mock.patch('crmsh.bootstrap.SBDManager._initialize_sbd')
    @mock.patch('crmsh.bootstrap.status_long')
    @mock.patch('crmsh.bootstrap.SBDManager._get_sbd_device')
    def test_sbd_init_return(self, mock_get_device, mock_status, mock_initialize, mock_update, mock_status_done):
        self.sbd_inst._sbd_devices = None
        self.sbd_inst.diskless_sbd = False

        self.sbd_inst.sbd_init()

        mock_get_device.assert_called_once_with()
        mock_status.assert_not_called()
        mock_initialize.assert_not_called()
        mock_update.assert_not_called()
        mock_status_done.assert_not_called()

    @mock.patch('crmsh.bootstrap.status_done')
    @mock.patch('crmsh.bootstrap.SBDManager._update_configuration')
    @mock.patch('crmsh.bootstrap.SBDManager._initialize_sbd')
    @mock.patch('crmsh.bootstrap.status_long')
    @mock.patch('crmsh.bootstrap.SBDManager._get_sbd_device')
    def test_sbd_init_return(self, mock_get_device, mock_status, mock_initialize, mock_update, mock_status_done):
        self.sbd_inst_diskless.sbd_init()

        mock_get_device.assert_called_once_with()
        mock_status.assert_called_once_with("Initializing diskless SBD...")
        mock_initialize.assert_called_once_with()
        mock_update.assert_called_once_with()
        mock_status_done.assert_called_once_with()

    @mock.patch('crmsh.bootstrap.invoke')
    def test_manage_sbd_service_enable(self, mock_invoke):
        self.sbd_inst._sbd_service_flag = True
        self.sbd_inst.manage_sbd_service()
        mock_invoke.assert_called_once_with("systemctl enable sbd.service")

    @mock.patch('crmsh.bootstrap.invoke')
    def test_manage_sbd_service_disable(self, mock_invoke):
        self.sbd_inst._sbd_service_flag = False
        self.sbd_inst.manage_sbd_service()
        mock_invoke.assert_called_once_with("systemctl disable sbd.service")

    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.bootstrap.invoke')
    @mock.patch('crmsh.bootstrap.SBDManager._get_sbd_device_from_config')
    def test_configure_sbd_resource_error_primitive(self, mock_get_device, mock_invoke, mock_error):
        self.sbd_inst._sbd_devices = ["/dev/sdb1"]
        mock_get_device.return_value = ["/dev/sdb1"]
        mock_invoke.return_value = False
        mock_error.side_effect = ValueError

        with self.assertRaises(ValueError):
            self.sbd_inst.configure_sbd_resource()

        mock_get_device.assert_called_once_with()
        mock_invoke.assert_called_once_with("crm configure primitive stonith-sbd stonith:external/sbd pcmk_delay_max=30s")
        mock_error.assert_called_once_with("Can't create stonith-sbd primitive")

    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.bootstrap.invoke')
    @mock.patch('crmsh.bootstrap.SBDManager._get_sbd_device_from_config')
    def test_configure_sbd_resource_error_property(self, mock_get_device, mock_invoke, mock_error):
        self.sbd_inst._sbd_devices = ["/dev/sdb1"]
        mock_get_device.return_value = ["/dev/sdb1"]
        mock_invoke.side_effect = [True, False]
        mock_error.side_effect = ValueError

        with self.assertRaises(ValueError):
            self.sbd_inst.configure_sbd_resource()

        mock_get_device.assert_called_once_with()
        mock_invoke.assert_has_calls([
            mock.call("crm configure primitive stonith-sbd stonith:external/sbd pcmk_delay_max=30s"),
            mock.call("crm configure property stonith-enabled=true")
            ])
        mock_error.assert_called_once_with("Can't enable STONITH for SBD")

    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.bootstrap.invoke')
    @mock.patch('crmsh.bootstrap.SBDManager._get_sbd_device_from_config')
    def test_configure_sbd_resource_diskless(self, mock_get_device, mock_invoke, mock_error):
        self.sbd_inst_diskless._sbd_devices = None
        mock_invoke.return_value = False
        mock_error.side_effect = ValueError

        with self.assertRaises(ValueError):
            self.sbd_inst_diskless.configure_sbd_resource()

        mock_get_device.assert_not_called()
        mock_invoke.assert_called_once_with("crm configure property stonith-enabled=true stonith-watchdog-timeout=5s")
        mock_error.assert_called_once_with("Can't enable STONITH for diskless SBD")

    @mock.patch('crmsh.bootstrap.invoke')
    @mock.patch('os.path.exists')
    def test_join_sbd_config_not_exist(self, mock_exists, mock_invoke):
        mock_exists.return_value = False
        self.sbd_inst.join_sbd("node1")
        mock_exists.assert_called_once_with("/etc/sysconfig/sbd")
        mock_invoke.assert_not_called()

    @mock.patch('crmsh.bootstrap.SBDManager._check_environment')
    @mock.patch('crmsh.bootstrap.invoke')
    @mock.patch('os.path.exists')
    def test_join_sbd_config_disabled(self, mock_exists, mock_invoke, mock_check):
        mock_exists.return_value = True
        mock_invoke.return_value = False

        self.sbd_inst.join_sbd("node1")

        mock_exists.assert_called_once_with("/etc/sysconfig/sbd")
        mock_invoke.assert_called_once_with("ssh -i /root/.ssh/id_rsa.crmsh -o StrictHostKeyChecking=no root@node1 systemctl is-enabled sbd.service")
        mock_check.assert_not_called()

    @mock.patch('crmsh.bootstrap.status')
    @mock.patch('crmsh.bootstrap.SBDManager._verify_sbd_device')
    @mock.patch('crmsh.bootstrap.SBDManager._get_sbd_device_from_config')
    @mock.patch('crmsh.bootstrap.SBDManager._check_environment')
    @mock.patch('crmsh.bootstrap.invoke')
    @mock.patch('os.path.exists')
    def test_join_sbd(self, mock_exists, mock_invoke, mock_check, mock_get_device, mock_verify, mock_status):
        mock_exists.return_value = True
        mock_invoke.return_value = True
        mock_get_device.return_value = ["/dev/sdb1"]

        self.sbd_inst.join_sbd("node1")

        mock_exists.assert_called_once_with("/etc/sysconfig/sbd")
        mock_invoke.assert_called_once_with("ssh -i /root/.ssh/id_rsa.crmsh -o StrictHostKeyChecking=no root@node1 systemctl is-enabled sbd.service")
        mock_check.assert_called_once_with()
        mock_get_device.assert_called_once_with()
        mock_verify.assert_called_once_with(["/dev/sdb1"])
        mock_status.assert_called_once_with("Got SBD configuration")


class TestBootstrap(unittest.TestCase):
    """
    Unitary tests for crmsh/bootstrap.py
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

    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('os.path.exists')
    @mock.patch('crmsh.bootstrap.start_service')
    def test_init_ssh_no_overwrite(self, mock_start, mock_exists, mock_confirm):
        mock_exists.return_value = True
        mock_confirm.return_value = False
        bootstrap.init_ssh()
        mock_start.assert_called_once_with("sshd.service")
        mock_exists.assert_called_once_with(SSH_KEY_CRMSH)
        mock_confirm.assert_called_once_with("{} already exists - overwrite?".format(SSH_KEY_CRMSH))

    @mock.patch('crmsh.bootstrap.append')
    @mock.patch('crmsh.bootstrap.invoke')
    @mock.patch('crmsh.bootstrap.rmfile')
    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('os.path.exists')
    @mock.patch('crmsh.bootstrap.start_service')
    def test_init_ssh_overwrite(self, mock_start, mock_exists, mock_confirm, mock_rmfile,
            mock_invoke, mock_append):
        mock_exists.return_value = True
        mock_confirm.return_value = True

        bootstrap.init_ssh()

        mock_start.assert_called_once_with("sshd.service")
        mock_exists.assert_called_once_with(SSH_KEY_CRMSH)
        mock_confirm.assert_called_once_with("{} already exists - overwrite?".format(SSH_KEY_CRMSH))
        mock_rmfile.assert_called_once_with(SSH_KEY_CRMSH)
        mock_invoke.assert_has_calls([
            mock.call("sed -i '/{}/d' /root/.ssh/authorized_keys".format(SSH_KEY_CRMSH_TAG)),
            mock.call("ssh-keygen -q -f {} -C '{}' -N ''".format(SSH_KEY_CRMSH, SSH_KEY_CRMSH_TAG))
            ])
        mock_append.assert_called_once_with("{}.pub".format(SSH_KEY_CRMSH), "/root/.ssh/authorized_keys")

    @mock.patch('crmsh.bootstrap.error')
    def test_join_ssh_error_no_seed_host(self, mock_error):
        mock_error.side_effect = ValueError

        with self.assertRaises(ValueError):
            bootstrap.join_ssh(None)
        mock_error.assert_called_once_with("No existing IP/hostname specified (use -c option)")

    @mock.patch('crmsh.bootstrap.status')
    @mock.patch('crmsh.bootstrap.invoke')
    @mock.patch('crmsh.bootstrap.start_service')
    @mock.patch('crmsh.bootstrap.error')
    def test_join_ssh_error_scp(self, mock_error, mock_start, mock_invoke, mock_status):
        mock_error.side_effect = ValueError
        mock_invoke.side_effect = [True, False]

        with self.assertRaises(ValueError):
            bootstrap.join_ssh("node1")

        mock_start.assert_called_once_with("sshd.service")
        mock_invoke.assert_has_calls([
            mock.call("mkdir -m 700 -p /root/.ssh"),
            mock.call("scp -oStrictHostKeyChecking=no root@node1:'{}*' /root/.ssh".format(SSH_KEY_CRMSH))
            ])
        mock_error.assert_called_once_with("Failed to retrieve ssh keys")
        mock_status.assert_called_once_with("Retrieving SSH keys - This may prompt for root@node1:")

    @mock.patch('crmsh.bootstrap.append')
    @mock.patch('crmsh.bootstrap.status')
    @mock.patch('crmsh.bootstrap.invoke')
    @mock.patch('crmsh.bootstrap.start_service')
    @mock.patch('crmsh.bootstrap.error')
    def test_join_ssh(self, mock_error, mock_start, mock_invoke, mock_status, mock_append):
        mock_invoke.side_effect = [True, True, True]

        bootstrap.join_ssh("node1")

        mock_start.assert_called_once_with("sshd.service")
        mock_invoke.assert_has_calls([
            mock.call("mkdir -m 700 -p /root/.ssh"),
            mock.call("scp -oStrictHostKeyChecking=no root@node1:'{}*' /root/.ssh".format(SSH_KEY_CRMSH)),
            mock.call("sed -i '/{}/d' /root/.ssh/authorized_keys".format(SSH_KEY_CRMSH_TAG))
            ])
        mock_error.assert_not_called()
        mock_status.assert_called_once_with("Retrieving SSH keys - This may prompt for root@node1:")
        mock_append.assert_called_once_with("{}.pub".format(SSH_KEY_CRMSH), "/root/.ssh/authorized_keys")

    @mock.patch('crmsh.utils.get_nodeinfo_from_cmaptool')
    @mock.patch('crmsh.corosync.add_node_ucast')
    def test_add_nodelist_from_cmaptool(self, mock_add_ucast, mock_nodeinfo):
        mock_nodeinfo.return_value = {'1': ['10.10.10.1', '20.20.20.1'],
                                      '2': ['10.10.10.2', '20.20.20.2']}

        bootstrap.add_nodelist_from_cmaptool()

        mock_nodeinfo.assert_called_once_with()
        mock_add_ucast.assert_has_calls([
            mock.call(['10.10.10.1', '20.20.20.1'], '1'),
            mock.call(['10.10.10.2', '20.20.20.2'], '2')
        ])

    @mock.patch('crmsh.utils.valid_ip_addr')
    @mock.patch('crmsh.utils.get_stdout_stderr')
    def test_get_cluster_node_hostname_None(self, mock_stdout_stderr, mock_valid_ip):
        bootstrap._context = mock.Mock(cluster_node=None)

        peer_node = bootstrap.get_cluster_node_hostname()
        assert peer_node is None

        mock_valid_ip.assert_not_called()
        mock_stdout_stderr.assert_not_called()

    @mock.patch('crmsh.utils.valid_ip_addr')
    @mock.patch('crmsh.utils.get_stdout_stderr')
    def test_get_cluster_node_hostname_IP(self, mock_stdout_stderr, mock_valid_ip):
        bootstrap._context = mock.Mock(cluster_node="1.1.1.1")
        mock_valid_ip.return_value = True
        mock_stdout_stderr.return_value = (0, "node1", None)

        peer_node = bootstrap.get_cluster_node_hostname()
        assert peer_node == "node1"

        mock_valid_ip.assert_called_once_with("1.1.1.1")
        mock_stdout_stderr.assert_called_once_with("ssh -i /root/.ssh/id_rsa.crmsh 1.1.1.1 crm_node --name")

    @mock.patch('crmsh.utils.valid_ip_addr')
    @mock.patch('crmsh.utils.get_stdout_stderr')
    def test_get_cluster_node_hostname_HOST(self, mock_stdout_stderr, mock_valid_ip):
        bootstrap._context = mock.Mock(cluster_node="node2")
        mock_valid_ip.return_value = False

        peer_node = bootstrap.get_cluster_node_hostname()
        assert peer_node == "node2"

        mock_valid_ip.assert_called_once_with("node2")
        mock_stdout_stderr.assert_not_called()

    @mock.patch('crmsh.utils.this_node')
    @mock.patch('re.search')
    @mock.patch('crmsh.bootstrap.get_cluster_node_hostname')
    def test_is_online_local_offline(self, mock_get_peer, mock_search, mock_this_node):
        mock_this_node.return_value = "node1"
        mock_search.return_value = None

        assert bootstrap.is_online("text") is False

        mock_this_node.assert_called_once_with()
        mock_get_peer.assert_not_called()
        mock_search.assert_called_once_with("Online: .* node1 ", "text")

    @mock.patch('crmsh.utils.this_node')
    @mock.patch('re.search')
    @mock.patch('crmsh.bootstrap.get_cluster_node_hostname')
    def test_is_online_on_init_node(self, mock_get_peer, mock_search, mock_this_node):
        mock_search.return_value = mock.Mock()
        mock_this_node.return_value = "node1"
        mock_get_peer.return_value = None

        assert bootstrap.is_online("text") is True

        mock_this_node.assert_called_once_with()
        mock_get_peer.assert_called_once_with()
        mock_search.assert_called_once_with("Online: .* node1 ", "text")

    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.bootstrap.stop_service')
    @mock.patch('crmsh.bootstrap.csync2_update')
    @mock.patch('crmsh.corosync.conf')
    @mock.patch('shutil.copy')
    @mock.patch('crmsh.utils.this_node')
    @mock.patch('re.search')
    @mock.patch('crmsh.bootstrap.get_cluster_node_hostname')
    def test_is_online_peer_offline(self, mock_get_peer, mock_search, mock_this_node,
            mock_copy, mock_corosync_conf, mock_csync2, mock_stop_service, mock_error):
        bootstrap.COROSYNC_CONF_ORIG = "/tmp/crmsh_tmpfile"
        mock_search.side_effect = [ mock.Mock(), None ]
        mock_this_node.return_value = "node2"
        mock_get_peer.return_value = "node1"
        mock_corosync_conf.side_effect = [ "/etc/corosync/corosync.conf", 
                "/etc/corosync/corosync.conf"]

        bootstrap.is_online("text")

        mock_this_node.assert_called_once_with()
        mock_get_peer.assert_called_once_with()
        mock_search.assert_has_calls([
            mock.call("Online: .* node2 ", "text"),
            mock.call("Online: .* node1 ", "text")
            ])
        mock_corosync_conf.assert_has_calls([
            mock.call(),
            mock.call()
            ])
        mock_copy.assert_called_once_with(bootstrap.COROSYNC_CONF_ORIG, "/etc/corosync/corosync.conf")
        mock_csync2.assert_called_once_with("/etc/corosync/corosync.conf")
        mock_stop_service.assert_called_once_with("corosync")
        mock_error.assert_called_once_with("Cannot see peer node \"node1\", please check the communication IP")

    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.bootstrap.stop_service')
    @mock.patch('crmsh.bootstrap.csync2_update')
    @mock.patch('crmsh.corosync.conf')
    @mock.patch('shutil.copy')
    @mock.patch('crmsh.utils.this_node')
    @mock.patch('re.search')
    @mock.patch('crmsh.bootstrap.get_cluster_node_hostname')
    def test_is_online_both_online(self, mock_get_peer, mock_search, mock_this_node,
            mock_copy, mock_corosync_conf, mock_csync2, mock_stop_service, mock_error):
        mock_search.side_effect = [ mock.Mock(), mock.Mock() ]
        mock_this_node.return_value = "node2"
        mock_get_peer.return_value = "node1"

        assert bootstrap.is_online("text") is True

        mock_this_node.assert_called_once_with()
        mock_get_peer.assert_called_once_with()
        mock_search.assert_has_calls([
            mock.call("Online: .* node2 ", "text"),
            mock.call("Online: .* node1 ", "text")
            ])
        mock_corosync_conf.assert_not_called()
        mock_copy.assert_not_called()
        mock_csync2.assert_not_called()
        mock_stop_service.assert_not_called()
        mock_error.assert_not_called()

    @mock.patch('crmsh.bootstrap.invoke')
    def test_csync2_update_no_conflicts(self, mock_invoke):
        mock_invoke.side_effect = [True, True]
        bootstrap.csync2_update("/etc/corosync.conf")
        mock_invoke.assert_has_calls([
            mock.call("csync2 -rm /etc/corosync.conf"),
            mock.call("csync2 -rxv /etc/corosync.conf")
            ])

    @mock.patch('crmsh.bootstrap.warn')
    @mock.patch('crmsh.bootstrap.invoke')
    def test_csync2_update(self, mock_invoke, mock_warn):
        mock_invoke.side_effect = [True, False, True, False]
        bootstrap.csync2_update("/etc/corosync.conf")
        mock_invoke.assert_has_calls([
            mock.call("csync2 -rm /etc/corosync.conf"),
            mock.call("csync2 -rxv /etc/corosync.conf"),
            mock.call("csync2 -rf /etc/corosync.conf"),
            mock.call("csync2 -rxv /etc/corosync.conf")
            ])
        mock_warn.assert_called_once_with("/etc/corosync.conf was not synced")
