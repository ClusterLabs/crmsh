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

    @mock.patch('crmsh.bootstrap.append')
    @mock.patch('crmsh.bootstrap.status')
    @mock.patch('os.path.exists')
    @mock.patch('crmsh.bootstrap.start_service')
    @mock.patch('crmsh.bootstrap.invoke')
    def test_init_ssh_no_exist_keys(self, mock_invoke, mock_start_service,
                                    mock_exists, mock_status, mock_append):
        mock_exists.return_value = False

        bootstrap.init_ssh()

        mock_start_service.assert_called_once_with("sshd.service")
        mock_invoke.assert_has_calls([
            mock.call("mkdir -m 700 -p /root/.ssh"),
            mock.call("ssh-keygen -q -f /root/.ssh/id_rsa -C 'Cluster Internal' -N ''")
        ])
        mock_exists.assert_called_once_with("/root/.ssh/id_rsa")
        mock_status.assert_called_once_with("Generating SSH key")
        mock_append.assert_called_once_with("/root/.ssh/id_rsa.pub", "/root/.ssh/authorized_keys")

    @mock.patch('crmsh.bootstrap.append')
    @mock.patch('crmsh.bootstrap.status')
    @mock.patch('os.remove')
    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('os.path.exists')
    @mock.patch('crmsh.bootstrap.start_service')
    @mock.patch('crmsh.bootstrap.invoke')
    def test_init_ssh_exits_keys_yes_to_all_confirm(self, mock_invoke, mock_start_service,
                         mock_exists, mock_confirm, mock_rmfile, mock_status, mock_append):
        mock_exists.return_value = True
        bootstrap._context = mock.Mock(yes_to_all=True, no_overwrite_sshkey=False)
        mock_confirm.return_value = True

        bootstrap.init_ssh()

        mock_start_service.assert_called_once_with("sshd.service")
        mock_invoke.assert_has_calls([
            mock.call("mkdir -m 700 -p /root/.ssh"),
            mock.call("ssh-keygen -q -f /root/.ssh/id_rsa -C 'Cluster Internal' -N ''")
        ])
        mock_exists.assert_called_once_with("/root/.ssh/id_rsa")
        mock_confirm.assert_called_once_with("/root/.ssh/id_rsa already exists - overwrite?")
        mock_rmfile.assert_has_calls([
            mock.call("/root/.ssh/id_rsa"),
            mock.call("/root/.ssh/authorized_keys")
            ])
        mock_status.assert_called_once_with("Generating SSH key")
        mock_append.assert_called_once_with("/root/.ssh/id_rsa.pub", "/root/.ssh/authorized_keys")

    @mock.patch('os.remove')
    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('os.path.exists')
    @mock.patch('crmsh.bootstrap.start_service')
    @mock.patch('crmsh.bootstrap.invoke')
    def test_init_ssh_exits_keys_no_overwrite(self, mock_invoke, mock_start_service,
                                              mock_exists, mock_confirm, mock_rmfile):
        mock_exists.return_value = True
        bootstrap._context = mock.Mock(yes_to_all=True, no_overwrite_sshkey=True)

        bootstrap.init_ssh()

        mock_start_service.assert_called_once_with("sshd.service")
        mock_invoke.assert_called_once_with("mkdir -m 700 -p /root/.ssh")
        mock_exists.assert_called_once_with("/root/.ssh/id_rsa")
        mock_confirm.assert_not_called()
        mock_rmfile.assert_not_called()

    def test_pick_default_value(self):
        default_list = ["10.10.10.1", "20.20.20.1"]
        prev_list = ["10.10.10.1"]
        value = bootstrap.pick_default_value(default_list, prev_list)
        self.assertEqual(value, "20.20.20.1")

        default_list = ["10.10.10.1", "20.20.20.1"]
        prev_list = []
        value = bootstrap.pick_default_value(default_list, prev_list)
        self.assertEqual(value, "10.10.10.1")

        default_list = ["10.10.10.1", "20.20.20.1"]
        prev_list = ["10.10.10.1", "20.20.20.1"]
        value = bootstrap.pick_default_value(default_list, prev_list)
        self.assertEqual(value, "")

    @mock.patch('__builtin__.open')
    @mock.patch('crmsh.bootstrap.append_to_file')
    @mock.patch('os.path.join')
    @mock.patch('os.path.exists')
    def test_init_ssh_remote(self, mock_exists, mock_join, mock_append, mock_open_file):
        mock_exists.side_effect = [False, True, False, False, False]
        mock_join.side_effect = ["/root/.ssh/id_rsa",
                                 "/root/.ssh/id_dsa",
                                 "/root/.ssh/id_ecdsa",
                                 "/root/.ssh/id_ed25519"]
        mock_open_file.return_value = mock.mock_open().return_value

        bootstrap.init_ssh_remote()

        mock_open_file.assert_called_once_with("/root/.ssh/authorized_keys", 'w')
        mock_exists.assert_has_calls([
            mock.call("/root/.ssh/authorized_keys"),
            mock.call("/root/.ssh/id_rsa"),
            mock.call("/root/.ssh/id_dsa"),
            mock.call("/root/.ssh/id_ecdsa"),
            mock.call("/root/.ssh/id_ed25519"),
        ])
        mock_append.assert_called_once_with("/root/.ssh/id_rsa.pub", "/root/.ssh/authorized_keys")

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
        mock_stdout_stderr.assert_called_once_with("ssh 1.1.1.1 crm_node --name")

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

    @mock.patch('os.path.exists')
    def test_append_to_file_no_exist(self, mock_exists):
        mock_exists.return_value = False
        bootstrap.append_to_file("file1", "file2")
        mock_exists.assert_called_once_with("file1")

    @mock.patch('crmsh.bootstrap.append')
    @mock.patch('crmsh.bootstrap.grep_file')
    @mock.patch('__builtin__.open', new_callable=mock.mock_open, read_data='data')
    @mock.patch('os.path.exists')
    def test_append_to_file(self, mock_exists, mock_open_file, mock_grep, mock_append):
        mock_exists.return_value = True
        mock_grep.return_value = False

        bootstrap.append_to_file("file1", "file2")

        mock_exists.assert_called_once_with("file1")
        mock_open_file.assert_called_once_with("file1")
        mock_grep.assert_called_once_with("file2", "data")
        mock_append.assert_called_once_with("file1", "file2")
