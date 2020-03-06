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
        mock_rmfile.assert_called_once_with("/root/.ssh/id_rsa")
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

    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.bootstrap.service_is_active')
    @mock.patch('crmsh.bootstrap.init')
    @mock.patch('crmsh.bootstrap.Context')
    def test_bootstrap_remove_cluster_is_active(self, mock_context, mock_init, mock_active,
            mock_error):
        mock_context_inst = mock.Mock()
        mock_context.return_value = mock_context_inst
        mock_active.return_value = False
        mock_error.side_effect = SystemExit

        with self.assertRaises(SystemExit):
             bootstrap.bootstrap_remove(mock_context_inst)

        mock_init.assert_called_once_with()
        mock_active.assert_called_once_with("corosync.service")
        mock_error.assert_called_once_with("Cluster is not active - can't execute removing action")

    @mock.patch('crmsh.bootstrap.prompt_for_string')
    @mock.patch('crmsh.bootstrap.status')
    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.bootstrap.service_is_active')
    @mock.patch('crmsh.bootstrap.init')
    @mock.patch('crmsh.bootstrap.Context')
    def test_bootstrap_remove_no_cluster_node(self, mock_context, mock_init, mock_active,
            mock_error, mock_status, mock_prompt):
        mock_context_inst = mock.Mock(yes_to_all=False, cluster_node=None)
        mock_context.return_value = mock_context_inst
        mock_active.return_value = True
        mock_prompt.return_value = None
        mock_error.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            bootstrap.bootstrap_remove(mock_context_inst)

        mock_init.assert_called_once_with()
        mock_active.assert_called_once_with("corosync.service")
        mock_status.assert_called_once_with('Remove This Node from Cluster:\n  You will be asked for the IP address or name of an existing node,\n  which will be removed from the cluster. This command must be\n  executed from a different node in the cluster.\n')
        mock_prompt.assert_called_once_with("IP address or hostname of cluster node (e.g.: 192.168.1.1)", ".+")
        mock_error.assert_called_once_with("No existing IP/hostname specified (use -c option)")

    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('crmsh.bootstrap.get_cluster_node_hostname')
    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.bootstrap.service_is_active')
    @mock.patch('crmsh.bootstrap.init')
    @mock.patch('crmsh.bootstrap.Context')
    def test_bootstrap_remove_no_confirm(self, mock_context, mock_init, mock_active,
            mock_error, mock_hostname, mock_confirm):
        mock_context_inst = mock.Mock(cluster_node="node1", force=False)
        mock_context.return_value = mock_context_inst
        mock_active.return_value = True
        mock_hostname.return_value = "node1"
        mock_confirm.return_value = False

        bootstrap.bootstrap_remove(mock_context_inst)

        mock_init.assert_called_once_with()
        mock_active.assert_called_once_with("corosync.service")
        mock_error.assert_not_called()
        mock_hostname.assert_called_once_with()
        mock_confirm.assert_called_once_with('Removing node "node1" from the cluster: Are you sure?')

    @mock.patch('crmsh.utils.this_node')
    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('crmsh.bootstrap.get_cluster_node_hostname')
    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.bootstrap.service_is_active')
    @mock.patch('crmsh.bootstrap.init')
    @mock.patch('crmsh.bootstrap.Context')
    def test_bootstrap_remove_self_need_force(self, mock_context, mock_init, mock_active,
            mock_error, mock_hostname, mock_confirm, mock_this_node):
        mock_context_inst = mock.Mock(cluster="node1", force=False)
        mock_context.return_value = mock_context_inst
        mock_active.return_value = True
        mock_hostname.return_value = "node1"
        mock_confirm.return_value = True
        mock_this_node.return_value = "node1"
        mock_error.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            bootstrap.bootstrap_remove(mock_context_inst)

        mock_init.assert_called_once_with()
        mock_active.assert_called_once_with("corosync.service")
        mock_hostname.assert_called_once_with()
        mock_confirm.assert_called_once_with('Removing node "node1" from the cluster: Are you sure?')
        mock_this_node.assert_called_once_with()
        mock_error.assert_called_once_with("Removing self requires --force")

    @mock.patch('crmsh.bootstrap.remove_self')
    @mock.patch('crmsh.utils.this_node')
    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('crmsh.bootstrap.get_cluster_node_hostname')
    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.bootstrap.service_is_active')
    @mock.patch('crmsh.bootstrap.init')
    @mock.patch('crmsh.bootstrap.Context')
    def test_bootstrap_remove_self(self, mock_context, mock_init, mock_active,
            mock_error, mock_hostname, mock_confirm, mock_this_node, mock_self):
        mock_context_inst = mock.Mock(cluster_node="node1", force=True)
        mock_context.return_value = mock_context_inst
        mock_active.return_value = True
        mock_hostname.return_value = "node1"
        mock_this_node.return_value = "node1"

        bootstrap.bootstrap_remove(mock_context_inst)

        mock_init.assert_called_once_with()
        mock_active.assert_called_once_with("corosync.service")
        mock_hostname.assert_called_once_with()
        mock_confirm.assert_not_called()
        mock_this_node.assert_called_once_with()
        mock_error.assert_not_called()
        mock_self.assert_called_once_with()

    @mock.patch('crmsh.xmlutil.listnodes')
    @mock.patch('crmsh.utils.this_node')
    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('crmsh.bootstrap.get_cluster_node_hostname')
    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.bootstrap.service_is_active')
    @mock.patch('crmsh.bootstrap.init')
    @mock.patch('crmsh.bootstrap.Context')
    def test_bootstrap_remove_not_in_cluster(self, mock_context, mock_init, mock_active,
            mock_error, mock_hostname, mock_confirm, mock_this_node, mock_list):
        mock_context_inst = mock.Mock(cluster_node="node2", force=True)
        mock_context.return_value = mock_context_inst
        mock_active.return_value = True
        mock_hostname.return_value = "node2"
        mock_this_node.return_value = "node1"
        mock_list.return_value = ["node1", "node3"]
        mock_error.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            bootstrap.bootstrap_remove(mock_context_inst)

        mock_init.assert_called_once_with()
        mock_active.assert_called_once_with("corosync.service")
        mock_hostname.assert_called_once_with()
        mock_confirm.assert_not_called()
        mock_this_node.assert_called_once_with()
        mock_error.assert_called_once_with("Specified node node2 is not configured in cluster! Unable to remove.")

    @mock.patch('crmsh.bootstrap.remove_node_from_cluster')
    @mock.patch('crmsh.xmlutil.listnodes')
    @mock.patch('crmsh.utils.this_node')
    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('crmsh.bootstrap.get_cluster_node_hostname')
    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.bootstrap.service_is_active')
    @mock.patch('crmsh.bootstrap.init')
    @mock.patch('crmsh.bootstrap.Context')
    def test_bootstrap_remove(self, mock_context, mock_init, mock_active,
            mock_error, mock_hostname, mock_confirm, mock_this_node, mock_list, mock_remove):
        mock_context_inst = mock.Mock(cluster_node="node2", force=True)
        mock_context.return_value = mock_context_inst
        mock_active.return_value = True
        mock_hostname.return_value = "node2"
        mock_this_node.return_value = "node1"
        mock_list.return_value = ["node1", "node2"]

        bootstrap.bootstrap_remove(mock_context_inst)

        mock_init.assert_called_once_with()
        mock_active.assert_called_once_with("corosync.service")
        mock_hostname.assert_called_once_with()
        mock_confirm.assert_not_called()
        mock_this_node.assert_called_once_with()
        mock_error.assert_not_called()
        mock_remove.assert_called_once_with()

    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.utils.ext_cmd_nosudo')
    @mock.patch('crmsh.xmlutil.listnodes')
    def test_remove_self_other_nodes(self, mock_list, mock_ext, mock_error):
        mock_list.return_value = ["node1", "node2"]
        mock_ext.return_value = 1
        mock_error.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            bootstrap._context = mock.Mock(cluster_node="node1", yes_to_all=True)
            bootstrap.remove_self()

        mock_list.assert_called_once_with()
        mock_ext.assert_called_once_with("ssh -o StrictHostKeyChecking=no node2 'crm cluster remove -y -c node1'")
        mock_error.assert_called_once_with("Failed to remove this node from node2")

    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.bootstrap.stop_service')
    @mock.patch('crmsh.xmlutil.listnodes')
    def test_remove_self_stop_failed(self, mock_list, mock_stop_service, mock_error):
        mock_list.return_value = ["node1"]
        mock_stop_service.return_value = False
        mock_error.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            bootstrap._context = mock.Mock(cluster_node="node1", yes_to_all=True)
            bootstrap.remove_self()

        mock_list.assert_called_once_with()
        mock_stop_service.assert_called_once_with("corosync")
        mock_error.assert_called_once_with("Stopping corosync failed")

    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.bootstrap.invoke')
    @mock.patch('crmsh.bootstrap.stop_service')
    @mock.patch('crmsh.xmlutil.listnodes')
    def test_remove_self_rm_failed(self, mock_list, mock_stop_service, mock_invoke, mock_error):
        mock_list.return_value = ["node1"]
        mock_stop_service.return_value = True
        mock_invoke.return_value = False
        mock_error.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            bootstrap._context = mock.Mock(cluster_node="node1", yes_to_all=True)
            bootstrap.remove_self()

        mock_list.assert_called_once_with()
        mock_stop_service.assert_called_once_with("corosync")
        mock_invoke.assert_called_once_with('bash -c "rm -f /etc/sysconfig/sbd /etc/csync2/csync2.cfg /etc/corosync/corosync.conf /etc/csync2/key_hagroup /etc/corosync/authkey /var/lib/heartbeat/crm/* /var/lib/pacemaker/cib/*"')
        mock_error.assert_called_once_with("Deleting the configuration files failed")

    @mock.patch('crmsh.utils.get_iplist_from_name')
    @mock.patch('crmsh.corosync.get_values')
    def test_get_cluster_node_ip_host(self, mock_get_values, mock_get_iplist):
        mock_get_values.return_value = ["node1", "node2"]
        bootstrap._context = mock.Mock(cluster_node="node1")
        bootstrap.get_cluster_node_ip()
        mock_get_values.assert_called_once_with("nodelist.node.ring0_addr")
        mock_get_iplist.assert_not_called()

    @mock.patch('crmsh.utils.get_iplist_from_name')
    @mock.patch('crmsh.corosync.get_values')
    def test_get_cluster_node_ip(self, mock_get_values, mock_get_iplist):
        mock_get_values.return_value = ["10.10.10.1", "10.10.10.2"]
        mock_get_iplist.return_value = ["10.10.10.1"]
        bootstrap._context = mock.Mock(cluster_node="node1")
        bootstrap.get_cluster_node_ip()
        mock_get_values.assert_called_once_with("nodelist.node.ring0_addr")
        mock_get_iplist.assert_called_once_with('node1')

    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.bootstrap.invoke')
    @mock.patch('crmsh.bootstrap.status')
    @mock.patch('crmsh.bootstrap.get_cluster_node_ip')
    def test_remove_node_from_cluster_stop_failed(self, mock_get_ip, mock_status,
            mock_invoke, mock_error):
        mock_invoke.return_value = False
        mock_error.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            bootstrap._context = mock.Mock(cluster_node="node1")
            bootstrap.remove_node_from_cluster()

        mock_get_ip.assert_called_once_with()
        mock_status.assert_called_once_with("Stopping the corosync service")
        mock_invoke.assert_called_once_with('ssh -o StrictHostKeyChecking=no root@node1 "systemctl stop corosync"')
        mock_error.assert_called_once_with("Stopping corosync on node1 failed")

    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.bootstrap.invoke')
    @mock.patch('crmsh.bootstrap.status')
    @mock.patch('crmsh.bootstrap.get_cluster_node_ip')
    def test_remove_node_from_cluster_rm_failed(self, mock_get_ip, mock_status,
            mock_invoke, mock_error):
        mock_invoke.side_effect = [True, False]
        mock_error.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            bootstrap._context = mock.Mock(cluster_node="node1")
            bootstrap.remove_node_from_cluster()

        mock_get_ip.assert_called_once_with()
        mock_status.assert_called_once_with("Stopping the corosync service")
        mock_invoke.assert_has_calls([
            mock.call('ssh -o StrictHostKeyChecking=no root@node1 "systemctl stop corosync"'),
            mock.call('ssh -o StrictHostKeyChecking=no root@node1 "bash -c \\"rm -f /etc/sysconfig/sbd /etc/csync2/csync2.cfg /etc/corosync/corosync.conf /etc/csync2/key_hagroup /etc/corosync/authkey && rm -f /var/lib/heartbeat/crm/* /var/lib/pacemaker/cib/*\\""')
            ])
        mock_error.assert_called_once_with("Deleting the configuration files failed")

    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.bootstrap.invoke')
    @mock.patch('crmsh.bootstrap.status')
    @mock.patch('crmsh.bootstrap.get_cluster_node_ip')
    def test_remove_node_from_cluster_rm_node_failed(self, mock_get_ip, mock_status,
            mock_invoke, mock_error):
        mock_invoke.side_effect = [True, True, False]
        mock_error.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            bootstrap._context = mock.Mock(cluster_node="node1")
            bootstrap.remove_node_from_cluster()

        mock_get_ip.assert_called_once_with()
        mock_status.assert_has_calls([
            mock.call("Stopping the corosync service"),
            mock.call("Removing the node node1")
            ])
        mock_invoke.assert_has_calls([
            mock.call('ssh -o StrictHostKeyChecking=no root@node1 "systemctl stop corosync"'),
            mock.call('ssh -o StrictHostKeyChecking=no root@node1 "bash -c \\"rm -f /etc/sysconfig/sbd /etc/csync2/csync2.cfg /etc/corosync/corosync.conf /etc/csync2/key_hagroup /etc/corosync/authkey && rm -f /var/lib/heartbeat/crm/* /var/lib/pacemaker/cib/*\\""'),
            mock.call('crm node delete node1')
            ])
        mock_error.assert_called_once_with("Failed to remove node1")

    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.bootstrap.invoke')
    @mock.patch('crmsh.bootstrap.status')
    @mock.patch('crmsh.bootstrap.get_cluster_node_ip')
    def test_remove_node_from_cluster_rm_csync_failed(self, mock_get_ip, mock_status,
            mock_invoke, mock_error):
        mock_invoke.side_effect = [True, True, True, False]
        mock_error.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            bootstrap._context = mock.Mock(cluster_node="node1")
            bootstrap.remove_node_from_cluster()

        mock_get_ip.assert_called_once_with()
        mock_status.assert_has_calls([
            mock.call("Stopping the corosync service"),
            mock.call("Removing the node node1")
            ])
        mock_invoke.assert_has_calls([
            mock.call('ssh -o StrictHostKeyChecking=no root@node1 "systemctl stop corosync"'),
            mock.call('ssh -o StrictHostKeyChecking=no root@node1 "bash -c \\"rm -f /etc/sysconfig/sbd /etc/csync2/csync2.cfg /etc/corosync/corosync.conf /etc/csync2/key_hagroup /etc/corosync/authkey && rm -f /var/lib/heartbeat/crm/* /var/lib/pacemaker/cib/*\\""'),
            mock.call('crm node delete node1'),
            mock.call("sed -i /node1/d {}".format(bootstrap.CSYNC2_CFG))
            ])
        mock_error.assert_called_once_with("Removing the node node1 from {} failed".format(bootstrap.CSYNC2_CFG))

    @mock.patch('crmsh.bootstrap.csync2_update')
    @mock.patch('crmsh.bootstrap.decrease_expected_votes')
    @mock.patch('crmsh.corosync.del_node')
    @mock.patch('crmsh.utils.is_unicast')
    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.bootstrap.invoke')
    @mock.patch('crmsh.bootstrap.status')
    @mock.patch('crmsh.bootstrap.get_cluster_node_ip')
    def test_remove_node_from_cluster_hostname(self, mock_get_ip, mock_status,
            mock_invoke, mock_error, mock_unicast, mock_del, mock_decrease, mock_csync2):
        mock_invoke.side_effect = [True, True, True, True, True]
        mock_unicast.return_value = True

        bootstrap._context = mock.Mock(cluster_node="node1", cluster_node_ip=None)
        bootstrap.remove_node_from_cluster()

        mock_get_ip.assert_called_once_with()
        mock_status.assert_has_calls([
            mock.call("Stopping the corosync service"),
            mock.call("Removing the node node1"),
            mock.call("Propagating configuration changes across the remaining nodes")
            ])
        mock_invoke.assert_has_calls([
            mock.call('ssh -o StrictHostKeyChecking=no root@node1 "systemctl stop corosync"'),
            mock.call('ssh -o StrictHostKeyChecking=no root@node1 "bash -c \\"rm -f /etc/sysconfig/sbd /etc/csync2/csync2.cfg /etc/corosync/corosync.conf /etc/csync2/key_hagroup /etc/corosync/authkey && rm -f /var/lib/heartbeat/crm/* /var/lib/pacemaker/cib/*\\""'),
            mock.call('crm node delete node1'),
            mock.call("sed -i /node1/d {}".format(bootstrap.CSYNC2_CFG)),
            mock.call("corosync-cfgtool -R")
            ])
        mock_error.assert_not_called()
        mock_unicast.assert_called_once_with()
        mock_del.assert_called_once_with("node1")
        mock_decrease.assert_called_once_with()
        mock_csync2.assert_has_calls([
            mock.call(bootstrap.CSYNC2_CFG),
            mock.call("/etc/corosync/corosync.conf")
            ])
