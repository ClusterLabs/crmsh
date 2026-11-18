import unittest
from unittest import mock

from crmsh import completers
from crmsh import corosync
from crmsh import ui_cluster
from crmsh import ui_corosync
from crmsh import ui_node
from crmsh import ui_resource


class TestExcludeCompleted(unittest.TestCase):
    def setUp(self):
        self.completer = completers.exclude_completed(completers.choice(['n1', 'n10', 'n2']))

    def test_no_completed(self):
        self.assertEqual(['n1', 'n10', 'n2'], self.completer(['remove', '']))

    def test_exclude_completed(self):
        self.assertEqual(['n10'], self.completer(['remove', 'n1', 'n2', 'n']))

    def test_current_word_is_kept(self):
        self.assertEqual(['n1', 'n10', 'n2'], self.completer(['remove', 'n1']))

    def test_start_index(self):
        completer = completers.exclude_completed(completers.choice(['a', 'b']), start_index=2)
        self.assertEqual(['a', 'b'], completer(['cmd', 'a', '']))
        self.assertEqual(['b'], completer(['cmd', 'x', 'a', '']))


class TestCommandCompleters(unittest.TestCase):
    @mock.patch('crmsh.xmlutil.CrmMonXMLParser')
    def test_cluster_remove_excludes_completed_nodes(self, mock_parser):
        mock_parser.return_value.get_node_list.return_value = ['n1', 'n2', 'n3']
        completer = ui_cluster.Cluster.do_remove._completer
        self.assertEqual(['n1', 'n3'], completer(['remove', 'n2', '']))

    @mock.patch('crmsh.xmlutil.CrmMonXMLParser')
    def test_node_online_completes_all_standby_nodes(self, mock_parser):
        mock_parser.return_value.get_node_list.return_value = ['n1', 'n2', 'n3']
        completer = ui_node.NodeMgmt.do_online._completer
        self.assertEqual(['n2', 'n3'], completer(['online', 'n1', '']))

    @mock.patch('crmsh.xmlutil.CrmMonXMLParser')
    def test_node_standby_completes_remaining_nodes(self, mock_parser):
        mock_parser.return_value.get_node_list.return_value = ['n1', 'n2']
        completer = ui_node.NodeMgmt.do_standby._completer
        self.assertEqual(['n2', 'on', 'off'], completer(['standby', 'n1', '']))
        self.assertEqual(['n1', 'n2', 'off'], completer(['standby', 'on', '']))

    @mock.patch('crmsh.completers.xmlutil.CrmMonXMLParser')
    def test_resource_move_and_ban_complete_only_one_node(self, mock_parser):
        mock_parser.return_value.get_node_list.return_value = ['n1', 'n2']
        for command in (ui_resource.RscMgmt.do_move, ui_resource.RscMgmt.do_ban):
            self.assertEqual(['n1', 'n2'], command._completer(['move', 'rsc1', '']))
            self.assertEqual([], command._completer(['move', 'rsc1', 'n1', '']))

    @mock.patch('crmsh.utils.this_node', return_value='n1')
    @mock.patch('crmsh.utils.list_cluster_nodes', return_value=['n1', 'n2', 'n3'])
    def test_corosync_push_and_pull(self, mock_nodes, mock_this):
        self.assertEqual(['n3'], ui_corosync.Corosync.do_push._completer(['push', 'n2', '']))
        self.assertEqual(['n2', 'n3'], ui_corosync.Corosync.do_pull._completer(['pull', '']))
        self.assertEqual([], ui_corosync.Corosync.do_pull._completer(['pull', 'n2', '']))

    @mock.patch('crmsh.utils.list_cluster_nodes', return_value=['n1', 'n2', 'n3', 'n4'])
    def test_corosync_diff(self, mock_nodes):
        completer = ui_corosync.Corosync.do_diff._completer
        self.assertEqual(['n1', 'n2', 'n3', 'n4'], completer(['diff', '']))
        self.assertEqual(['n3', 'n4'], completer(['diff', 'n1', 'n2', '']))

    @mock.patch('crmsh.utils.list_cluster_nodes', return_value=None)
    def test_corosync_diff_without_cluster(self, mock_nodes):
        self.assertEqual([], ui_corosync.Corosync.do_diff._completer(['diff', '']))

    @mock.patch('crmsh.corosync.LinkManager.load_config_file')
    def test_corosync_link_remove(self, mock_load):
        mock_load.return_value.links.return_value = [
            corosync.Link(0, []), None, corosync.Link(2, []),
        ]
        completer = ui_corosync.Link.do_remove._completer
        self.assertEqual(['0', '2'], completer(['remove', '']))
        self.assertEqual([], completer(['remove', '0', '']))
