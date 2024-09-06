import unittest
from unittest import mock

from crmsh import ui_corosync
from crmsh import corosync
from crmsh.ui_corosync import LinkArgumentParser
from crmsh.corosync import LinkManager
from crmsh.prun import prun


class TestLinkArgumentParser(unittest.TestCase):
    def test_parse_empty(self):
        with self.assertRaises(LinkArgumentParser.SyntaxException):
            LinkArgumentParser().parse(True, True, list())

    def test_invalid_link_number(self):
        with self.assertRaises(LinkArgumentParser.SyntaxException):
            LinkArgumentParser().parse(True, True, ['a0'])

    def test_no_spec(self):
        args = LinkArgumentParser().parse(True, True, ['0'])
        self.assertEqual(0, args.linknumber)
        self.assertFalse(args.nodes)
        self.assertFalse(args.options)

    def test_addr_spec(self):
        args = LinkArgumentParser().parse(True, True, ['0', 'node1=192.0.2.100', 'node2=fd00:a0::10'])
        self.assertEqual(0, args.linknumber)
        self.assertFalse(args.options)
        self.assertListEqual([('node1', '192.0.2.100'), ('node2', 'fd00:a0::10')], args.nodes)

    def test_invalid_addr_spec(self):
        with self.assertRaises(LinkArgumentParser.SyntaxException):
            LinkArgumentParser().parse(True, True, ['0', 'node1=192.0.2.300'])
        with self.assertRaises(LinkArgumentParser.SyntaxException):
            LinkArgumentParser().parse(True, True, ['0', 'node1=fd00::a0::10'])
        with self.assertRaises(LinkArgumentParser.SyntaxException):
            LinkArgumentParser().parse(True, True, ['0', 'node1=node1.example.com'])
        with self.assertRaises(LinkArgumentParser.SyntaxException):
            LinkArgumentParser().parse(True, True, ['0', 'node1=192.0.2'])

    def test_option_spec(self):
        args = LinkArgumentParser().parse(True, True, ['0', 'options', 'node1=192.0.2.100', 'node2=fd00:a0::10', 'foo='])
        self.assertEqual(0, args.linknumber)
        self.assertFalse(args.nodes)
        self.assertDictEqual({'node1': '192.0.2.100', 'node2': 'fd00:a0::10', 'foo': None}, args.options)

    def test_addrs_and_options(self):
        args = LinkArgumentParser().parse(True, True, ['0', 'node1=192.0.2.100', 'node2=fd00:a0::10', 'options', 'foo=bar=1'])
        self.assertEqual(0, args.linknumber)
        self.assertListEqual([('node1', '192.0.2.100'), ('node2', 'fd00:a0::10')], args.nodes)
        self.assertDictEqual({'foo': 'bar=1'}, args.options)

    def test_no_options(self):
        with self.assertRaises(LinkArgumentParser.SyntaxException):
            LinkArgumentParser().parse(True, True, ['0', 'options'])

    def test_garbage_inputs(self):
        with self.assertRaises(LinkArgumentParser.SyntaxException):
            LinkArgumentParser().parse(True, True, ['0', 'foo'])
        with self.assertRaises(LinkArgumentParser.SyntaxException):
            LinkArgumentParser().parse(True, True, ['0', 'node1=192.0.2.100', 'foo'])
        with self.assertRaises(LinkArgumentParser.SyntaxException):
            LinkArgumentParser().parse(True, True, ['0', 'node1=192.0.2.100', 'options', 'foo'])
        with self.assertRaises(LinkArgumentParser.SyntaxException):
            LinkArgumentParser().parse(True, True, ['0', 'node1=192.0.2.100', 'options', 'foo=bar', 'foo'])


@mock.patch('crmsh.prun.prun.prun')
@mock.patch('crmsh.utils.list_cluster_nodes')
@mock.patch('crmsh.service_manager.ServiceManager.service_is_active')
class TestCheckLinkRemovable(unittest.TestCase):
    def setUp(self):
        self.mock_lm = mock.Mock(LinkManager)

    def test_corosync_not_running(self, mock_sia, mock_lcn, mock_prun):
        mock_sia.return_value = False
        ui_corosync.Link._check_link_removable(self.mock_lm, 0)
        mock_sia.assert_called_once()
        mock_lcn.assert_not_called()
        mock_prun.assert_not_called()
        self.mock_lm.links.assert_not_called()

    def test_prun_failure(self, mock_sia, mock_lcn, mock_prun):
        mock_sia.return_value = True
        mock_lcn.return_value = ['node1', 'node2', 'node3']
        mock_prun.return_value = {
            'node2': prun.SSHError('root', 'node2', 'msg'),
        }
        with self.assertRaises(ValueError):
            ui_corosync.Link._check_link_removable(self.mock_lm, 0)
        mock_prun.assert_called_once()
        self.mock_lm.links.assert_not_called()

    def test_cmapctl_failure(self, mock_sia, mock_lcn, mock_prun):
        mock_sia.return_value = True
        mock_lcn.return_value = ['node1', 'node2', 'node3']
        mock_prun.return_value = {
            'node2': prun.ProcessResult(1, b'', b'msg'),
        }
        with self.assertRaises(ValueError):
            ui_corosync.Link._check_link_removable(self.mock_lm, 0)
        mock_prun.assert_called_once()
        self.mock_lm.links.assert_not_called()

    def test_all_links_connected(self, mock_sia, mock_lcn, mock_prun):
        mock_sia.return_value = True
        mock_lcn.return_value = ['node1', 'node2', 'node3']
        mock_prun.return_value = {
            'node1': prun.ProcessResult(
                returncode=0, stderr=b'',
                stdout=b'Local node ID 1, transport knet\n'
                       b'LINK ID 0 udp\n'
                       b'	addr	= 192.0.2.100\n'
                       b'	status:\n'
                       b'		nodeid:          1:	localhost\n'
                       b'		nodeid:          2:	connected\n'
                       b'		nodeid:          3:	connected\n'
                       b'LINK ID 1 udp\n'
                       b'	addr	= 192.0.2.200\n'
                       b'	status:\n'
                       b'		nodeid:          1:	localhost\n'
                       b'		nodeid:          2:	connected\n'
                       b'		nodeid:          3:	connected\n',
            ),
            'node2': prun.ProcessResult(
                returncode=0, stderr=b'',
                stdout=b'Local node ID 1, transport knet\n'
                       b'LINK ID 0 udp\n'
                       b'	addr	= 192.0.2.101\n'
                       b'	status:\n'
                       b'		nodeid:          1:	connected\n'
                       b'		nodeid:          2:	localhost\n'
                       b'		nodeid:          3:	connected\n'
                       b'LINK ID 1 udp\n'
                       b'	addr	= 192.0.2.201\n'
                       b'	status:\n'
                       b'		nodeid:          1:	connected\n'
                       b'		nodeid:          2:	localhost\n'
                       b'		nodeid:          3:	connected\n',
            ),
            'node3': prun.ProcessResult(
                returncode=0, stderr=b'',
                stdout=b'Local node ID 1, transport knet\n'
                       b'LINK ID 0 udp\n'
                       b'	addr	= 192.0.2.102\n'
                       b'	status:\n'
                       b'		nodeid:          1:	connected\n'
                       b'		nodeid:          2:	connected\n'
                       b'		nodeid:          3:	localhost\n'
                       b'LINK ID 1 udp\n'
                       b'	addr	= 192.0.2.202\n'
                       b'	status:\n'
                       b'		nodeid:          1:	connected\n'
                       b'		nodeid:          2:	connected\n'
                       b'		nodeid:          3:	localhost\n',
            ),
        }
        self.mock_lm.links.return_value = [
            corosync.Link(0, [
                corosync.LinkNode(1, 'node1', '192.0.2.100'),
                corosync.LinkNode(2, 'node2', '192.0.2.101'),
                corosync.LinkNode(3, 'node3', '192.0.2.102'),
            ]),
            corosync.Link(1, [
                corosync.LinkNode(1, 'node1', '192.0.2.100'),
                corosync.LinkNode(2, 'node2', '192.0.2.101'),
                corosync.LinkNode(3, 'node3', '192.0.2.102'),
            ]),
            0, 0, 0, 0, 0, 0,
        ]
        ui_corosync.Link._check_link_removable(self.mock_lm, 0)

    def test_one_node_pair_disconnected(self, mock_sia, mock_lcn, mock_prun):
        mock_sia.return_value = True
        mock_lcn.return_value = ['node1', 'node2', 'node3']
        mock_prun.return_value = {
            'node1': prun.ProcessResult(
                returncode=0, stderr=b'',
                stdout=b'Local node ID 1, transport knet\n'
                       b'LINK ID 0 udp\n'
                       b'	addr	= 192.0.2.100\n'
                       b'	status:\n'
                       b'		nodeid:          1:	localhost\n'
                       b'		nodeid:          2:	connected\n'
                       b'		nodeid:          3:	connected\n'
                       b'LINK ID 1 udp\n'
                       b'	addr	= 192.0.2.200\n'
                       b'	status:\n'
                       b'		nodeid:          1:	localhost\n'
                       b'		nodeid:          2:	connected\n'
                       b'		nodeid:          3:	connected\n',
            ),
            'node2': prun.ProcessResult(
                returncode=0, stderr=b'',
                stdout=b'Local node ID 1, transport knet\n'
                       b'LINK ID 0 udp\n'
                       b'	addr	= 192.0.2.101\n'
                       b'	status:\n'
                       b'		nodeid:          1:	connected\n'
                       b'		nodeid:          2:	localhost\n'
                       b'		nodeid:          3:	connected\n'
                       b'LINK ID 1 udp\n'
                       b'	addr	= 192.0.2.201\n'
                       b'	status:\n'
                       b'		nodeid:          1:	connected\n'
                       b'		nodeid:          2:	localhost\n'
                       b'		nodeid:          3:	disconnected\n',
            ),
            'node3': prun.ProcessResult(
                returncode=0, stderr=b'',
                stdout=b'Local node ID 1, transport knet\n'
                       b'LINK ID 0 udp\n'
                       b'	addr	= 192.0.2.102\n'
                       b'	status:\n'
                       b'		nodeid:          1:	connected\n'
                       b'		nodeid:          2:	connected\n'
                       b'		nodeid:          3:	localhost\n'
                       b'LINK ID 1 udp\n'
                       b'	addr	= 192.0.2.202\n'
                       b'	status:\n'
                       b'		nodeid:          1:	connected\n'
                       b'		nodeid:          2:	disconnected\n'
                       b'		nodeid:          3:	localhost\n',
            ),
        }
        self.mock_lm.links.return_value = [
            corosync.Link(0, [
                corosync.LinkNode(1, 'node1', '192.0.2.100'),
                corosync.LinkNode(2, 'node2', '192.0.2.101'),
                corosync.LinkNode(3, 'node3', '192.0.2.102'),
            ]),
            corosync.Link(1, [
                corosync.LinkNode(1, 'node1', '192.0.2.100'),
                corosync.LinkNode(2, 'node2', '192.0.2.101'),
                corosync.LinkNode(3, 'node3', '192.0.2.102'),
            ]),
            0, 0, 0, 0, 0, 0,
        ]
        with self.assertRaises(ValueError):
            ui_corosync.Link._check_link_removable(self.mock_lm, 0)

    def test_pair_connected(self, mock_sia, mock_lcn, mock_prun):
        mock_sia.return_value = True
        mock_lcn.return_value = ['node1', 'node2', 'node3']
        mock_prun.return_value = {
            'node1': prun.ProcessResult(
                returncode=0, stderr=b'',
                stdout=b'Local node ID 1, transport knet\n'
                       b'LINK ID 0 udp\n'
                       b'	addr	= 192.0.2.100\n'
                       b'	status:\n'
                       b'		nodeid:          1:	localhost\n'
                       b'		nodeid:          2:	connected\n'
                       b'		nodeid:          3:	connected\n'
                       b'LINK ID 1 udp\n'
                       b'	addr	= 192.0.2.100\n'
                       b'	status:\n'
                       b'		nodeid:          1:	localhost\n'
                       b'		nodeid:          2:	connected\n'
                       b'		nodeid:          3:	disconnected\n'
                       b'LINK ID 2 udp\n'
                       b'	addr	= 192.0.2.100\n'
                       b'	status:\n'
                       b'		nodeid:          1:	localhost\n'
                       b'		nodeid:          2:	disconnected\n'
                       b'		nodeid:          3:	disconnected\n'
                       b'LINK ID 3 udp\n'
                       b'	addr	= 192.0.2.100\n'
                       b'	status:\n'
                       b'		nodeid:          1:	localhost\n'
                       b'		nodeid:          2:	disconnected\n'
                       b'		nodeid:          3:	connected\n'
            ),
            'node2': prun.ProcessResult(
                returncode=0, stderr=b'',
                stdout=b'Local node ID 1, transport knet\n'
                       b'LINK ID 0 udp\n'
                       b'	addr	= 192.0.2.100\n'
                       b'	status:\n'
                       b'		nodeid:          1:	connected\n'
                       b'		nodeid:          2:	localhost\n'
                       b'		nodeid:          3:	connected\n'
                       b'LINK ID 1 udp\n'
                       b'	addr	= 192.0.2.101\n'
                       b'	status:\n'
                       b'		nodeid:          1:	connected\n'
                       b'		nodeid:          2:	localhost\n'
                       b'		nodeid:          3:	disconnected\n'
                       b'LINK ID 2 udp\n'
                       b'	addr	= 192.0.2.101\n'
                       b'	status:\n'
                       b'		nodeid:          1:	disconnected\n'
                       b'		nodeid:          2:	localhost\n'
                       b'		nodeid:          3:	connected\n'
                       b'LINK ID 3 udp\n'
                       b'	addr	= 192.0.2.101\n'
                       b'	status:\n'
                       b'		nodeid:          1:	disconnected\n'
                       b'		nodeid:          2:	localhost\n'
                       b'		nodeid:          3:	disconnected\n'
            ),
            'node3': prun.ProcessResult(
                returncode=0, stderr=b'',
                stdout=b'Local node ID 1, transport knet\n'
                       b'LINK ID 0 udp\n'
                       b'	addr	= 192.0.2.100\n'
                       b'	status:\n'
                       b'		nodeid:          1:	connected\n'
                       b'		nodeid:          2:	connected\n'
                       b'		nodeid:          3:	localhost\n'
                       b'LINK ID 1 udp\n'
                       b'	addr	= 192.0.2.102\n'
                       b'	status:\n'
                       b'		nodeid:          1:	disconnected\n'
                       b'		nodeid:          2:	disconnected\n'
                       b'		nodeid:          3:	localhost\n'
                       b'LINK ID 2 udp\n'
                       b'	addr	= 192.0.2.102\n'
                       b'	status:\n'
                       b'		nodeid:          1:	disconnected\n'
                       b'		nodeid:          2:	connected\n'
                       b'		nodeid:          3:	localhost\n'
                       b'LINK ID 3 udp\n'
                       b'	addr	= 192.0.2.102\n'
                       b'	status:\n'
                       b'		nodeid:          1:	connected\n'
                       b'		nodeid:          2:	disconnected\n'
                       b'		nodeid:          3:	localhost\n'
            ),
        }
        self.mock_lm.links.return_value = [
            corosync.Link(0, [
                corosync.LinkNode(1, 'node1', '192.0.2.100'),
                corosync.LinkNode(2, 'node2', '192.0.2.101'),
                corosync.LinkNode(3, 'node3', '192.0.2.102'),
            ]),
            corosync.Link(1, [
                corosync.LinkNode(1, 'node1', '192.0.2.100'),
                corosync.LinkNode(2, 'node2', '192.0.2.101'),
                corosync.LinkNode(3, 'node3', '192.0.2.102'),
            ]),
            corosync.Link(2, [
                corosync.LinkNode(1, 'node1', '192.0.2.100'),
                corosync.LinkNode(2, 'node2', '192.0.2.101'),
                corosync.LinkNode(3, 'node3', '192.0.2.102'),
            ]),
            corosync.Link(3, [
                corosync.LinkNode(1, 'node1', '192.0.2.100'),
                corosync.LinkNode(2, 'node2', '192.0.2.101'),
                corosync.LinkNode(3, 'node3', '192.0.2.102'),
            ]),
            0, 0, 0, 0,
        ]
        ui_corosync.Link._check_link_removable(self.mock_lm, 0)
