from __future__ import print_function
from __future__ import unicode_literals
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.
#
# unit tests for parse.py

from builtins import str
from builtins import object
import os
import unittest
from unittest import mock
from crmsh import corosync
from crmsh.corosync import Parser, make_section, make_value


F1 = open(os.path.join(os.path.dirname(__file__), 'corosync.conf.1')).read()
F2 = open(os.path.join(os.path.dirname(__file__), 'corosync.conf.2')).read()
F3 = open(os.path.join(os.path.dirname(__file__), 'bug-862577_corosync.conf')).read()


def _valid(parser):
    depth = 0
    for t in parser._tokens:
        if t.token not in (corosync._tCOMMENT,
                           corosync._tBEGIN,
                           corosync._tEND,
                           corosync._tVALUE):
            raise AssertionError("illegal token " + str(t))
        if t.token == corosync._tBEGIN:
            depth += 1
        if t.token == corosync._tEND:
            depth -= 1
    if depth != 0:
        raise AssertionError("Unbalanced sections")


def _print(parser):
    print(parser.to_string())


class TestCorosyncParser(unittest.TestCase):
    def test_parse(self):
        p = Parser(F1)
        _valid(p)
        self.assertEqual(p.get('logging.logfile'), '/var/log/cluster/corosync.log')
        self.assertEqual(p.get('totem.interface.ttl'), '1')
        p.set('totem.interface.ttl', '2')
        _valid(p)
        self.assertEqual(p.get('totem.interface.ttl'), '2')
        p.remove('quorum')
        _valid(p)
        self.assertEqual(p.count('quorum'), 0)
        p.add('', make_section('quorum', []))
        _valid(p)
        self.assertEqual(p.count('quorum'), 1)
        p.set('quorum.votequorum', '2')
        _valid(p)
        self.assertEqual(p.get('quorum.votequorum'), '2')
        p.set('bananas', '5')
        _valid(p)
        self.assertEqual(p.get('bananas'), '5')

    def test_logfile(self):
        self.assertEqual(corosync.logfile(F1), '/var/log/cluster/corosync.log')
        self.assertEqual(corosync.logfile('# nothing\n'), None)

    def test_udpu(self):
        p = Parser(F2)
        _valid(p)
        self.assertEqual(p.count('nodelist.node'), 5)
        p.add('nodelist',
              make_section('nodelist.node',
                           make_value('nodelist.node.ring0_addr', '10.10.10.10') +
                           make_value('nodelist.node.nodeid', str(corosync.get_free_nodeid(p)))))
        _valid(p)
        self.assertEqual(p.count('nodelist.node'), 6)
        self.assertEqual(p.get_all('nodelist.node.nodeid'),
                         ['1', '2', '3'])

    def test_add_node_no_nodelist(self):
        "test checks that if there is no nodelist, no node is added"
        from crmsh.corosync import make_section, make_value, get_free_nodeid

        p = Parser(F1)
        _valid(p)
        nid = get_free_nodeid(p)
        self.assertEqual(p.count('nodelist.node'), nid - 1)
        p.add('nodelist',
              make_section('nodelist.node',
                           make_value('nodelist.node.ring0_addr', 'foo') +
                           make_value('nodelist.node.nodeid', str(nid))))
        _valid(p)
        self.assertEqual(p.count('nodelist.node'), nid - 1)
 
    @mock.patch("crmsh.utils.is_ipv6")
    @mock.patch("crmsh.utils.ip_in_local")
    @mock.patch("re.search")
    @mock.patch("crmsh.corosync.Parser")
    @mock.patch("crmsh.corosync.conf")
    @mock.patch("builtins.open", new_callable=mock.mock_open, read_data="corosync conf data")
    def test_find_configured_ip_no_exception(self, mock_open_file, mock_conf, mock_parser, mock_search, mock_ip_local, mock_isv6):
        mock_conf.return_value = "/etc/corosync/corosync.conf"
        mock_parser_inst = mock.Mock()
        mock_parser.return_value = mock_parser_inst
        mock_parser_inst.all_paths.return_value = ["nodelist.node.ring0_addr"]
        mock_search.return_value = mock.Mock()
        mock_parser_inst.get_all.return_value = ["10.10.10.1"]
        mock_isv6.return_value = False
        mock_ip_local.return_value = ["192.168.1.1", "10.10.10.2", "20.20.20.2"]

        corosync.find_configured_ip(["10.10.10.2"])

        mock_conf.assert_called_once_with()
        mock_parser_inst.all_paths.assert_called_once_with()
        mock_parser_inst.get_all.assert_called_once_with("nodelist.node.ring0_addr")
        mock_open_file.assert_called_once_with(mock_conf.return_value)
        mock_isv6.assert_called_once_with("10.10.10.2")
        mock_ip_local.assert_called_once_with(False)
        mock_search.assert_called_once_with("nodelist.node.ring[0-9]*_addr", "nodelist.node.ring0_addr")

    @mock.patch("crmsh.utils.is_ipv6")
    @mock.patch("crmsh.utils.ip_in_local")
    @mock.patch("re.search")
    @mock.patch("crmsh.corosync.Parser")
    @mock.patch("crmsh.corosync.conf")
    @mock.patch("builtins.open", new_callable=mock.mock_open, read_data="corosync conf data")
    def test_find_configured_ip_exception(self, mock_open_file, mock_conf, mock_parser, mock_search, mock_ip_local, mock_isv6):
        mock_conf.return_value = "/etc/corosync/corosync.conf"
        mock_parser_inst = mock.Mock()
        mock_parser.return_value = mock_parser_inst
        mock_parser_inst.all_paths.return_value = ["nodelist.node.ring0_addr"]
        mock_search.return_value = mock.Mock()
        mock_parser_inst.get_all.return_value = ["10.10.10.1", "10.10.10.2"]
        mock_isv6.return_value = False
        mock_ip_local.return_value = ["192.168.1.1", "10.10.10.2", "20.20.20.2"]

        with self.assertRaises(corosync.IPAlreadyConfiguredError) as err:
            corosync.find_configured_ip(["10.10.10.2"])
        self.assertEqual("IP 10.10.10.2 was already configured", str(err.exception))

        mock_conf.assert_called_once_with()
        mock_parser_inst.all_paths.assert_called_once_with()
        mock_parser_inst.get_all.assert_called_once_with("nodelist.node.ring0_addr")
        mock_open_file.assert_called_once_with(mock_conf.return_value)
        mock_isv6.assert_called_once_with("10.10.10.2")
        mock_ip_local.assert_called_once_with(False)
        mock_search.assert_called_once_with("nodelist.node.ring[0-9]*_addr", "nodelist.node.ring0_addr")

    def test_add_node_ucast(self):
        from crmsh.corosync import add_node_ucast, get_values

        os.environ["COROSYNC_MAIN_CONFIG_FILE"] = os.path.join(os.path.dirname(__file__), 'corosync.conf.2')

        exist_iplist = get_values('nodelist.node.ring0_addr')
        try:
            add_node_ucast(['10.10.10.11'])
        except corosync.IPAlreadyConfiguredError:
            self.fail("corosync.add_node_ucast raised ValueError unexpectedly!")
        now_iplist = get_values('nodelist.node.ring0_addr')
        self.assertEqual(len(exist_iplist) + 1, len(now_iplist))
        self.assertTrue('10.10.10.11' in get_values('nodelist.node.ring0_addr'))

        # bsc#1127095, 1127096; address 10.10.10.11 already exist
        with self.assertRaises(corosync.IPAlreadyConfiguredError) as err:
            add_node_ucast(['10.10.10.11'])
        self.assertEqual("IP 10.10.10.11 was already configured", str(err.exception))
        now_iplist = get_values('nodelist.node.ring0_addr')
        self.assertEqual(len(exist_iplist) + 1, len(now_iplist))

    def test_add_node_nodelist(self):
        from crmsh.corosync import make_section, make_value, get_free_nodeid

        p = Parser(F2)
        _valid(p)
        nid = get_free_nodeid(p)
        c = p.count('nodelist.node')
        p.add('nodelist',
              make_section('nodelist.node',
                           make_value('nodelist.node.ring0_addr', 'foo') +
                           make_value('nodelist.node.nodeid', str(nid))))
        _valid(p)
        self.assertEqual(p.count('nodelist.node'), c + 1)
        self.assertEqual(get_free_nodeid(p), nid + 1)

    def test_remove_node(self):
        p = Parser(F2)
        _valid(p)
        self.assertEqual(p.count('nodelist.node'), 5)
        p.remove_section_where('nodelist.node', 'nodeid', '2')
        _valid(p)
        self.assertEqual(p.count('nodelist.node'), 4)
        self.assertEqual(p.get_all('nodelist.node.nodeid'),
                         ['1'])

    def test_bnc862577(self):
        p = Parser(F3)
        _valid(p)
        self.assertEqual(p.count('service.ver'), 1)

    def test_get_free_nodeid(self):
        def ids(*lst):
            class Ids(object):
                def get_all(self, _arg):
                    return lst
            return Ids()
        self.assertEqual(1, corosync.get_free_nodeid(ids('2', '5')))
        self.assertEqual(3, corosync.get_free_nodeid(ids('1', '2', '5')))
        self.assertEqual(4, corosync.get_free_nodeid(ids('1', '2', '3')))

if __name__ == '__main__':
    unittest.main()
