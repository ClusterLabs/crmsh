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
import pytest
from unittest import mock
from crmsh import corosync
from crmsh.corosync import Parser, make_section, make_value


F1 = open(os.path.join(os.path.dirname(__file__), 'corosync.conf.1')).read()
F2 = open(os.path.join(os.path.dirname(__file__), 'corosync.conf.2')).read()
F3 = open(os.path.join(os.path.dirname(__file__), 'bug-862577_corosync.conf')).read()
F4 = open(os.path.join(os.path.dirname(__file__), 'corosync.conf.3')).read()


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


def test_query_status_exception():
    with pytest.raises(ValueError) as err:
        corosync.query_status("test")
    assert str(err.value) == "Wrong type \"test\" to query status"


@mock.patch('crmsh.corosync.query_ring_status')
def test_query_status(mock_ring_status):
    corosync.query_status("ring")
    mock_ring_status.assert_called_once_with()


@mock.patch('crmsh.utils.is_qdevice_configured')
def test_query_qdevice_status_exception(mock_configured):
    mock_configured.return_value = False
    with pytest.raises(ValueError) as err:
        corosync.query_qdevice_status()
    assert str(err.value) == "QDevice/QNetd not configured!"
    mock_configured.assert_called_once_with()


@mock.patch('crmsh.utils.print_cluster_nodes')
@mock.patch('crmsh.utils.get_stdout_or_raise_error')
@mock.patch('crmsh.utils.is_qdevice_configured')
def test_query_qdevice_status(mock_configured, mock_run, mock_print):
    mock_configured.return_value = True
    corosync.query_qdevice_status()
    mock_run.assert_called_once_with("corosync-qdevice-tool -sv")
    mock_print.assert_called_once_with()


@mock.patch("crmsh.corosync.query_ring_status")
def test_query_status_ring(mock_ring_status):
    corosync.query_status("ring")
    mock_ring_status.assert_called_once_with()


@mock.patch("crmsh.corosync.query_quorum_status")
def test_query_status_quorum(mock_quorum_status):
    corosync.query_status("quorum")
    mock_quorum_status.assert_called_once_with()


@mock.patch("crmsh.corosync.query_qnetd_status")
def test_query_status_qnetd(mock_qnetd_status):
    corosync.query_status("qnetd")
    mock_qnetd_status.assert_called_once_with()


def test_query_status_except():
    with pytest.raises(ValueError) as err:
        corosync.query_status("xxx")
    assert str(err.value) == "Wrong type \"xxx\" to query status"


@mock.patch("crmsh.utils.get_stdout_stderr")
def test_query_ring_status_except(mock_run):
    mock_run.return_value = (1, None, "error")
    with pytest.raises(ValueError) as err:
        corosync.query_ring_status()
    assert str(err.value) == "error"
    mock_run.assert_called_once_with("corosync-cfgtool -s")


@mock.patch("crmsh.utils.get_stdout_stderr")
def test_query_ring_status(mock_run):
    mock_run.return_value = (0, "data", None)
    corosync.query_ring_status()
    mock_run.assert_called_once_with("corosync-cfgtool -s")


@mock.patch("crmsh.utils.print_cluster_nodes")
@mock.patch("crmsh.utils.get_stdout_stderr")
def test_query_quorum_status_except(mock_run, mock_print_nodes):
    mock_run.return_value = (1, None, "error")
    with pytest.raises(ValueError) as err:
        corosync.query_quorum_status()
    assert str(err.value) == "error"
    mock_run.assert_called_once_with("corosync-quorumtool -s")
    mock_print_nodes.assert_called_once_with()


@mock.patch("crmsh.utils.print_cluster_nodes")
@mock.patch("crmsh.utils.get_stdout_stderr")
def test_query_quorum_status(mock_run, mock_print_nodes):
    mock_run.return_value = (0, "data", None)
    corosync.query_quorum_status()
    mock_run.assert_called_once_with("corosync-quorumtool -s")
    mock_print_nodes.assert_called_once_with()


@mock.patch("crmsh.utils.print_cluster_nodes")
@mock.patch("crmsh.utils.get_stdout_stderr")
def test_query_quorum_status_no_quorum(mock_run, mock_print_nodes):
    mock_run.return_value = (2, "no quorum", None)
    corosync.query_quorum_status()
    mock_run.assert_called_once_with("corosync-quorumtool -s")
    mock_print_nodes.assert_called_once_with()


@mock.patch("crmsh.utils.is_qdevice_configured")
def test_query_qnetd_status_no_qdevice(mock_qdevice_configured):
    mock_qdevice_configured.return_value = False
    with pytest.raises(ValueError) as err:
        corosync.query_qnetd_status()
    assert str(err.value) == "QDevice/QNetd not configured!"
    mock_qdevice_configured.assert_called_once_with()


@mock.patch("crmsh.corosync.get_value")
@mock.patch("crmsh.utils.is_qdevice_configured")
def test_query_qnetd_status_no_cluster_name(mock_qdevice_configured, mock_get_value):
    mock_qdevice_configured.return_value = True
    mock_get_value.return_value = None
    with pytest.raises(ValueError) as err:
        corosync.query_qnetd_status()
    assert str(err.value) == "cluster_name not configured!"
    mock_qdevice_configured.assert_called_once_with()
    mock_get_value.assert_called_once_with("totem.cluster_name")


@mock.patch("crmsh.corosync.get_value")
@mock.patch("crmsh.utils.is_qdevice_configured")
def test_query_qnetd_status_no_host(mock_qdevice_configured, mock_get_value):
    mock_qdevice_configured.return_value = True
    mock_get_value.side_effect = ["hacluster", None]
    with pytest.raises(ValueError) as err:
        corosync.query_qnetd_status()
    assert str(err.value) == "host for qnetd not configured!"
    mock_qdevice_configured.assert_called_once_with()
    mock_get_value.assert_has_calls([
        mock.call("totem.cluster_name"),
        mock.call("quorum.device.net.host")
        ])


@mock.patch('crmsh.utils.user_of')
@mock.patch("crmsh.parallax.parallax_call")
@mock.patch("crmsh.utils.ssh_copy_id")
@mock.patch("crmsh.utils.check_ssh_passwd_need")
@mock.patch("crmsh.corosync.get_value")
@mock.patch("crmsh.utils.is_qdevice_configured")
def test_query_qnetd_status_copy_id_failed(mock_qdevice_configured,
        mock_get_value, mock_check_passwd, mock_ssh_copy_id, mock_parallax_call, mock_userof):
    mock_userof.side_effect = [
        "alice",
        "root",
    ]
    mock_parallax_call.side_effect = ValueError("Failed on 10.10.10.123: foo")
    mock_qdevice_configured.return_value = True
    mock_get_value.side_effect = ["hacluster", "10.10.10.123"]
    mock_check_passwd.return_value = True
    with pytest.raises(ValueError) as err:
        corosync.query_qnetd_status()
    assert err.value.args[0] == "Failed on 10.10.10.123: foo"
    mock_qdevice_configured.assert_called_once_with()
    mock_get_value.assert_has_calls([
        mock.call("totem.cluster_name"),
        mock.call("quorum.device.net.host")
        ])
    mock_check_passwd.assert_called_once_with("alice", "root", "10.10.10.123")
    mock_ssh_copy_id.assert_called_once_with('alice', 'root', '10.10.10.123')


@mock.patch('crmsh.utils.user_of')
@mock.patch("crmsh.utils.print_cluster_nodes")
@mock.patch("crmsh.parallax.parallax_call")
@mock.patch("crmsh.utils.ssh_copy_id")
@mock.patch("crmsh.utils.check_ssh_passwd_need")
@mock.patch("crmsh.corosync.get_value")
@mock.patch("crmsh.utils.is_qdevice_configured")
def test_query_qnetd_status_copy(mock_qdevice_configured, mock_get_value,
        mock_check_passwd, mock_ssh_copy_id, mock_parallax_call, mock_print_nodes,
        mock_userof):
    mock_userof.side_effect = [
        "alice",
        "root",
    ]
    mock_qdevice_configured.return_value = True
    mock_get_value.side_effect = ["hacluster", "10.10.10.123"]
    mock_check_passwd.return_value = True
    mock_parallax_call.return_value = [("node1", (0, "data", None)), ]

    corosync.query_qnetd_status()

    mock_qdevice_configured.assert_called_once_with()
    mock_get_value.assert_has_calls([
        mock.call("totem.cluster_name"),
        mock.call("quorum.device.net.host")
        ])
    mock_check_passwd.assert_called_once_with("alice", "root", "10.10.10.123")
    mock_ssh_copy_id.assert_called_once_with('alice', 'root', '10.10.10.123')
    mock_parallax_call.assert_called_once_with(["10.10.10.123"], "corosync-qnetd-tool -lv -c hacluster")
    mock_print_nodes.assert_called_once_with()


@mock.patch('crmsh.utils.get_nodeinfo_from_cmaptool')
@mock.patch('crmsh.corosync.add_node_ucast')
def test_add_nodelist_from_cmaptool(mock_add_ucast, mock_nodeinfo):
    mock_nodeinfo.return_value = {'1': ['10.10.10.1', '20.20.20.1'],'2': ['10.10.10.2', '20.20.20.2']}

    corosync.add_nodelist_from_cmaptool()

    mock_nodeinfo.assert_called_once_with()
    mock_add_ucast.assert_has_calls([
        mock.call(['10.10.10.1', '20.20.20.1'], '1'),
        mock.call(['10.10.10.2', '20.20.20.2'], '2')
        ])


@mock.patch("crmsh.corosync.get_value")
def test_is_unicast(mock_get_value):
    mock_get_value.return_value = "udpu"
    assert corosync.is_unicast() is True
    mock_get_value.assert_called_once_with("totem.transport")


@mock.patch('crmsh.corosync.get_corosync_value_dict')
def test_token_and_consensus_timeout(mock_get_dict):
    mock_get_dict.return_value = {"token": 10, "consensus": 12}
    assert corosync.token_and_consensus_timeout() == 22


@mock.patch('crmsh.corosync.get_corosync_value')
def test_get_corosync_value_dict(mock_get_value):
    mock_get_value.side_effect = ["10000", None]
    res = corosync.get_corosync_value_dict()
    assert res == {"token": 10, "consensus": 12}


@mock.patch('crmsh.corosync.get_value')
@mock.patch('crmsh.utils.get_stdout_or_raise_error')
def test_get_corosync_value_raise(mock_run, mock_get_value):
    mock_run.side_effect = ValueError
    mock_get_value.return_value = None
    assert corosync.get_corosync_value("xxx") is None
    mock_run.assert_called_once_with("corosync-cmapctl xxx")
    mock_get_value.assert_called_once_with("xxx")


@mock.patch('crmsh.utils.get_stdout_or_raise_error')
def test_get_corosync_value(mock_run):
    mock_run.return_value = "totem.token = 10000"
    assert corosync.get_corosync_value("totem.token") == "10000"
    mock_run.assert_called_once_with("corosync-cmapctl totem.token")


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
 
    @mock.patch("crmsh.utils.InterfacesInfo.get_local_ip_list")
    @mock.patch("crmsh.utils.IP.is_ipv6")
    @mock.patch("re.search")
    @mock.patch("crmsh.corosync.Parser")
    @mock.patch("crmsh.corosync.conf")
    @mock.patch("crmsh.utils.read_from_file")
    def test_find_configured_ip_no_exception(self, mock_read_file, mock_conf, mock_parser, mock_search, mock_isv6, mock_ip_local):
        mock_conf.return_value = "/etc/corosync/corosync.conf"
        mock_parser_inst = mock.Mock()
        mock_parser.return_value = mock_parser_inst
        mock_parser_inst.all_paths.return_value = ["nodelist.node.ring0_addr"]
        mock_read_file.return_value = "data"
        mock_search.return_value = mock.Mock()
        mock_parser_inst.get_all.return_value = ["10.10.10.1"]
        mock_isv6.return_value = False
        mock_ip_local.return_value = ["192.168.1.1", "10.10.10.2", "20.20.20.2"]

        corosync.find_configured_ip(["10.10.10.2"])

        mock_conf.assert_called_once_with()
        mock_parser.assert_called_once_with("data")
        mock_parser_inst.all_paths.assert_called_once_with()
        mock_parser_inst.get_all.assert_called_once_with("nodelist.node.ring0_addr")
        mock_isv6.assert_called_once_with("10.10.10.2")
        mock_ip_local.assert_called_once_with(False)
        mock_search.assert_called_once_with("nodelist.node.ring[0-9]*_addr", "nodelist.node.ring0_addr")

    @mock.patch("crmsh.utils.InterfacesInfo.get_local_ip_list")
    @mock.patch("crmsh.utils.IP.is_ipv6")
    @mock.patch("re.search")
    @mock.patch("crmsh.corosync.Parser")
    @mock.patch("crmsh.corosync.conf")
    @mock.patch("crmsh.utils.read_from_file")
    def test_find_configured_ip_exception(self, mock_read_file, mock_conf, mock_parser, mock_search, mock_isv6, mock_ip_local):
        mock_conf.return_value = "/etc/corosync/corosync.conf"
        mock_parser_inst = mock.Mock()
        mock_parser.return_value = mock_parser_inst
        mock_parser_inst.all_paths.return_value = ["nodelist.node.ring0_addr"]
        mock_read_file.return_value = "data"
        mock_search.return_value = mock.Mock()
        mock_parser_inst.get_all.return_value = ["10.10.10.1", "10.10.10.2"]
        mock_isv6.return_value = False
        mock_ip_local.return_value = ["192.168.1.1", "10.10.10.2", "20.20.20.2"]

        with self.assertRaises(corosync.IPAlreadyConfiguredError) as err:
            corosync.find_configured_ip(["10.10.10.2"])
        self.assertEqual("IP 10.10.10.2 was already configured", str(err.exception))

        mock_conf.assert_called_once_with()
        mock_parser.assert_called_once_with("data")
        mock_parser_inst.all_paths.assert_called_once_with()
        mock_parser_inst.get_all.assert_called_once_with("nodelist.node.ring0_addr")
        mock_isv6.assert_called_once_with("10.10.10.2")
        mock_ip_local.assert_called_once_with(False)
        # For some reason mock_search.assert_called_once_with does not work
        mock_search.assert_has_calls([mock.call("nodelist.node.ring[0-9]*_addr", "nodelist.node.ring0_addr")])

    @mock.patch("crmsh.utils.str2file")
    @mock.patch("crmsh.corosync.make_section")
    @mock.patch("crmsh.corosync.get_values")
    @mock.patch("crmsh.corosync.make_value")
    @mock.patch("crmsh.corosync.get_free_nodeid")
    @mock.patch("crmsh.corosync.Parser")
    @mock.patch("crmsh.utils.read_from_file")
    @mock.patch("crmsh.corosync.conf")
    @mock.patch("crmsh.corosync.find_configured_ip")
    def test_add_node_ucast(self, mock_find_ip, mock_conf, mock_read_file, mock_parser,
            mock_free_id, mock_make_value, mock_get_values, mock_make_section, mock_str2file):
        mock_parser_inst = mock.Mock()
        mock_conf.side_effect = ["corosync.conf", "corosync.conf"]
        mock_read_file.return_value = "data"
        mock_parser.return_value = mock_parser_inst
        mock_free_id.return_value = 2
        mock_make_value.side_effect = [["value1"], ["value2"]]
        mock_get_values.return_value = []
        mock_make_section.side_effect = ["section1", "section2"]
        mock_parser_inst.count.return_value = 2
        mock_parser_inst.get.return_value = "net"
        mock_parser_inst.to_string.return_value = "string data"

        corosync.add_node_ucast(['10.10.10.1'])

        mock_find_ip.assert_called_once_with(['10.10.10.1'])
        mock_parser.assert_called_once_with("data")
        mock_free_id.assert_called_once_with(mock_parser_inst)
        mock_make_value.assert_has_calls([
            mock.call('nodelist.node.ring0_addr', '10.10.10.1'),
            mock.call('nodelist.node.nodeid', '2')
            ])
        mock_get_values.assert_called_once_with("nodelist.node.ring0_addr")
        mock_make_section.assert_has_calls([
            mock.call('nodelist', []),
            mock.call('nodelist.node', ["value1", "value2"])
            ])
        mock_parser_inst.add.assert_has_calls([
            mock.call('', 'section1'),
            mock.call('nodelist', 'section2')
            ])
        mock_parser_inst.count.assert_called_once_with("nodelist.node")
        mock_parser_inst.set.assert_has_calls([
            mock.call('quorum.two_node', '1'),
            mock.call('quorum.two_node', '0')
            ])
        mock_parser_inst.get.assert_called_once_with('quorum.device.model')
        mock_parser_inst.to_string.assert_called_once_with()
        mock_str2file.assert_called_once_with("string data", "corosync.conf")

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
