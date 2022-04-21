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
import socket
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


@mock.patch("crmsh.utils.get_stdout_stderr")
@mock.patch("crmsh.utils.check_ssh_passwd_need")
@mock.patch("crmsh.corosync.get_value")
@mock.patch("crmsh.utils.is_qdevice_configured")
def test_query_qnetd_status_copy_id_failed(mock_qdevice_configured, mock_get_value, mock_check_passwd, mock_run):
    mock_qdevice_configured.return_value = True
    mock_get_value.side_effect = ["hacluster", "10.10.10.123"]
    mock_check_passwd.return_value = True
    mock_run.return_value = [1, None, "error"]
    with pytest.raises(ValueError) as err:
        corosync.query_qnetd_status()
    assert str(err.value) == "error"
    mock_qdevice_configured.assert_called_once_with()
    mock_get_value.assert_has_calls([
        mock.call("totem.cluster_name"),
        mock.call("quorum.device.net.host")
        ])
    mock_check_passwd.assert_called_once_with("10.10.10.123")
    mock_run.assert_called_once_with("ssh-copy-id -i /root/.ssh/id_rsa.pub root@10.10.10.123")


@mock.patch("crmsh.utils.print_cluster_nodes")
@mock.patch("crmsh.parallax.parallax_call")
@mock.patch("crmsh.utils.get_stdout_stderr")
@mock.patch("crmsh.utils.check_ssh_passwd_need")
@mock.patch("crmsh.corosync.get_value")
@mock.patch("crmsh.utils.is_qdevice_configured")
def test_query_qnetd_status_copy(mock_qdevice_configured, mock_get_value, mock_check_passwd, mock_run, mock_parallax_call, mock_print_nodes):
    mock_qdevice_configured.return_value = True
    mock_get_value.side_effect = ["hacluster", "10.10.10.123"]
    mock_check_passwd.return_value = True
    mock_run.return_value = [0, "data", None]
    mock_parallax_call.return_value = [("node1", (0, "data", None)), ]

    corosync.query_qnetd_status()

    mock_qdevice_configured.assert_called_once_with()
    mock_get_value.assert_has_calls([
        mock.call("totem.cluster_name"),
        mock.call("quorum.device.net.host")
        ])
    mock_check_passwd.assert_called_once_with("10.10.10.123")
    mock_run.assert_called_once_with("ssh-copy-id -i /root/.ssh/id_rsa.pub root@10.10.10.123")
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
        mock_search.return_value = mock.Mock()
        mock_parser_inst.get_all.return_value = ["10.10.10.1"]
        mock_isv6.return_value = False
        mock_ip_local.return_value = ["192.168.1.1", "10.10.10.2", "20.20.20.2"]
        mock_read_file.return_value = "data"

        corosync.find_configured_ip(["10.10.10.2"])

        mock_conf.assert_called_once_with()
        mock_parser_inst.all_paths.assert_called_once_with()
        mock_parser_inst.get_all.assert_called_once_with("nodelist.node.ring0_addr")
        mock_isv6.assert_called_once_with("10.10.10.2")
        mock_ip_local.assert_called_once_with(False)
        mock_search.assert_called_once_with("nodelist.node.ring[0-9]*_addr", "nodelist.node.ring0_addr")
        mock_read_file.assert_called_once_with(mock_conf.return_value)

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
        mock_search.return_value = mock.Mock()
        mock_parser_inst.get_all.return_value = ["10.10.10.1", "10.10.10.2"]
        mock_isv6.return_value = False
        mock_ip_local.return_value = ["192.168.1.1", "10.10.10.2", "20.20.20.2"]
        mock_read_file.return_value = "data"

        with self.assertRaises(corosync.IPAlreadyConfiguredError) as err:
            corosync.find_configured_ip(["10.10.10.2"])
        self.assertEqual("IP 10.10.10.2 was already configured", str(err.exception))

        mock_conf.assert_called_once_with()
        mock_parser_inst.all_paths.assert_called_once_with()
        mock_parser_inst.get_all.assert_called_once_with("nodelist.node.ring0_addr")
        mock_isv6.assert_called_once_with("10.10.10.2")
        mock_ip_local.assert_called_once_with(False)
        # For some reason mock_search.assert_called_once_with does not work
        mock_search.assert_has_calls([mock.call("nodelist.node.ring[0-9]*_addr", "nodelist.node.ring0_addr")])
        mock_read_file.assert_called_once_with(mock_conf.return_value)

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
        mock_read_file.return_value = "data"
        mock_conf.side_effect = ["corosync.conf", "corosync.conf"]
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
        mock_read_file.assert_called_once_with("corosync.conf")

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


class TestQDevice(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

    def setUp(self):
        """
        Test setUp.
        """
        # Use the setup to create a fresh instance for each test
        self.qdevice_with_ip = corosync.QDevice("10.10.10.123")
        self.qdevice_with_hostname = corosync.QDevice("node.qnetd")
        self.qdevice_with_invalid_port = corosync.QDevice("10.10.10.123", port=100)
        self.qdevice_with_invalid_tie_breaker = corosync.QDevice("10.10.10.123", tie_breaker="wrong")
        self.qdevice_with_ip_cluster_node = corosync.QDevice("10.10.10.123", cluster_node="node1.com")
        self.qdevice_with_invalid_cmds_relative_path = corosync.QDevice("10.10.10.123", cmds="ls")
        self.qdevice_with_invalid_cmds_not_exist = corosync.QDevice("10.10.10.123", cmds="/not_exist")

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    @mock.patch("crmsh.utils.package_is_installed")
    def test_valid_attr_not_installed(self, mock_installed):
        mock_installed.return_value = False
        with self.assertRaises(ValueError) as err:
            self.qdevice_with_ip.valid_attr()
        self.assertEqual("Package \"corosync-qdevice\" not installed on this node", str(err.exception))
        mock_installed.assert_called_once_with("corosync-qdevice")

    @mock.patch("crmsh.utils.InterfacesInfo.ip_in_local")
    @mock.patch("crmsh.utils.ping_node")
    @mock.patch("socket.getaddrinfo")
    @mock.patch("crmsh.utils.package_is_installed")
    def test_valid_attr_remote_exception(self, mock_installed, mock_getaddrinfo, mock_ping, mock_ip_local):
        mock_installed.return_value = True
        mock_getaddrinfo.return_value = [(None, ("10.10.10.123",)),]
        mock_ip_local.return_value = True

        with self.assertRaises(ValueError) as err:
            self.qdevice_with_ip.valid_attr()
        self.assertEqual("host for qnetd must be a remote one", str(err.exception))

        mock_installed.assert_called_once_with("corosync-qdevice")
        mock_getaddrinfo.assert_called_once_with("10.10.10.123", None)
        mock_ping.assert_called_once_with("10.10.10.123")
        mock_ip_local.assert_called_once_with("10.10.10.123")

    @mock.patch("socket.getaddrinfo")
    @mock.patch("crmsh.utils.package_is_installed")
    def test_valid_attr_getaddrinfo_exception(self, mock_installed, mock_getaddrinfo):
        mock_installed.return_value = True
        mock_getaddrinfo.side_effect = socket.error

        with self.assertRaises(ValueError) as err:
            self.qdevice_with_hostname.valid_attr()
        self.assertEqual("host \"node.qnetd\" is unreachable", str(err.exception))

        mock_installed.assert_called_once_with("corosync-qdevice")
        mock_getaddrinfo.assert_called_once_with("node.qnetd", None)

    @mock.patch("crmsh.utils.check_port_open")
    @mock.patch("crmsh.utils.InterfacesInfo.ip_in_local")
    @mock.patch("crmsh.utils.ping_node")
    @mock.patch("socket.getaddrinfo")
    @mock.patch("crmsh.utils.package_is_installed")
    def test_valid_attr_ssh_service_exception(self, mock_installed, mock_getaddrinfo,
            mock_ping, mock_ip_local, mock_port_open):
        mock_installed.return_value = True
        mock_getaddrinfo.return_value = [(None, ("10.10.10.123",)),]
        mock_ip_local.return_value = False
        mock_port_open.return_value = False

        with self.assertRaises(ValueError) as err:
            self.qdevice_with_ip.valid_attr()
        self.assertEqual("ssh service on \"10.10.10.123\" not available", str(err.exception))

        mock_installed.assert_called_once_with("corosync-qdevice")
        mock_getaddrinfo.assert_called_once_with("10.10.10.123", None)
        mock_ping.assert_called_once_with("10.10.10.123")
        mock_port_open.assert_called_once_with("10.10.10.123", 22)
        mock_ip_local.assert_called_once_with("10.10.10.123")

    @mock.patch("crmsh.utils.valid_port")
    @mock.patch("crmsh.utils.check_port_open")
    @mock.patch("crmsh.utils.InterfacesInfo.ip_in_local")
    @mock.patch("crmsh.utils.ping_node")
    @mock.patch("socket.getaddrinfo")
    @mock.patch("crmsh.utils.package_is_installed")
    def test_valid_attr_invalid_port_exception(self, mock_installed, mock_getaddrinfo,
            mock_ping, mock_ip_local, mock_port_open, mock_valid_port):
        mock_installed.return_value = True
        mock_getaddrinfo.return_value = [(None, ("10.10.10.123",)),]
        mock_ip_local.return_value = False
        mock_port_open.return_value = True
        mock_valid_port.return_value = False

        with self.assertRaises(ValueError) as err:
            self.qdevice_with_invalid_port.valid_attr()
        self.assertEqual("invalid qdevice port range(1024 - 65535)", str(err.exception))

        mock_installed.assert_called_once_with("corosync-qdevice")
        mock_getaddrinfo.assert_called_once_with("10.10.10.123", None)
        mock_ping.assert_called_once_with("10.10.10.123")
        mock_ip_local.assert_called_once_with("10.10.10.123")
        mock_port_open.assert_called_once_with("10.10.10.123", 22)
        mock_valid_port.assert_called_once_with(100)

    @mock.patch("crmsh.utils.valid_nodeid")
    @mock.patch("crmsh.utils.valid_port")
    @mock.patch("crmsh.utils.check_port_open")
    @mock.patch("crmsh.utils.InterfacesInfo.ip_in_local")
    @mock.patch("crmsh.utils.ping_node")
    @mock.patch("socket.getaddrinfo")
    @mock.patch("crmsh.utils.package_is_installed")
    def test_valid_attr_invalid_nodeid_exception(self, mock_installed, mock_getaddrinfo,
            mock_ping, mock_ip_local, mock_port_open, mock_valid_port, mock_valid_nodeid):
        mock_installed.return_value = True
        mock_getaddrinfo.return_value = [(None, ("10.10.10.123",)),]
        mock_ip_local.return_value = False
        mock_port_open.return_value = True
        mock_valid_port.return_value = True
        mock_valid_nodeid.return_value = False

        with self.assertRaises(ValueError) as err:
            self.qdevice_with_invalid_tie_breaker.valid_attr()
        self.assertEqual("invalid qdevice tie_breaker(lowest/highest/valid_node_id)", str(err.exception))

        mock_installed.assert_called_once_with("corosync-qdevice")
        mock_ip_local.assert_called_once_with("10.10.10.123")
        mock_getaddrinfo.assert_called_once_with("10.10.10.123", None)
        mock_ping.assert_called_once_with("10.10.10.123")
        mock_port_open.assert_called_once_with("10.10.10.123", 22)
        mock_valid_port.assert_called_once_with(5403)
        mock_valid_nodeid.assert_called_once_with("wrong")

    @mock.patch("crmsh.utils.valid_nodeid")
    @mock.patch("crmsh.utils.valid_port")
    @mock.patch("crmsh.utils.check_port_open")
    @mock.patch("crmsh.utils.InterfacesInfo.ip_in_local")
    @mock.patch("crmsh.utils.ping_node")
    @mock.patch("socket.getaddrinfo")
    @mock.patch("crmsh.utils.package_is_installed")
    def test_valid_attr_invalid_cmds_relative_path(self, mock_installed, mock_getaddrinfo,
            mock_ping, mock_ip_local, mock_port_open, mock_valid_port, mock_valid_nodeid):
        mock_installed.return_value = True
        mock_getaddrinfo.return_value = [(None, ("10.10.10.123",)),]
        mock_ip_local.return_value = False
        mock_port_open.return_value = True
        mock_valid_port.return_value = True
        mock_valid_nodeid.return_value = True

        with self.assertRaises(ValueError) as err:
            self.qdevice_with_invalid_cmds_relative_path.valid_attr()
        self.assertEqual("commands for heuristics should be absolute path", str(err.exception))

        mock_installed.assert_called_once_with("corosync-qdevice")
        mock_getaddrinfo.assert_called_once_with("10.10.10.123", None)
        mock_ping.assert_called_once_with("10.10.10.123")
        mock_ip_local.assert_called_once_with("10.10.10.123")
        mock_port_open.assert_called_once_with("10.10.10.123", 22)
        mock_valid_port.assert_called_once_with(5403)
        mock_valid_nodeid.assert_not_called()

    @mock.patch("crmsh.utils.valid_nodeid")
    @mock.patch("crmsh.utils.valid_port")
    @mock.patch("crmsh.utils.check_port_open")
    @mock.patch("crmsh.utils.InterfacesInfo.ip_in_local")
    @mock.patch("crmsh.utils.ping_node")
    @mock.patch("socket.getaddrinfo")
    @mock.patch("crmsh.utils.package_is_installed")
    def test_valid_attr_invalid_cmds_not_exist(self, mock_installed, mock_getaddrinfo,
            mock_ping, mock_ip_local, mock_port_open, mock_valid_port, mock_valid_nodeid):
        mock_installed.return_value = True
        mock_getaddrinfo.return_value = [(None, ("10.10.10.123",)),]
        mock_ip_local.return_value = False
        mock_port_open.return_value = True
        mock_valid_port.return_value = True
        mock_valid_nodeid.return_value = True

        with self.assertRaises(ValueError) as err:
            self.qdevice_with_invalid_cmds_not_exist.valid_attr()
        self.assertEqual("command /not_exist not exist", str(err.exception))

        mock_installed.assert_called_once_with("corosync-qdevice")
        mock_getaddrinfo.assert_called_once_with("10.10.10.123", None)
        mock_ping.assert_called_once_with("10.10.10.123")
        mock_ip_local.assert_called_once_with("10.10.10.123")
        mock_port_open.assert_called_once_with("10.10.10.123", 22)
        mock_valid_port.assert_called_once_with(5403)
        mock_valid_nodeid.assert_not_called()

    @mock.patch("crmsh.utils.service_is_active")
    @mock.patch("crmsh.utils.check_ssh_passwd_need")
    def test_valid_qnetd_remote_cluster_node(self, mock_check_ssh, mock_remote):
        self.qdevice_with_ip.qnetd_ip = "10.10.10.123"
        mock_check_ssh.return_value = True
        mock_remote.return_value = True
        excepted_err_string = 'host for qnetd must be a non-cluster node\nCluster service already successfully started on this node except qdevice service\nIf you still want to use qdevice, change to another host or stop cluster service on 10.10.10.123\nThen run command "crm cluster init" with "qdevice" stage, like:\n  crm cluster init qdevice qdevice_related_options\nThat command will setup qdevice separately'
        self.maxDiff = None

        with self.assertRaises(ValueError) as err:
            self.qdevice_with_ip.valid_qnetd()
        self.assertEqual(excepted_err_string, str(err.exception))

        mock_check_ssh.assert_called_once_with("10.10.10.123")
        mock_remote.assert_called_once_with("pacemaker", "10.10.10.123")

    @mock.patch("crmsh.utils.package_is_installed")
    @mock.patch("crmsh.utils.service_is_active")
    @mock.patch("crmsh.utils.check_ssh_passwd_need")
    def test_valid_qnetd_not_installed(self, mock_check_ssh, mock_remote, mock_installed):
        self.qdevice_with_ip.qnetd_ip = "10.10.10.123"
        mock_check_ssh.return_value = True
        mock_remote.return_value = False
        mock_installed.return_value = False
        excepted_err_string = 'Package "corosync-qnetd" not installed on 10.10.10.123\nCluster service already successfully started on this node except qdevice service\nIf you still want to use qdevice, install "corosync-qnetd" on 10.10.10.123\nThen run command "crm cluster init" with "qdevice" stage, like:\n  crm cluster init qdevice qdevice_related_options\nThat command will setup qdevice separately'
        self.maxDiff = None

        with self.assertRaises(ValueError) as err:
            self.qdevice_with_ip.valid_qnetd()
        self.assertEqual(excepted_err_string, str(err.exception))

        mock_check_ssh.assert_called_once_with("10.10.10.123")
        mock_remote.assert_called_once_with("pacemaker", "10.10.10.123")
        mock_installed.assert_called_once_with("corosync-qnetd", "10.10.10.123")

    @mock.patch("crmsh.parallax.parallax_call")
    def test_manage_qnetd(self, mock_call):
        mock_call.return_value = ["10.10.10.123", (0, None, None)]
        self.qdevice_with_ip.manage_qnetd("test")
        mock_call.assert_called_once_with(["10.10.10.123"], "systemctl test corosync-qnetd.service", False)

    @mock.patch("crmsh.corosync.QDevice.manage_qnetd")
    def test_enable_qnetd(self, mock_manage_qnetd):
        self.qdevice_with_ip.enable_qnetd()
        mock_manage_qnetd.assert_called_once_with("enable")

    @mock.patch("crmsh.corosync.QDevice.manage_qnetd")
    def test_disable_qnetd(self, mock_manage_qnetd):
        self.qdevice_with_ip.disable_qnetd()
        mock_manage_qnetd.assert_called_once_with("disable")

    @mock.patch("crmsh.corosync.QDevice.manage_qnetd")
    def test_start_qnetd(self, mock_manage_qnetd):
        self.qdevice_with_ip.start_qnetd()
        mock_manage_qnetd.assert_called_once_with("start")

    @mock.patch("crmsh.corosync.QDevice.manage_qnetd")
    def test_stop_qnetd(self, mock_manage_qnetd):
        self.qdevice_with_ip.stop_qnetd()
        mock_manage_qnetd.assert_called_once_with("stop")

    @mock.patch("crmsh.corosync.QDevice.debug_and_log_to_bootstrap")
    @mock.patch("crmsh.parallax.parallax_call")
    @mock.patch("crmsh.corosync.QDevice.qnetd_cacert_on_qnetd", new_callable=mock.PropertyMock)
    def test_init_db_on_qnetd_already_exists(self, mock_qnetd_cacert, mock_call, mock_log):
        mock_call.return_value = [("10.10.10.123", (0, None, None))]
        mock_qnetd_cacert.return_value = "/etc/corosync/qnetd/nssdb/qnetd-cacert.crt"
        self.qdevice_with_ip.init_db_on_qnetd()
        mock_call.assert_called_once_with(["10.10.10.123"],
                                          "test -f {}".format(mock_qnetd_cacert.return_value),
                                          False)
        mock_qnetd_cacert.assert_called_once_with()
        mock_log.assert_not_called()

    @mock.patch("crmsh.corosync.QDevice.debug_and_log_to_bootstrap")
    @mock.patch("crmsh.parallax.parallax_call")
    @mock.patch("crmsh.corosync.QDevice.qnetd_cacert_on_qnetd", new_callable=mock.PropertyMock)
    def test_init_db_on_qnetd(self, mock_qnetd_cacert, mock_call, mock_log):
        mock_call.side_effect = [ValueError(mock.Mock(), "Failed on 10.10.10.123: error happen"),
                                 [("10.10.10.123", (0, None, None))]]
        mock_qnetd_cacert.return_value = "/etc/corosync/qnetd/nssdb/qnetd-cacert.crt"

        self.qdevice_with_ip.init_db_on_qnetd()

        mock_call.assert_has_calls([
            mock.call(["10.10.10.123"], "test -f {}".format(mock_qnetd_cacert.return_value), False),
            mock.call(["10.10.10.123"], "corosync-qnetd-certutil -i", False)
        ])
        mock_qnetd_cacert.assert_called_once_with()
        mock_log.assert_called_once_with("Step 1: Initialize database on 10.10.10.123")

    @mock.patch("crmsh.corosync.QDevice.debug_and_log_to_bootstrap")
    @mock.patch("os.path.exists")
    @mock.patch("crmsh.parallax.parallax_slurp")
    @mock.patch("crmsh.corosync.QDevice.qnetd_cacert_on_local", new_callable=mock.PropertyMock)
    def test_fetch_qnetd_crt_from_qnetd_exist(self, mock_qnetd_cacert_local,
                                              mock_slurp, mock_exists, mock_log):
        mock_qnetd_cacert_local.return_value = "/etc/corosync/qdevice/net/10.10.10.123/qnetd-cacert.crt"
        mock_exists.return_value = True

        self.qdevice_with_ip.fetch_qnetd_crt_from_qnetd()

        mock_exists.assert_called_once_with(mock_qnetd_cacert_local.return_value)
        mock_qnetd_cacert_local.assert_called_once_with()
        mock_slurp.assert_not_called()
        mock_log.assert_not_called()

    @mock.patch("crmsh.corosync.QDevice.debug_and_log_to_bootstrap")
    @mock.patch("os.path.exists")
    @mock.patch("crmsh.parallax.parallax_slurp")
    @mock.patch("crmsh.corosync.QDevice.qnetd_cacert_on_local", new_callable=mock.PropertyMock)
    def test_fetch_qnetd_crt_from_qnetd(self, mock_qnetd_cacert_local,
                                        mock_slurp, mock_exists, mock_log):
        mock_qnetd_cacert_local.return_value = "/etc/corosync/qdevice/net/10.10.10.123/qnetd-cacert.crt"
        mock_exists.return_value = False
        mock_slurp.return_value = [("10.10.10.123", (0, None, None, "test"))]

        self.qdevice_with_ip.fetch_qnetd_crt_from_qnetd()

        mock_exists.assert_called_once_with(mock_qnetd_cacert_local.return_value)
        mock_qnetd_cacert_local.assert_called_once_with()
        mock_log.assert_called_once_with("Step 2: Fetch qnetd-cacert.crt from 10.10.10.123")
        mock_slurp.assert_called_once_with(["10.10.10.123"], "/etc/corosync/qdevice/net",
                                           "/etc/corosync/qnetd/nssdb/qnetd-cacert.crt", False)

    @mock.patch("crmsh.corosync.QDevice.debug_and_log_to_bootstrap")
    @mock.patch("crmsh.utils.list_cluster_nodes")
    @mock.patch("crmsh.utils.this_node")
    @mock.patch("crmsh.parallax.parallax_copy")
    def test_copy_qnetd_crt_to_cluster_one_node(self, mock_copy, mock_this_node, mock_list_nodes, mock_log):
        mock_this_node.return_value = "node1.com"
        mock_list_nodes.return_value = ["node1.com"]

        self.qdevice_with_ip.copy_qnetd_crt_to_cluster()

        mock_this_node.assert_called_once_with()
        mock_list_nodes.assert_called_once_with()
        mock_copy.assert_not_called()
        mock_log.assert_not_called()

    @mock.patch("crmsh.corosync.QDevice.debug_and_log_to_bootstrap")
    @mock.patch("crmsh.utils.list_cluster_nodes")
    @mock.patch("crmsh.utils.this_node")
    @mock.patch("crmsh.parallax.parallax_copy")
    @mock.patch("crmsh.corosync.QDevice.qnetd_cacert_on_local", new_callable=mock.PropertyMock)
    @mock.patch("os.path.dirname")
    def test_copy_qnetd_crt_to_cluster(self, mock_dirname, mock_qnetd_cacert_local,
                                       mock_copy, mock_this_node, mock_list_nodes, mock_log):
        mock_qnetd_cacert_local.return_value = "/etc/corosync/qdevice/net/10.10.10.123/qnetd-cacert.crt"
        mock_dirname.return_value = "/etc/corosync/qdevice/net/10.10.10.123"
        mock_this_node.return_value = "node1.com"
        mock_list_nodes.return_value = ["node1.com", "node2.com"]
        mock_copy.return_value = [("node1.com", (0, None, None)), ("node2.com", (0, None, None))]

        self.qdevice_with_ip.copy_qnetd_crt_to_cluster()

        mock_this_node.assert_called_once_with()
        mock_list_nodes.assert_called_once_with()
        mock_log.assert_called_once_with("Step 3: Copy exported qnetd-cacert.crt to ['node2.com']")
        mock_copy.assert_called_once_with(["node2.com"], mock_dirname.return_value,
                                          "/etc/corosync/qdevice/net", False)

    @mock.patch("crmsh.corosync.QDevice.debug_and_log_to_bootstrap")
    @mock.patch("crmsh.parallax.parallax_call")
    @mock.patch("crmsh.corosync.QDevice.qnetd_cacert_on_local", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.utils.list_cluster_nodes")
    def test_init_db_on_cluster(self, mock_list_nodes, mock_qnetd_cacert_local, mock_call, mock_log):
        mock_list_nodes.return_value = ["node1", "node2"]
        mock_qnetd_cacert_local.return_value = "/etc/corosync/qdevice/net/10.10.10.123/qnetd-cacert.crt"
        mock_call.return_value = [("node1", (0, None, None)), ("node2", (0, None, None))]

        self.qdevice_with_ip.init_db_on_cluster()

        mock_list_nodes.assert_called_once_with()
        mock_qnetd_cacert_local.assert_called_once_with()
        mock_log.assert_called_once_with("Step 4: Initialize database on ['node1', 'node2']")
        mock_call.assert_called_once_with(mock_list_nodes.return_value,
                                          "corosync-qdevice-net-certutil -i -c {}".format(mock_qnetd_cacert_local.return_value),
                                          False)

    @mock.patch("crmsh.corosync.QDevice.debug_and_log_to_bootstrap")
    @mock.patch("crmsh.corosync.conf")
    @mock.patch("crmsh.corosync.get_value")
    def test_create_ca_request_exception(self, mock_get_value, mock_conf, mock_log):
        mock_get_value.return_value = None
        mock_conf.return_value = "/etc/corosync/corosync.conf"

        with self.assertRaises(ValueError) as err:
            self.qdevice_with_ip.create_ca_request()
        self.assertEqual("No cluster_name found in {}".format(mock_conf.return_value), str(err.exception))

        mock_log.assert_called_once_with("Step 5: Generate certificate request qdevice-net-node.crq")
        mock_get_value.assert_called_once_with("totem.cluster_name")
        mock_conf.assert_called_once_with()

    @mock.patch("crmsh.corosync.QDevice.debug_and_log_to_bootstrap")
    @mock.patch("crmsh.utils.get_stdout_stderr")
    @mock.patch("crmsh.corosync.conf")
    @mock.patch("crmsh.corosync.get_value")
    def test_create_ca_request(self, mock_get_value, mock_conf, mock_stdout_stderr, mock_log):
        mock_get_value.return_value = "hacluster"
        mock_stdout_stderr.return_value = (0, None, None)

        self.qdevice_with_ip.create_ca_request()

        mock_log.assert_called_once_with("Step 5: Generate certificate request qdevice-net-node.crq")
        mock_get_value.assert_called_once_with("totem.cluster_name")
        mock_conf.assert_not_called()
        mock_stdout_stderr.assert_called_once_with("corosync-qdevice-net-certutil -r -n {}".format(mock_get_value.return_value))

    @mock.patch("crmsh.corosync.QDevice.debug_and_log_to_bootstrap")
    @mock.patch("os.path.dirname")
    @mock.patch("crmsh.corosync.QDevice.qdevice_crq_on_qnetd", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.corosync.QDevice.qdevice_crq_on_local", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.parallax.parallax_copy")
    def test_copy_crq_to_qnetd(self, mock_copy, mock_qdevice_crq_local,
                               mock_qdevice_crq_qnetd, mock_dirname, mock_log):
        mock_copy.return_value = [("10.10.10.123", (0, None, None))]
        mock_qdevice_crq_local.return_value = "/etc/corosync/qdevice/net/nssdb/qdevice-net-node.crq"
        mock_qdevice_crq_qnetd.return_value = "/etc/corosync/qnetd/nssdb/qdevice-net-node.crq"
        mock_dirname.return_value = "/etc/corosync/qnetd/nssdb"

        self.qdevice_with_ip.copy_crq_to_qnetd()

        mock_log.assert_called_once_with("Step 6: Copy qdevice-net-node.crq to 10.10.10.123")
        mock_copy.assert_called_once_with(["10.10.10.123"], mock_qdevice_crq_local.return_value,
                                          mock_dirname.return_value, False)
        mock_qdevice_crq_local.assert_called_once_with()
        mock_qdevice_crq_qnetd.assert_called_once_with()
        mock_dirname.assert_called_once_with(mock_qdevice_crq_qnetd.return_value)

    @mock.patch("crmsh.corosync.QDevice.debug_and_log_to_bootstrap")
    @mock.patch("crmsh.parallax.parallax_call")
    @mock.patch("crmsh.corosync.QDevice.qdevice_crq_on_qnetd", new_callable=mock.PropertyMock)
    def test_sign_crq_on_qnetd(self, mock_qdevice_crq_qnetd, mock_call, mock_log):
        mock_qdevice_crq_qnetd.return_value = "/etc/corosync/qnetd/nssdb/qdevice-net-node.crq"
        mock_call.return_value = ["10.10.10.123", (0, None, None)]

        self.qdevice_with_ip.cluster_name = "hacluster"
        self.qdevice_with_ip.sign_crq_on_qnetd()

        mock_log.assert_called_once_with("Step 7: Sign and export cluster certificate on 10.10.10.123")
        mock_qdevice_crq_qnetd.assert_called_once_with()
        mock_call.assert_called_once_with(["10.10.10.123"],
                                          "corosync-qnetd-certutil -s -c {} -n hacluster".format(mock_qdevice_crq_qnetd.return_value),
                                          False)

    @mock.patch("crmsh.corosync.QDevice.debug_and_log_to_bootstrap")
    @mock.patch("crmsh.corosync.QDevice.qnetd_cluster_crt_on_qnetd", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.parallax.parallax_slurp")
    def test_fetch_cluster_crt_from_qnetd(self, mock_slurp, mock_crt_on_qnetd, mock_log):
        mock_crt_on_qnetd.return_value = "/etc/corosync/qnetd/nssdb/cluster-hacluster.crt"
        mock_slurp.return_value = [("10.10.10.123", (0, None, None, "test"))]

        self.qdevice_with_ip.cluster_name = "hacluster"
        self.qdevice_with_ip.fetch_cluster_crt_from_qnetd()

        mock_log.assert_called_once_with("Step 8: Fetch cluster-hacluster.crt from 10.10.10.123")
        mock_crt_on_qnetd.assert_has_calls([mock.call(), mock.call()])
        mock_slurp.assert_called_once_with(["10.10.10.123"], "/etc/corosync/qdevice/net",
                                           mock_crt_on_qnetd.return_value, False)

    @mock.patch("crmsh.corosync.QDevice.debug_and_log_to_bootstrap")
    @mock.patch("crmsh.utils.get_stdout_stderr")
    @mock.patch("crmsh.corosync.QDevice.qnetd_cluster_crt_on_local", new_callable=mock.PropertyMock)
    def test_import_cluster_crt_exception(self, mock_crt_on_local, mock_stdout_stderr, mock_log):
        mock_crt_on_local.return_value = "/etc/corosync/qdevice/net/10.10.10.123/cluster-hacluster.crt"
        mock_stdout_stderr.return_value = (1, None, "errors happen")

        with self.assertRaises(ValueError) as err:
            self.qdevice_with_ip.import_cluster_crt()
        self.assertEqual("errors happen", str(err.exception))

        mock_log.assert_called_once_with("Step 9: Import certificate file cluster-hacluster.crt on local")
        mock_crt_on_local.assert_has_calls([mock.call(), mock.call()])
        mock_stdout_stderr.assert_called_once_with("corosync-qdevice-net-certutil -M -c {}".format(mock_crt_on_local.return_value))

    @mock.patch("crmsh.corosync.QDevice.debug_and_log_to_bootstrap")
    @mock.patch("crmsh.utils.get_stdout_stderr")
    @mock.patch("crmsh.corosync.QDevice.qnetd_cluster_crt_on_local", new_callable=mock.PropertyMock)
    def test_import_cluster_crt(self, mock_crt_on_local, mock_stdout_stderr, mock_log):
        mock_crt_on_local.return_value = "/etc/corosync/qdevice/net/10.10.10.123/cluster-hacluster.crt"
        mock_stdout_stderr.return_value = (0, None, None)

        self.qdevice_with_ip.import_cluster_crt()

        mock_log.assert_called_once_with("Step 9: Import certificate file cluster-hacluster.crt on local")
        mock_crt_on_local.assert_has_calls([mock.call(), mock.call()])
        mock_stdout_stderr.assert_called_once_with("corosync-qdevice-net-certutil -M -c {}".format(mock_crt_on_local.return_value))

    @mock.patch("crmsh.corosync.QDevice.debug_and_log_to_bootstrap")
    @mock.patch("crmsh.utils.list_cluster_nodes")
    @mock.patch("crmsh.utils.this_node")
    @mock.patch("crmsh.parallax.parallax_copy")
    def test_copy_p12_to_cluster_one_node(self, mock_copy, mock_this_node, mock_list_nodes, mock_log):
        mock_this_node.return_value = "node1.com"
        mock_list_nodes.return_value = ["node1.com"]

        self.qdevice_with_ip.copy_p12_to_cluster()

        mock_log.assert_not_called()
        mock_this_node.assert_called_once_with()
        mock_list_nodes.assert_called_once_with()
        mock_copy.assert_not_called()

    @mock.patch("crmsh.corosync.QDevice.debug_and_log_to_bootstrap")
    @mock.patch("crmsh.utils.list_cluster_nodes")
    @mock.patch("crmsh.utils.this_node")
    @mock.patch("crmsh.parallax.parallax_copy")
    @mock.patch("crmsh.corosync.QDevice.qdevice_p12_on_local", new_callable=mock.PropertyMock)
    @mock.patch("os.path.dirname")
    def test_copy_p12_to_cluster(self, mock_dirname, mock_p12_on_local,
                                       mock_copy, mock_this_node, mock_list_nodes, mock_log):
        mock_this_node.return_value = "node1.com"
        mock_list_nodes.return_value = ["node1.com", "node2.com"]
        mock_p12_on_local.return_value = "/etc/corosync/qdevice/net/nssdb/qdevice-net-node.p12"
        mock_dirname.return_value = "/etc/corosync/qdevice/net/nssdb"
        mock_copy.return_value = [("node1.com", (0, None, None)), ("node2.com", (0, None, None))]

        self.qdevice_with_ip.copy_p12_to_cluster()

        mock_log.assert_called_once_with("Step 10: Copy qdevice-net-node.p12 to ['node2.com']")
        mock_this_node.assert_called_once_with()
        mock_list_nodes.assert_called_once_with()
        mock_copy.assert_called_once_with(["node2.com"], mock_p12_on_local.return_value,
                                          mock_dirname.return_value, False)
        mock_dirname.assert_called_once_with(mock_p12_on_local.return_value)
        mock_p12_on_local.assert_has_calls([mock.call(), mock.call()])

    @mock.patch("crmsh.corosync.QDevice.debug_and_log_to_bootstrap")
    @mock.patch("crmsh.parallax.parallax_call")
    @mock.patch("crmsh.utils.list_cluster_nodes_except_me")
    def test_import_p12_on_cluster_one_node(self, mock_list_nodes, mock_call, mock_log):
        mock_list_nodes.return_value = []

        self.qdevice_with_ip.import_p12_on_cluster()

        mock_log.assert_not_called()
        mock_list_nodes.assert_called_once_with()
        mock_call.assert_not_called()

    @mock.patch("crmsh.parallax.parallax_call")
    @mock.patch("crmsh.corosync.QDevice.debug_and_log_to_bootstrap")
    @mock.patch("crmsh.corosync.QDevice.qdevice_p12_on_local", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.utils.list_cluster_nodes_except_me")
    def test_import_p12_on_cluster(self, mock_list_nodes, mock_p12_on_local, mock_log, mock_call):
        mock_list_nodes.return_value = ["node2", "node3"]
        mock_p12_on_local.return_value = "/etc/corosync/qdevice/net/nssdb/qdevice-net-node.p12"
        mock_call.return_value = [("node2", (0, None, None)), ("node3", (0, None, None))]

        self.qdevice_with_ip.import_p12_on_cluster()

        mock_log.assert_called_once_with("Step 11: Import qdevice-net-node.p12 on ['node2', 'node3']")
        mock_list_nodes.assert_called_once_with()
        mock_call.assert_called_once_with(
                ["node2", "node3"],
                "corosync-qdevice-net-certutil -m -c {}".format(mock_p12_on_local.return_value),
                False)
        mock_p12_on_local.assert_called_once_with()

    @mock.patch("crmsh.corosync.QDevice.import_p12_on_cluster")
    @mock.patch("crmsh.corosync.QDevice.copy_p12_to_cluster")
    @mock.patch("crmsh.corosync.QDevice.import_cluster_crt")
    @mock.patch("crmsh.corosync.QDevice.fetch_cluster_crt_from_qnetd")
    @mock.patch("crmsh.corosync.QDevice.sign_crq_on_qnetd")
    @mock.patch("crmsh.corosync.QDevice.copy_crq_to_qnetd")
    @mock.patch("crmsh.corosync.QDevice.create_ca_request")
    @mock.patch("crmsh.corosync.QDevice.init_db_on_cluster")
    @mock.patch("crmsh.corosync.QDevice.copy_qnetd_crt_to_cluster")
    @mock.patch("crmsh.corosync.QDevice.fetch_qnetd_crt_from_qnetd")
    @mock.patch("crmsh.corosync.QDevice.init_db_on_qnetd")
    def test_certificate_process_on_init(self, mock_init_db_on_qnetd, mock_fetch_qnetd_crt_from_qnetd,
            mock_copy_qnetd_crt_to_cluster, mock_init_db_on_cluster, mock_create_ca_request,
            mock_copy_crq_to_qnetd, mock_sign_crq_on_qnetd, mock_fetch_cluster_crt_from_qnetd,
            mock_import_cluster_crt, mock_copy_p12_to_cluster, mock_import_p12_on_cluster):

        self.qdevice_with_ip.certificate_process_on_init()
        mock_init_db_on_qnetd.assert_called_once_with()
        mock_fetch_qnetd_crt_from_qnetd.assert_called_once_with()
        mock_copy_qnetd_crt_to_cluster.assert_called_once_with()
        mock_init_db_on_cluster.assert_called_once_with()
        mock_create_ca_request.assert_called_once_with()
        mock_copy_crq_to_qnetd.assert_called_once_with()
        mock_sign_crq_on_qnetd.assert_called_once_with()
        mock_fetch_cluster_crt_from_qnetd.assert_called_once_with()
        mock_import_cluster_crt.assert_called_once_with()
        mock_copy_p12_to_cluster.assert_called_once_with()
        mock_import_p12_on_cluster.assert_called_once_with()

    @mock.patch("crmsh.corosync.QDevice.debug_and_log_to_bootstrap")
    @mock.patch("os.path.exists")
    @mock.patch("crmsh.corosync.QDevice.qnetd_cacert_on_cluster", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.corosync.QDevice.qnetd_cacert_on_local", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.parallax.parallax_slurp")
    def test_fetch_qnetd_crt_from_cluster_exist(self, mock_slurp, mock_qnetd_cacert_local,
                                                mock_qnetd_cacert_cluster, mock_exists, mock_log):
        mock_exists.return_value = True
        mock_qnetd_cacert_cluster.return_value = "/etc/corosync/qdevice/net/node1.com/qnetd-cacert.crt"

        self.qdevice_with_ip_cluster_node.fetch_qnetd_crt_from_cluster()

        mock_log.assert_not_called()
        mock_exists.assert_called_once_with(mock_qnetd_cacert_cluster.return_value)
        mock_qnetd_cacert_cluster.assert_called_once_with()
        mock_qnetd_cacert_local.assert_not_called()
        mock_slurp.assert_not_called()

    @mock.patch("crmsh.corosync.QDevice.debug_and_log_to_bootstrap")
    @mock.patch("os.path.exists")
    @mock.patch("crmsh.corosync.QDevice.qnetd_cacert_on_cluster", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.corosync.QDevice.qnetd_cacert_on_local", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.parallax.parallax_slurp")
    def test_fetch_qnetd_crt_from_cluster(self, mock_slurp, mock_qnetd_cacert_local,
                                          mock_qnetd_cacert_cluster, mock_exists, mock_log):
        mock_exists.return_value = False
        mock_qnetd_cacert_cluster.return_value = "/etc/corosync/qdevice/net/node1.com/qnetd-cacert.crt"
        mock_qnetd_cacert_local.return_value = "/etc/corosync/qdevice/net/10.10.10.123/qnetd-cacert.crt"
        mock_slurp.return_value = [("node1.com", (0, None, None, "test"))]

        self.qdevice_with_ip_cluster_node.fetch_qnetd_crt_from_cluster()

        mock_log.assert_called_once_with("Step 1: Fetch qnetd-cacert.crt from node1.com")
        mock_exists.assert_called_once_with(mock_qnetd_cacert_cluster.return_value)
        mock_qnetd_cacert_cluster.assert_called_once_with()
        mock_qnetd_cacert_local.assert_called_once_with()
        mock_slurp.assert_called_once_with(["node1.com"], "/etc/corosync/qdevice/net",
                                           mock_qnetd_cacert_local.return_value, False)

    @mock.patch("crmsh.corosync.QDevice.debug_and_log_to_bootstrap")
    @mock.patch("crmsh.utils.get_stdout_stderr")
    @mock.patch("crmsh.corosync.QDevice.qnetd_cacert_on_cluster", new_callable=mock.PropertyMock)
    def test_init_db_on_local_exception(self, mock_qnetd_cacert_cluster, mock_stdout_stderr, mock_log):
        mock_qnetd_cacert_cluster.return_value = "/etc/corosync/qdevice/net/node1.com/qnetd-cacert.crt"
        mock_stdout_stderr.return_value = (1, None, "errors happen")

        with self.assertRaises(ValueError) as err:
            self.qdevice_with_ip_cluster_node.init_db_on_local()
        self.assertEqual("errors happen", str(err.exception))

        mock_log.assert_called_once_with("Step 2: Initialize database on local")
        mock_qnetd_cacert_cluster.assert_called_once_with()
        mock_stdout_stderr.assert_called_once_with("corosync-qdevice-net-certutil -i -c {}".format(mock_qnetd_cacert_cluster.return_value))

    @mock.patch("crmsh.corosync.QDevice.debug_and_log_to_bootstrap")
    @mock.patch("crmsh.utils.get_stdout_stderr")
    @mock.patch("crmsh.corosync.QDevice.qnetd_cacert_on_cluster", new_callable=mock.PropertyMock)
    def test_init_db_on_local(self, mock_qnetd_cacert_cluster, mock_stdout_stderr, mock_log):
        mock_qnetd_cacert_cluster.return_value = "/etc/corosync/qdevice/net/node1.com/qnetd-cacert.crt"
        mock_stdout_stderr.return_value = (0, None, None)

        self.qdevice_with_ip_cluster_node.init_db_on_local()

        mock_log.assert_called_once_with("Step 2: Initialize database on local")
        mock_qnetd_cacert_cluster.assert_called_once_with()
        mock_stdout_stderr.assert_called_once_with("corosync-qdevice-net-certutil -i -c {}".format(mock_qnetd_cacert_cluster.return_value))

    @mock.patch("crmsh.corosync.QDevice.debug_and_log_to_bootstrap")
    @mock.patch("os.path.exists")
    @mock.patch("crmsh.corosync.QDevice.qdevice_p12_on_cluster", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.corosync.QDevice.qdevice_p12_on_local", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.parallax.parallax_slurp")
    def test_fetch_p12_from_cluster_exist(self, mock_slurp, mock_p12_on_local,
                                          mock_p12_on_cluster, mock_exists, mock_log):
        mock_exists.return_value = True
        mock_p12_on_cluster.return_value = "/etc/corosync/qdevice/net/node1.com/qdevice-net-node.p12"

        self.qdevice_with_ip_cluster_node.fetch_p12_from_cluster()

        mock_log.assert_not_called()
        mock_exists.assert_called_once_with(mock_p12_on_cluster.return_value)
        mock_p12_on_cluster.assert_called_once_with()
        mock_p12_on_local.assert_not_called()
        mock_slurp.assert_not_called()

    @mock.patch("crmsh.corosync.QDevice.debug_and_log_to_bootstrap")
    @mock.patch("os.path.exists")
    @mock.patch("crmsh.corosync.QDevice.qdevice_p12_on_cluster", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.corosync.QDevice.qdevice_p12_on_local", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.parallax.parallax_slurp")
    def test_fetch_p12_from_cluster(self, mock_slurp, mock_p12_on_local,
                                    mock_p12_on_cluster, mock_exists, mock_log):
        mock_exists.return_value = False
        mock_p12_on_cluster.return_value = "/etc/corosync/qdevice/net/node1.com/qdevice-net-node.p12"
        mock_p12_on_local.return_value = "/etc/corosync/qdevice/net/nssdb/qdevice-net-node.p12"
        mock_slurp.return_value = [("node1.com", (0, None, None, "test"))]

        self.qdevice_with_ip_cluster_node.fetch_p12_from_cluster()

        mock_log.assert_called_once_with("Step 3: Fetch qdevice-net-node.p12 from node1.com")
        mock_exists.assert_called_once_with(mock_p12_on_cluster.return_value)
        mock_p12_on_cluster.assert_called_once_with()
        mock_p12_on_local.assert_called_once_with()
        mock_slurp.assert_called_once_with(["node1.com"], "/etc/corosync/qdevice/net",
                                           mock_p12_on_local.return_value, False)

    @mock.patch("crmsh.corosync.QDevice.debug_and_log_to_bootstrap")
    @mock.patch("crmsh.utils.get_stdout_stderr")
    @mock.patch("crmsh.corosync.QDevice.qdevice_p12_on_cluster", new_callable=mock.PropertyMock)
    def test_import_p12_on_local_exception(self, mock_p12_on_cluster, mock_stdout_stderr, mock_log):
        mock_p12_on_cluster.return_value = "/etc/corosync/qdevice/net/node1.com/qdevice-net-node.p12"
        mock_stdout_stderr.return_value = (1, None, "errors happen")

        with self.assertRaises(ValueError) as err:
            self.qdevice_with_ip_cluster_node.import_p12_on_local()
        self.assertEqual("errors happen", str(err.exception))

        mock_log.assert_called_once_with("Step 4: Import cluster certificate and key")
        mock_p12_on_cluster.assert_called_once_with()
        mock_stdout_stderr.assert_called_once_with("corosync-qdevice-net-certutil -m -c {}".format(mock_p12_on_cluster.return_value))

    @mock.patch("crmsh.corosync.QDevice.debug_and_log_to_bootstrap")
    @mock.patch("crmsh.utils.get_stdout_stderr")
    @mock.patch("crmsh.corosync.QDevice.qdevice_p12_on_cluster", new_callable=mock.PropertyMock)
    def test_import_p12_on_local(self, mock_p12_on_cluster, mock_stdout_stderr, mock_log):
        mock_p12_on_cluster.return_value = "/etc/corosync/qdevice/net/node1.com/qdevice-net-node.p12"
        mock_stdout_stderr.return_value = (0, None, None)

        self.qdevice_with_ip_cluster_node.import_p12_on_local()

        mock_log.assert_called_once_with("Step 4: Import cluster certificate and key")
        mock_p12_on_cluster.assert_called_once_with()
        mock_stdout_stderr.assert_called_once_with("corosync-qdevice-net-certutil -m -c {}".format(mock_p12_on_cluster.return_value))

    @mock.patch("crmsh.corosync.QDevice.import_p12_on_local")
    @mock.patch("crmsh.corosync.QDevice.fetch_p12_from_cluster")
    @mock.patch("crmsh.corosync.QDevice.init_db_on_local")
    @mock.patch("crmsh.corosync.QDevice.fetch_qnetd_crt_from_cluster")
    def test_certificate_process_on_join(self, mock_fetch_qnetd_crt_from_cluster, mock_init_db_on_local,
            mock_fetch_p12_from_cluster, mock_import_p12_on_local):
        self.qdevice_with_ip.certificate_process_on_join()
        mock_fetch_qnetd_crt_from_cluster.assert_called_once_with()
        mock_init_db_on_local.assert_called_once_with()
        mock_fetch_p12_from_cluster.assert_called_once_with()
        mock_import_p12_on_local.assert_called_once_with()

    @mock.patch("crmsh.utils.str2file")
    @mock.patch("crmsh.corosync.make_section")
    @mock.patch("crmsh.corosync.Parser")
    @mock.patch("crmsh.corosync.conf")
    @mock.patch("crmsh.utils.read_from_file")
    def test_write_qdevice_config(self, mock_read_file, mock_conf, mock_parser, mock_mksection, mock_str2file):
        mock_read_file.return_value = "data"
        mock_mksection.side_effect = [
            ["device {", "}"],
            ["net {", "}"]
        ]
        mock_conf.side_effect = ["corosync.conf", "corosync.conf"]
        mock_instance = mock.Mock()
        mock_parser.return_value = mock_instance
        mock_instance.to_string.return_value = "string data"

        self.qdevice_with_ip.write_qdevice_config()

        mock_conf.assert_has_calls([mock.call(), mock.call()])
        mock_parser.assert_called_once_with("data")
        mock_instance.remove.assert_called_once_with("quorum.device")
        mock_instance.add.assert_has_calls([
            mock.call('quorum', ["device {", "}"]),
            mock.call('quorum.device', ["net {", "}"])
        ])
        mock_instance.set.assert_has_calls([
            mock.call('quorum.device.votes', '1'),
            mock.call('quorum.device.model', 'net'),
            mock.call('quorum.device.net.tls', 'on'),
            mock.call('quorum.device.net.host', '10.10.10.123'),
            mock.call('quorum.device.net.port', 5403),
            mock.call('quorum.device.net.algorithm', 'ffsplit'),
            mock.call('quorum.device.net.tie_breaker', 'lowest')
        ])
        mock_instance.to_string.assert_called_once_with()
        mock_mksection.assert_has_calls([
            mock.call('quorum.device', []),
            mock.call('quorum.device.net', [])
        ])
        mock_str2file.assert_called_once_with("string data", "corosync.conf")
        mock_read_file.assert_called_once_with("corosync.conf")

    @mock.patch("crmsh.utils.str2file")
    @mock.patch("crmsh.corosync.Parser")
    @mock.patch("crmsh.corosync.conf")
    @mock.patch("crmsh.utils.read_from_file")
    def test_remove_qdevice_config(self, mock_read_file, mock_conf, mock_parser, mock_str2file):
        mock_read_file.return_value = "data"
        mock_conf.side_effect = ["corosync.conf", "corosync.conf"]
        mock_instance = mock.Mock()
        mock_parser.return_value = mock_instance
        mock_instance.to_string.return_value = "string data"

        self.qdevice_with_ip.remove_qdevice_config()

        mock_conf.assert_has_calls([mock.call(), mock.call()])
        mock_parser.assert_called_once_with("data")
        mock_read_file.assert_called_once_with("corosync.conf")
        mock_instance.remove.assert_called_once_with("quorum.device")
        mock_instance.to_string.assert_called_once_with()
        mock_str2file.assert_called_once_with("string data", "corosync.conf")

    @mock.patch("crmsh.parallax.parallax_call")
    @mock.patch('crmsh.utils.list_cluster_nodes')
    @mock.patch('os.path.exists')
    def test_remove_qdevice_db_not_exist(self, mock_exists, mock_list_nodes, mock_call):
        mock_exists.return_value = False

        self.qdevice_with_ip.remove_qdevice_db()

        mock_exists.assert_called_once_with('/etc/corosync/qdevice/net/nssdb')
        mock_list_nodes.assert_not_called()
        mock_call.assert_not_called()

    @mock.patch("crmsh.parallax.parallax_call")
    @mock.patch('crmsh.utils.list_cluster_nodes')
    @mock.patch('os.path.exists')
    def test_remove_qdevice_db(self, mock_exists, mock_list_nodes, mock_call):
        mock_exists.return_value = True
        mock_list_nodes.return_value = ["node1.com", "node2.com"]
        mock_call.return_value = [("node1.com", (0, None, None)), ("node2.com", (0, None, None))]

        self.qdevice_with_ip.remove_qdevice_db()

        mock_exists.assert_called_once_with('/etc/corosync/qdevice/net/nssdb')
        mock_list_nodes.assert_called_once_with()
        mock_call.assert_called_once_with(mock_list_nodes.return_value,
                                          'rm -rf /etc/corosync/qdevice/net/*'.format(), False)


if __name__ == '__main__':
    unittest.main()
