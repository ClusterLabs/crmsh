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
        self.qdevice_with_invalid_algo = corosync.QDevice("10.10.10.123", algo="wrong")
        self.qdevice_with_invalid_tie_breaker = corosync.QDevice("10.10.10.123", tie_breaker="wrong")
        self.qdevice_with_invalid_tls = corosync.QDevice("10.10.10.123", tls="wrong")
        self.qdevice_with_ip_cluster_node = corosync.QDevice("10.10.10.123", cluster_node="node1.com")

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    @mock.patch("crmsh.utils.this_node")
    @mock.patch("crmsh.utils.ip_in_local")
    def test_valid_attr_remote_exception(self, mock_ip_in_local, mock_this_node):
        mock_ip_in_local.return_value = ["192.168.1.1", "10.10.10.123"]
        mock_this_node.return_value = "node1.com"

        with self.assertRaises(ValueError) as err:
            self.qdevice_with_ip.valid_attr()

        self.assertEqual("host for qnetd must be a remote one", str(err.exception))
        mock_ip_in_local.assert_called_once_with()
        mock_this_node.assert_called_once_with()

    @mock.patch("crmsh.utils.this_node")
    @mock.patch("crmsh.utils.ip_in_local")
    @mock.patch("crmsh.utils.resolve_hostnames")
    def test_valid_attr_unreachable_exception(self, mock_resolve, mock_ip_in_local, mock_this_node):
        mock_resolve.return_value = (False, "node.qnetd")
        mock_ip_in_local.return_value = ["192.168.1.1", "10.10.10.123"]
        mock_this_node.return_value = "node1.com"

        with self.assertRaises(ValueError) as err:
            self.qdevice_with_hostname.valid_attr()
        self.assertEqual("host \"node.qnetd\" is unreachable", str(err.exception))

        mock_ip_in_local.assert_called_once_with()
        mock_this_node.assert_called_once_with()
        mock_resolve.assert_called_once_with(["node.qnetd"])

    @mock.patch("crmsh.utils.this_node")
    @mock.patch("crmsh.utils.ip_in_local")
    @mock.patch("crmsh.utils.resolve_hostnames")
    @mock.patch("crmsh.utils.check_port_open")
    def test_valid_attr_ssh_service_exception(self, mock_port_open, mock_resolve,
                                              mock_ip_in_local, mock_this_node):
        mock_resolve.return_value = (True, None)
        mock_ip_in_local.return_value = ["192.168.1.1", "10.10.10.11"]
        mock_this_node.return_value = "node1.com"
        mock_port_open.return_value = False

        with self.assertRaises(ValueError) as err:
            self.qdevice_with_ip.valid_attr()
        self.assertEqual("ssh service on \"10.10.10.123\" not available", str(err.exception))

        mock_ip_in_local.assert_called_once_with()
        mock_this_node.assert_called_once_with()
        mock_resolve.assert_called_once_with(["10.10.10.123"])
        mock_port_open.assert_called_once_with("10.10.10.123", 22)

    @mock.patch("crmsh.utils.this_node")
    @mock.patch("crmsh.utils.ip_in_local")
    @mock.patch("crmsh.utils.resolve_hostnames")
    @mock.patch("crmsh.utils.check_port_open")
    @mock.patch("crmsh.utils.valid_port")
    def test_valid_attr_invalid_port_exception(self, mock_valid_port, mock_port_open,
                                               mock_resolve, mock_ip_in_local, mock_this_node):
        mock_resolve.return_value = (True, None)
        mock_ip_in_local.return_value = ["192.168.1.1", "10.10.10.11"]
        mock_this_node.return_value = "node1.com"
        mock_port_open.return_value = True
        mock_valid_port.return_value = False

        with self.assertRaises(ValueError) as err:
            self.qdevice_with_invalid_port.valid_attr()
        self.assertEqual("invalid qdevice port range(1024 - 65535)", str(err.exception))

        mock_ip_in_local.assert_called_once_with()
        mock_this_node.assert_called_once_with()
        mock_resolve.assert_called_once_with(["10.10.10.123"])
        mock_port_open.assert_called_once_with("10.10.10.123", 22)
        mock_valid_port.assert_called_once_with(100)

    @mock.patch("crmsh.utils.this_node")
    @mock.patch("crmsh.utils.ip_in_local")
    @mock.patch("crmsh.utils.resolve_hostnames")
    @mock.patch("crmsh.utils.check_port_open")
    @mock.patch("crmsh.utils.valid_port")
    def test_valid_attr_invalid_port_exception(self, mock_valid_port, mock_port_open,
                                               mock_resolve, mock_ip_in_local, mock_this_node):
        mock_resolve.return_value = (True, None)
        mock_ip_in_local.return_value = ["192.168.1.1", "10.10.10.11"]
        mock_this_node.return_value = "node1.com"
        mock_port_open.return_value = True
        mock_valid_port.return_value = True

        with self.assertRaises(ValueError) as err:
            self.qdevice_with_invalid_algo.valid_attr()
        self.assertEqual("invalid qdevice algorithm(ffsplit/lms)", str(err.exception))

        mock_ip_in_local.assert_called_once_with()
        mock_this_node.assert_called_once_with()
        mock_resolve.assert_called_once_with(["10.10.10.123"])
        mock_port_open.assert_called_once_with("10.10.10.123", 22)
        mock_valid_port.assert_called_once_with(5403)

    @mock.patch("crmsh.utils.this_node")
    @mock.patch("crmsh.utils.ip_in_local")
    @mock.patch("crmsh.utils.resolve_hostnames")
    @mock.patch("crmsh.utils.check_port_open")
    @mock.patch("crmsh.utils.valid_port")
    @mock.patch("crmsh.utils.valid_nodeid")
    def test_valid_attr_invalid_nodeid_exception(self, mock_valid_nodeid, mock_valid_port, mock_port_open,
                                                 mock_resolve, mock_ip_in_local, mock_this_node):
        mock_resolve.return_value = (True, None)
        mock_ip_in_local.return_value = ["192.168.1.1", "10.10.10.11"]
        mock_this_node.return_value = "node1.com"
        mock_port_open.return_value = True
        mock_valid_port.return_value = True
        mock_valid_nodeid.return_value = False

        with self.assertRaises(ValueError) as err:
            self.qdevice_with_invalid_tie_breaker.valid_attr()
        self.assertEqual("invalid qdevice tie_breaker(lowest/highest/valid_node_id)", str(err.exception))

        mock_ip_in_local.assert_called_once_with()
        mock_this_node.assert_called_once_with()
        mock_resolve.assert_called_once_with(["10.10.10.123"])
        mock_port_open.assert_called_once_with("10.10.10.123", 22)
        mock_valid_port.assert_called_once_with(5403)
        mock_valid_nodeid.assert_called_once_with("wrong")

    @mock.patch("crmsh.utils.this_node")
    @mock.patch("crmsh.utils.ip_in_local")
    @mock.patch("crmsh.utils.resolve_hostnames")
    @mock.patch("crmsh.utils.check_port_open")
    @mock.patch("crmsh.utils.valid_port")
    @mock.patch("crmsh.utils.valid_nodeid")
    def test_valid_attr_invalid_tls_exception(self, mock_valid_nodeid, mock_valid_port, mock_port_open,
                                              mock_resolve, mock_ip_in_local, mock_this_node):
        mock_resolve.return_value = (True, None)
        mock_ip_in_local.return_value = ["192.168.1.1", "10.10.10.11"]
        mock_this_node.return_value = "node1.com"
        mock_port_open.return_value = True
        mock_valid_port.return_value = True
        mock_valid_nodeid.return_value = True

        with self.assertRaises(ValueError) as err:
            self.qdevice_with_invalid_tls.valid_attr()
        self.assertEqual("invalid qdevice tls(on/off/required)", str(err.exception))

        mock_ip_in_local.assert_called_once_with()
        mock_this_node.assert_called_once_with()
        mock_resolve.assert_called_once_with(["10.10.10.123"])
        mock_port_open.assert_called_once_with("10.10.10.123", 22)
        mock_valid_port.assert_called_once_with(5403)
        mock_valid_nodeid.assert_not_called()

    def test_valid_qnetd_exception(self):
        self.qdevice_with_ip.check_ssh_passwd_need = mock.Mock(return_value=True)
        self.qdevice_with_ip.remote_running_cluster = mock.Mock(return_value=True)

        with self.assertRaises(ValueError) as err:
            self.qdevice_with_ip.valid_qnetd()
        self.assertEqual("host for qnetd must be a non-cluster node", str(err.exception))

        self.qdevice_with_ip.check_ssh_passwd_need.assert_called_once_with()
        self.qdevice_with_ip.remote_running_cluster.assert_called_once_with()

    @mock.patch("crmsh.utils.check_ssh_passwd_need")
    def test_check_ssh_passwd_need(self, mock_ssh_passwd):
        mock_ssh_passwd.return_value = True
        self.assertTrue(self.qdevice_with_ip.check_ssh_passwd_need())
        mock_ssh_passwd.assert_called_once_with(["10.10.10.123"])

    @mock.patch("crmsh.parallax.parallax_call")
    def test_remote_running_cluster_false(self, mock_call):
        mock_call.side_effect = ValueError(mock.Mock(), "Failed on 10.10.10.123: error happen")
        self.assertFalse(self.qdevice_with_ip.remote_running_cluster())
        mock_call.assert_called_once_with(["10.10.10.123"], "systemctl -q is-active pacemaker", False)

    @mock.patch("crmsh.parallax.parallax_call")
    def test_remote_running_cluster_true(self, mock_call):
        mock_call.return_value = ["10.10.10.123", (0, None, None)]
        self.assertTrue(self.qdevice_with_ip.remote_running_cluster())
        mock_call.assert_called_once_with(["10.10.10.123"], "systemctl -q is-active pacemaker", False)

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
    @mock.patch("crmsh.utils.list_cluster_nodes")
    @mock.patch("crmsh.utils.this_node")
    @mock.patch("crmsh.parallax.parallax_call")
    def test_import_p12_on_cluster_one_node(self, mock_call, mock_this_node, mock_list_nodes, mock_log):
        mock_this_node.return_value = "node1.com"
        mock_list_nodes.return_value = ["node1.com"]

        self.qdevice_with_ip.import_p12_on_cluster()

        mock_log.assert_not_called()
        mock_this_node.assert_called_once_with()
        mock_list_nodes.assert_called_once_with()
        mock_call.assert_not_called()

    @mock.patch("crmsh.corosync.QDevice.debug_and_log_to_bootstrap")
    @mock.patch("crmsh.utils.list_cluster_nodes")
    @mock.patch("crmsh.utils.this_node")
    @mock.patch("crmsh.parallax.parallax_call")
    @mock.patch("crmsh.corosync.QDevice.qdevice_p12_on_local", new_callable=mock.PropertyMock)
    def test_import_p12_on_cluster(self, mock_p12_on_local, mock_call, mock_this_node, mock_list_nodes, mock_log):
        mock_this_node.return_value = "node1.com"
        mock_list_nodes.return_value = ["node1.com", "node2.com"]
        mock_p12_on_local.return_value = "/etc/corosync/qdevice/net/nssdb/qdevice-net-node.p12"
        mock_call.return_value = [("node1.com", (0, None, None)), ("node2.com", (0, None, None))]

        self.qdevice_with_ip.import_p12_on_cluster()

        mock_log.assert_called_once_with("Step 11: Import qdevice-net-node.p12 on ['node1.com', 'node2.com']")
        mock_this_node.assert_not_called()
        mock_list_nodes.assert_called_once_with()
        mock_call.assert_called_once_with(["node1.com", "node2.com"],
                                          "corosync-qdevice-net-certutil -m -c {}".format(mock_p12_on_local.return_value),
                                          False)
        mock_p12_on_local.assert_called_once_with()

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

    @mock.patch("os.fsync")
    @mock.patch("crmsh.corosync.make_section")
    @mock.patch("crmsh.corosync.Parser")
    @mock.patch("crmsh.corosync.conf")
    @mock.patch("builtins.open")
    def test_config(self, mock_open_file, mock_conf, mock_parser, mock_mksection, mock_fsync):
        open_return_value_1 = mock.mock_open(read_data=F2).return_value
        open_return_value_2 = mock.mock_open().return_value
        mock_open_file.side_effect = [
            open_return_value_1,
            open_return_value_2
        ]
        mock_mksection.side_effect = [
            ["device {", "}"],
            ["net {", "}"]
        ]
        mock_conf.return_value = "/etc/corosync/corosync.conf"
        mock_instance = mock.Mock()
        mock_parser.return_value = mock_instance

        self.qdevice_with_ip.config()

        mock_open_file.assert_has_calls([
            mock.call(mock_conf.return_value),
            mock.call(mock_conf.return_value, 'w')
        ])
        mock_conf.assert_has_calls([mock.call(), mock.call()])
        mock_parser.assert_called_once_with(F2)
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
        mock_fsync.assert_called_once_with(open_return_value_2)
        open_return_value_2.write.assert_called_once_with(mock_instance.to_string())
        open_return_value_2.flush.assert_called_once_with()
        open_return_value_2.close.assert_called_once_with()

    @mock.patch("os.fsync")
    @mock.patch("crmsh.corosync.Parser")
    @mock.patch("crmsh.corosync.conf")
    @mock.patch("builtins.open")
    def test_remove_config(self, mock_open_file, mock_conf, mock_parser, mock_fsync):
        open_return_value_1 = mock.mock_open(read_data=F4).return_value
        open_return_value_2 = mock.mock_open().return_value
        mock_open_file.side_effect = [
            open_return_value_1,
            open_return_value_2
        ]
        mock_conf.return_value = "/etc/corosync/corosync.conf"
        mock_instance = mock.Mock()
        mock_parser.return_value = mock_instance

        self.qdevice_with_ip.remove_config()

        mock_open_file.assert_has_calls([
            mock.call(mock_conf.return_value),
            mock.call(mock_conf.return_value, 'w')
        ])
        mock_conf.assert_has_calls([mock.call(), mock.call()])
        mock_parser.assert_called_once_with(F4)
        mock_instance.remove.assert_called_once_with("quorum.device")
        mock_instance.to_string.assert_called_once_with()
        mock_fsync.assert_called_once_with(open_return_value_2)
        open_return_value_2.write.assert_called_once_with(mock_instance.to_string())
        open_return_value_2.flush.assert_called_once_with()
        open_return_value_2.close.assert_called_once_with()

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
