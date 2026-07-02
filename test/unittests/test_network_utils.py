# Copyright (C) 2014 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.
#
# unit tests for network_utils.py

import socket
import unittest
from unittest import mock

import pytest

from crmsh import network_utils


@mock.patch("crmsh.network_utils.sh.LocalShell.get_rc_and_error")
def test_check_ssh_passwd_need(mock_run):
    mock_run.return_value = (1, 'foo')
    res = network_utils.check_ssh_passwd_need("bob", "alice", "node1")
    assert res is True
    mock_run.assert_called_once_with(
        "bob",
        "ssh -o StrictHostKeyChecking=no -o EscapeChar=none -o ConnectTimeout=15 -T -o Batchmode=yes alice@node1 true",
    )


@mock.patch("crmsh.network_utils.socket.getaddrinfo")
@mock.patch("crmsh.network_utils.socket.socket")
@mock.patch("crmsh.network_utils.selectors.DefaultSelector")
@mock.patch("crmsh.network_utils.time.sleep")
def test_check_port_open_false(mock_sleep, mock_selector_cls, mock_socket, mock_getaddrinfo):
    sock_inst = mock.Mock()
    mock_socket.return_value = sock_inst
    sock_inst.connect_ex.return_value = 1
    mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 22))]

    mock_selector = mock.Mock()
    mock_selector_cls.return_value = mock_selector
    mock_selector.select.return_value = []

    assert network_utils.check_port_open("localhost", 22) is False

    assert mock_socket.call_count == 3
    assert sock_inst.connect_ex.call_count == 3
    assert mock_selector_cls.call_count == 3
    assert mock_selector.select.call_count == 3
    assert mock_sleep.call_count == 2

@mock.patch("crmsh.network_utils.socket.getaddrinfo")
@mock.patch("crmsh.network_utils.socket.socket")
@mock.patch("crmsh.network_utils.selectors.DefaultSelector")
def test_check_port_open_true(mock_selector_cls, mock_socket, mock_getaddrinfo):
    sock_inst = mock.Mock()
    mock_socket.return_value = sock_inst
    sock_inst.connect_ex.return_value = 0
    mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 22))]

    mock_selector = mock.Mock()
    mock_selector_cls.return_value = mock_selector

    assert network_utils.check_port_open("localhost", 22) is True

    assert mock_socket.call_count == 1
    assert sock_inst.connect_ex.call_count == 1
    assert mock_selector_cls.call_count == 1

def test_valid_port():
    assert network_utils.valid_port(1) is False
    assert network_utils.valid_port(10000000) is False
    assert network_utils.valid_port(1234) is True



class TestIP(unittest.TestCase):
    """
    Unitary tests for class network_utils.IP
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
        self.ip_inst = network_utils.IP("10.10.10.1")

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    @mock.patch("crmsh.network_utils.ipaddress.ip_address")
    def test_ip_address(self, mock_ip_address):
        mock_ip_address_inst = mock.Mock()
        mock_ip_address.return_value = mock_ip_address_inst
        self.ip_inst.ip_address
        mock_ip_address.assert_called_once_with("10.10.10.1")

    @mock.patch('crmsh.network_utils.IP.ip_address', new_callable=mock.PropertyMock)
    def test_version(self, mock_ip_address):
        mock_ip_address_inst = mock.Mock(version=4)
        mock_ip_address.return_value = mock_ip_address_inst
        res = self.ip_inst.version
        self.assertEqual(res, mock_ip_address_inst.version)
        mock_ip_address.assert_called_once_with()

    @mock.patch('crmsh.network_utils.IP.ip_address', new_callable=mock.PropertyMock)
    def test_is_mcast(self, mock_ip_address):
        mock_ip_address_inst = mock.Mock(is_multicast=False)
        mock_ip_address.return_value = mock_ip_address_inst
        res = network_utils.IP.is_mcast("10.10.10.1")
        self.assertEqual(res, False)
        mock_ip_address.assert_called_once_with()

    @mock.patch('crmsh.network_utils.IP.version', new_callable=mock.PropertyMock)
    def test_is_ipv6(self, mock_version):
        mock_version.return_value = 4
        res = network_utils.IP.is_ipv6("10.10.10.1")
        self.assertEqual(res, False)
        mock_version.assert_called_once_with()

    @mock.patch('crmsh.network_utils.IP.ip_address', new_callable=mock.PropertyMock)
    def test_is_loopback(self, mock_ip_address):
        mock_ip_address_inst = mock.Mock(is_loopback=False)
        mock_ip_address.return_value = mock_ip_address_inst
        res = self.ip_inst.is_loopback
        self.assertEqual(res, mock_ip_address_inst.is_loopback)
        mock_ip_address.assert_called_once_with()


class TestInterface(unittest.TestCase):
    """
    Unitary tests for class network_utils.Interface
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
        self.interface = network_utils.Interface("10.10.10.123/24")

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    def test_ip_with_mask(self):
        assert self.interface.ip_with_mask == "10.10.10.123/24"

    @mock.patch("crmsh.network_utils.ipaddress.ip_interface")
    def test_ip_interface(self, mock_ip_interface):
        mock_ip_interface_inst = mock.Mock()
        mock_ip_interface.return_value = mock_ip_interface_inst
        self.interface.ip_interface
        mock_ip_interface.assert_called_once_with("10.10.10.123/24")

    @mock.patch('crmsh.network_utils.Interface.ip_interface', new_callable=mock.PropertyMock)
    def test_network(self, mock_ip_interface):
        mock_ip_interface_inst = mock.Mock()
        mock_ip_interface.return_value = mock_ip_interface_inst
        mock_ip_interface_inst.network = mock.Mock(network_address="10.10.10.0")
        assert self.interface.network == "10.10.10.0"
        mock_ip_interface.assert_called_once_with()


class TestInterfacesInfo(unittest.TestCase):
    """
    Unitary tests for class network_utils.InterfacesInfo
    """

    network_output_error = """1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: enp1s0    inet 192.168.122.241/24 brd 192.168.122.255 scope global enp1s0
61: tun0    inet 10.163.45.46 peer 10.163.45.45/32 scope global tun0"""

    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

    def setUp(self):
        """
        Test setUp.
        """
        self.interfaces_info = network_utils.InterfacesInfo()
        self.interfaces_info_with_custom_nic = network_utils.InterfacesInfo(custom_nic_addr_list=['eth1'])
        self.interfaces_info_with_wrong_nic = network_utils.InterfacesInfo(custom_nic_addr_list=['eth7'])
        self.interfaces_info_fake = network_utils.InterfacesInfo()
        self.interfaces_info_fake._nic_info_dict = {
                "eth0": [mock.Mock(ip="10.10.10.1", network="10.10.10.0"), mock.Mock(ip="10.10.10.2", network="10.10.10.0")],
                "eth1": [mock.Mock(ip="20.20.20.1", network="20.20.20.0")]
                }
        self.interfaces_info_fake._default_nic_list = ["eth7"]

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    @mock.patch("crmsh.network_utils.ShellUtils.get_stdout_stderr")
    def test_get_interfaces_info_no_address(self, mock_run):
        only_lo = "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever"
        mock_run.return_value = (0, only_lo, None)
        with self.assertRaises(ValueError) as err:
            self.interfaces_info.get_interfaces_info()
        self.assertEqual("No address configured", str(err.exception))
        mock_run.assert_called_once_with("ip -4 -o addr show")

    def test_nic_list(self):
        res = self.interfaces_info_fake.nic_list
        self.assertEqual(res, ["eth0", "eth1"])
 
    def test_interface_list(self):
        res = self.interfaces_info_fake.interface_list
        assert len(res) == 3

    @mock.patch('crmsh.network_utils.InterfacesInfo.interface_list', new_callable=mock.PropertyMock)
    def test_ip_list(self, mock_interface_list):
        mock_interface_list.return_value = [
                mock.Mock(ip="10.10.10.1"),
                mock.Mock(ip="10.10.10.2")
                ]
        res = self.interfaces_info_fake.ip_list
        self.assertEqual(res, ["10.10.10.1", "10.10.10.2"])
        mock_interface_list.assert_called_once_with()

    @mock.patch('crmsh.network_utils.InterfacesInfo.ip_list', new_callable=mock.PropertyMock)
    @mock.patch('crmsh.network_utils.InterfacesInfo.get_interfaces_info')
    def test_get_local_ip_list(self, mock_get_info, mock_ip_list):
        mock_ip_list.return_value = ["10.10.10.1", "10.10.10.2"]
        res = network_utils.InterfacesInfo.get_local_ip_list(False)
        self.assertEqual(res, mock_ip_list.return_value)
        mock_get_info.assert_called_once_with()
        mock_ip_list.assert_called_once_with()

    @mock.patch('crmsh.network_utils.InterfacesInfo.ip_list', new_callable=mock.PropertyMock)
    @mock.patch('crmsh.network_utils.IP.is_ipv6')
    @mock.patch('crmsh.network_utils.InterfacesInfo.get_interfaces_info')
    def test_ip_in_local(self, mock_get_info, mock_is_ipv6, mock_ip_list):
        mock_is_ipv6.return_value = False
        mock_ip_list.return_value = ["10.10.10.1", "10.10.10.2"]
        res = network_utils.InterfacesInfo.ip_in_local("10.10.10.1")
        assert res is True
        mock_get_info.assert_called_once_with()
        mock_ip_list.assert_called_once_with()
        mock_is_ipv6.assert_called_once_with("10.10.10.1")

    @mock.patch('crmsh.network_utils.InterfacesInfo.interface_list', new_callable=mock.PropertyMock)
    def test_network_list(self, mock_interface_list):
        mock_interface_list.return_value = [
                mock.Mock(network="10.10.10.0"),
                mock.Mock(network="20.20.20.0")
                ]
        res = self.interfaces_info.network_list
        self.assertEqual(res, list(set(["10.10.10.0", "20.20.20.0"])))
        mock_interface_list.assert_called_once_with()

    def test_nic_first_ip(self):
        res = self.interfaces_info_fake.nic_first_ip("eth0")
        self.assertEqual(res, "10.10.10.1")

    @mock.patch("crmsh.network_utils.sh.cluster_shell")
    def test_get_default_nic_from_route(self, mock_run):
        output = """default via 192.168.122.1 dev eth8 proto dhcp 
        10.10.10.0/24 dev eth1 proto kernel scope link src 10.10.10.51 
        20.20.20.0/24 dev eth2 proto kernel scope link src 20.20.20.51 
        192.168.122.0/24 dev eth8 proto kernel scope link src 192.168.122.120"""
        mock_run_inst = mock.Mock()
        mock_run.return_value = mock_run_inst
        mock_run_inst.get_stdout_or_raise_error.return_value = output

        res = self.interfaces_info.get_default_nic_from_route()
        self.assertEqual(res, "eth8")

        mock_run_inst.get_stdout_or_raise_error.assert_called_once_with("ip -o route show")



@mock.patch('crmsh.network_utils.ssh_port_reachable_check')
@mock.patch("crmsh.network_utils.xmlutil.CrmMonXmlParser")
def test_check_all_nodes_reachable_dead_nodes(mock_xml, mock_reachable):
    mock_xml_inst = mock.Mock()
    mock_xml.return_value = mock_xml_inst
    mock_xml_inst.not_connected.return_value = False
    mock_xml_inst.get_node_list.side_effect = [["node1"], ["node2"]]
    mock_reachable.side_effect = ValueError

    with pytest.raises(network_utils.DeadNodeError) as err:
        network_utils.check_all_nodes_reachable("testing")
    assert err.value.summary.dead_nodes == ["node2"]


@mock.patch('crmsh.network_utils.check_ssh_passwd_need')
@mock.patch("crmsh.network_utils.crmsh.user_of_host.UserOfHost.instance")
@mock.patch('crmsh.network_utils.ssh_port_reachable_check')
@mock.patch("crmsh.network_utils.xmlutil.CrmMonXmlParser")
def test_check_all_nodes_reachable(mock_xml, mock_reachable, mock_user_of_host, mock_check_passwd):
    mock_xml_inst = mock.Mock()
    mock_xml.return_value = mock_xml_inst
    mock_xml_inst.not_connected.return_value = False
    mock_xml_inst.get_node_list.side_effect = [["node1"], []]
    mock_user_of_host_inst = mock.Mock()
    mock_user_of_host.return_value = mock_user_of_host_inst
    mock_user_of_host_inst.user_pair_for_ssh = mock.Mock(return_value=("root", "root"))
    mock_check_passwd.return_value = False
    network_utils.check_all_nodes_reachable("testing")
    mock_reachable.assert_called_once_with("node1")


@mock.patch("crmsh.network_utils.logger.warning")
@mock.patch('crmsh.network_utils.ssh_port_reachable_check')
def test_get_reachable_node_list(mock_reachable, mock_warn):
    mock_reachable.side_effect = [False, True, ValueError("error for node3")]
    assert network_utils.get_reachable_node_list(["node1", "node2", "node3"]) == ["node2"]
    mock_warn.assert_called_once_with("error for node3")
    mock_reachable.assert_has_calls([
        mock.call("node1"),
        mock.call("node2"),
        mock.call("node3")
    ])


