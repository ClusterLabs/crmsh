from __future__ import unicode_literals
# Copyright (C) 2014 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.
#
# unit tests for utils.py

import os
import socket
import re
import imp
from unittest import mock
from itertools import chain
from crmsh import utils
from crmsh import config
from crmsh import tmpfiles

def setup_function():
    utils._ip_for_cloud = None
    # Mock memoize method and reload the module under test later with imp
    mock.patch('crmsh.utils.memoize', lambda x: x).start()
    imp.reload(utils)


@mock.patch('re.search')
@mock.patch('crmsh.utils.get_stdout')
def test_get_nodeid_from_name_run_None1(mock_get_stdout, mock_re_search):
    mock_get_stdout.return_value = (1, None)
    mock_re_search_inst = mock.Mock()
    mock_re_search.return_value = mock_re_search_inst
    res = utils.get_nodeid_from_name("node1")
    assert res is None
    mock_get_stdout.assert_called_once_with('crm_node -l')
    mock_re_search.assert_not_called()


@mock.patch('re.search')
@mock.patch('crmsh.utils.get_stdout')
def test_get_nodeid_from_name_run_None2(mock_get_stdout, mock_re_search):
    mock_get_stdout.return_value = (0, "172167901 node1 member\n172168231 node2 member")
    mock_re_search.return_value = None
    res = utils.get_nodeid_from_name("node111")
    assert res is None
    mock_get_stdout.assert_called_once_with('crm_node -l')
    mock_re_search.assert_called_once_with(r'^([0-9]+) node111 ', mock_get_stdout.return_value[1], re.M)


@mock.patch('re.search')
@mock.patch('crmsh.utils.get_stdout')
def test_get_nodeid_from_name(mock_get_stdout, mock_re_search):
    mock_get_stdout.return_value = (0, "172167901 node1 member\n172168231 node2 member")
    mock_re_search_inst = mock.Mock()
    mock_re_search.return_value = mock_re_search_inst
    mock_re_search_inst.group.return_value = '172168231'
    res = utils.get_nodeid_from_name("node2")
    assert res == '172168231'
    mock_get_stdout.assert_called_once_with('crm_node -l')
    mock_re_search.assert_called_once_with(r'^([0-9]+) node2 ', mock_get_stdout.return_value[1], re.M)
    mock_re_search_inst.group.assert_called_once_with(1)


def test_check_ssh_passwd_need_True():
    with mock.patch('crmsh.utils.get_stdout_stderr') as mock_get_stdout_stderr:
        mock_get_stdout_stderr.side_effect = [(0, None, None), (1, None, None)]
        assert utils.check_ssh_passwd_need(["node1", "node2"]) == True
    mock_get_stdout_stderr.assert_has_calls([
            mock.call('ssh -o StrictHostKeyChecking=no -o EscapeChar=none -o ConnectTimeout=15 -T -o Batchmode=yes node1 true'),
            mock.call('ssh -o StrictHostKeyChecking=no -o EscapeChar=none -o ConnectTimeout=15 -T -o Batchmode=yes node2 true')
        ])


def test_check_ssh_passwd_need_Flase():
    with mock.patch('crmsh.utils.get_stdout_stderr') as mock_get_stdout_stderr:
        mock_get_stdout_stderr.side_effect = [(0, None, None), (0, None, None)]
        assert utils.check_ssh_passwd_need(["node1", "node2"]) == False
    mock_get_stdout_stderr.assert_has_calls([
            mock.call('ssh -o StrictHostKeyChecking=no -o EscapeChar=none -o ConnectTimeout=15 -T -o Batchmode=yes node1 true'),
            mock.call('ssh -o StrictHostKeyChecking=no -o EscapeChar=none -o ConnectTimeout=15 -T -o Batchmode=yes node2 true')
        ])


@mock.patch('crmsh.utils.common_debug')
@mock.patch('crmsh.utils.get_stdout_stderr')
def test_get_member_iplist_None(mock_get_stdout_stderr, mock_common_debug):
    mock_get_stdout_stderr.return_value = (1, None, "Failed to initialize the cmap API. Error CS_ERR_LIBRARY")
    assert utils.get_member_iplist() is None
    mock_get_stdout_stderr.assert_called_once_with('corosync-cmapctl -b runtime.totem.pg.mrp.srp.members')
    mock_common_debug.assert_called_once_with('Failed to initialize the cmap API. Error CS_ERR_LIBRARY')


def test_get_member_iplist():
    with mock.patch('crmsh.utils.get_stdout_stderr') as mock_get_stdout_stderr:
        cmap_value = '''
runtime.totem.pg.mrp.srp.members.336860211.config_version (u64) = 0
runtime.totem.pg.mrp.srp.members.336860211.ip (str) = r(0) ip(20.20.20.51)
runtime.totem.pg.mrp.srp.members.336860211.join_count (u32) = 1
runtime.totem.pg.mrp.srp.members.336860211.status (str) = joined
runtime.totem.pg.mrp.srp.members.336860212.config_version (u64) = 0
runtime.totem.pg.mrp.srp.members.336860212.ip (str) = r(0) ip(20.20.20.52)
runtime.totem.pg.mrp.srp.members.336860212.join_count (u32) = 1
runtime.totem.pg.mrp.srp.members.336860212.status (str) = joined
        '''
        mock_get_stdout_stderr.return_value = (0, cmap_value, None)
        assert utils.get_member_iplist() == ['20.20.20.51', '20.20.20.52']
    mock_get_stdout_stderr.assert_called_once_with('corosync-cmapctl -b runtime.totem.pg.mrp.srp.members')


def test_list_cluster_nodes_pacemaker_running():
    with mock.patch('crmsh.utils.stdout2list') as mock_stdout2list:
        crm_node_value= ["336860211 15sp1-1 member", "336860212 15sp1-2 member"]
        mock_stdout2list.return_value = (0, crm_node_value)
        assert utils.list_cluster_nodes() == ['15sp1-1', '15sp1-2']
    mock_stdout2list.assert_called_once_with(['crm_node', '-l'], shell=False, stderr_on=False)


@mock.patch('crmsh.utils.stdout2list')
@mock.patch('crmsh.utils.get_member_iplist')
def test_list_cluster_nodes_corosync_running(mock_get_member_iplist, mock_stdout2list):
    mock_stdout2list.return_value = (1, None)
    mock_get_member_iplist.return_value = ["node1", "node2"]
    assert utils.list_cluster_nodes() == ["node1", "node2"]
    mock_stdout2list.assert_called_once_with(['crm_node', '-l'], shell=False, stderr_on=False)
    mock_get_member_iplist.assert_called_once_with()


def test_to_ascii():
    assert utils.to_ascii(None) is None
    assert utils.to_ascii('test') == 'test'
    assert utils.to_ascii(b'test') == 'test'
    # Test not utf-8 characters
    with mock.patch('traceback.print_exc') as mock_traceback:
        assert utils.to_ascii(b'te\xe9st') == 'test'
    mock_traceback.assert_called_once_with()


def test_systeminfo():
    assert utils.getuser() is not None
    assert utils.gethomedir() is not None
    assert utils.get_tempdir() is not None


def test_shadowcib():
    assert utils.get_cib_in_use() == ""
    utils.set_cib_in_use("foo")
    assert utils.get_cib_in_use() == "foo"
    utils.clear_cib_in_use()
    assert utils.get_cib_in_use() == ""


def test_booleans():
    truthy = ['yes', 'Yes', 'True', 'true', 'TRUE',
              'YES', 'on', 'On', 'ON']
    falsy = ['no', 'false', 'off', 'OFF', 'FALSE', 'nO']
    not_truthy = ['', 'not', 'ONN', 'TRUETH', 'yess']
    for case in chain(truthy, falsy):
        assert utils.verify_boolean(case) is True
    for case in truthy:
        assert utils.is_boolean_true(case) is True
        assert utils.is_boolean_false(case) is False
        assert utils.get_boolean(case) is True
    for case in falsy:
        assert utils.is_boolean_true(case) is False
        assert utils.is_boolean_false(case) is True
        assert utils.get_boolean(case, dflt=True) is False
    for case in not_truthy:
        assert utils.verify_boolean(case) is False
        assert utils.is_boolean_true(case) is False
        assert utils.is_boolean_false(case) is False
        assert utils.get_boolean(case) is False


def test_olist():
    lst = utils.olist(['B', 'C', 'A'])
    lst.append('f')
    lst.append('aA')
    lst.append('_')
    assert 'aa' in lst
    assert 'a' in lst
    assert list(lst) == ['b', 'c', 'a', 'f', 'aa', '_']


def test_add_sudo():
    tmpuser = config.core.user
    try:
        config.core.user = 'root'
        assert utils.add_sudo('ls').startswith('sudo')
        config.core.user = ''
        assert utils.add_sudo('ls') == 'ls'
    finally:
        config.core.user = tmpuser


def test_str2tmp():
    txt = "This is a test string"
    filename = utils.str2tmp(txt)
    assert os.path.isfile(filename)
    assert open(filename).read() == txt + "\n"
    assert utils.file2str(filename) == txt
    # TODO: should this really return
    # an empty line at the end?
    assert utils.file2list(filename) == [txt, '']
    os.unlink(filename)


def test_sanity():
    sane_paths = ['foo/bar', 'foo', '/foo/bar', 'foo0',
                  'foo_bar', 'foo-bar', '0foo', '.foo',
                  'foo.bar']
    insane_paths = ['#foo', 'foo?', 'foo*', 'foo$', 'foo[bar]',
                    'foo`', "foo'", 'foo/*']
    for p in sane_paths:
        assert utils.is_path_sane(p)
    for p in insane_paths:
        assert not utils.is_path_sane(p)
    sane_filenames = ['foo', '0foo', '0', '.foo']
    insane_filenames = ['foo/bar']
    for p in sane_filenames:
        assert utils.is_filename_sane(p)
    for p in insane_filenames:
        assert not utils.is_filename_sane(p)
    sane_names = ['foo']
    insane_names = ["f'o"]
    for n in sane_names:
        assert utils.is_name_sane(n)
    for n in insane_names:
        assert not utils.is_name_sane(n)


def test_nvpairs2dict():
    assert utils.nvpairs2dict(['a=b', 'c=d']) == {'a': 'b', 'c': 'd'}
    assert utils.nvpairs2dict(['a=b=c', 'c=d']) == {'a': 'b=c', 'c': 'd'}
    assert utils.nvpairs2dict(['a']) == {'a': None}


def test_validity():
    assert utils.is_id_valid('foo0')
    assert not utils.is_id_valid('0foo')


def test_msec():
    assert utils.crm_msec('1ms') == 1
    assert utils.crm_msec('1s') == 1000
    assert utils.crm_msec('1us') == 0
    assert utils.crm_msec('1') == 1000
    assert utils.crm_msec('1m') == 60*1000
    assert utils.crm_msec('1h') == 60*60*1000


def test_network():
    ip = utils.IP('192.168.1.2')
    assert ip.version() == 4
    ip = utils.IP('2001:db3::1')
    assert ip.version() == 6

    assert (utils.ip_in_network('192.168.2.0', '192.0.2.0/24') is False)
    assert (utils.ip_in_network('192.0.2.42', '192.0.2.0/24') is True)

    assert (utils.ip_in_network('2001:db3::1', '2001:db8::2/64') is False)
    assert (utils.ip_in_network('2001:db8::1', '2001:db8::2/64') is True)

    assert utils.get_ipv6_network("2002:db8::2/64") == "2002:db8::"


def test_parse_sysconfig():
    """
    bsc#1129317: Fails on this line

    FW_SERVICES_ACCEPT_EXT="0/0,tcp,22,,hitcount=3,blockseconds=60,recentname=ssh"
    """
    s = '''
FW_SERVICES_ACCEPT_EXT="0/0,tcp,22,,hitcount=3,blockseconds=60,recentname=ssh"
'''

    fd, fname = tmpfiles.create()
    with open(fname, 'w') as f:
        f.write(s)
    sc = utils.parse_sysconfig(fname)
    assert ("FW_SERVICES_ACCEPT_EXT" in sc)

def test_sysconfig_set():
    s = '''
FW_SERVICES_ACCEPT_EXT="0/0,tcp,22,,hitcount=3,blockseconds=60,recentname=ssh"
'''
    fd, fname = tmpfiles.create()
    with open(fname, 'w') as f:
        f.write(s)
    utils.sysconfig_set(fname, FW_SERVICES_ACCEPT_EXT="foo=bar", FOO="bar")
    sc = utils.parse_sysconfig(fname)
    assert (sc.get("FW_SERVICES_ACCEPT_EXT") == "foo=bar")
    assert (sc.get("FOO") == "bar")

def test_sysconfig_set_bsc1145823():
    s = '''# this is test
#age=1000
'''
    fd, fname = tmpfiles.create()
    with open(fname, 'w') as f:
        f.write(s)
    utils.sysconfig_set(fname, age="100")
    sc = utils.parse_sysconfig(fname)
    assert (sc.get("age") == "100")

@mock.patch("socket.socket")
@mock.patch("crmsh.utils.closing")
def test_check_port_open_false(mock_closing, mock_socket):
    sock_inst = mock.Mock()
    mock_socket.return_value = sock_inst
    mock_closing.return_value.__enter__.return_value = sock_inst
    sock_inst.connect_ex.return_value = 1

    assert utils.check_port_open("node1.com", 22) is False

    mock_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
    mock_closing.assert_called_once_with(sock_inst)
    sock_inst.connect_ex.assert_called_once_with(("node1.com", 22))

@mock.patch("socket.socket")
@mock.patch("crmsh.utils.closing")
def test_check_port_open_true(mock_closing, mock_socket):
    sock_inst = mock.Mock()
    mock_socket.return_value = sock_inst
    mock_closing.return_value.__enter__.return_value = sock_inst
    sock_inst.connect_ex.return_value = 0

    assert utils.check_port_open("node1.com", 22) is True

    mock_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
    mock_closing.assert_called_once_with(sock_inst)
    sock_inst.connect_ex.assert_called_once_with(("node1.com", 22))

def test_valid_port():
    assert utils.valid_port(1) is False
    assert utils.valid_port(10000000) is False
    assert utils.valid_port(1234) is True

@mock.patch("crmsh.corosync.get_value")
def test_is_qdevice_configured_false(mock_get_value):
    mock_get_value.return_value = "ip"
    assert utils.is_qdevice_configured() is False
    mock_get_value.assert_called_once_with("quorum.device.model")

@mock.patch("crmsh.corosync.get_value")
def test_is_qdevice_configured_true(mock_get_value):
    mock_get_value.return_value = "net"
    assert utils.is_qdevice_configured() is True
    mock_get_value.assert_called_once_with("quorum.device.model")

@mock.patch("crmsh.corosync.get_value")
def test_is_qdevice_tls_on_false(mock_get_value):
    mock_get_value.return_value = "off"
    assert utils.is_qdevice_tls_on() is False
    mock_get_value.assert_called_once_with("quorum.device.net.tls")

@mock.patch("crmsh.corosync.get_value")
def test_is_qdevice_tls_on_true(mock_get_value):
    mock_get_value.return_value = "on"
    assert utils.is_qdevice_tls_on() is True
    mock_get_value.assert_called_once_with("quorum.device.net.tls")

@mock.patch("crmsh.utils.get_stdout")
def test_get_nodeinfo_from_cmaptool_return_none(mock_get_stdout):
    mock_get_stdout.return_value = (1, None)
    assert bool(utils.get_nodeinfo_from_cmaptool()) is False
    mock_get_stdout.assert_called_once_with("corosync-cmapctl -b runtime.totem.pg.mrp.srp.members")

@mock.patch("re.findall")
@mock.patch("re.search")
@mock.patch("crmsh.utils.get_stdout")
def test_get_nodeinfo_from_cmaptool(mock_get_stdout, mock_search, mock_findall):
    mock_get_stdout.return_value = (0, 'runtime.totem.pg.mrp.srp.members.1.ip (str) = r(0) ip(192.168.43.129)\nruntime.totem.pg.mrp.srp.members.2.ip (str) = r(0) ip(192.168.43.128)')
    match_inst1 = mock.Mock()
    match_inst2 = mock.Mock()
    mock_search.side_effect = [match_inst1, match_inst2]
    match_inst1.group.return_value = '1'
    match_inst2.group.return_value = '2'
    mock_findall.side_effect = [["192.168.43.129"], ["192.168.43.128"]]

    result = utils.get_nodeinfo_from_cmaptool()
    assert result['1'] == ["192.168.43.129"]
    assert result['2'] == ["192.168.43.128"]

    mock_get_stdout.assert_called_once_with("corosync-cmapctl -b runtime.totem.pg.mrp.srp.members")
    mock_search.assert_has_calls([
        mock.call(r'members\.(.*)\.ip', 'runtime.totem.pg.mrp.srp.members.1.ip (str) = r(0) ip(192.168.43.129)'),
        mock.call(r'members\.(.*)\.ip', 'runtime.totem.pg.mrp.srp.members.2.ip (str) = r(0) ip(192.168.43.128)')
    ])
    match_inst1.group.assert_called_once_with(1)
    match_inst2.group.assert_called_once_with(1)
    mock_findall.assert_has_calls([
        mock.call(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', 'runtime.totem.pg.mrp.srp.members.1.ip (str) = r(0) ip(192.168.43.129)'),
        mock.call(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', 'runtime.totem.pg.mrp.srp.members.2.ip (str) = r(0) ip(192.168.43.128)')
    ])

@mock.patch("crmsh.utils.get_nodeinfo_from_cmaptool")
@mock.patch("crmsh.bootstrap.service_is_active")
def test_valid_nodeid_false_service_not_active(mock_is_active, mock_nodeinfo):
    mock_is_active.return_value = False
    assert utils.valid_nodeid("3") is False
    mock_is_active.assert_called_once_with('corosync.service')
    mock_nodeinfo.assert_not_called()

@mock.patch("crmsh.utils.get_nodeinfo_from_cmaptool")
@mock.patch("crmsh.bootstrap.service_is_active")
def test_valid_nodeid_false(mock_is_active, mock_nodeinfo):
    mock_is_active.return_value = True
    mock_nodeinfo.return_value = {'1': ["10.10.10.1"], "2": ["20.20.20.2"]}
    assert utils.valid_nodeid("3") is False
    mock_is_active.assert_called_once_with('corosync.service')
    mock_nodeinfo.assert_called_once_with()

@mock.patch("crmsh.utils.get_nodeinfo_from_cmaptool")
@mock.patch("crmsh.bootstrap.service_is_active")
def test_valid_nodeid_true(mock_is_active, mock_nodeinfo):
    mock_is_active.return_value = True
    mock_nodeinfo.return_value = {'1': ["10.10.10.1"], "2": ["20.20.20.2"]}
    assert utils.valid_nodeid("2") is True
    mock_is_active.assert_called_once_with('corosync.service')
    mock_nodeinfo.assert_called_once_with()

@mock.patch("crmsh.corosync.get_value")
def test_is_unicast_false(mock_get_value):
    mock_get_value.return_value = None
    assert utils.is_unicast() is False
    mock_get_value.assert_called_once_with("totem.transport")

@mock.patch("crmsh.corosync.get_value")
def test_is_unicast_true(mock_get_value):
    mock_get_value.return_value = "udpu"
    assert utils.is_unicast() is True
    mock_get_value.assert_called_once_with("totem.transport")


@mock.patch("crmsh.utils.is_program")
def test_detect_cloud_not_dmidecode(mock_is_program):
    mock_is_program.return_value = False
    assert utils.detect_cloud() is None
    mock_is_program.assert_called_once_with("dmidecode")

@mock.patch("crmsh.utils.is_program")
@mock.patch("crmsh.utils.get_stdout")
def test_detect_cloud_aws(mock_get_stdout, mock_is_program):
    mock_is_program.return_value = True
    mock_get_stdout.return_value = (0, "4.2.amazon")
    assert utils.detect_cloud() == "amazon-web-services"
    mock_is_program.assert_called_once_with("dmidecode")
    mock_get_stdout.assert_called_once_with("dmidecode -s system-version")


@mock.patch("crmsh.utils.is_program")
@mock.patch("crmsh.utils.get_stdout")
def test_detect_cloud_aws_error(mock_get_stdout, mock_is_program):
    mock_is_program.return_value = True
    mock_get_stdout.return_value = (1, "other")
    assert utils.detect_cloud() is None
    mock_is_program.assert_called_once_with("dmidecode")
    mock_get_stdout.assert_called_once_with("dmidecode -s system-version")


@mock.patch("crmsh.utils.is_program")
@mock.patch("crmsh.utils.get_stdout")
@mock.patch("crmsh.utils._cloud_metadata_request")
def test_detect_cloud_microsoft(mock_metadata, mock_get_stdout, mock_is_program):
    mock_is_program.return_value = True
    mock_get_stdout.side_effect = [(0, "other"), (0, "microsoft corporation")]
    mock_metadata.return_value = "10.10.10.10"
    assert utils.detect_cloud() == "microsoft-azure"
    mock_is_program.assert_called_once_with("dmidecode")
    mock_get_stdout.assert_has_calls([
        mock.call("dmidecode -s system-version"),
        mock.call("dmidecode -s system-manufacturer")
    ])
    mock_metadata.assert_called_once_with(
        "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/privateIpAddress?api-version=2017-08-01&format=text",
        headers={"Metadata": "true"})
    assert utils._ip_for_cloud == "10.10.10.10"


@mock.patch("crmsh.utils.is_program")
@mock.patch("crmsh.utils.get_stdout")
@mock.patch("crmsh.utils._cloud_metadata_request")
def test_detect_cloud_microsoft_error(mock_metadata, mock_get_stdout, mock_is_program):
    mock_is_program.return_value = True
    mock_get_stdout.side_effect = [
        (0, "other"), (0, "microsoft corporation"), (0, "microsoft corporation")]
    mock_metadata.return_value = None
    assert utils.detect_cloud() is None
    mock_is_program.assert_called_once_with("dmidecode")
    mock_get_stdout.assert_has_calls([
        mock.call("dmidecode -s system-version"),
        mock.call("dmidecode -s system-manufacturer")
    ])
    mock_metadata.assert_called_once_with(
        "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/privateIpAddress?api-version=2017-08-01&format=text",
        headers={"Metadata": "true"})
    assert utils._ip_for_cloud is None


@mock.patch("crmsh.utils.is_program")
@mock.patch("crmsh.utils.get_stdout")
@mock.patch("crmsh.utils._cloud_metadata_request")
def test_detect_cloud_microsoft_rc_error(mock_metadata, mock_get_stdout, mock_is_program):
    mock_is_program.return_value = True
    mock_get_stdout.side_effect = [
        (0, "other"), (1, "other"), (0, "other")]
    mock_metadata.return_value = None
    assert utils.detect_cloud() is None
    mock_is_program.assert_called_once_with("dmidecode")
    mock_get_stdout.assert_has_calls([
        mock.call("dmidecode -s system-version"),
        mock.call("dmidecode -s system-manufacturer")
    ])
    assert mock_metadata.call_count == 0
    assert utils._ip_for_cloud is None


@mock.patch("crmsh.utils.is_program")
@mock.patch("crmsh.utils.get_stdout")
@mock.patch("crmsh.utils._cloud_metadata_request")
def test_detect_cloud_gcp(mock_metadata, mock_get_stdout, mock_is_program):
    mock_is_program.return_value = True
    mock_get_stdout.side_effect = [
        (0, "other"), (1, "other"), (0, "Google")]
    mock_metadata.return_value = "10.10.10.10"
    assert utils.detect_cloud() == "google-cloud-platform"
    mock_is_program.assert_called_once_with("dmidecode")
    mock_get_stdout.assert_has_calls([
        mock.call("dmidecode -s system-version"),
        mock.call("dmidecode -s system-manufacturer"),
        mock.call("dmidecode -s bios-vendor")
    ])
    mock_metadata.assert_called_once_with(
        "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/ip",
        headers={"Metadata-Flavor": "Google"})
    assert utils._ip_for_cloud == "10.10.10.10"


@mock.patch("crmsh.utils.is_program")
@mock.patch("crmsh.utils.get_stdout")
@mock.patch("crmsh.utils._cloud_metadata_request")
def test_detect_cloud_gcp_error(mock_metadata, mock_get_stdout, mock_is_program):
    mock_is_program.return_value = True
    mock_get_stdout.side_effect = [
        (0, "other"), (0, "other"), (0, "Google")]
    mock_metadata.return_value = None
    assert utils.detect_cloud() is None
    mock_is_program.assert_called_once_with("dmidecode")
    mock_get_stdout.assert_has_calls([
        mock.call("dmidecode -s system-version"),
        mock.call("dmidecode -s system-manufacturer"),
        mock.call("dmidecode -s bios-vendor")
    ])
    mock_metadata.assert_called_once_with(
        "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/ip",
        headers={"Metadata-Flavor": "Google"})
    assert utils._ip_for_cloud is None


@mock.patch("crmsh.utils.is_program")
@mock.patch("crmsh.utils.get_stdout")
@mock.patch("crmsh.utils._cloud_metadata_request")
def test_detect_cloud_gcp_rc_error(mock_metadata, mock_get_stdout, mock_is_program):
    mock_is_program.return_value = True
    mock_get_stdout.side_effect = [
        (0, "other"), (0, "other"), (1, "other")]
    mock_metadata.return_value = None
    assert utils.detect_cloud() is None
    mock_is_program.assert_called_once_with("dmidecode")
    mock_get_stdout.assert_has_calls([
        mock.call("dmidecode -s system-version"),
        mock.call("dmidecode -s system-manufacturer"),
        mock.call("dmidecode -s bios-vendor")
    ])
    assert mock_metadata.call_count == 0
    assert utils._ip_for_cloud is None


@mock.patch("crmsh.utils.get_stdout")
def test_interface_choice(mock_get_stdout):
    ip_a_output = """
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: enp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 52:54:00:9e:1b:4f brd ff:ff:ff:ff:ff:ff
    inet 192.168.122.241/24 brd 192.168.122.255 scope global enp1s0
       valid_lft forever preferred_lft forever
    inet6 fe80::5054:ff:fe9e:1b4f/64 scope link 
       valid_lft forever preferred_lft forever
3: br-933fa0e1438c: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 9e:fe:24:df:59:49 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.1/24 brd 10.10.10.255 scope global br-933fa0e1438c
       valid_lft forever preferred_lft forever
    inet6 fe80::9cfe:24ff:fedf:5949/64 scope link 
       valid_lft forever preferred_lft forever
4: veth3fff6e9@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether 1e:2c:b3:73:6b:42 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::1c2c:b3ff:fe73:6b42/64 scope link 
       valid_lft forever preferred_lft forever
       valid_lft forever preferred_lft forever
"""
    mock_get_stdout.return_value = (0, ip_a_output)
    assert utils.interface_choice() == ["enp1s0", "br-933fa0e1438c", "veth3fff6e9"]
    mock_get_stdout.assert_called_once_with("ip a")
