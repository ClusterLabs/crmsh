from __future__ import unicode_literals
# Copyright (C) 2014 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.
#
# unit tests for utils.py

import os
import socket
import re
import imp
import subprocess
import unittest
import pytest
import logging
from unittest import mock
from itertools import chain

import crmsh.utils
from crmsh import utils, config, tmpfiles, constants, parallax

logging.basicConfig(level=logging.DEBUG)

def setup_function():
    utils._ip_for_cloud = None
    # Mock memoize method and reload the module under test later with imp
    mock.patch('crmsh.utils.memoize', lambda x: x).start()
    imp.reload(utils)


@mock.patch("crmsh.utils.get_stdout_stderr")
def test_print_cluster_nodes(mock_run):
    mock_run.return_value = (0, "data", None)
    utils.print_cluster_nodes()
    mock_run.assert_called_once_with("crm_node -l")


@mock.patch("crmsh.utils.get_stdout")
def test_package_is_installed_local(mock_run):
    mock_run.return_value = (0, None)
    res = utils.package_is_installed("crmsh")
    assert res is True
    mock_run.assert_called_once_with("rpm -q --quiet crmsh")


@mock.patch('crmsh.utils.detect_file')
def test_check_file_content_included_target_not_exist(mock_detect):
    mock_detect.side_effect = [True, False]
    res = utils.check_file_content_included("file1", "file2")
    assert res is False
    mock_detect.assert_has_calls([
        mock.call("file1", remote=None),
        mock.call("file2", remote=None)
        ])


@mock.patch('crmsh.utils.get_stdout_or_raise_error')
@mock.patch('crmsh.utils.detect_file')
def test_check_file_content_included(mock_detect, mock_run):
    mock_detect.side_effect = [True, True]
    mock_run.side_effect = ["data data", "data"]

    res = utils.check_file_content_included("file1", "file2")
    assert res is True

    mock_detect.assert_has_calls([
        mock.call("file1", remote=None),
        mock.call("file2", remote=None)
        ])
    mock_run.assert_has_calls([
        mock.call("cat file2", remote=None),
        mock.call("cat file1", remote=None)
        ])


@mock.patch("crmsh.utils.get_stdout_stderr")
def test_get_iplist_corosync_using_exception(mock_run):
    mock_run.return_value = (1, None, "error of cfgtool")
    with pytest.raises(ValueError) as err:
        utils.get_iplist_corosync_using()
    assert str(err.value) == "error of cfgtool"
    mock_run.assert_called_once_with("corosync-cfgtool -s")


@mock.patch("crmsh.utils.get_stdout_stderr")
def test_get_iplist_corosync_using(mock_run):
    output = """
RING ID 0
        id      = 192.168.122.193
        status  = ring 0 active with no faults
RING ID 1
        id      = 10.10.10.121
        status  = ring 1 active with no faults
"""
    mock_run.return_value = (0, output, None)
    res = utils.get_iplist_corosync_using()
    assert res == ["192.168.122.193", "10.10.10.121"]
    mock_run.assert_called_once_with("corosync-cfgtool -s")


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


@mock.patch('crmsh.utils.su_get_stdout_stderr')
def test_check_ssh_passwd_need(mock_su_get_stdout_stderr):
    mock_su_get_stdout_stderr.return_value = (1, None, None)
    res = utils.check_ssh_passwd_need("bob", "alice", "node1")
    assert res is True
    mock_su_get_stdout_stderr.assert_called_once_with(
        "bob",
        "ssh -o StrictHostKeyChecking=no -o EscapeChar=none -o ConnectTimeout=15 -T -o Batchmode=yes alice@node1 true",
    )


@mock.patch('logging.Logger.debug')
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


@mock.patch('crmsh.utils.list_cluster_nodes')
def test_cluster_run_cmd_exception(mock_list_nodes):
    mock_list_nodes.return_value = None
    with pytest.raises(ValueError) as err:
        utils.cluster_run_cmd("test")
    assert str(err.value) == "Failed to get node list from cluster"
    mock_list_nodes.assert_called_once_with()


@mock.patch('crmsh.utils.list_cluster_nodes')
def test_list_cluster_nodes_except_me_exception(mock_list_nodes):
    mock_list_nodes.return_value = None
    with pytest.raises(ValueError) as err:
        utils.list_cluster_nodes_except_me()
    assert str(err.value) == "Failed to get node list from cluster"
    mock_list_nodes.assert_called_once_with()


@mock.patch('crmsh.utils.this_node')
@mock.patch('crmsh.utils.list_cluster_nodes')
def test_list_cluster_nodes_except_me(mock_list_nodes, mock_this_node):
    mock_list_nodes.return_value = ["node1", "node2"]
    mock_this_node.return_value = "node1"
    res = utils.list_cluster_nodes_except_me()
    assert res == ["node2"]
    mock_list_nodes.assert_called_once_with()
    mock_this_node.assert_called_once_with()


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


@mock.patch('logging.Logger.error')
def test_sanity(mock_error):
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

@mock.patch("crmsh.utils.IP.is_ipv6")
@mock.patch("socket.socket")
@mock.patch("crmsh.utils.closing")
def test_check_port_open_false(mock_closing, mock_socket, mock_is_ipv6):
    mock_is_ipv6.return_value = False
    sock_inst = mock.Mock()
    mock_socket.return_value = sock_inst
    mock_closing.return_value.__enter__.return_value = sock_inst
    sock_inst.connect_ex.return_value = 1

    assert utils.check_port_open("10.10.10.1", 22) is False

    mock_is_ipv6.assert_called_once_with("10.10.10.1")
    mock_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
    mock_closing.assert_called_once_with(sock_inst)
    sock_inst.connect_ex.assert_called_once_with(("10.10.10.1", 22))

@mock.patch("crmsh.utils.IP.is_ipv6")
@mock.patch("socket.socket")
@mock.patch("crmsh.utils.closing")
def test_check_port_open_true(mock_closing, mock_socket, mock_is_ipv6):
    mock_is_ipv6.return_value = True
    sock_inst = mock.Mock()
    mock_socket.return_value = sock_inst
    mock_closing.return_value.__enter__.return_value = sock_inst
    sock_inst.connect_ex.return_value = 0

    assert utils.check_port_open("2001:db8:10::7", 22) is True

    mock_is_ipv6.assert_called_once_with("2001:db8:10::7")
    mock_socket.assert_called_once_with(socket.AF_INET6, socket.SOCK_STREAM)
    mock_closing.assert_called_once_with(sock_inst)
    sock_inst.connect_ex.assert_called_once_with(("2001:db8:10::7", 22))

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
@mock.patch("crmsh.utils.service_is_active")
def test_valid_nodeid_false_service_not_active(mock_is_active, mock_nodeinfo):
    mock_is_active.return_value = False
    assert utils.valid_nodeid("3") is False
    mock_is_active.assert_called_once_with('corosync.service')
    mock_nodeinfo.assert_not_called()

@mock.patch("crmsh.utils.get_nodeinfo_from_cmaptool")
@mock.patch("crmsh.utils.service_is_active")
def test_valid_nodeid_false(mock_is_active, mock_nodeinfo):
    mock_is_active.return_value = True
    mock_nodeinfo.return_value = {'1': ["10.10.10.1"], "2": ["20.20.20.2"]}
    assert utils.valid_nodeid("3") is False
    mock_is_active.assert_called_once_with('corosync.service')
    mock_nodeinfo.assert_called_once_with()

@mock.patch("crmsh.utils.get_nodeinfo_from_cmaptool")
@mock.patch("crmsh.utils.service_is_active")
def test_valid_nodeid_true(mock_is_active, mock_nodeinfo):
    mock_is_active.return_value = True
    mock_nodeinfo.return_value = {'1': ["10.10.10.1"], "2": ["20.20.20.2"]}
    assert utils.valid_nodeid("2") is True
    mock_is_active.assert_called_once_with('corosync.service')
    mock_nodeinfo.assert_called_once_with()

@mock.patch("crmsh.utils.get_stdout_or_raise_error")
def test_detect_aws_false(mock_run):
    mock_run.side_effect = ["test", "test"]
    assert utils.detect_aws() is False
    mock_run.assert_has_calls([
        mock.call("dmidecode -s system-version"),
        mock.call("dmidecode -s system-manufacturer")
        ])

@mock.patch("crmsh.utils.get_stdout_or_raise_error")
def test_detect_aws_xen(mock_run):
    mock_run.side_effect = ["4.2.amazon", "Xen"]
    assert utils.detect_aws() is True
    mock_run.assert_has_calls([
        mock.call("dmidecode -s system-version"),
        mock.call("dmidecode -s system-manufacturer")
        ])

@mock.patch("crmsh.utils.get_stdout_or_raise_error")
def test_detect_aws_kvm(mock_run):
    mock_run.side_effect = ["Not Specified", "Amazon EC2"]
    assert utils.detect_aws() is True
    mock_run.assert_has_calls([
        mock.call("dmidecode -s system-version"),
        mock.call("dmidecode -s system-manufacturer")
        ])

@mock.patch("crmsh.utils.get_stdout_or_raise_error")
def test_detect_azure_false(mock_run):
    mock_run.side_effect = ["test", "test"]
    assert utils.detect_azure() is False
    mock_run.assert_has_calls([
        mock.call("dmidecode -s system-manufacturer"),
        mock.call("dmidecode -s chassis-asset-tag")
        ])

@mock.patch("crmsh.utils._cloud_metadata_request")
@mock.patch("crmsh.utils.get_stdout_or_raise_error")
def test_detect_azure_microsoft_corporation(mock_run, mock_request):
    mock_run.side_effect = ["microsoft corporation", "test"]
    mock_request.return_value = "data"
    assert utils.detect_azure() is True
    mock_run.assert_has_calls([
        mock.call("dmidecode -s system-manufacturer"),
        mock.call("dmidecode -s chassis-asset-tag")
        ])

@mock.patch("crmsh.utils._cloud_metadata_request")
@mock.patch("crmsh.utils.get_stdout_or_raise_error")
def test_detect_azure_chassis(mock_run, mock_request):
    mock_run.side_effect = ["test", "7783-7084-3265-9085-8269-3286-77"]
    mock_request.return_value = "data"
    assert utils.detect_azure() is True
    mock_run.assert_has_calls([
        mock.call("dmidecode -s system-manufacturer"),
        mock.call("dmidecode -s chassis-asset-tag")
        ])

@mock.patch("crmsh.utils.get_stdout_or_raise_error")
def test_detect_gcp_false(mock_run):
    mock_run.return_value = "test"
    assert utils.detect_gcp() is False
    mock_run.assert_called_once_with("dmidecode -s bios-vendor")

@mock.patch("crmsh.utils._cloud_metadata_request")
@mock.patch("crmsh.utils.get_stdout_or_raise_error")
def test_detect_gcp(mock_run, mock_request):
    mock_run.return_value = "Google instance"
    mock_request.return_value = "data"
    assert utils.detect_gcp() is True
    mock_run.assert_called_once_with("dmidecode -s bios-vendor")

@mock.patch("crmsh.utils.is_program")
def test_detect_cloud_no_cmd(mock_is_program):
    mock_is_program.return_value = False
    assert utils.detect_cloud() is None
    mock_is_program.assert_called_once_with("dmidecode")

@mock.patch("crmsh.utils.detect_aws")
@mock.patch("crmsh.utils.is_program")
def test_detect_cloud_aws(mock_is_program, mock_aws):
    mock_is_program.return_value = True
    mock_aws.return_value = True
    assert utils.detect_cloud() == constants.CLOUD_AWS
    mock_is_program.assert_called_once_with("dmidecode")
    mock_aws.assert_called_once_with()

@mock.patch("crmsh.utils.detect_azure")
@mock.patch("crmsh.utils.detect_aws")
@mock.patch("crmsh.utils.is_program")
def test_detect_cloud_azure(mock_is_program, mock_aws, mock_azure):
    mock_is_program.return_value = True
    mock_aws.return_value = False
    mock_azure.return_value = True
    assert utils.detect_cloud() == constants.CLOUD_AZURE
    mock_is_program.assert_called_once_with("dmidecode")
    mock_aws.assert_called_once_with()
    mock_azure.assert_called_once_with()

@mock.patch("crmsh.utils.detect_gcp")
@mock.patch("crmsh.utils.detect_azure")
@mock.patch("crmsh.utils.detect_aws")
@mock.patch("crmsh.utils.is_program")
def test_detect_cloud_gcp(mock_is_program, mock_aws, mock_azure, mock_gcp):
    mock_is_program.return_value = True
    mock_aws.return_value = False
    mock_azure.return_value = False
    mock_gcp.return_value = True
    assert utils.detect_cloud() == constants.CLOUD_GCP
    mock_is_program.assert_called_once_with("dmidecode")
    mock_aws.assert_called_once_with()
    mock_azure.assert_called_once_with()
    mock_gcp.assert_called_once_with()

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


class TestIP(unittest.TestCase):
    """
    Unitary tests for class utils.IP
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
        self.ip_inst = utils.IP("10.10.10.1")

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    @mock.patch('ipaddress.ip_address')
    def test_ip_address(self, mock_ip_address):
        mock_ip_address_inst = mock.Mock()
        mock_ip_address.return_value = mock_ip_address_inst
        self.ip_inst.ip_address
        mock_ip_address.assert_called_once_with("10.10.10.1")

    @mock.patch('crmsh.utils.IP.ip_address', new_callable=mock.PropertyMock)
    def test_version(self, mock_ip_address):
        mock_ip_address_inst = mock.Mock(version=4)
        mock_ip_address.return_value = mock_ip_address_inst
        res = self.ip_inst.version
        self.assertEqual(res, mock_ip_address_inst.version)
        mock_ip_address.assert_called_once_with()

    @mock.patch('crmsh.utils.IP.ip_address', new_callable=mock.PropertyMock)
    def test_is_mcast(self, mock_ip_address):
        mock_ip_address_inst = mock.Mock(is_multicast=False)
        mock_ip_address.return_value = mock_ip_address_inst
        res = utils.IP.is_mcast("10.10.10.1")
        self.assertEqual(res, False)
        mock_ip_address.assert_called_once_with()

    @mock.patch('crmsh.utils.IP.version', new_callable=mock.PropertyMock)
    def test_is_ipv6(self, mock_version):
        mock_version.return_value = 4
        res = utils.IP.is_ipv6("10.10.10.1")
        self.assertEqual(res, False)
        mock_version.assert_called_once_with()

    @mock.patch('crmsh.utils.IP.ip_address', new_callable=mock.PropertyMock)
    def test_is_valid_ip_exception(self, mock_ip_address):
        mock_ip_address.side_effect = ValueError
        res = utils.IP.is_valid_ip("xxxx")
        self.assertEqual(res, False)
        mock_ip_address.assert_called_once_with()

    @mock.patch('crmsh.utils.IP.ip_address', new_callable=mock.PropertyMock)
    def test_is_valid_ip(self, mock_ip_address):
        res = utils.IP.is_valid_ip("10.10.10.1")
        self.assertEqual(res, True)
        mock_ip_address.assert_called_once_with()

    @mock.patch('crmsh.utils.IP.ip_address', new_callable=mock.PropertyMock)
    def test_is_loopback(self, mock_ip_address):
        mock_ip_address_inst = mock.Mock(is_loopback=False)
        mock_ip_address.return_value = mock_ip_address_inst
        res = self.ip_inst.is_loopback
        self.assertEqual(res, mock_ip_address_inst.is_loopback)
        mock_ip_address.assert_called_once_with()

    @mock.patch('crmsh.utils.IP.ip_address', new_callable=mock.PropertyMock)
    def test_is_link_local(self, mock_ip_address):
        mock_ip_address_inst = mock.Mock(is_link_local=False)
        mock_ip_address.return_value = mock_ip_address_inst
        res = self.ip_inst.is_link_local
        self.assertEqual(res, mock_ip_address_inst.is_link_local)
        mock_ip_address.assert_called_once_with()


class TestInterface(unittest.TestCase):
    """
    Unitary tests for class utils.Interface
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
        self.interface = utils.Interface("10.10.10.123/24")

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

    @mock.patch('ipaddress.ip_interface')
    def test_ip_interface(self, mock_ip_interface):
        mock_ip_interface_inst = mock.Mock()
        mock_ip_interface.return_value = mock_ip_interface_inst
        self.interface.ip_interface
        mock_ip_interface.assert_called_once_with("10.10.10.123/24")

    @mock.patch('crmsh.utils.Interface.ip_interface', new_callable=mock.PropertyMock)
    def test_network(self, mock_ip_interface):
        mock_ip_interface_inst = mock.Mock()
        mock_ip_interface.return_value = mock_ip_interface_inst
        mock_ip_interface_inst.network = mock.Mock(network_address="10.10.10.0")
        assert self.interface.network == "10.10.10.0"
        mock_ip_interface.assert_called_once_with()

    @mock.patch('crmsh.utils.Interface.ip_interface', new_callable=mock.PropertyMock)
    @mock.patch('crmsh.utils.IP')
    def test_ip_in_network(self, mock_ip, mock_ip_interface):
        mock_ip_inst = mock.Mock(ip_address="10.10.10.123")
        mock_ip.return_value = mock_ip_inst
        mock_ip_interface_inst = mock.Mock(network=["10.10.10.123"])
        mock_ip_interface.return_value = mock_ip_interface_inst
        res = self.interface.ip_in_network("10.10.10.123")
        assert res is True
        mock_ip.assert_called_once_with("10.10.10.123")
        mock_ip_interface.assert_called_once_with()


class TestInterfacesInfo(unittest.TestCase):
    """
    Unitary tests for class utils.InterfacesInfo
    """

    network_output_error = """1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
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
        self.interfaces_info = utils.InterfacesInfo()
        self.interfaces_info_with_second_hb = utils.InterfacesInfo(second_heartbeat=True)
        self.interfaces_info_with_custom_nic = utils.InterfacesInfo(second_heartbeat=True, custom_nic_list=['eth1'])
        self.interfaces_info_with_wrong_nic = utils.InterfacesInfo(custom_nic_list=['eth7'])
        self.interfaces_info_fake = utils.InterfacesInfo()
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

    @mock.patch('crmsh.utils.get_stdout_stderr')
    def test_get_interfaces_info_no_address(self, mock_run):
        only_lo = "1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever"
        mock_run.return_value = (0, only_lo, None)
        with self.assertRaises(ValueError) as err:
            self.interfaces_info.get_interfaces_info()
        self.assertEqual("No address configured", str(err.exception))
        mock_run.assert_called_once_with("ip -4 -o addr show")

    @mock.patch('crmsh.utils.Interface')
    @mock.patch('crmsh.utils.get_stdout_stderr')
    def test_get_interfaces_info_one_addr(self, mock_run, mock_interface):
        mock_run.return_value = (0, self.network_output_error, None)
        mock_interface_inst_1 = mock.Mock(is_loopback=True, is_link_local=False)
        mock_interface_inst_2 = mock.Mock(is_loopback=False, is_link_local=False)
        mock_interface.side_effect = [mock_interface_inst_1, mock_interface_inst_2]

        with self.assertRaises(ValueError) as err:
            self.interfaces_info_with_second_hb.get_interfaces_info()
        self.assertEqual("Cannot configure second heartbeat, since only one address is available", str(err.exception))

        mock_run.assert_called_once_with("ip -4 -o addr show")
        mock_interface.assert_has_calls([
            mock.call("127.0.0.1/8"),
            mock.call("192.168.122.241/24")
            ])

    def test_nic_list(self):
        res = self.interfaces_info_fake.nic_list
        self.assertEqual(res, ["eth0", "eth1"])
 
    def test_interface_list(self):
        res = self.interfaces_info_fake.interface_list
        assert len(res) == 3

    @mock.patch('crmsh.utils.InterfacesInfo.interface_list', new_callable=mock.PropertyMock)
    def test_ip_list(self, mock_interface_list):
        mock_interface_list.return_value = [
                mock.Mock(ip="10.10.10.1"),
                mock.Mock(ip="10.10.10.2")
                ]
        res = self.interfaces_info_fake.ip_list
        self.assertEqual(res, ["10.10.10.1", "10.10.10.2"])
        mock_interface_list.assert_called_once_with()

    @mock.patch('crmsh.utils.InterfacesInfo.ip_list', new_callable=mock.PropertyMock)
    @mock.patch('crmsh.utils.InterfacesInfo.get_interfaces_info')
    def test_get_local_ip_list(self, mock_get_info, mock_ip_list):
        mock_ip_list.return_value = ["10.10.10.1", "10.10.10.2"]
        res = utils.InterfacesInfo.get_local_ip_list(False)
        self.assertEqual(res, mock_ip_list.return_value)
        mock_get_info.assert_called_once_with()
        mock_ip_list.assert_called_once_with()

    @mock.patch('crmsh.utils.InterfacesInfo.ip_list', new_callable=mock.PropertyMock)
    @mock.patch('crmsh.utils.IP.is_ipv6')
    @mock.patch('crmsh.utils.InterfacesInfo.get_interfaces_info')
    def test_ip_in_local(self, mock_get_info, mock_is_ipv6, mock_ip_list):
        mock_is_ipv6.return_value = False
        mock_ip_list.return_value = ["10.10.10.1", "10.10.10.2"]
        res = utils.InterfacesInfo.ip_in_local("10.10.10.1")
        assert res is True
        mock_get_info.assert_called_once_with()
        mock_ip_list.assert_called_once_with()
        mock_is_ipv6.assert_called_once_with("10.10.10.1")

    @mock.patch('crmsh.utils.InterfacesInfo.interface_list', new_callable=mock.PropertyMock)
    def test_network_list(self, mock_interface_list):
        mock_interface_list.return_value = [
                mock.Mock(network="10.10.10.0"),
                mock.Mock(network="20.20.20.0")
                ]
        res = self.interfaces_info.network_list
        self.assertEqual(res, list(set(["10.10.10.0", "20.20.20.0"])))
        mock_interface_list.assert_called_once_with()

    def test_nic_first_ip(self):
        res = self.interfaces_info_fake._nic_first_ip("eth0")
        self.assertEqual(res, "10.10.10.1")

    @mock.patch('crmsh.utils.InterfacesInfo.nic_list', new_callable=mock.PropertyMock)
    @mock.patch('logging.Logger.warning')
    @mock.patch('crmsh.utils.InterfacesInfo.get_interfaces_info')
    @mock.patch('crmsh.utils.get_stdout_stderr')
    def test_get_default_nic_list_from_route_no_default(self, mock_run, mock_get_interfaces_info, mock_warn, mock_nic_list):
        output = """10.10.10.0/24 dev eth1 proto kernel scope link src 10.10.10.51 
        20.20.20.0/24 dev eth2 proto kernel scope link src 20.20.20.51"""
        mock_run.return_value = (0, output, None)
        mock_nic_list.side_effect = [["eth0", "eth1"], ["eth0", "eth1"]]

        res = self.interfaces_info.get_default_nic_list_from_route()
        self.assertEqual(res, ["eth0"])

        mock_run.assert_called_once_with("ip -o route show")
        mock_warn.assert_called_once_with("No default route configured. Using the first found nic")
        mock_nic_list.assert_has_calls([mock.call(), mock.call()])

    @mock.patch('crmsh.utils.get_stdout_stderr')
    def test_get_default_nic_list_from_route(self, mock_run):
        output = """default via 192.168.122.1 dev eth8 proto dhcp 
        10.10.10.0/24 dev eth1 proto kernel scope link src 10.10.10.51 
        20.20.20.0/24 dev eth2 proto kernel scope link src 20.20.20.51 
        192.168.122.0/24 dev eth8 proto kernel scope link src 192.168.122.120"""
        mock_run.return_value = (0, output, None)

        res = self.interfaces_info.get_default_nic_list_from_route()
        self.assertEqual(res, ["eth8"])

        mock_run.assert_called_once_with("ip -o route show")

    @mock.patch('crmsh.utils.InterfacesInfo.nic_list', new_callable=mock.PropertyMock)
    def test_get_default_ip_list_failed_detect(self, mock_nic_list):
        mock_nic_list.side_effect = [["eth0", "eth1"], ["eth0", "eth1"]]

        with self.assertRaises(ValueError) as err:
            self.interfaces_info_with_wrong_nic.get_default_ip_list()
        self.assertEqual("Failed to detect IP address for eth7", str(err.exception))

        mock_nic_list.assert_has_calls([mock.call(), mock.call()])

    @mock.patch('crmsh.utils.InterfacesInfo._nic_first_ip')
    @mock.patch('crmsh.utils.InterfacesInfo.nic_list', new_callable=mock.PropertyMock)
    def test_get_default_ip_list(self, mock_nic_list, mock_first_ip):
        mock_nic_list.side_effect = [["eth0", "eth1"], ["eth0", "eth1"], ["eth0", "eth1"]]
        mock_first_ip.side_effect = ["10.10.10.1", "20.20.20.1"]

        res = self.interfaces_info_with_custom_nic.get_default_ip_list()
        self.assertEqual(res, ["10.10.10.1", "20.20.20.1"])

        mock_nic_list.assert_has_calls([mock.call(), mock.call(), mock.call()])
        mock_first_ip.assert_has_calls([mock.call("eth1"), mock.call("eth0")])

    @mock.patch('crmsh.utils.Interface')
    @mock.patch('crmsh.utils.InterfacesInfo.interface_list', new_callable=mock.PropertyMock)
    @mock.patch('crmsh.utils.InterfacesInfo.get_interfaces_info')
    @mock.patch('crmsh.utils.IP.is_ipv6')
    def test_ip_in_network(self, mock_is_ipv6, mock_get_interfaces_info, mock_interface_list, mock_interface):
        mock_is_ipv6.return_value = False
        mock_interface_inst_1 = mock.Mock()
        mock_interface_inst_2 = mock.Mock()
        mock_interface_inst_1.ip_in_network.return_value = False
        mock_interface_inst_2.ip_in_network.return_value = True
        mock_interface_list.return_value = [mock_interface_inst_1, mock_interface_inst_2]

        res = utils.InterfacesInfo.ip_in_network("10.10.10.1")
        assert res is True

        mock_is_ipv6.assert_called_once_with("10.10.10.1")
        mock_get_interfaces_info.assert_called_once_with()
        mock_interface_list.assert_called_once_with()
        mock_interface_inst_1.ip_in_network.assert_called_once_with("10.10.10.1")
        mock_interface_inst_2.ip_in_network.assert_called_once_with("10.10.10.1")

    @mock.patch('crmsh.utils.Interface')
    @mock.patch('crmsh.utils.InterfacesInfo.interface_list', new_callable=mock.PropertyMock)
    @mock.patch('crmsh.utils.InterfacesInfo.get_interfaces_info')
    @mock.patch('crmsh.utils.IP.is_ipv6')
    def test_ip_in_network_false(self, mock_is_ipv6, mock_get_interfaces_info, mock_interface_list, mock_interface):
        mock_is_ipv6.return_value = False
        mock_interface_inst_1 = mock.Mock()
        mock_interface_inst_2 = mock.Mock()
        mock_interface_inst_1.ip_in_network.return_value = False
        mock_interface_inst_2.ip_in_network.return_value = False
        mock_interface_list.return_value = [mock_interface_inst_1, mock_interface_inst_2]

        res = utils.InterfacesInfo.ip_in_network("10.10.10.1")
        assert res is False

        mock_is_ipv6.assert_called_once_with("10.10.10.1")
        mock_get_interfaces_info.assert_called_once_with()
        mock_interface_list.assert_called_once_with()
        mock_interface_inst_1.ip_in_network.assert_called_once_with("10.10.10.1")
        mock_interface_inst_2.ip_in_network.assert_called_once_with("10.10.10.1")


class TestServiceManager(unittest.TestCase):
    """
    Unitary tests for class utils.ServiceManager
    """
    @mock.patch('crmsh.utils.ServiceManager._call_with_parallax')
    @mock.patch('crmsh.utils.ServiceManager._run_on_single_host')
    def test_call_single_node(
            self,
            mock_run_on_single_host:mock.MagicMock,
            mock_call_with_parallax: mock.MagicMock,
    ):
        mock_run_on_single_host.return_value = 0
        self.assertEqual(['node1'], utils.ServiceManager._call('node1', list(), 'foo'))
        mock_run_on_single_host.assert_called_once_with('foo', 'node1')
        mock_call_with_parallax.assert_not_called()

    @mock.patch('crmsh.utils.ServiceManager._call_with_parallax')
    @mock.patch('crmsh.utils.ServiceManager._run_on_single_host')
    def test_call_single_node_failure(
            self,
            mock_run_on_single_host:mock.MagicMock,
            mock_call_with_parallax: mock.MagicMock,
    ):
        mock_run_on_single_host.return_value = 1
        self.assertEqual(list(), utils.ServiceManager._call('node1', list(), 'foo'))
        mock_run_on_single_host.assert_called_once_with('foo', 'node1')
        mock_call_with_parallax.assert_not_called()

    @mock.patch('crmsh.utils.ServiceManager._call_with_parallax')
    @mock.patch('crmsh.utils.ServiceManager._run_on_single_host')
    def test_call_multiple_node(
            self,
            mock_run_on_single_host: mock.MagicMock,
            mock_call_with_parallax: mock.MagicMock,
    ):
        mock_call_with_parallax.return_value = {'node1': (0, '', ''), 'node2': (1, 'out', 'err')}
        self.assertEqual(['node1'], utils.ServiceManager._call(None, ['node1', 'node2'], 'foo'))
        mock_run_on_single_host.assert_not_called()
        mock_call_with_parallax.assert_called_once_with('foo', ['node1', 'node2'])

    @mock.patch('crmsh.utils.get_stdout_stderr_auto_ssh_no_input')
    def test_run_on_single_host_return_1(self, mock_run: mock.MagicMock):
        mock_run.return_value = (1, 'bar', 'err')
        self.assertEqual(1, crmsh.utils.ServiceManager._run_on_single_host('foo', 'node1'))
        mock_run.assert_called_once_with('node1', 'foo')

    @mock.patch('crmsh.utils.get_stdout_stderr_auto_ssh_no_input')
    def test_run_on_single_host_return_255(self, mock_run: mock.MagicMock):
        mock_run.return_value = (255, 'bar', 'err')
        with self.assertRaises(ValueError):
            crmsh.utils.ServiceManager._run_on_single_host('foo', 'node1')
        mock_run.assert_called_once_with('node1', 'foo')

    @mock.patch('crmsh.utils.ServiceManager._call')
    def test_start_service(self, mock_call: mock.MagicMock):
        mock_call.return_value = ['node1']
        self.assertEqual(['node1'], utils.ServiceManager.start_service('service1', remote_addr='node1'))
        mock_call.assert_called_once_with('node1', [], "systemctl start 'service1'")

    @mock.patch('crmsh.utils.ServiceManager._call')
    def test_start_service_on_multiple_host(self, mock_call: mock.MagicMock):
        mock_call.return_value = ['node1', 'node2']
        self.assertEqual(['node1', 'node2'], utils.ServiceManager.start_service('service1', node_list=['node1', 'node2']))
        mock_call.assert_called_once_with(None, ['node1', 'node2'], "systemctl start 'service1'")

    @mock.patch('crmsh.utils.ServiceManager._call')
    def test_start_and_enable_service(self, mock_call: mock.MagicMock):
        mock_call.return_value = ['node1']
        self.assertEqual(['node1'], utils.ServiceManager.start_service('service1', enable=True, remote_addr='node1'))
        mock_call.assert_called_once_with('node1', [], "systemctl enable --now 'service1'")

    @mock.patch('crmsh.utils.ServiceManager._call')
    def test_stop_service(self, mock_call: mock.MagicMock):
        mock_call.return_value = ['node1']
        self.assertEqual(['node1'], utils.ServiceManager.stop_service('service1', remote_addr='node1'))
        mock_call.assert_called_once_with('node1', [], "systemctl stop 'service1'")

    @mock.patch('crmsh.utils.ServiceManager._call')
    def test_enable_service(self, mock_call: mock.MagicMock):
        mock_call.return_value = ['node1']
        self.assertEqual(['node1'], utils.ServiceManager.enable_service('service1', remote_addr='node1'))
        mock_call.assert_called_once_with('node1', [], "systemctl enable 'service1'")

    @mock.patch('crmsh.utils.ServiceManager._call')
    def test_disable_service(self, mock_call: mock.MagicMock):
        mock_call.return_value = ['node1']
        self.assertEqual(['node1'], utils.ServiceManager.disable_service('service1', remote_addr='node1'))
        mock_call.assert_called_once_with('node1', [], "systemctl disable 'service1'")


@mock.patch("crmsh.utils.get_nodeid_from_name")
def test_get_iplist_from_name_no_nodeid(mock_get_nodeid):
    mock_get_nodeid.return_value = None
    res = utils.get_iplist_from_name("test")
    assert res == []
    mock_get_nodeid.assert_called_once_with("test")


@mock.patch("crmsh.utils.get_nodeinfo_from_cmaptool")
@mock.patch("crmsh.utils.get_nodeid_from_name")
def test_get_iplist_from_name_no_nodeinfo(mock_get_nodeid, mock_get_nodeinfo):
    mock_get_nodeid.return_value = "1"
    mock_get_nodeinfo.return_value = None
    res = utils.get_iplist_from_name("test")
    assert res == []
    mock_get_nodeid.assert_called_once_with("test")
    mock_get_nodeinfo.assert_called_once_with()


@mock.patch("crmsh.utils.get_nodeinfo_from_cmaptool")
@mock.patch("crmsh.utils.get_nodeid_from_name")
def test_get_iplist_from_name(mock_get_nodeid, mock_get_nodeinfo):
    mock_get_nodeid.return_value = "1"
    mock_get_nodeinfo.return_value = {"1": ["10.10.10.1"], "2": ["10.10.10.2"]}
    res = utils.get_iplist_from_name("test")
    assert res == ["10.10.10.1"]
    mock_get_nodeid.assert_called_once_with("test")
    mock_get_nodeinfo.assert_called_once_with()


@mock.patch("crmsh.utils.get_stdout_stderr")
def test_ping_node(mock_run):
    mock_run.return_value = (1, None, "error data")
    with pytest.raises(ValueError) as err:
        utils.ping_node("node_unreachable")
    assert str(err.value) == 'host "node_unreachable" is unreachable: error data'
    mock_run.assert_called_once_with("ping -c 1 node_unreachable")


def test_calculate_quorate_status():
    assert utils.calculate_quorate_status(3, 2) is True
    assert utils.calculate_quorate_status(3, 1) is False


@mock.patch("crmsh.utils.subprocess_run_auto_ssh_no_input")
@mock.patch("subprocess.run")
def test_get_stdout_or_raise_error_local(
        mock_subprocess_run: mock.MagicMock,
        mock_subprocess_run_auto_ssh_no_input: mock.MagicMock,
):
    mock_subprocess_run.return_value = mock.Mock(returncode=0, stdout=b'bar', stderr=b'')
    out = utils.get_stdout_or_raise_error("foo")
    mock_subprocess_run.assert_called_once_with(
        ['/bin/sh'],
        input=b'foo',
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    mock_subprocess_run_auto_ssh_no_input.assert_not_called()
    assert "bar" == out


@mock.patch("crmsh.utils.subprocess_run_auto_ssh_no_input")
@mock.patch("subprocess.run")
def test_get_stdout_or_raise_error_local_failure(
        mock_subprocess_run: mock.MagicMock,
        mock_subprocess_run_auto_ssh_no_input: mock.MagicMock,
):
    mock_subprocess_run.return_value = mock.Mock(returncode=1, stdout=b'bar', stderr=b'err')
    exception = None
    try:
        out = utils.get_stdout_or_raise_error("foo")
    except ValueError as e:
        exception = e

    mock_subprocess_run.assert_called_once_with(
        ['/bin/sh'],
        input=b'foo',
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    mock_subprocess_run_auto_ssh_no_input.assert_not_called()
    assert isinstance(exception, ValueError)


@mock.patch("crmsh.utils.subprocess_run_auto_ssh_no_input")
@mock.patch("subprocess.run")
def test_get_stdout_or_raise_error_local_failure_no_raise(
        mock_subprocess_run: mock.MagicMock,
        mock_subprocess_run_auto_ssh_no_input: mock.MagicMock,
):
    mock_subprocess_run.return_value = mock.Mock(returncode=1, stdout=b'bar', stderr=b'err')
    out = utils.get_stdout_or_raise_error("foo", no_raise=True)

    mock_subprocess_run.assert_called_once_with(
        ['/bin/sh'],
        input=b'foo',
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    mock_subprocess_run_auto_ssh_no_input.assert_not_called()
    assert "bar" == out


@mock.patch("crmsh.utils.subprocess_run_auto_ssh_no_input")
@mock.patch("subprocess.run")
def test_get_stdout_or_raise_error_remote(
        mock_subprocess_run: mock.MagicMock,
        mock_subprocess_run_auto_ssh_no_input: mock.MagicMock,
):
    mock_subprocess_run_auto_ssh_no_input.return_value = mock.Mock(returncode=0, stdout=b'bar', stderr=b'')
    out = utils.get_stdout_or_raise_error("foo", 'node1')
    mock_subprocess_run.assert_not_called()
    mock_subprocess_run_auto_ssh_no_input.assert_called_once_with(
        "foo",
        'node1',
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert "bar" == out


class TestSubprocessRunUtils(unittest.TestCase):
    @mock.patch("subprocess.run")
    def test_subprocess_run_auto_ssh_no_input_local_no_su(self, mock_subprocess_run):
        mock_subprocess_run.return_value = mock.Mock(returncode=0, stdout=b'bar', stderr=b'')
        result = utils.subprocess_run_auto_ssh_no_input("foo", stderr=subprocess.DEVNULL)
        mock_subprocess_run.assert_called_once_with(['/bin/sh'], input=b'foo', stderr=subprocess.DEVNULL)
        self.assertEqual(0, result.returncode)
        self.assertEqual(b'bar', result.stdout)

    @mock.patch("subprocess.run")
    def test_subprocess_run_auto_ssh_no_input_local_su(self, mock_subprocess_run):
        mock_subprocess_run.return_value = mock.Mock(returncode=0, stdout=b'bar', stderr=b'')
        result = utils.subprocess_run_auto_ssh_no_input("foo", user="alice", stderr=subprocess.DEVNULL)
        mock_subprocess_run.assert_called_once_with(
            ['sudo', '-H', '-u', 'alice', '/bin/sh'],
            input=b'foo',
            stderr=subprocess.DEVNULL,
        )
        self.assertEqual(0, result.returncode)
        self.assertEqual(b'bar', result.stdout)

    @mock.patch("crmsh.utils.this_node")
    @mock.patch('crmsh.utils.user_pair_for_ssh')
    @mock.patch("crmsh.utils.su_subprocess_run")
    @mock.patch("subprocess.run")
    def test_subprocess_run_auto_ssh_no_input_remote_no_user(
            self,
            mock_subprocess_run: mock.MagicMock,
            mock_su_subprocess_run: mock.MagicMock,
            mock_user_pair_for_ssh: mock.MagicMock,
            mock_this_node: mock.MagicMock,
    ):
        mock_this_node.return_value = 'node1'
        mock_user_pair_for_ssh.return_value = "alice", "bob"
        mock_su_subprocess_run.return_value = mock.Mock(returncode=0, stdout=b'bar', stderr=b'')
        result = utils.subprocess_run_auto_ssh_no_input("foo", "node2", stderr=subprocess.DEVNULL)
        mock_user_pair_for_ssh.assert_called_once_with('node2')
        mock_subprocess_run.assert_not_called()
        mock_su_subprocess_run.assert_called_once_with(
            'alice',
            'ssh -o StrictHostKeyChecking=no bob@node2 sudo -H -u root /bin/sh',
            input=b'foo',
            stderr=subprocess.DEVNULL,
        )
        self.assertEqual(0, result.returncode)
        self.assertEqual(b'bar', result.stdout)

    @mock.patch("os.geteuid")
    @mock.patch("crmsh.userdir.getuser")
    @mock.patch("subprocess.run")
    def test_su_subprocess_run(
            self,
            mock_subprocess_run: mock.MagicMock,
            mock_get_user: mock.MagicMock,
            mock_geteuid: mock.MagicMock,
    ):
        mock_geteuid.return_value = 0
        mock_get_user.return_value = 'root'
        mock_subprocess_run.return_value = mock.Mock(returncode=0, stdout=b'bar', stderr=b'')
        result = utils.su_subprocess_run('alice', 'foo')
        mock_subprocess_run.assert_called_once_with(
            ['su', 'alice', '--login', '-c', 'foo']
        )
        self.assertEqual(0, result.returncode)
        self.assertEqual(b'bar', result.stdout)

    @mock.patch("os.geteuid")
    @mock.patch("crmsh.userdir.getuser")
    @mock.patch("subprocess.run")
    def test_su_subprocess_run_with_non_root_user(
            self,
            mock_subprocess_run: mock.MagicMock,
            mock_get_user: mock.MagicMock,
            mock_geteuid: mock.MagicMock,
    ):
        mock_geteuid.return_value = 1000
        mock_get_user.return_value = 'bob'
        with self.assertRaises(AssertionError):
            result = utils.su_subprocess_run('alice', 'foo')

    @mock.patch("os.geteuid")
    @mock.patch("crmsh.userdir.getuser")
    @mock.patch("subprocess.run")
    def test_su_subprocess_run_to_self(
            self,
            mock_subprocess_run: mock.MagicMock,
            mock_get_user: mock.MagicMock,
            mock_geteuid: mock.MagicMock,
    ):
        mock_geteuid.return_value = 1000
        mock_get_user.return_value = 'alice'
        mock_subprocess_run.return_value = mock.Mock(returncode=0, stdout=b'bar', stderr=b'')
        result = utils.su_subprocess_run('alice', 'foo')
        mock_subprocess_run.assert_called_once_with(
            ['/bin/sh', '-c', 'foo'],
        )
        self.assertEqual(0, result.returncode)
        self.assertEqual(b'bar', result.stdout)


@mock.patch("crmsh.utils.get_stdout_or_raise_error")
def test_get_quorum_votes_dict(mock_run):
    mock_run.return_value = """
Votequorum information
----------------------
Expected votes:   1
Highest expected: 1
Total votes:      1
Quorum:           1
Flags:            Quorate
    """
    res = utils.get_quorum_votes_dict()
    assert res == {'Expected': '1', 'Total': '1'}
    mock_run.assert_called_once_with("corosync-quorumtool -s", remote=None, success_val_list=[0, 2])


def test_re_split_string():
    assert utils.re_split_string('[; ]', "/dev/sda1; /dev/sdb1 ; ") == ["/dev/sda1", "/dev/sdb1"]
    assert utils.re_split_string('[; ]', "/dev/sda1 ") == ["/dev/sda1"]


@mock.patch('crmsh.utils.get_dev_info')
def test_has_dev_partitioned(mock_get_dev_info):
    mock_get_dev_info.return_value = """
disk
part
    """
    res = utils.has_dev_partitioned("/dev/sda1")
    assert res is True
    mock_get_dev_info.assert_called_once_with("/dev/sda1", "NAME", peer=None)


@mock.patch('crmsh.utils.get_dev_uuid')
def test_compare_uuid_with_peer_dev_cannot_find_local(mock_get_dev_uuid):
    mock_get_dev_uuid.return_value = ""
    with pytest.raises(ValueError) as err:
        utils.compare_uuid_with_peer_dev(["/dev/sdb1"], "node2")
    assert str(err.value) == "Cannot find UUID for /dev/sdb1 on local"
    mock_get_dev_uuid.assert_called_once_with("/dev/sdb1")


@mock.patch('crmsh.utils.get_dev_uuid')
def test_compare_uuid_with_peer_dev_cannot_find_peer(mock_get_dev_uuid):
    mock_get_dev_uuid.side_effect = ["1234", ""]
    with pytest.raises(ValueError) as err:
        utils.compare_uuid_with_peer_dev(["/dev/sdb1"], "node2")
    assert str(err.value) == "Cannot find UUID for /dev/sdb1 on node2"
    mock_get_dev_uuid.assert_has_calls([
        mock.call("/dev/sdb1"),
        mock.call("/dev/sdb1", "node2")
        ])


@mock.patch('crmsh.utils.get_dev_uuid')
def test_compare_uuid_with_peer_dev(mock_get_dev_uuid):
    mock_get_dev_uuid.side_effect = ["1234", "5678"]
    with pytest.raises(ValueError) as err:
        utils.compare_uuid_with_peer_dev(["/dev/sdb1"], "node2")
    assert str(err.value) == "UUID of /dev/sdb1 not same with peer node2"
    mock_get_dev_uuid.assert_has_calls([
        mock.call("/dev/sdb1"),
        mock.call("/dev/sdb1", "node2")
        ])


@mock.patch('crmsh.utils.get_dev_info')
def test_is_dev_used_for_lvm(mock_dev_info):
    mock_dev_info.return_value = "lvm"
    res = utils.is_dev_used_for_lvm("/dev/sda1")
    assert res is True
    mock_dev_info.assert_called_once_with("/dev/sda1", "TYPE", peer=None)


@mock.patch('crmsh.utils.get_dev_info')
def test_is_dev_a_plain_raw_disk_or_partition(mock_dev_info):
    mock_dev_info.return_value = "raid1\nlvm"
    res = utils.is_dev_a_plain_raw_disk_or_partition("/dev/md127")
    assert res is False
    mock_dev_info.assert_called_once_with("/dev/md127", "TYPE", peer=None)


@mock.patch('crmsh.utils.get_stdout_or_raise_error')
def test_get_dev_info(mock_run):
    mock_run.return_value = "data"
    res = utils.get_dev_info("/dev/sda1", "TYPE")
    assert res == "data"
    mock_run.assert_called_once_with("lsblk -fno TYPE /dev/sda1", remote=None)


@mock.patch('crmsh.utils.get_dev_info')
def test_get_dev_fs_type(mock_get_info):
    mock_get_info.return_value = "data"
    res = utils.get_dev_fs_type("/dev/sda1")
    assert res == "data"
    mock_get_info.assert_called_once_with("/dev/sda1", "FSTYPE", peer=None)


@mock.patch('crmsh.utils.get_dev_info')
def test_get_dev_uuid(mock_get_info):
    mock_get_info.return_value = "uuid"
    res = utils.get_dev_uuid("/dev/sda1")
    assert res == "uuid"
    mock_get_info.assert_called_once_with("/dev/sda1", "UUID", peer=None)


@mock.patch('crmsh.utils.get_stdout_or_raise_error')
def test_get_pe_number_except(mock_run):
    mock_run.return_value = "data"
    with pytest.raises(ValueError) as err:
        utils.get_pe_number("vg1")
    assert str(err.value) == "Cannot find PE on VG(vg1)"
    mock_run.assert_called_once_with("vgdisplay vg1")


@mock.patch('crmsh.utils.get_stdout_or_raise_error')
def test_get_pe_number(mock_run):
    mock_run.return_value = """
PE Size               4.00 MiB
Total PE              1534
Alloc PE / Size       1534 / 5.99 GiB
    """
    res = utils.get_pe_number("vg1")
    assert res == 1534
    mock_run.assert_called_once_with("vgdisplay vg1")


@mock.patch('crmsh.utils.get_stdout_or_raise_error')
def test_get_all_vg_name(mock_run):
    mock_run.return_value = """
--- Volume group ---
  VG Name               ocfs2-vg
  System ID
    """
    res = utils.get_all_vg_name()
    assert res == ["ocfs2-vg"]
    mock_run.assert_called_once_with("vgdisplay")


@mock.patch('crmsh.utils.randomword')
def test_gen_unused_id(mock_rand):
    mock_rand.return_value = "1234xxxx"
    res = utils.gen_unused_id(["test-id"], "test-id")
    assert res == "test-id-1234xxxx"
    mock_rand.assert_called_once_with(6)


@mock.patch('random.choice')
def test_randomword(mock_rand):
    import string
    mock_rand.side_effect = ['z', 'f', 'k', 'e', 'c', 'd']
    res = utils.randomword()
    assert res == "zfkecd"
    mock_rand.assert_has_calls([mock.call(string.ascii_lowercase) for x in range(6)])


@mock.patch('crmsh.cibconfig.cib_factory')
def test_all_exist_id(mock_cib):
    mock_cib.refresh = mock.Mock()
    mock_cib.id_list = mock.Mock()
    mock_cib.id_list.return_value = ['1', '2']
    res = utils.all_exist_id()
    assert res == ['1', '2']
    mock_cib.id_list.assert_called_once_with()
    mock_cib.refresh.assert_called_once_with()


@mock.patch('crmsh.utils.get_stdout_or_raise_error')
def test_has_mount_point_used(mock_run):
    mock_run.return_value = """
/dev/vda2 on /usr/local type btrfs (rw,relatime,space_cache,subvolid=259,subvol=/@/usr/local)
/dev/vda2 on /opt type btrfs (rw,relatime,space_cache,subvolid=263,subvol=/@/opt)
/dev/vda2 on /var/lib/docker/btrfs type btrfs (rw,relatime,space_cache,subvolid=258,subvol=/@/var)
    """
    res = utils.has_mount_point_used("/opt")
    assert res is True
    mock_run.assert_called_once_with("mount")


@mock.patch('crmsh.utils.get_stdout_or_raise_error')
def test_has_disk_mounted(mock_run):
    mock_run.return_value = """
/dev/vda2 on /usr/local type btrfs (rw,relatime,space_cache,subvolid=259,subvol=/@/usr/local)
/dev/vda2 on /opt type btrfs (rw,relatime,space_cache,subvolid=263,subvol=/@/opt)
/dev/vda2 on /var/lib/docker/btrfs type btrfs (rw,relatime,space_cache,subvolid=258,subvol=/@/var)
    """
    res = utils.has_disk_mounted("/dev/vda2")
    assert res is True
    mock_run.assert_called_once_with("mount")


@mock.patch('crmsh.sbd.SBDManager.is_using_diskless_sbd')
@mock.patch('crmsh.utils.get_stdout_or_raise_error')
def test_has_stonith_running(mock_run, mock_diskless):
    mock_run.return_value = """
stonith-sbd
1 fence device found
    """
    mock_diskless.return_value = True
    res = utils.has_stonith_running()
    assert res is True
    mock_run.assert_called_once_with("stonith_admin -L")
    mock_diskless.assert_called_once_with()


@mock.patch('crmsh.utils.S_ISBLK')
@mock.patch('os.stat')
def test_is_block_device_error(mock_stat, mock_isblk):
    mock_stat_inst = mock.Mock(st_mode=12345)
    mock_stat.return_value = mock_stat_inst
    mock_isblk.side_effect = OSError
    res = utils.is_block_device("/dev/sda1")
    assert res is False
    mock_stat.assert_called_once_with("/dev/sda1")
    mock_isblk.assert_called_once_with(12345)


@mock.patch('crmsh.utils.S_ISBLK')
@mock.patch('os.stat')
def test_is_block_device(mock_stat, mock_isblk):
    mock_stat_inst = mock.Mock(st_mode=12345)
    mock_stat.return_value = mock_stat_inst
    mock_isblk.return_value = True
    res = utils.is_block_device("/dev/sda1")
    assert res is True
    mock_stat.assert_called_once_with("/dev/sda1")
    mock_isblk.assert_called_once_with(12345)


@mock.patch('crmsh.utils.ping_node')
@mock.patch('crmsh.utils.get_stdout_or_raise_error')
def test_check_all_nodes_reachable(mock_run, mock_ping):
    mock_run.return_value = "1084783297 15sp2-1 member"
    utils.check_all_nodes_reachable()
    mock_run.assert_called_once_with("crm_node -l")
    mock_ping.assert_called_once_with("15sp2-1")


@mock.patch('crmsh.utils.get_stdout_stderr')
def test_detect_virt(mock_run):
    mock_run.return_value = (0, None, None)
    assert utils.detect_virt() is True
    mock_run.assert_called_once_with("systemd-detect-virt")


@mock.patch('crmsh.utils.get_stdout_or_raise_error')
def test_is_standby(mock_run):
    mock_run.return_value = """
Node List:
* Node 15sp2-1: standby
    """
    assert utils.is_standby("15sp2-1") is True
    mock_run.assert_called_once_with("crm_mon -1")


@mock.patch('crmsh.utils.get_stdout_or_raise_error')
def test_get_dlm_option_dict(mock_run):
    mock_run.return_value = """
key1=value1
key2=value2
    """
    res_dict = utils.get_dlm_option_dict()
    assert res_dict == {
            "key1": "value1",
            "key2": "value2"
            }
    mock_run.assert_called_once_with("dlm_tool dump_config")


@mock.patch('crmsh.utils.get_dlm_option_dict')
def test_set_dlm_option_exception(mock_get_dict):
    mock_get_dict.return_value = {
            "key1": "value1",
            "key2": "value2"
            }
    with pytest.raises(ValueError) as err:
        utils.set_dlm_option(name="xin")
    assert str(err.value) == '"name" is not dlm config option'


@mock.patch('crmsh.utils.get_stdout_or_raise_error')
@mock.patch('crmsh.utils.get_dlm_option_dict')
def test_set_dlm_option(mock_get_dict, mock_run):
    mock_get_dict.return_value = {
            "key1": "value1",
            "key2": "value2"
            }
    utils.set_dlm_option(key2="test")
    mock_run.assert_called_once_with('dlm_tool set_config "key2=test"')


@mock.patch('crmsh.xmlutil.CrmMonXmlParser.is_resource_configured')
def test_is_dlm_configured(mock_configured):
    mock_configured.return_value = True
    assert utils.is_dlm_configured() is True
    mock_configured.assert_called_once_with(constants.DLM_CONTROLD_RA)


@mock.patch('crmsh.utils.get_stdout_or_raise_error')
def test_is_quorate_exception(mock_run):
    mock_run.return_value = "data"
    with pytest.raises(ValueError) as err:
        utils.is_quorate()
    assert str(err.value) == "Failed to get quorate status from corosync-quorumtool"
    mock_run.assert_called_once_with("corosync-quorumtool -s", success_val_list=[0, 2])


@mock.patch('crmsh.utils.get_stdout_or_raise_error')
def test_is_quorate(mock_run):
    mock_run.return_value = """
Ring ID:          1084783297/440
Quorate:          Yes
    """
    assert utils.is_quorate() is True
    mock_run.assert_called_once_with("corosync-quorumtool -s", success_val_list=[0, 2])


@mock.patch('crmsh.utils.etree.fromstring')
@mock.patch('crmsh.utils.get_stdout_stderr')
def test_list_cluster_nodes_none(mock_run, mock_etree):
    mock_run.return_value = (0, "data", None)
    mock_etree.return_value = None
    res = utils.list_cluster_nodes()
    assert res is None
    mock_run.assert_called_once_with(constants.CIB_QUERY, no_reg=False)
    mock_etree.assert_called_once_with("data")


@mock.patch('crmsh.utils.etree.fromstring')
@mock.patch('crmsh.utils.get_stdout_stderr')
def test_list_cluster_nodes_none_no_reg(mock_run, mock_etree):
    mock_run.return_value = (0, "data", None)
    mock_etree.return_value = None
    res = utils.list_cluster_nodes(no_reg=True)
    assert res is None
    mock_run.assert_called_once_with(constants.CIB_QUERY, no_reg=True)
    mock_etree.assert_called_once_with("data")


@mock.patch('os.path.isfile')
@mock.patch('os.getenv')
@mock.patch('crmsh.utils.get_stdout_stderr')
def test_list_cluster_nodes_cib_not_exist(mock_run, mock_env, mock_isfile):
    mock_run.return_value = (1, None, None)
    mock_env.return_value = constants.CIB_RAW_FILE
    mock_isfile.return_value = False
    res = utils.list_cluster_nodes()
    assert res is None
    mock_run.assert_called_once_with(constants.CIB_QUERY, no_reg=False)
    mock_env.assert_called_once_with("CIB_file", constants.CIB_RAW_FILE)
    mock_isfile.assert_called_once_with(constants.CIB_RAW_FILE)


@mock.patch('crmsh.xmlutil.file2cib_elem')
@mock.patch('os.path.isfile')
@mock.patch('os.getenv')
@mock.patch('crmsh.utils.get_stdout_stderr')
def test_list_cluster_nodes(mock_run, mock_env, mock_isfile, mock_file2elem):
    mock_run.return_value = (1, None, None)
    mock_env.return_value = constants.CIB_RAW_FILE
    mock_isfile.return_value = True
    mock_cib_inst = mock.Mock()
    mock_file2elem.return_value = mock_cib_inst
    mock_node_inst1 = mock.Mock()
    mock_node_inst2 = mock.Mock()
    mock_node_inst1.get.side_effect = ["node1", "remote"]
    mock_node_inst2.get.side_effect = ["node2", "member"]
    mock_cib_inst.xpath.side_effect = [[mock_node_inst1, mock_node_inst2], "data"]

    res = utils.list_cluster_nodes()
    assert res == ["node2"]

    mock_run.assert_called_once_with(constants.CIB_QUERY, no_reg=False)
    mock_env.assert_called_once_with("CIB_file", constants.CIB_RAW_FILE)
    mock_isfile.assert_called_once_with(constants.CIB_RAW_FILE)
    mock_file2elem.assert_called_once_with(constants.CIB_RAW_FILE)
    mock_cib_inst.xpath.assert_has_calls([
        mock.call(constants.XML_NODE_PATH),
        mock.call("//primitive[@id='node1']/instance_attributes/nvpair[@name='server']")
        ])


@mock.patch('os.getenv')
@mock.patch('crmsh.utils.get_stdout_stderr')
def test_get_property(mock_run, mock_env):
    mock_run.return_value = (0, "data", None)
    mock_env.return_value = "cib.xml"
    assert utils.get_property("no-quorum-policy") == "data"
    mock_run.assert_called_once_with("CIB_file=cib.xml sudo --preserve-env=CIB_file crm configure get_property no-quorum-policy")


@mock.patch('logging.Logger.warning')
@mock.patch('crmsh.utils.get_stdout_or_raise_error')
@mock.patch('crmsh.utils.get_property')
def test_set_property(mock_get, mock_run, mock_warn):
    mock_get.return_value = "start"
    utils.set_property("no-quorum-policy", "stop")
    mock_run.assert_called_once_with("crm configure property no-quorum-policy=stop")
    mock_warn.assert_called_once_with('"no-quorum-policy" in crm_config is set to stop, it was start')


@mock.patch('crmsh.utils.get_property')
def test_set_property_the_same(mock_get):
    mock_get.return_value = "value1"
    utils.set_property("no-quorum-policy", "value1")
    mock_get.assert_called_once_with("no-quorum-policy", "crm_config")


@mock.patch('crmsh.utils.crm_msec')
@mock.patch('crmsh.utils.get_property')
def test_set_property_conditional(mock_get, mock_msec):
    mock_get.return_value = "10s"
    mock_msec.side_effect = ["1000", "1000"]
    utils.set_property("timeout", "10", conditional=True)
    mock_get.assert_called_once_with("timeout", "crm_config")
    mock_msec.assert_has_calls([mock.call("10s"), mock.call("10")])


@mock.patch('crmsh.utils.is_dlm_configured')
def test_check_no_quorum_policy_with_dlm_return(mock_dlm):
    mock_dlm.return_value = False
    utils.check_no_quorum_policy_with_dlm()
    mock_dlm.assert_called_once_with()


@mock.patch('logging.Logger.warning')
@mock.patch('crmsh.utils.get_property')
@mock.patch('crmsh.utils.is_dlm_configured')
def test_check_no_quorum_policy_with_dlm(mock_dlm, mock_get_property, mock_warn):
    mock_dlm.return_value = True
    mock_get_property.return_value = "stop"
    utils.check_no_quorum_policy_with_dlm()
    mock_dlm.assert_called_once_with()
    mock_get_property.assert_called_once_with("no-quorum-policy")
    mock_warn.assert_called_once_with('The DLM cluster best practice suggests to set the cluster property "no-quorum-policy=freeze"')


@mock.patch('crmsh.utils.is_qdevice_configured')
@mock.patch('crmsh.utils.list_cluster_nodes')
def test_is_2node_cluster_without_qdevice(mock_list, mock_is_qdevice):
    mock_list.return_value = ["node1", "node2"]
    mock_is_qdevice.return_value = False
    res = utils.is_2node_cluster_without_qdevice()
    assert res is True
    mock_list.assert_called_once_with()
    mock_is_qdevice.assert_called_once_with()


def test_get_systemd_timeout_start_in_sec():
    res = utils.get_systemd_timeout_start_in_sec("1min 31s")
    assert res == 91


@mock.patch('crmsh.utils.is_larger_than_min_version')
@mock.patch('crmsh.cibconfig.cib_factory')
def test_is_ocf_1_1_cib_schema_detected(mock_cib, mock_larger):
    config.core.OCF_1_1_SUPPORT = True
    mock_cib.get_schema = mock.Mock()
    mock_cib.get_schema.return_value = "pacemaker-3.5"
    mock_larger.return_value = True
    assert utils.is_ocf_1_1_cib_schema_detected() is True
    mock_cib.get_schema.assert_called_once_with()
    mock_larger.assert_called_once_with("pacemaker-3.5", constants.SCHEMA_MIN_VER_SUPPORT_OCF_1_1)


@mock.patch('logging.Logger.warning')
@mock.patch('crmsh.utils.is_ocf_1_1_cib_schema_detected')
def test_handle_role_for_ocf_1_1(mock_support, mock_warn):
    mock_support.return_value = False
    assert utils.handle_role_for_ocf_1_1("Promoted") == "Master"
    mock_support.assert_called_once_with()
    mock_warn.assert_called_once_with('Convert "%s" to "%s" since the current schema version is old and not upgraded yet. Please consider "%s"', "Promoted", "Master", constants.CIB_UPGRADE)


@mock.patch('logging.Logger.info')
@mock.patch('crmsh.utils.is_ocf_1_1_cib_schema_detected')
def test_handle_role_for_ocf_1_1_convert_new(mock_support, mock_info):
    config.core.OCF_1_1_SUPPORT = True
    mock_support.return_value = True
    assert utils.handle_role_for_ocf_1_1("Master") == "Promoted"
    mock_support.assert_called_once_with()
    mock_info.assert_called_once_with('Convert deprecated "%s" to "%s"', "Master", "Promoted")


@mock.patch('crmsh.utils.is_ocf_1_1_cib_schema_detected')
def test_handle_role_for_ocf_1_1_return(mock_support):
    mock_support.return_value = True
    assert utils.handle_role_for_ocf_1_1("Promoted") == "Promoted"
    mock_support.assert_called_once_with()


def test_handle_role_for_ocf_1_1_return_not_role():
    assert utils.handle_role_for_ocf_1_1("test", name='other') == "test"


def test_compatible_role():
    assert utils.compatible_role("Slave", "Unpromoted") is True


@mock.patch('logging.Logger.warning')
@mock.patch('crmsh.utils.get_stdout_or_raise_error')
def test_fetch_cluster_node_list_from_node(mock_run, mock_warn):
    mock_run.return_value = """

    1 node1
    2 node2 lost
    3 node3 member
    """
    assert utils.fetch_cluster_node_list_from_node("node1") == ["node3"]
    mock_run.assert_called_once_with("crm_node -l", remote="node1")
    mock_warn.assert_has_calls([
        mock.call("The node '%s' has no known name and/or state information", "1"),
        mock.call("The node '%s'(state '%s') is not a current member", "node2", "lost")
        ])


@mock.patch('crmsh.utils.list_cluster_nodes_except_me')
def test_cluster_copy_file_return(mock_list_nodes):
    mock_list_nodes.return_value = []
    assert utils.cluster_copy_file("/file1") == True


@mock.patch('crmsh.utils.get_stdout_stderr')
def test_has_sudo_access(mock_run):
    mock_run.return_value = (0, None, None)
    assert utils.has_sudo_access() is True
    mock_run.assert_called_once_with("sudo -S -k -n id -u")


@mock.patch('grp.getgrgid')
@mock.patch('os.getgroups')
def test_in_haclient(mock_group, mock_getgrgid):
    mock_group.return_value = [90, 100]
    mock_getgrgid_inst1 = mock.Mock(gr_name=constants.HA_GROUP)
    mock_getgrgid_inst2 = mock.Mock(gr_name="other")
    mock_getgrgid.side_effect = [mock_getgrgid_inst1, mock_getgrgid_inst2]
    assert utils.in_haclient() is True
    mock_group.assert_called_once_with()


@mock.patch('crmsh.utils.in_haclient')
@mock.patch('crmsh.userdir.getuser')
def test_check_user_access_root(mock_user, mock_in):
    mock_user.return_value = 'root'
    utils.check_user_access('cluster')
    mock_in.assert_not_called()


@mock.patch('crmsh.utils.has_sudo_access')
@mock.patch('crmsh.utils.in_haclient')
@mock.patch('crmsh.userdir.getuser')
def test_check_user_access_haclient(mock_user, mock_in, mock_sudo):
    mock_user.return_value = 'user'
    mock_in.return_value = True
    utils.check_user_access('ra')
    mock_sudo.assert_not_called()


@mock.patch('logging.Logger.error')
@mock.patch('crmsh.utils.has_sudo_access')
@mock.patch('crmsh.utils.in_haclient')
@mock.patch('crmsh.userdir.getuser')
def test_check_user_access_need_sudo(mock_user, mock_in, mock_sudo, mock_error):
    mock_user.return_value = 'user'
    mock_in.return_value = False
    mock_sudo.return_value = True
    with pytest.raises(utils.TerminateSubCommand) as err:
        utils.check_user_access('ra')
    mock_error.assert_called_once_with('Please run this command starting with "sudo"')


@mock.patch('logging.Logger.error')
@mock.patch('crmsh.utils.has_sudo_access')
@mock.patch('crmsh.utils.in_haclient')
@mock.patch('crmsh.userdir.getuser')
def test_check_user_access_acl(mock_user, mock_in, mock_sudo, mock_error):
    mock_user.return_value = 'user'
    mock_in.return_value = False
    mock_sudo.return_value = False
    with pytest.raises(utils.TerminateSubCommand) as err:
        utils.check_user_access('ra')
    mock_error.assert_called_once_with('This command needs higher privilege.\nOption 1) Please consider to add "user" as sudoer. For example:\n  sudo bash -c \'echo "user ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/user\'\nOption 2) Add "user" to the haclient group. For example:\n  sudo usermod -g haclient user')


@mock.patch('logging.Logger.error')
@mock.patch('crmsh.utils.has_sudo_access')
@mock.patch('crmsh.utils.in_haclient')
@mock.patch('crmsh.userdir.getuser')
def test_check_user_access_cluster(mock_user, mock_in, mock_sudo, mock_error):
    mock_user.return_value = 'user'
    mock_in.return_value = False
    mock_sudo.return_value = False
    with pytest.raises(utils.TerminateSubCommand) as err:
        utils.check_user_access('cluster')
    mock_error.assert_called_once_with('Please run this command starting with "sudo".\nCurrently, this command needs to use sudo to escalate itself as root.\nPlease consider to add "user" as sudoer. For example:\n  sudo bash -c \'echo "user ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/user\'')
