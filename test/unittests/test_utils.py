# Copyright (C) 2014 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.
#
# unit tests for utils.py

import os
import re
import unittest
import pytest
import logging
from unittest import mock
from itertools import chain

import crmsh.utils
from crmsh import utils, config, tmpfiles, constants, options

logging.basicConfig(level=logging.DEBUG)


@mock.patch("crmsh.sh.ShellUtils.get_stdout")
def test_package_is_installed_local(mock_run):
    mock_run.return_value = (0, None)
    res = utils.package_is_installed("crmsh")
    assert res is True
    mock_run.assert_called_once_with("rpm -q --quiet crmsh")


@mock.patch("crmsh.utils.xmlutil.CrmMonXmlParser")
def test_get_nodeid_from_name_remote(mock_parser):
    mock_parser_inst = mock.Mock()
    mock_parser.return_value = mock_parser_inst
    mock_parser_inst.is_node_remote.return_value = True
    assert utils.get_nodeid_from_name("node1") == "node1"
    mock_parser.assert_called_once_with()
    mock_parser_inst.is_node_remote.assert_called_once_with("node1")


@mock.patch("crmsh.utils.xmlutil.CrmMonXmlParser")
def test_get_nodeid_from_name(mock_parser):
    mock_parser_inst = mock.Mock()
    mock_parser.return_value = mock_parser_inst
    mock_parser_inst.is_node_remote.return_value = False
    mock_parser_inst.get_node_id_from_name.return_value = "1"
    assert utils.get_nodeid_from_name("node1") == "1"
    mock_parser.assert_called_once_with()
    mock_parser_inst.is_node_remote.assert_called_once_with("node1")
    mock_parser_inst.get_node_id_from_name.assert_called_once_with("node1")



@mock.patch("crmsh.sh.ShellUtils.get_stdout")
def test_get_nodeinfo_from_cmaptool_return_none(mock_get_stdout):
    mock_get_stdout.return_value = (1, None)
    assert bool(utils.get_nodeinfo_from_cmaptool()) is False
    mock_get_stdout.assert_called_once_with("corosync-cmapctl -b runtime.members")


@mock.patch("crmsh.utils.re.findall")
@mock.patch("crmsh.utils.re.search")
@mock.patch("crmsh.sh.ShellUtils.get_stdout")
def test_get_nodeinfo_from_cmaptool(mock_get_stdout, mock_search, mock_findall):
    mock_get_stdout.return_value = (0, 'runtime.members.1.ip (str) = r(0) ip(192.168.43.129)\nruntime.members.2.ip (str) = r(0) ip(192.168.43.128)')
    match_inst1 = mock.Mock()
    match_inst2 = mock.Mock()
    mock_search.side_effect = [match_inst1, match_inst2]
    match_inst1.group.return_value = '1'
    match_inst2.group.return_value = '2'
    mock_findall.side_effect = [["192.168.43.129"], ["192.168.43.128"]]

    result = utils.get_nodeinfo_from_cmaptool()
    assert result['1'] == ["192.168.43.129"]
    assert result['2'] == ["192.168.43.128"]

    mock_get_stdout.assert_called_once_with("corosync-cmapctl -b runtime.members")
    mock_search.assert_has_calls([
        mock.call(r'members\.(.*)\.ip', 'runtime.members.1.ip (str) = r(0) ip(192.168.43.129)'),
        mock.call(r'members\.(.*)\.ip', 'runtime.members.2.ip (str) = r(0) ip(192.168.43.128)')
    ])
    match_inst1.group.assert_called_once_with(1)
    match_inst2.group.assert_called_once_with(1)
    mock_findall.assert_has_calls([
        mock.call(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', 'runtime.members.1.ip (str) = r(0) ip(192.168.43.129)'),
        mock.call(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', 'runtime.members.2.ip (str) = r(0) ip(192.168.43.128)')
    ])

@mock.patch("crmsh.utils.get_nodeinfo_from_cmaptool")
@mock.patch("crmsh.service_manager.ServiceManager.service_is_active")
def test_valid_nodeid_false_service_not_active(mock_is_active, mock_nodeinfo):
    mock_is_active.return_value = False
    assert utils.valid_nodeid("3") is False
    mock_is_active.assert_called_once_with('corosync.service')
    mock_nodeinfo.assert_not_called()

@mock.patch("crmsh.utils.get_nodeinfo_from_cmaptool")
@mock.patch("crmsh.service_manager.ServiceManager.service_is_active")
def test_valid_nodeid_false(mock_is_active, mock_nodeinfo):
    mock_is_active.return_value = True
    mock_nodeinfo.return_value = {'1': ["10.10.10.1"], "2": ["20.20.20.2"]}
    assert utils.valid_nodeid("3") is False
    mock_is_active.assert_called_once_with('corosync.service')
    mock_nodeinfo.assert_called_once_with()

@mock.patch("crmsh.utils.get_nodeinfo_from_cmaptool")
@mock.patch("crmsh.service_manager.ServiceManager.service_is_active")
def test_valid_nodeid_true(mock_is_active, mock_nodeinfo):
    mock_is_active.return_value = True
    mock_nodeinfo.return_value = {'1': ["10.10.10.1"], "2": ["20.20.20.2"]}
    assert utils.valid_nodeid("2") is True
    mock_is_active.assert_called_once_with('corosync.service')
    mock_nodeinfo.assert_called_once_with()


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


@mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
def test_detect_aws_false(mock_run):
    mock_run.side_effect = ["test", "test"]
    assert utils.detect_aws() is False
    mock_run.assert_has_calls([
        mock.call("dmidecode -s system-version"),
        mock.call("dmidecode -s system-manufacturer")
        ])

@mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
def test_detect_aws_xen(mock_run):
    mock_run.side_effect = ["4.2.amazon", "Xen"]
    assert utils.detect_aws() is True
    mock_run.assert_has_calls([
        mock.call("dmidecode -s system-version"),
        mock.call("dmidecode -s system-manufacturer")
        ])

@mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
def test_detect_aws_kvm(mock_run):
    mock_run.side_effect = ["Not Specified", "Amazon EC2"]
    assert utils.detect_aws() is True
    mock_run.assert_has_calls([
        mock.call("dmidecode -s system-version"),
        mock.call("dmidecode -s system-manufacturer")
        ])

@mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
def test_detect_azure_false(mock_run):
    mock_run.side_effect = ["test", "test"]
    assert utils.detect_azure() is False
    mock_run.assert_has_calls([
        mock.call("dmidecode -s system-manufacturer"),
        mock.call("dmidecode -s chassis-asset-tag")
        ])

@mock.patch("crmsh.utils._cloud_metadata_request")
@mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
def test_detect_azure_microsoft_corporation(mock_run, mock_request):
    mock_run.side_effect = ["microsoft corporation", "test"]
    mock_request.return_value = "data"
    assert utils.detect_azure() is True
    mock_run.assert_has_calls([
        mock.call("dmidecode -s system-manufacturer"),
        mock.call("dmidecode -s chassis-asset-tag")
        ])

@mock.patch("crmsh.utils._cloud_metadata_request")
@mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
def test_detect_azure_chassis(mock_run, mock_request):
    mock_run.side_effect = ["test", "7783-7084-3265-9085-8269-3286-77"]
    mock_request.return_value = "data"
    assert utils.detect_azure() is True
    mock_run.assert_has_calls([
        mock.call("dmidecode -s system-manufacturer"),
        mock.call("dmidecode -s chassis-asset-tag")
        ])

@mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
def test_detect_gcp_false(mock_run):
    mock_run.return_value = "test"
    assert utils.detect_gcp() is False
    mock_run.assert_called_once_with("dmidecode -s bios-vendor")

@mock.patch("crmsh.utils._cloud_metadata_request")
@mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
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
    assert utils.detect_cloud.__wrapped__() == constants.CLOUD_AWS
    mock_is_program.assert_called_once_with("dmidecode")
    mock_aws.assert_called_once_with()

@mock.patch("crmsh.utils.detect_azure")
@mock.patch("crmsh.utils.detect_aws")
@mock.patch("crmsh.utils.is_program")
def test_detect_cloud_azure(mock_is_program, mock_aws, mock_azure):
    mock_is_program.return_value = True
    mock_aws.return_value = False
    mock_azure.return_value = True
    assert utils.detect_cloud.__wrapped__() == constants.CLOUD_AZURE
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
    assert utils.detect_cloud.__wrapped__() == constants.CLOUD_GCP
    mock_is_program.assert_called_once_with("dmidecode")
    mock_aws.assert_called_once_with()
    mock_azure.assert_called_once_with()
    mock_gcp.assert_called_once_with()




def test_calculate_quorate_status():
    assert utils.calculate_quorate_status(3, 2) is True
    assert utils.calculate_quorate_status(3, 1) is False


@mock.patch("crmsh.sh.ClusterShell.get_stdout_or_raise_error")
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
    mock_run.assert_called_once_with("corosync-quorumtool -s", None, success_exit_status={0, 2})


def test_re_split_string():
    assert utils.re_split_string('[; ]', "/dev/sda1; /dev/sdb1 ; ") == ["/dev/sda1", "/dev/sdb1"]
    assert utils.re_split_string('[; ]', "/dev/sda1 ") == ["/dev/sda1"]


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


@mock.patch('crmsh.sbd.SBDUtils.is_using_diskless_sbd')
@mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
def test_has_fence_device_registered(mock_run, mock_diskless):
    mock_run.return_value = """
fencing-sbd
1 fence device found
    """
    mock_diskless.return_value = True
    res = utils.has_fence_device_registered()
    assert res is True
    mock_run.assert_called_once_with("stonith_admin -L")
    mock_diskless.assert_called_once_with()




@mock.patch('crmsh.sh.ShellUtils.get_stdout_stderr')
def test_detect_virt(mock_run):
    mock_run.return_value = (0, None, None)
    assert utils.detect_virt() is True
    mock_run.assert_called_once_with("systemd-detect-virt")


@mock.patch('crmsh.xmlutil.CrmMonXmlParser')
def test_cluster_with_quorum(mock_crmmon):
    mock_crmmon_inst = mock.Mock()
    mock_crmmon.return_value = mock_crmmon_inst
    mock_crmmon_inst.with_quorum.return_value = True
    assert utils.cluster_with_quorum() is True
    mock_crmmon_inst.with_quorum.assert_called_once_with()


@mock.patch('crmsh.cibquery.get_cluster_nodes')
@mock.patch('crmsh.utils.etree.fromstring')
@mock.patch('crmsh.sh.ShellUtils.get_stdout_stderr')
def test_list_cluster_nodes_none(mock_run, mock_etree, mock_get_cluster_nodes):
    mock_run.return_value = (0, "data", None)
    mock_etree.return_value = None
    res = utils.list_cluster_nodes()
    assert res is None
    mock_run.assert_called_once_with(constants.CIB_QUERY, no_reg=False)
    mock_etree.assert_called_once_with("data")
    mock_get_cluster_nodes.assert_not_called()


@mock.patch('crmsh.cibquery.get_cluster_nodes')
@mock.patch('os.path.isfile')
@mock.patch('os.getenv')
@mock.patch('crmsh.sh.ShellUtils.get_stdout_stderr')
def test_list_cluster_nodes_cib_not_exist(mock_run, mock_env, mock_isfile, mock_get_cluster_nodes):
    mock_run.return_value = (1, None, None)
    mock_env.return_value = constants.CIB_RAW_FILE
    mock_isfile.return_value = False
    res = utils.list_cluster_nodes()
    assert res is None
    mock_run.assert_called_once_with(constants.CIB_QUERY, no_reg=False)
    mock_env.assert_called_once_with("CIB_file", constants.CIB_RAW_FILE)
    mock_isfile.assert_called_once_with(constants.CIB_RAW_FILE)
    mock_get_cluster_nodes.assert_not_called()


@mock.patch('crmsh.cibquery.get_cluster_nodes')
@mock.patch('crmsh.xmlutil.file2cib_elem')
@mock.patch('os.path.isfile')
@mock.patch('os.getenv')
@mock.patch('crmsh.sh.ShellUtils.get_stdout_stderr')
def test_list_cluster_nodes(mock_run, mock_env, mock_isfile, mock_file2elem, mock_get_cluster_nodes):
    mock_run.return_value = (1, None, None)
    mock_env.return_value = constants.CIB_RAW_FILE
    mock_isfile.return_value = True
    mock_cib_inst = mock.Mock()
    mock_file2elem.return_value = mock_cib_inst

    res = utils.list_cluster_nodes()

    mock_run.assert_called_once_with(constants.CIB_QUERY, no_reg=False)
    mock_env.assert_called_once_with("CIB_file", constants.CIB_RAW_FILE)
    mock_isfile.assert_called_once_with(constants.CIB_RAW_FILE)
    mock_file2elem.assert_called_once_with(constants.CIB_RAW_FILE)
    mock_get_cluster_nodes.assert_called_once_with(mock_cib_inst)


@mock.patch('crmsh.utils.DeprecatedTermTranslator')
@mock.patch('os.getenv')
@mock.patch('crmsh.sh.cluster_shell')
def test_get_property(mock_run, mock_env, mock_translator):
    mock_inst = mock.Mock()
    mock_translator.return_value = mock_inst
    mock_inst.translate = mock.Mock(return_value="no-quorum-policy")
    mock_run_inst = mock.Mock()
    mock_run.return_value = mock_run_inst
    mock_run_inst.get_rc_stdout_stderr_without_input.return_value = (0, "data", "")
    mock_env.return_value = "cib.xml"
    assert utils.get_property("no-quorum-policy") == "data"
    mock_run_inst.get_rc_stdout_stderr_without_input.assert_called_once_with(None, "CIB_file=cib.xml sudo --preserve-env=CIB_file crm configure get_property no-quorum-policy")


@mock.patch('crmsh.utils.delete_property')
@mock.patch('crmsh.utils.DeprecatedTermTranslator')
@mock.patch('logging.Logger.warning')
@mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
@mock.patch('crmsh.utils.get_property')
def test_set_property(mock_get, mock_run, mock_warn, mock_translator, mock_delete):
    mock_inst = mock.Mock()
    mock_translator.return_value = mock_inst
    mock_inst.both_configured = mock.Mock(return_value=True)
    mock_get.return_value = "start"
    utils.set_property("no-quorum-policy", "stop")
    mock_run.assert_called_once_with("crm configure property no-quorum-policy=stop")
    mock_warn.assert_called_once_with('"%s" in %s is set to %s, it was %s', 'no-quorum-policy', 'crm_config', 'stop', 'start')


@mock.patch('crmsh.utils.DeprecatedTermTranslator')
@mock.patch('crmsh.utils.get_property')
def test_set_property_the_same(mock_get, mock_translator):
    mock_inst = mock.Mock()
    mock_translator.return_value = mock_inst
    mock_translator.using_new_term = False
    mock_get.return_value = "value1"
    utils.set_property("no-quorum-policy", "value1")
    mock_get.assert_called_once_with("no-quorum-policy", "crm_config")


@mock.patch('crmsh.utils.DeprecatedTermTranslator')
@mock.patch('crmsh.utils.crm_msec')
@mock.patch('crmsh.utils.get_property')
def test_set_property_conditional(mock_get, mock_msec, mock_translator):
    mock_inst = mock.Mock()
    mock_translator.return_value = mock_inst
    mock_translator.using_new_term = False
    mock_get.return_value = "10s"
    mock_msec.side_effect = ["1000", "1000"]
    utils.set_property("timeout", "10", conditional=True)
    mock_get.assert_called_once_with("timeout", "crm_config")
    mock_msec.assert_has_calls([mock.call("10s"), mock.call("10")])


@mock.patch('crmsh.corosync.is_qdevice_configured')
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


def test_is_larger_than_min_version():
    assert utils.is_larger_than_min_version("pacemaker-3.7", "pacemaker-3.1") is True
    assert utils.is_larger_than_min_version("pacemaker-3.0", "pacemaker-3.0") is True
    assert utils.is_larger_than_min_version("pacemaker-3.0", "pacemaker-3.1") is False
    with pytest.raises(ValueError) as err:
        utils.is_larger_than_min_version("wrong-format", "pacemaker-3.7")
    assert str(err.value) == "Invalid version string: wrong-format"


@mock.patch('crmsh.utils.is_larger_than_min_version')
@mock.patch('crmsh.cibconfig.cib_factory')
def test_is_ocf_1_1_cib_schema_detected(mock_cib, mock_larger):
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
    mock_support.return_value = True
    utils.auto_convert_role = True
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


@mock.patch('crmsh.utils.list_cluster_nodes_except_me')
def test_cluster_copy_path_return(mock_list_nodes):
    mock_list_nodes.return_value = []
    assert utils.cluster_copy_path("/file1") == True


@mock.patch('crmsh.sh.ShellUtils.get_stdout_stderr')
def test_has_sudo_access(mock_run):
    mock_run.return_value = (0, None, None)
    assert utils.has_sudo_access() is True
    mock_run.assert_called_once_with("sudo -S -k -n id -u")


@mock.patch('grp.getgrnam')
@mock.patch('os.getegid')
@mock.patch('os.getgroups')
def test_in_haclient(mock_getgroups, mock_getegid, mock_getgrnam):
    mock_getgroups.return_value = [90]
    mock_getegid.return_value = 90
    mock_getgrnam_inst = mock.Mock(gr_gid=90)
    mock_getgrnam.return_value = mock_getgrnam_inst
    assert utils.in_haclient() is True
    mock_getgrnam.assert_called_once_with(constants.HA_GROUP)


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
    mock_error.assert_called_once_with('Operation is denied. The current user lacks the necessary privilege.')


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
    mock_error.assert_called_once_with('Operation is denied. The current user lacks the necessary privilege.')


@mock.patch('logging.Logger.warning')
@mock.patch('crmsh.utils.is_dc_idle')
@mock.patch('crmsh.utils.is_cluster_in_maintenance_mode')
def test_leverage_maintenance_mode_skip(mock_cluster_maintenance, mock_idle, mock_warn):
    mock_cluster_maintenance.return_value = False
    options.force = True
    mock_idle.return_value = False
    with utils.leverage_maintenance_mode() as result:
        assert result is False
    mock_warn.assert_called_once_with("Pacemaker state transition is in progress. Skip restarting cluster in maintenance mode.")


@mock.patch('crmsh.utils.delete_property')
@mock.patch('crmsh.utils.set_property')
@mock.patch('logging.Logger.info')
@mock.patch('crmsh.utils.is_dc_idle')
@mock.patch('crmsh.utils.is_cluster_in_maintenance_mode')
def test_leverage_maintenance_mode(mock_cluster_maintenance, mock_idle, mock_info, mock_set, mock_delete):
    mock_cluster_maintenance.return_value = False
    options.force = True
    mock_idle.return_value = True
    with utils.leverage_maintenance_mode() as result:
        assert result is True
    mock_set.assert_called_once_with("maintenance-mode", "true")
    mock_delete.assert_called_once_with("maintenance-mode")


@mock.patch('crmsh.utils.get_dc')
def test_is_dc_idle_no_dc(mock_dc):
    mock_dc.return_value = None
    assert utils.is_dc_idle() is False


@mock.patch('logging.Logger.error')
@mock.patch('crmsh.utils.ShellUtils')
@mock.patch('crmsh.utils.get_dc')
def test_is_dc_idle_failed_get_dc_status(mock_dc, mock_shell, mock_error):
    mock_dc.return_value = "test"
    mock_shell_inst = mock.Mock()
    mock_shell.return_value = mock_shell_inst
    mock_shell_inst.get_stdout_stderr.return_value = (1, None, "error")
    assert utils.is_dc_idle() is False
    mock_error.assert_called_once_with("Failed to get DC status: %s", "error")


@mock.patch('crmsh.utils.ShellUtils')
@mock.patch('crmsh.utils.get_dc')
def test_is_dc_idle(mock_dc, mock_shell):
    mock_dc.return_value = "test"
    mock_shell_inst = mock.Mock()
    mock_shell.return_value = mock_shell_inst
    mock_shell_inst.get_stdout_stderr.return_value = (0, "in S_IDLE: ok", None)
    assert utils.is_dc_idle() is True




def test_verify_result():
    rc1 = utils.VerifyResult.SUCCESS
    rc2 = utils.VerifyResult.WARNING
    rc3 = utils.VerifyResult.NON_FATAL_ERROR
    rc4 = utils.VerifyResult.FATAL_ERROR

    rc = rc1
    assert bool(rc) is True
    rc = rc2
    assert bool(rc) is True
    rc = rc1 | rc2
    assert bool(rc) is True
    rc = rc3
    assert bool(rc) is False
    rc = rc3 | rc4
    assert bool(rc) is False
    rc = rc1 | rc2 | rc3
    assert bool(rc) is False
    assert utils.VerifyResult.NON_FATAL_ERROR in rc


@mock.patch('crmsh.utils.fatal')
@mock.patch('crmsh.utils.get_address_list_from_corosync_conf')
@mock.patch('crmsh.utils.list_cluster_nodes')
def test_validate_and_get_reachable_nodes_cannot_get_member(mock_list_nodes, mock_get_address, mock_fatal):
    mock_list_nodes.return_value = None
    mock_get_address.return_value = None
    mock_fatal.side_effect = ValueError
    with pytest.raises(ValueError):
        utils.validate_and_get_reachable_nodes([])
    mock_fatal.assert_called_once_with("Cannot get the member list of the cluster")
    mock_get_address.assert_called_once_with()


@mock.patch('crmsh.utils.fatal')
@mock.patch('crmsh.utils.list_cluster_nodes')
def test_validate_and_get_reachable_nodes_not_a_member(mock_list_nodes, mock_fatal):
    mock_list_nodes.return_value = ["node1", "node2"]
    mock_fatal.side_effect = ValueError
    with pytest.raises(ValueError):
        utils.validate_and_get_reachable_nodes(["node3"])
    mock_fatal.assert_called_once_with("Node \"node3\" is not in the cluster")


@mock.patch('crmsh.utils.this_node')
@mock.patch('crmsh.utils.list_cluster_nodes')
def test_validate_and_get_reachable_nodes_return_local(mock_list_nodes, mock_this_node):
    mock_list_nodes.return_value = ["node1", "node2"]
    mock_this_node.return_value = "node1"
    res = utils.validate_and_get_reachable_nodes()
    assert res == ["node1"]


@mock.patch('crmsh.network_utils.get_reachable_node_list')
@mock.patch('crmsh.utils.this_node')
@mock.patch('crmsh.utils.get_address_list_from_corosync_conf')
@mock.patch('crmsh.utils.list_cluster_nodes')
def test_validate_and_get_reachable_nodes_no_cib(mock_list_nodes, mock_get_address, mock_this_node, mock_get_reachable):
    mock_list_nodes.return_value = None
    mock_get_address.return_value = ["node1", "node2"]
    mock_get_reachable.return_value = ["node1"]
    mock_this_node.return_value = "node1"
    res = utils.validate_and_get_reachable_nodes(all_nodes=True)
    assert res == ["node1"]


@mock.patch('logging.Logger.error')
@mock.patch('crmsh.xmlutil.CrmMonXmlParser')
@mock.patch('crmsh.sh.cluster_shell')
@mock.patch('crmsh.network_utils.get_reachable_node_list')
@mock.patch('crmsh.utils.this_node')
@mock.patch('crmsh.utils.list_cluster_nodes')
def test_validate_and_get_reachable_nodes(mock_list_nodes, mock_this_node, mock_get_reachable, mock_shell, mock_xml, mock_error):
    mock_list_nodes.return_value = ["node1", "node2"]
    mock_get_reachable.return_value = ["node1", "node2"]
    mock_this_node.return_value = "node2"
    mock_shell_inst = mock.Mock()
    mock_shell.return_value = mock_shell_inst
    mock_shell_inst.get_stdout_or_raise_error.return_value = """
node1(1): member
    """
    mock_xml_inst = mock.Mock()
    mock_xml.return_value = mock_xml_inst
    mock_xml_inst.is_node_online.return_value = False

    res = utils.validate_and_get_reachable_nodes(all_nodes=True)
    assert res == ["node2"]

    mock_error.assert_called_once_with("From the view of node '%s', node '%s' is not a member of the cluster", 'node1', 'node2')

