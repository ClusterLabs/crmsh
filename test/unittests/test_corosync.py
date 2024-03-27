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


@mock.patch('crmsh.corosync.is_qdevice_configured')
def test_query_qdevice_status_exception(mock_configured):
    mock_configured.return_value = False
    with pytest.raises(ValueError) as err:
        corosync.query_qdevice_status()
    assert str(err.value) == "QDevice/QNetd not configured!"
    mock_configured.assert_called_once_with()


@mock.patch('crmsh.utils.print_cluster_nodes')
@mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
@mock.patch('crmsh.corosync.is_qdevice_configured')
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


@mock.patch("crmsh.sh.ShellUtils.get_stdout_stderr")
def test_query_ring_status_except(mock_run):
    mock_run.return_value = (1, None, "error")
    with pytest.raises(ValueError) as err:
        corosync.query_ring_status()
    assert str(err.value) == "error"
    mock_run.assert_called_once_with("corosync-cfgtool -s")


@mock.patch("crmsh.sh.ShellUtils.get_stdout_stderr")
def test_query_ring_status(mock_run):
    mock_run.return_value = (0, "data", None)
    corosync.query_ring_status()
    mock_run.assert_called_once_with("corosync-cfgtool -s")


@mock.patch("crmsh.utils.print_cluster_nodes")
@mock.patch("crmsh.sh.ShellUtils.get_stdout_stderr")
def test_query_quorum_status_except(mock_run, mock_print_nodes):
    mock_run.return_value = (1, None, "error")
    with pytest.raises(ValueError) as err:
        corosync.query_quorum_status()
    assert str(err.value) == "error"
    mock_run.assert_called_once_with("corosync-quorumtool -s")
    mock_print_nodes.assert_called_once_with()


@mock.patch("crmsh.utils.print_cluster_nodes")
@mock.patch("crmsh.sh.ShellUtils.get_stdout_stderr")
def test_query_quorum_status(mock_run, mock_print_nodes):
    mock_run.return_value = (0, "data", None)
    corosync.query_quorum_status()
    mock_run.assert_called_once_with("corosync-quorumtool -s")
    mock_print_nodes.assert_called_once_with()


@mock.patch("crmsh.utils.print_cluster_nodes")
@mock.patch("crmsh.sh.ShellUtils.get_stdout_stderr")
def test_query_quorum_status_no_quorum(mock_run, mock_print_nodes):
    mock_run.return_value = (2, "no quorum", None)
    corosync.query_quorum_status()
    mock_run.assert_called_once_with("corosync-quorumtool -s")
    mock_print_nodes.assert_called_once_with()


@mock.patch("crmsh.corosync.is_qdevice_configured")
def test_query_qnetd_status_no_qdevice(mock_qdevice_configured):
    mock_qdevice_configured.return_value = False
    with pytest.raises(ValueError) as err:
        corosync.query_qnetd_status()
    assert str(err.value) == "QDevice/QNetd not configured!"
    mock_qdevice_configured.assert_called_once_with()


@mock.patch("crmsh.corosync.get_value")
@mock.patch("crmsh.corosync.is_qdevice_configured")
def test_query_qnetd_status_no_cluster_name(mock_qdevice_configured, mock_get_value):
    mock_qdevice_configured.return_value = True
    mock_get_value.return_value = None
    with pytest.raises(ValueError) as err:
        corosync.query_qnetd_status()
    assert str(err.value) == "cluster_name not configured!"
    mock_qdevice_configured.assert_called_once_with()
    mock_get_value.assert_called_once_with("totem.cluster_name")


@mock.patch("crmsh.corosync.get_value")
@mock.patch("crmsh.corosync.is_qdevice_configured")
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


@mock.patch('crmsh.utils.user_pair_for_ssh')
@mock.patch("crmsh.parallax.parallax_call")
@mock.patch("crmsh.corosync.get_value")
@mock.patch("crmsh.corosync.is_qdevice_configured")
def test_query_qnetd_status_copy_id_failed(mock_qdevice_configured,
        mock_get_value, mock_parallax_call, mock_user_pair_for_ssh):
    mock_user_pair_for_ssh.return_value = "alice", "root"
    mock_parallax_call.side_effect = ValueError("Failed on 10.10.10.123: foo")
    mock_qdevice_configured.return_value = True
    mock_get_value.side_effect = ["hacluster", "10.10.10.123"]
    with pytest.raises(ValueError) as err:
        corosync.query_qnetd_status()
    assert err.value.args[0] == "Failed on 10.10.10.123: foo"
    mock_qdevice_configured.assert_called_once_with()
    mock_get_value.assert_has_calls([
        mock.call("totem.cluster_name"),
        mock.call("quorum.device.net.host")
        ])


@mock.patch('crmsh.utils.user_pair_for_ssh')
@mock.patch("crmsh.utils.print_cluster_nodes")
@mock.patch("crmsh.parallax.parallax_call")
@mock.patch("crmsh.corosync.get_value")
@mock.patch("crmsh.corosync.is_qdevice_configured")
def test_query_qnetd_status_copy(mock_qdevice_configured, mock_get_value,
        mock_parallax_call, mock_print_nodes,
        mock_user_pair_for_ssh):
    mock_user_pair_for_ssh.return_value = "alice", "root"
    mock_qdevice_configured.return_value = True
    mock_get_value.side_effect = ["hacluster", "10.10.10.123"]
    mock_parallax_call.return_value = [("node1", (0, "data", None)), ]

    corosync.query_qnetd_status()

    mock_qdevice_configured.assert_called_once_with()
    mock_get_value.assert_has_calls([
        mock.call("totem.cluster_name"),
        mock.call("quorum.device.net.host")
        ])
    mock_parallax_call.assert_called_once_with(["10.10.10.123"], "corosync-qnetd-tool -lv -c hacluster")
    mock_print_nodes.assert_called_once_with()


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
@mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
def test_get_corosync_value_raise(mock_run, mock_get_value):
    mock_run.side_effect = ValueError
    mock_get_value.return_value = None
    assert corosync.get_corosync_value("xxx") is None
    mock_run.assert_called_once_with("corosync-cmapctl xxx")
    mock_get_value.assert_called_once_with("xxx")


@mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
def test_get_corosync_value(mock_run):
    mock_run.return_value = "totem.token = 10000"
    assert corosync.get_corosync_value("totem.token") == "10000"
    mock_run.assert_called_once_with("corosync-cmapctl totem.token")


if __name__ == '__main__':
    unittest.main()
