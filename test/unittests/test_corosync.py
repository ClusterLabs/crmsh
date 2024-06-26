# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.
#
# unit tests for parse.py

import copy
import unittest
import pytest
from unittest import mock
from crmsh import corosync


def test_query_status_exception():
    with pytest.raises(ValueError) as err:
        corosync.query_status("test")
    assert str(err.value) == "Wrong type \"test\" to query status"


@mock.patch('crmsh.sh.cluster_shell')
@mock.patch('crmsh.corosync.query_ring_status')
def test_query_status(mock_ring_status, mock_cluster_shell):
    mock_cluster_shell_inst = mock.Mock()
    mock_cluster_shell.return_value = mock_cluster_shell_inst
    mock_cluster_shell_inst.get_stdout_or_raise_error.return_value = "data"
    corosync.query_status("ring")
    mock_ring_status.assert_called_once_with()


@mock.patch('crmsh.corosync.is_qdevice_configured')
def test_query_qdevice_status_exception(mock_configured):
    mock_configured.return_value = False
    with pytest.raises(ValueError) as err:
        corosync.query_qdevice_status()
    assert str(err.value) == "QDevice/QNetd not configured!"
    mock_configured.assert_called_once_with()


@mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
@mock.patch('crmsh.corosync.is_qdevice_configured')
def test_query_qdevice_status(mock_configured, mock_run):
    mock_configured.return_value = True
    corosync.query_qdevice_status()
    mock_run.assert_called_once_with("corosync-qdevice-tool -sv")


@mock.patch('crmsh.sh.cluster_shell')
@mock.patch("crmsh.corosync.query_ring_status")
def test_query_status_ring(mock_ring_status, mock_cluster_shell):
    mock_cluster_shell_inst = mock.Mock()
    mock_cluster_shell.return_value = mock_cluster_shell_inst
    mock_cluster_shell_inst.get_stdout_or_raise_error.return_value = "data"
    corosync.query_status("ring")
    mock_ring_status.assert_called_once_with()


@mock.patch('crmsh.sh.cluster_shell')
@mock.patch("crmsh.corosync.query_quorum_status")
def test_query_status_quorum(mock_quorum_status, mock_cluster_shell):
    mock_cluster_shell_inst = mock.Mock()
    mock_cluster_shell.return_value = mock_cluster_shell_inst
    mock_cluster_shell_inst.get_stdout_or_raise_error.return_value = "data"
    corosync.query_status("quorum")
    mock_quorum_status.assert_called_once_with()


@mock.patch('crmsh.sh.cluster_shell')
@mock.patch("crmsh.corosync.query_qnetd_status")
def test_query_status_qnetd(mock_qnetd_status, mock_cluster_shell):
    mock_cluster_shell_inst = mock.Mock()
    mock_cluster_shell.return_value = mock_cluster_shell_inst
    mock_cluster_shell_inst.get_stdout_or_raise_error.return_value = "data"
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


@mock.patch("crmsh.sh.ShellUtils.get_stdout_stderr")
def test_query_quorum_status_except(mock_run):
    mock_run.return_value = (1, None, "error")
    with pytest.raises(ValueError) as err:
        corosync.query_quorum_status()
    assert str(err.value) == "error"
    mock_run.assert_called_once_with("corosync-quorumtool -s")


@mock.patch("crmsh.sh.ShellUtils.get_stdout_stderr")
def test_query_quorum_status(mock_run):
    mock_run.return_value = (0, "data", None)
    corosync.query_quorum_status()
    mock_run.assert_called_once_with("corosync-quorumtool -s")


@mock.patch("crmsh.sh.ShellUtils.get_stdout_stderr")
def test_query_quorum_status_no_quorum(mock_run):
    mock_run.return_value = (2, "no quorum", None)
    corosync.query_quorum_status()
    mock_run.assert_called_once_with("corosync-quorumtool -s")


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
@mock.patch("crmsh.parallax.parallax_call")
@mock.patch("crmsh.corosync.get_value")
@mock.patch("crmsh.corosync.is_qdevice_configured")
def test_query_qnetd_status_copy(mock_qdevice_configured, mock_get_value,
        mock_parallax_call, mock_user_pair_for_ssh):
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


class TestConfigParserSet(unittest.TestCase):
    def setUp(self) -> None:
        self.inst = corosync.ConfParser(config_data='')

    def test_set_scalar_should_ignore_index(self):
        self.inst._raw_set('scalar.scalar', 'foo', 0)
        self.assertDictEqual({'scalar': {'scalar': 'foo'}}, self.inst._dom)
        self.inst._raw_set('scalar.scalar', 'bar', 1)
        self.assertDictEqual({'scalar': {'scalar': 'bar'}}, self.inst._dom)

    def test_set_vector(self):
        self.inst._dom = {'vector': []}
        self.inst._raw_set('vector.scalar', 'foo', 0)
        self.assertDictEqual({'vector': [{'scalar': 'foo'}]}, self.inst._dom)
        self.inst._raw_set('vector.scalar', 'bar', 1)
        self.assertDictEqual({'vector': [{'scalar': 'foo'}, {'scalar': 'bar'}]}, self.inst._dom)
        with self.assertRaises(IndexError):
            self.inst._raw_set('vector.scalar', 'bar', 3)

    def test_set_predefined_vector(self):
        self.inst._raw_set('totem.interface.foo', 0, 0)
        self.assertDictEqual({'totem': {'interface': {'foo': 0}}}, self.inst._dom)
        self.inst._raw_set('totem.interface.foo', 0, 1)
        self.assertDictEqual({'totem': {'interface': [{'foo': 0}, {'foo': 0}]}}, self.inst._dom)
        with self.assertRaises(IndexError):
            self.inst._raw_set('totem.interface.foo', 0, 3)


class TestLinkLoadOptions(unittest.TestCase):
    def test_load_int(self):
        link = corosync.Link()
        link.load_options({'mcastport': '1234'})
        self.assertEqual(1234, link.mcastport)
        self.assertIsNone(link.knet_link_priority)
        self.assertIsNone(link.knet_transport)

    def test_load_int_invalid(self):
        link = corosync.Link()
        with self.assertRaises(ValueError):
            link.load_options({'mcastport': 'sctp'})

    def test_load_str(self):
        link = corosync.Link()
        link.load_options({'knet_transport': 'sctp'})
        self.assertIsNone(link.mcastport)
        self.assertIsNone(link.knet_link_priority)
        self.assertEqual('sctp', link.knet_transport)


class TestLinkManagerGetTotemTransport(unittest.TestCase):
    def test_get_value_from_config(self):
        lm = corosync.LinkManager({'totem': {'transport': 'udpu'}})
        self.assertEqual('udpu', lm.totem_transport())

    def test_get_value_from_default(self):
        lm = corosync.LinkManager({'totem': {'foo': 'bar'}})
        self.assertEqual('knet', lm.totem_transport())


class TestLinkManagerShowLinks(unittest.TestCase):
    def test_non_knet(self):
        lm = corosync.LinkManager({'totem': {'transport': 'udpu'}})
        with self.assertRaises(AssertionError):
            lm.links()

    def test_link_without_options(self):
        lm = corosync.LinkManager({
            'totem': {
                'interface': [{
                    'linknumber': '0',
                    'knet_link_priority': '1',
                }, {
                    'linknumber': '2',
                    'knet_link_priority': '10',
                    'knet_transport': 'sctp',
                }]
            },
            'nodelist': {
                'node': [{
                    'nodeid': '1',
                    'name': 'node1',
                    'ring0_addr': '192.0.2.1',
                    'ring1_addr': '192.0.2.101',
                    'ring2_addr': '192.0.2.201',
                }, {
                    'nodeid': '3',
                    'name': 'node3',
                    'ring0_addr': '192.0.2.3',
                    'ring1_addr': '192.0.2.103',
                    'ring2_addr': '192.0.2.203',
                }, {
                    'nodeid': '2',
                    'name': 'node2',
                    'ring0_addr': '192.0.2.3',
                    'ring1_addr': '192.0.2.102',
                    'ring2_addr': '192.0.2.202',
                }]
            }
        })
        links = lm.links()
        self.assertEqual(3, len(links))
        self.assertEqual(1, links[1].linknumber)
        self.assertEqual(3, len(links[1].nodes))
        self.assertEqual(1, links[1].nodes[0].nodeid)
        self.assertEqual(2, links[1].nodes[1].nodeid)
        self.assertEqual(3, links[1].nodes[2].nodeid)
        self.assertEqual(1, links[0].knet_link_priority)
        self.assertIsNone(links[1].knet_link_priority)
        self.assertEqual(10, links[2].knet_link_priority)
        self.assertEqual('sctp', links[2].knet_transport)

    def test_only_one_node(self):
        lm = corosync.LinkManager({
            'nodelist': {
                'node': [{
                    'nodeid': '1',
                    'name': 'node1',
                    'ring0_addr': '192.0.2.1',
                }]
            }
        })
        links = lm.links()
        self.assertEqual(1, len(links))
        self.assertEqual(0, links[0].linknumber)
        self.assertEqual(1, len(links[0].nodes))
        self.assertEqual(1, links[0].nodes[0].nodeid)
        self.assertIsNone(links[0].knet_link_priority)


class TestLinkManagerUpdateLink(unittest.TestCase):
    ORIGINAL = {
        'totem': {
            'interface': [{
                'linknumber': '0',
                'knet_link_priority': '1',
            }, {
                'linknumber': '2',
                'knet_link_priority': '10',
                'knet_transport': 'sctp',
            }]
        },
        'nodelist': {
            'node': [{
                'nodeid': '1',
                'name': 'node1',
                'ring0_addr': '192.0.2.1',
                'ring1_addr': '192.0.2.101',
                'ring2_addr': '192.0.2.201',
            }, {
                'nodeid': '3',
                'name': 'node3',
                'ring0_addr': '192.0.2.3',
                'ring1_addr': '192.0.2.103',
                'ring2_addr': '192.0.2.203',
            }, {
                'nodeid': '2',
                'name': 'node2',
                'ring0_addr': '192.0.2.3',
                'ring1_addr': '192.0.2.102',
                'ring2_addr': '192.0.2.202',
            }]
        }
    }

    def setUp(self):
        self.lm = corosync.LinkManager(copy.deepcopy(self.ORIGINAL))

    def test_update_and_add_new_option(self):
        dom = self.lm.update_link(0, {'knet_transport': 'sctp', 'knet_link_priority': '2'})
        self.assertEqual(2, len(dom['totem']['interface']))
        self.assertDictEqual({
            'linknumber': '0',
            'knet_link_priority': '2',
            'knet_transport': 'sctp'
        }, dom['totem']['interface'][0])
        self.assertDictEqual(self.ORIGINAL['totem']['interface'][1], dom['totem']['interface'][1])
        self.assertDictEqual(self.ORIGINAL['nodelist'], dom['nodelist'])

    def test_add_new_interface_section(self):
        dom = self.lm.update_link(1, {'knet_link_priority': '2'})
        self.assertEqual(3, len(dom['totem']['interface']))
        self.assertDictEqual({
            'linknumber': '1',
            'knet_link_priority': '2',
        }, dom['totem']['interface'][2])
        self.assertDictEqual(self.ORIGINAL['totem']['interface'][0], dom['totem']['interface'][0])
        self.assertDictEqual(self.ORIGINAL['totem']['interface'][1], dom['totem']['interface'][1])
        self.assertDictEqual(self.ORIGINAL['nodelist'], dom['nodelist'])

    def test_remove_option(self):
        dom = self.lm.update_link(2, {'knet_transport': None})
        self.assertEqual(2, len(dom['totem']['interface']))
        self.assertEqual('2', dom['totem']['interface'][1]['linknumber'])
        self.assertNotIn('knet_transport', dom['totem']['interface'][1])
        self.assertDictEqual(self.ORIGINAL['nodelist'], dom['nodelist'])

    def test_remove_interface_section(self):
        dom = self.lm.update_link(0, {'knet_link_priority': None})
        self.assertEqual(1, len(dom['totem']['interface']))
        self.assertEqual('2', dom['totem']['interface'][0]['linknumber'])
        self.assertDictEqual(self.ORIGINAL['nodelist'], dom['nodelist'])

    def test_add_non_unsupported_option(self):
        with self.assertRaises(ValueError):
            self.lm.update_link(0, {'knet_link_priority': '2', 'foo': 'bar'})
        self.assertDictEqual({
            'linknumber': '0',
            'knet_link_priority': '1',
        }, self.lm._config['totem']['interface'][0])
        with self.assertRaises(ValueError):
            self.lm.update_link(0, {'linknumber': '1'})
        with self.assertRaises(ValueError):
            self.lm.update_link(0, {'nodes': [{'foo': 'bar'}]})

    def test_remove_non_unsupported_option(self):
        with self.assertRaises(ValueError):
            self.lm.update_link(0, {'knet_link_priority': '2', 'foo': None})
        self.assertDictEqual({
            'linknumber': '0',
            'knet_link_priority': '1',
        }, self.lm._config['totem']['interface'][0])
        with self.assertRaises(ValueError):
            self.lm.update_link(0, {'linknumber': None})
        with self.assertRaises(ValueError):
            self.lm.update_link(0, {'nodes': None})

    def test_update_non_existing_link(self):
        with self.assertRaises(ValueError):
            self.lm.update_link(3, dict())


class TestLinkManagerUpdateNodeAddr(unittest.TestCase):
    ORIGINAL = {
        'nodelist': {
            'node': [{
                'nodeid': '1',
                'name': 'node1',
                'ring0_addr': '192.0.2.1',
                'ring1_addr': '192.0.2.101',
                'ring2_addr': '192.0.2.201',
            }, {
                'nodeid': '3',
                'name': 'node3',
                'ring0_addr': '192.0.2.3',
                'ring1_addr': '192.0.2.103',
                'ring2_addr': '192.0.2.203',
            }, {
                'nodeid': '2',
                'name': 'node2',
                'ring0_addr': '192.0.2.3',
                'ring1_addr': '192.0.2.102',
                'ring2_addr': '192.0.2.202',
            }]
        }
    }

    def setUp(self):
        self.lm = corosync.LinkManager(copy.deepcopy(self.ORIGINAL))

    def test_update_addr(self):
        self.lm.update_node_addr(
            1,
            {
                1: "192.0.2.65",
                2: "192.0.2.66",
                3: "192.0.2.67",
            }
        )
        self.assertEqual('1', self.lm._config['nodelist']['node'][0]['nodeid'])
        self.assertEqual('3', self.lm._config['nodelist']['node'][1]['nodeid'])
        self.assertEqual('2', self.lm._config['nodelist']['node'][2]['nodeid'])
        self.assertEqual('192.0.2.65', self.lm._config['nodelist']['node'][0]['ring1_addr'])
        self.assertEqual('192.0.2.67', self.lm._config['nodelist']['node'][1]['ring1_addr'])
        self.assertEqual('192.0.2.66', self.lm._config['nodelist']['node'][2]['ring1_addr'])

    def test_update_unknown_node(self):
        with self.assertRaises(ValueError):
            self.lm.update_node_addr(
                1,
                {
                    1: "192.0.2.65",
                    4: "192.0.2.66",
                }
            )
        self.assertEqual('1', self.lm._config['nodelist']['node'][0]['nodeid'])
        self.assertEqual('192.0.2.101', self.lm._config['nodelist']['node'][0]['ring1_addr'])

    def test_update_unknown_link(self):
        with self.assertRaises(ValueError):
            self.lm.update_node_addr(
                3,
                {
                    1: "192.0.2.65",
                    2: "192.0.2.66",
                    3: "192.0.2.67",
                }
            )
        self.assertDictEqual(self.ORIGINAL, self.lm._config)


class TestLinkManagerRemoveLink(unittest.TestCase):
    ORIGINAL = {
        'totem': {
            'interface': [{
                'linknumber': '0',
                'knet_link_priority': '1',
            }, {
                'linknumber': '2',
                'knet_link_priority': '10',
                'knet_transport': 'sctp',
            }]
        },
        'nodelist': {
            'node': [{
                'nodeid': '1',
                'name': 'node1',
                'ring0_addr': '192.0.2.1',
                'ring1_addr': '192.0.2.101',
                'ring2_addr': '192.0.2.201',
            }, {
                'nodeid': '3',
                'name': 'node3',
                'ring0_addr': '192.0.2.3',
                'ring1_addr': '192.0.2.103',
                'ring2_addr': '192.0.2.203',
            }, {
                'nodeid': '2',
                'name': 'node2',
                'ring0_addr': '192.0.2.3',
                'ring1_addr': '192.0.2.102',
                'ring2_addr': '192.0.2.202',
            }]
        }
    }

    def setUp(self):
        self.lm = corosync.LinkManager(copy.deepcopy(self.ORIGINAL))

    def test_remove(self):
        self.lm.remove_link(1)
        self.assertEqual(2, len(self.lm._config['totem']['interface']))
        self.assertEqual('0', self.lm._config['totem']['interface'][0]['linknumber'])
        self.assertEqual('1', self.lm._config['totem']['interface'][1]['linknumber'])
        self.assertEqual(3, len(self.lm._config['nodelist']['node']))
        self.assertNotIn('ring2_addr', self.lm._config['nodelist']['node'][0])
        self.assertNotIn('ring2_addr', self.lm._config['nodelist']['node'][1])
        self.assertNotIn('ring2_addr', self.lm._config['nodelist']['node'][2])
        self.assertEqual('192.0.2.201', self.lm._config['nodelist']['node'][0]['ring1_addr'])
        self.assertEqual('192.0.2.203', self.lm._config['nodelist']['node'][1]['ring1_addr'])
        self.assertEqual('192.0.2.202', self.lm._config['nodelist']['node'][2]['ring1_addr'])

    def test_remove_unknown_link(self):
        with self.assertRaises(ValueError):
            self.lm.remove_link(3)

    def test_remove_last_link(self):
        self.lm.remove_link(1)
        self.lm.remove_link(1)
        self.assertEqual(1, len(self.lm._config['totem']['interface']))
        self.assertNotIn('ring1_addr', self.lm._config['nodelist']['node'][0])
        self.assertNotIn('ring1_addr', self.lm._config['nodelist']['node'][1])
        self.assertNotIn('ring1_addr', self.lm._config['nodelist']['node'][2])
        with self.assertRaises(ValueError):
            self.lm.remove_link(0)


@mock.patch('crmsh.corosync.LinkManager.update_link')
@mock.patch('crmsh.corosync.LinkManager._LinkManager__upsert_node_addr_impl')
@mock.patch('crmsh.corosync.LinkManager.links')
class TestLinkManagerAddLink(unittest.TestCase):
    def test_unspecified_node(self, mock_links, mock_upsert_node, mock_update_link):
        mock_links.return_value = [corosync.Link(0, [
            corosync.LinkNode(1, 'node1', '192.0.2.101'),
            corosync.LinkNode(2, 'node2', '192.0.2.102'),
        ])]
        lm = corosync.LinkManager(dict())
        with self.assertRaises(ValueError):
            lm.add_link({1: '192.0.2.201'}, dict())
        mock_upsert_node.assert_not_called()
        mock_update_link.assert_not_called()

    def test_unknown_node(self, mock_links, mock_upsert_node, mock_update_link):
        mock_links.return_value = [corosync.Link(0, [
            corosync.LinkNode(1, 'node1', '192.0.2.101'),
        ])]
        mock_upsert_node.side_effect = ValueError()
        lm = corosync.LinkManager(dict())
        with self.assertRaises(ValueError):
            lm.add_link({1: '192.0.2.201', 2: '192.0.2.202'}, dict())
        mock_upsert_node.assert_called_once()
        mock_update_link.assert_not_called()


if __name__ == '__main__':
    unittest.main()
