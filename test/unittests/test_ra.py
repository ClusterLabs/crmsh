import unittest
from unittest import mock

from crmsh import ra, sh


class TestRAInfoSystemdMeta(unittest.TestCase):
    @mock.patch('crmsh.ra.ra_meta')
    @mock.patch('crmsh.ra.ra_types')
    @mock.patch('crmsh.cache.is_cached', return_value=False)
    def test_meta_unknown_unit(self, mock_is_cached, mock_types, mock_meta):
        mock_types.return_value = ["sshd"]
        mock_meta.return_value = ["<resource-agent name='unknown2'/>"]
        self.assertIsNone(ra.RAInfo("systemd", "unknown2").meta())
        mock_types.assert_called_once_with("systemd")
        mock_meta.assert_not_called()

    @mock.patch('crmsh.cache.store', side_effect=lambda sid, xml: xml)
    @mock.patch('crmsh.ra.ra_meta')
    @mock.patch('crmsh.ra.ra_types')
    @mock.patch('crmsh.cache.is_cached', return_value=False)
    def test_meta_known_unit(self, mock_is_cached, mock_types, mock_meta, mock_store):
        mock_types.return_value = ["sshd"]
        mock_meta.return_value = ["<resource-agent name='sshd'/>"]
        for unit in ("sshd", "sshd.service"):
            self.assertIsNotNone(ra.RAInfo("systemd", unit).meta())

    @mock.patch('crmsh.cache.store', side_effect=lambda sid, xml: xml)
    @mock.patch('crmsh.ra.ra_meta')
    @mock.patch('crmsh.ra.ra_types')
    @mock.patch('crmsh.cache.is_cached', return_value=False)
    def test_meta_instance_unit(self, mock_is_cached, mock_types, mock_meta, mock_store):
        mock_types.return_value = ["getty@"]
        mock_meta.return_value = ["<resource-agent name='getty@tty1'/>"]
        for unit in ("getty@tty1", "getty@tty1.service"):
            self.assertIsNotNone(ra.RAInfo("systemd", unit).meta())


class TestRAInfoMissingNodes(unittest.TestCase):
    @mock.patch('crmsh.sh.cluster_shell')
    @mock.patch('crmsh.utils.list_cluster_nodes_except_me')
    def test_unsupported_class(self, mock_nodes, mock_shell):
        self.assertEqual([], ra.RAInfo("lsb", "foo").missing_nodes())
        mock_nodes.assert_not_called()

    @mock.patch('crmsh.utils.list_cluster_nodes_except_me', side_effect=ValueError)
    def test_no_node_list(self, mock_nodes):
        self.assertEqual([], ra.RAInfo("systemd", "sshd").missing_nodes())

    @mock.patch('crmsh.sh.cluster_shell')
    @mock.patch('crmsh.utils.list_cluster_nodes_except_me', return_value=["node2", "node3", "node4"])
    def test_missing_nodes(self, mock_nodes, mock_shell):
        shell = mock_shell.return_value
        shell.get_rc_stdout_stderr_without_input.side_effect = [
            (0, "IPaddr2\nDummy", ""),
            (0, "Dummy", ""),
            (255, "", "ssh error"),
        ]
        self.assertEqual(["node3"], ra.RAInfo("ocf", "IPaddr2", "heartbeat").missing_nodes())
        shell.get_rc_stdout_stderr_without_input.assert_has_calls([
            mock.call("node2", "crm_resource --list-agents ocf:heartbeat"),
            mock.call("node3", "crm_resource --list-agents ocf:heartbeat"),
            mock.call("node4", "crm_resource --list-agents ocf:heartbeat"),
        ])

    @mock.patch('crmsh.sh.cluster_shell')
    @mock.patch('crmsh.utils.list_cluster_nodes_except_me', return_value=["node2", "node3"])
    def test_missing_systemd_and_stonith(self, mock_nodes, mock_shell):
        shell = mock_shell.return_value
        shell.get_rc_stdout_stderr_without_input.side_effect = [(0, "sshd", ""), (0, "chronyd", "")]
        self.assertEqual(["node3"], ra.RAInfo("systemd", "sshd.service").missing_nodes())
        shell.get_rc_stdout_stderr_without_input.side_effect = [(0, "fence_sbd", ""), (0, "fence_xvm", "")]
        self.assertEqual(["node3"], ra.RAInfo("stonith", "fence_sbd", None).missing_nodes())
        shell.get_rc_stdout_stderr_without_input.assert_called_with("node3", "crm_resource --list-agents stonith")

    @mock.patch('crmsh.sh.cluster_shell')
    @mock.patch('crmsh.utils.list_cluster_nodes_except_me', return_value=["node2", "node3"])
    def test_node_unreachable(self, mock_nodes, mock_shell):
        shell = mock_shell.return_value
        shell.get_rc_stdout_stderr_without_input.side_effect = [
            sh.NonInteractiveSSHAuthorizationError("cmd", "node2", "root", "refused"),
            (0, "Dummy", ""),
        ]
        self.assertEqual(["node3"], ra.RAInfo("ocf", "IPaddr2", "heartbeat").missing_nodes())
