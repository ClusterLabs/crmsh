# Copyright (C) 2026 Nicholas <nicholas@example.com>
# See COPYING for license information.
#
# unit tests for corosync_healthcheck.py

import subprocess
import unittest
from unittest import mock
from crmsh import corosync_healthcheck


class TestParseQuorumStatus(unittest.TestCase):
    def setUp(self):
        self.valid_output = """Quorum information
------------------
Date:             Fri Jun 26 13:44:28 2026
Quorum provider:  corosync_votequorum
Nodes:            2
Node ID:          1
Ring ID:          1.e
Quorate:          Yes

Votequorum information
----------------------
Expected votes:   3
Highest expected: 3
Total votes:      3
Quorum:           2  
Flags:            Quorate Qdevice 

Membership information
----------------------
    Nodeid      Votes    Qdevice Name
         1          1    A,V,NMW ha-3-1 (local)
         2          1    A,V,NMW ha-3-2
         0          1            Qdevice"""

        self.not_quorate_output = """Quorum information
------------------
Date:             Fri Jun 26 13:44:28 2026
Quorum provider:  corosync_votequorum
Nodes:            2
Node ID:          1
Ring ID:          1.e
Quorate:          No

Votequorum information
----------------------
Expected votes:   3
Highest expected: 3
Total votes:      1
Quorum:           2  
Flags:            Qdevice 

Membership information
----------------------
    Nodeid      Votes    Qdevice Name
         1          1    A,V,NMW ha-3-1 (local)
         0          0            Qdevice"""

        self.blocked_output = """Quorum information
------------------
Date:             Fri Jun 26 13:44:28 2026
Quorum provider:  corosync_votequorum
Nodes:            2
Node ID:          1
Ring ID:          1.e
Quorate:          No

Votequorum information
----------------------
Expected votes:   3
Highest expected: 3
Total votes:      2
Quorum:           2 Activity blocked
Flags:            Qdevice 

Membership information
----------------------
    Nodeid      Votes    Qdevice Name
         1          1    A,V,NMW ha-3-1 (local)
         0          1            Qdevice"""

    def test_parse_quorum_status_success(self):
        info = corosync_healthcheck._parse_quorum_status(self.valid_output)
        self.assertEqual(info.expected_votes, 3)
        self.assertEqual(info.total_votes, 3)
        self.assertEqual(info.quorum, 2)
        self.assertTrue(info.quorate)

    def test_parse_quorum_status_not_quorate(self):
        info = corosync_healthcheck._parse_quorum_status(self.not_quorate_output)
        self.assertEqual(info.expected_votes, 3)
        self.assertEqual(info.total_votes, 1)
        self.assertEqual(info.quorum, 2)
        self.assertFalse(info.quorate)

    def test_parse_quorum_status_activity_blocked(self):
        info = corosync_healthcheck._parse_quorum_status(self.blocked_output)
        self.assertEqual(info.expected_votes, 3)
        self.assertEqual(info.total_votes, 2)
        self.assertEqual(info.quorum, 2)
        self.assertFalse(info.quorate)

    def test_parse_quorum_status_missing_expected_votes(self):
        output = """Votequorum information
----------------------
Highest expected: 3
Total votes:      3
Quorum:           2
Flags:            Quorate"""
        with self.assertRaises(ValueError) as excinfo:
            corosync_healthcheck._parse_quorum_status(output)
        self.assertIn("Missing 'Expected votes'", str(excinfo.exception))

    def test_parse_quorum_status_missing_total_votes(self):
        output = """Votequorum information
----------------------
Expected votes:   3
Highest expected: 3
Quorum:           2
Flags:            Quorate"""
        with self.assertRaises(ValueError) as excinfo:
            corosync_healthcheck._parse_quorum_status(output)
        self.assertIn("Missing 'Total votes'", str(excinfo.exception))

    def test_parse_quorum_status_missing_quorum(self):
        output = """Votequorum information
----------------------
Expected votes:   3
Highest expected: 3
Total votes:      3
Flags:            Quorate"""
        with self.assertRaises(ValueError) as excinfo:
            corosync_healthcheck._parse_quorum_status(output)
        self.assertIn("Missing 'Quorum'", str(excinfo.exception))

    def test_parse_quorum_status_missing_flags(self):
        output = """Votequorum information
----------------------
Expected votes:   3
Highest expected: 3
Total votes:      3
Quorum:           2"""
        with self.assertRaises(ValueError) as excinfo:
            corosync_healthcheck._parse_quorum_status(output)
        self.assertIn("Missing 'Flags'", str(excinfo.exception))

    def test_parse_quorum_status_invalid_int(self):
        output = """Votequorum information
----------------------
Expected votes:   three
Highest expected: 3
Total votes:      3
Quorum:           2
Flags:            Quorate"""
        with self.assertRaises(ValueError):
            corosync_healthcheck._parse_quorum_status(output)


class TestCheckQuorumStatus(unittest.TestCase):
    @mock.patch("subprocess.run")
    @mock.patch("crmsh.corosync_healthcheck._parse_quorum_status")
    def test_check_quorum_status_success(self, mock_parse, mock_run):
        mock_proc = mock.MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = b"some raw stdout"
        mock_run.return_value = mock_proc

        mock_info = mock.MagicMock()
        mock_info.expected_votes = 3
        mock_info.total_votes = 3
        mock_info.quorum = 2
        mock_info.quorate = True
        mock_parse.return_value = mock_info

        result = corosync_healthcheck.check_quorum_status("ha-3-1")
        self.assertEqual(result.check_name, "Check Quorum Status")
        self.assertEqual(result.returncode, 0)
        self.assertIsNone(result.result_description)
        self.assertIsNone(result.recommended_action)
        mock_parse.assert_called_once_with("some raw stdout")

    @mock.patch("subprocess.run")
    @mock.patch("crmsh.corosync_healthcheck._parse_quorum_status")
    def test_check_quorum_status_not_quorate(self, mock_parse, mock_run):
        mock_proc = mock.MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = b"some raw stdout"
        mock_run.return_value = mock_proc

        mock_info = mock.MagicMock()
        mock_info.expected_votes = 3
        mock_info.total_votes = 1
        mock_info.quorum = 2
        mock_info.quorate = False
        mock_parse.return_value = mock_info

        result = corosync_healthcheck.check_quorum_status("ha-3-1")
        self.assertEqual(result.check_name, "Check Quorum Status")
        self.assertEqual(result.returncode, 1)
        self.assertIn("The cluster is not quorate", result.result_description)
        self.assertEqual(result.recommended_action, "Ensure that enough nodes are online and connected to form a quorum.")
        mock_parse.assert_called_once_with("some raw stdout")

    @mock.patch("subprocess.run")
    @mock.patch("crmsh.corosync_healthcheck._parse_quorum_status")
    def test_check_quorum_status_votes_less_than_expected(self, mock_parse, mock_run):
        mock_proc = mock.MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = b"some raw stdout"
        mock_run.return_value = mock_proc

        mock_info = mock.MagicMock()
        mock_info.expected_votes = 3
        mock_info.total_votes = 2
        mock_info.quorum = 2
        mock_info.quorate = True
        mock_parse.return_value = mock_info

        result = corosync_healthcheck.check_quorum_status("ha-3-1")
        self.assertEqual(result.check_name, "Check Quorum Status")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.result_description, "Total votes (2) is less than expected votes (3).")
        self.assertEqual(result.recommended_action, "Check that all expected cluster nodes are online and connected.")
        mock_parse.assert_called_once_with("some raw stdout")

    @mock.patch("subprocess.run")
    def test_check_quorum_status_command_failure(self, mock_run):
        mock_proc = mock.MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = b"corosync-quorumtool: cannot connect to corosync"
        mock_run.return_value = mock_proc

        result = corosync_healthcheck.check_quorum_status("ha-3-1")
        self.assertEqual(result.check_name, "Check Quorum Status")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.result_description, "corosync-quorumtool: cannot connect to corosync")
        self.assertEqual(result.recommended_action, "Check if the corosync service is running.")

    @mock.patch("subprocess.run")
    @mock.patch("crmsh.corosync_healthcheck._parse_quorum_status")
    def test_check_quorum_status_parse_failure(self, mock_parse, mock_run):
        mock_proc = mock.MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = b"some raw stdout"
        mock_run.return_value = mock_proc

        mock_parse.side_effect = ValueError("Missing 'Expected votes' in quorum status output")

        result = corosync_healthcheck.check_quorum_status("ha-3-1")
        self.assertEqual(result.check_name, "Check Quorum Status")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Failed to parse 'corosync-quorumtool -s' output", result.result_description)
        mock_parse.assert_called_once_with("some raw stdout")


class TestCheckNodeIDToNodeNameMapping(unittest.TestCase):
    def setUp(self):
        self.local_node = "node1"
        self.valid_cib_xml = """<cib>
  <configuration>
    <nodes>
      <node id="1" uname="node1"/>
      <node id="2" uname="node2"/>
    </nodes>
  </configuration>
</cib>"""

    @mock.patch("crmsh.sh.ShellUtils.get_stdout_stderr")
    def test_success(self, mock_get):
        mock_get.return_value = (0, self.valid_cib_xml, "")
        mock_lm = mock.MagicMock()
        mock_lm._config = {
            "nodelist": {
                "node": [
                    {"nodeid": "1", "name": "node1"},
                    {"nodeid": "2", "name": "node2"}
                ]
            }
        }

        result = corosync_healthcheck.check_nodeid_to_nodename_mapping(self.local_node, mock_lm)
        self.assertEqual(result.check_name, "Check Node ID to Node Name Mapping")
        self.assertEqual(result.returncode, 0)
        self.assertIsNone(result.result_description)

    @mock.patch("crmsh.sh.ShellUtils.get_stdout_stderr")
    def test_cib_load_failure(self, mock_get):
        mock_get.return_value = (1, "", "cibadmin not found")
        mock_lm = mock.MagicMock()

        result = corosync_healthcheck.check_nodeid_to_nodename_mapping(self.local_node, mock_lm)
        self.assertEqual(result.check_name, "Check Node ID to Node Name Mapping")
        self.assertEqual(result.returncode, 255)
        self.assertIn("Failed to load CIB: cibadmin not found", result.result_description)

    @mock.patch("crmsh.sh.ShellUtils.get_stdout_stderr")
    def test_cib_parse_failure(self, mock_get):
        mock_get.return_value = (0, "invalid xml", "")
        mock_lm = mock.MagicMock()

        result = corosync_healthcheck.check_nodeid_to_nodename_mapping(self.local_node, mock_lm)
        self.assertEqual(result.check_name, "Check Node ID to Node Name Mapping")
        self.assertEqual(result.returncode, 255)
        self.assertIn("Failed to parse CIB", result.result_description)

    @mock.patch("crmsh.sh.ShellUtils.get_stdout_stderr")
    def test_mismatch_missing_in_cib(self, mock_get):
        mock_get.return_value = (0, self.valid_cib_xml, "")
        mock_lm = mock.MagicMock()
        mock_lm._config = {
            "nodelist": {
                "node": [
                    {"nodeid": "1", "name": "node1"},
                    {"nodeid": "2", "name": "node2"},
                    {"nodeid": "3", "name": "node3"}
                ]
            }
        }

        result = corosync_healthcheck.check_nodeid_to_nodename_mapping(self.local_node, mock_lm)
        self.assertEqual(result.check_name, "Check Node ID to Node Name Mapping")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Node ID 3 with name 'node3' in corosync.conf is not found in CIB.", result.result_description)

    @mock.patch("crmsh.sh.ShellUtils.get_stdout_stderr")
    def test_mismatch_missing_in_corosync(self, mock_get):
        mock_get.return_value = (0, self.valid_cib_xml, "")
        mock_lm = mock.MagicMock()
        mock_lm._config = {
            "nodelist": {
                "node": [
                    {"nodeid": "1", "name": "node1"}
                ]
            }
        }

        result = corosync_healthcheck.check_nodeid_to_nodename_mapping(self.local_node, mock_lm)
        self.assertEqual(result.check_name, "Check Node ID to Node Name Mapping")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Node ID 2 with name 'node2' in CIB is not found in corosync.conf.", result.result_description)

    @mock.patch("crmsh.sh.ShellUtils.get_stdout_stderr")
    def test_mismatch_different_name(self, mock_get):
        mock_get.return_value = (0, self.valid_cib_xml, "")
        mock_lm = mock.MagicMock()
        mock_lm._config = {
            "nodelist": {
                "node": [
                    {"nodeid": "1", "name": "node1"},
                    {"nodeid": "2", "name": "node2-alt"}
                ]
            }
        }

        result = corosync_healthcheck.check_nodeid_to_nodename_mapping(self.local_node, mock_lm)
        self.assertEqual(result.check_name, "Check Node ID to Node Name Mapping")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Node ID 2 is associated with name 'node2-alt' in corosync.conf but 'node2' in CIB.", result.result_description)


class TestParseLinksStatus(unittest.TestCase):
    def test_parse_links_status_success_all_connected(self):
        output = """Local node ID 1, transport knet
LINK ID 0 udp
	addr	= 192.168.122.73
	status:
		nodeid:          1:	localhost
		nodeid:          2:	connected
LINK ID 1 udp
	addr	= 192.168.123.73
	status:
		nodeid:          1:	localhost
		nodeid:          2:	connected"""
        links = corosync_healthcheck._parse_links_status(output)
        self.assertEqual(links, {
            0: {1: "localhost", 2: "connected"},
            1: {1: "localhost", 2: "connected"}
        })

    def test_parse_links_status_success_some_disconnected(self):
        output = """Local node ID 1, transport knet
LINK ID 0 udp
	addr	= 192.168.122.73
	status:
		nodeid:          1:	localhost
		nodeid:          2:	disconnected
LINK ID 1 udp
	addr	= 192.168.123.73
	status:
		nodeid:          1:	localhost
		nodeid:          2:	disconnected"""
        links = corosync_healthcheck._parse_links_status(output)
        self.assertEqual(links, {
            0: {1: "localhost", 2: "disconnected"},
            1: {1: "localhost", 2: "disconnected"}
        })

    def test_parse_links_status_missing_link_id_before_nodeid(self):
        output = """		nodeid:          1:	localhost"""
        with self.assertRaises(ValueError) as excinfo:
            corosync_healthcheck._parse_links_status(output)
        self.assertIn("Found node ID status before any LINK ID section", str(excinfo.exception))

    def test_parse_links_status_no_links(self):
        output = """Local node ID 1, transport knet"""
        with self.assertRaises(ValueError) as excinfo:
            corosync_healthcheck._parse_links_status(output)
        self.assertIn("No corosync links found in output", str(excinfo.exception))


class TestCheckLinksStatus(unittest.TestCase):
    @mock.patch("subprocess.run")
    @mock.patch("crmsh.corosync_healthcheck._parse_links_status")
    def test_check_links_status_success(self, mock_parse, mock_run):
        mock_proc = mock.MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = b"some raw stdout"
        mock_run.return_value = mock_proc

        mock_parse.return_value = {
            0: {1: "localhost", 2: "connected"},
            1: {1: "localhost", 2: "connected"}
        }

        result = corosync_healthcheck.check_links_status("ha-3-1")
        self.assertEqual(result.check_name, "Check Corosync Links Status")
        self.assertEqual(result.returncode, 0)
        self.assertIsNone(result.result_description)
        self.assertIsNone(result.recommended_action)
        mock_parse.assert_called_once_with("some raw stdout")

    @mock.patch("subprocess.run")
    @mock.patch("crmsh.corosync_healthcheck._parse_links_status")
    def test_check_links_status_some_disconnected(self, mock_parse, mock_run):
        mock_proc = mock.MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = b"some raw stdout"
        mock_run.return_value = mock_proc

        mock_parse.return_value = {
            0: {1: "localhost", 2: "disconnected"},
            1: {1: "localhost", 2: "connected"}
        }

        result = corosync_healthcheck.check_links_status("ha-3-1")
        self.assertEqual(result.check_name, "Check Corosync Links Status")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Corosync link(s) are not operational", result.result_description)
        self.assertIn("Link 0 to node 2 has status 'disconnected'", result.result_description)
        self.assertEqual(result.recommended_action, "Check network connectivity and corosync configuration/service on the affected nodes.")
        mock_parse.assert_called_once_with("some raw stdout")

    @mock.patch("subprocess.run")
    def test_check_links_status_command_failure(self, mock_run):
        mock_proc = mock.MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = b"corosync-cfgtool: cannot connect to corosync"
        mock_run.return_value = mock_proc

        result = corosync_healthcheck.check_links_status("ha-3-1")
        self.assertEqual(result.check_name, "Check Corosync Links Status")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.result_description, "corosync-cfgtool: cannot connect to corosync")
        self.assertEqual(result.recommended_action, "Check if the corosync service is running.")

    @mock.patch("subprocess.run")
    @mock.patch("crmsh.corosync_healthcheck._parse_links_status")
    def test_check_links_status_parse_failure(self, mock_parse, mock_run):
        mock_proc = mock.MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = b"some raw stdout"
        mock_run.return_value = mock_proc

        mock_parse.side_effect = ValueError("No corosync links found in output")

        result = corosync_healthcheck.check_links_status("ha-3-1")
        self.assertEqual(result.check_name, "Check Corosync Links Status")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Failed to parse 'corosync-cfgtool -s' output", result.result_description)
        mock_parse.assert_called_once_with("some raw stdout")


class TestValidateConfigFileConsistency(unittest.TestCase):
    @mock.patch("crmsh.corosync.conf")
    @mock.patch("crmsh.prun.prun.prun")
    def test_validate_config_file_consistency_success(self, mock_prun, mock_conf):
        mock_conf.return_value = "/etc/corosync/corosync.conf"
        from crmsh.prun.prun import ProcessResult
        mock_prun.return_value = {
            "node1": ProcessResult(0, b"hash1  /etc/corosync/corosync.conf\n", b""),
            "node2": ProcessResult(0, b"hash1  /etc/corosync/corosync.conf\n", b"")
        }
        res = corosync_healthcheck.validate_config_file_consistency(["node1", "node2"])
        self.assertEqual(res.returncode, 0)
        self.assertIsNone(res.result_description)

    @mock.patch("crmsh.corosync.conf")
    @mock.patch("crmsh.prun.prun.prun")
    def test_validate_config_file_consistency_inconsistent(self, mock_prun, mock_conf):
        mock_conf.return_value = "/etc/corosync/corosync.conf"
        from crmsh.prun.prun import ProcessResult
        mock_prun.return_value = {
            "node1": ProcessResult(0, b"hash1  /etc/corosync/corosync.conf\n", b""),
            "node2": ProcessResult(0, b"hash2  /etc/corosync/corosync.conf\n", b"")
        }
        res = corosync_healthcheck.validate_config_file_consistency(["node1", "node2"])
        self.assertEqual(res.returncode, 1)
        self.assertIn("Corosync configuration file /etc/corosync/corosync.conf is inconsistent across nodes:", res.result_description)
        self.assertIn("  hash1  node1\n", res.result_description)
        self.assertIn("  hash2  node2\n", res.result_description)
        self.assertEqual(res.recommended_action, 'Run "crm corosync diff" to inspect the differences, and then "crm corosync push" to synchronize the configuration across cluster nodes.')

    @mock.patch("crmsh.corosync.conf")
    @mock.patch("crmsh.prun.prun.prun")
    def test_validate_config_file_consistency_ssh_error(self, mock_prun, mock_conf):
        mock_conf.return_value = "/etc/corosync/corosync.conf"
        from crmsh.prun.prun import SSHError
        mock_prun.return_value = {
            "node1": SSHError("root", "node1", "host unreachable")
        }
        res = corosync_healthcheck.validate_config_file_consistency(["node1"])
        self.assertEqual(res.returncode, 255)
        self.assertEqual(res.result_description, "ssh error")

    @mock.patch("crmsh.corosync.conf")
    @mock.patch("crmsh.prun.prun.prun")
    def test_validate_config_file_consistency_command_error(self, mock_prun, mock_conf):
        mock_conf.return_value = "/etc/corosync/corosync.conf"
        from crmsh.prun.prun import ProcessResult
        mock_prun.return_value = {
            "node1": ProcessResult(1, b"", b"sha256sum: error")
        }
        res = corosync_healthcheck.validate_config_file_consistency(["node1"])
        self.assertEqual(res.returncode, 1)
        self.assertEqual(res.result_description, "sha256sum error")


class TestValidateConfigFile(unittest.TestCase):
    @mock.patch("crmsh.sh.cluster_shell")
    def test_validate_config_file_success(self, mock_cluster_shell):
        mock_shell_inst = mock.Mock()
        mock_cluster_shell.return_value = mock_shell_inst
        mock_result = mock.Mock()
        mock_result.returncode = 0
        mock_result.stdout = b"success"
        mock_shell_inst.subprocess_run_without_input.return_value = mock_result

        result = corosync_healthcheck.validate_config_file("node1")
        self.assertEqual(result.check_name, "Validate Corosync Configuration File")
        self.assertEqual(result.returncode, 0)
        self.assertIsNone(result.result_description)
        self.assertIsNone(result.recommended_action)
        self.assertEqual(result.checked_nodes, ["node1"])
        mock_shell_inst.subprocess_run_without_input.assert_called_once_with(
            "node1", "root", "corosync -t",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
        )

    @mock.patch("crmsh.sh.cluster_shell")
    def test_validate_config_file_failure(self, mock_cluster_shell):
        mock_shell_inst = mock.Mock()
        mock_cluster_shell.return_value = mock_shell_inst
        mock_result = mock.Mock()
        mock_result.returncode = 1
        # Include an invalid UTF-8 byte to test 'replace' decoder option
        mock_result.stdout = b"error in config: \xff\n"
        mock_shell_inst.subprocess_run_without_input.return_value = mock_result

        result = corosync_healthcheck.validate_config_file("node1")
        self.assertEqual(result.check_name, "Validate Corosync Configuration File")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.result_description, "error in config: \ufffd")
        self.assertIsNone(result.recommended_action)
        self.assertEqual(result.checked_nodes, ["node1"])
        mock_shell_inst.subprocess_run_without_input.assert_called_once_with(
            "node1", "root", "corosync -t",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
        )


class TestCheckDeprecatedTransport(unittest.TestCase):
    def test_check_deprecated_transport_knet(self):
        mock_lm = mock.MagicMock()
        mock_lm.totem_transport.return_value = "knet"

        result = corosync_healthcheck.check_deprecated_transport("node1", mock_lm)
        self.assertEqual(result.check_name, "Check Deprecated Corosync Transport")
        self.assertEqual(result.returncode, 0)
        self.assertIsNone(result.result_description)
        self.assertIsNone(result.recommended_action)

    def test_check_deprecated_transport_non_knet(self):
        mock_lm = mock.MagicMock()
        mock_lm.totem_transport.return_value = "udp"

        result = corosync_healthcheck.check_deprecated_transport("node1", mock_lm)
        self.assertEqual(result.check_name, "Check Deprecated Corosync Transport")
        self.assertEqual(result.returncode, 2)
        self.assertIn('Corosync transport "udp" is deprecated. Please use knet.', result.result_description)
        self.assertEqual(result.recommended_action, "Upgrade corosync transport to knet.")


class TestCheckKnetLinkNetworkInterface(unittest.TestCase):
    def test_check_knet_link_network_interface_non_knet(self):
        mock_lm = mock.MagicMock()
        mock_lm.totem_transport.return_value = "udpu"

        result = corosync_healthcheck.check_knet_link_network_interface("node1", mock_lm)
        self.assertEqual(result.check_name, "Check Knet Link Network Interface")
        self.assertEqual(result.returncode, 0)
        self.assertIsNone(result.result_description)

    def test_check_knet_link_network_interface_one_link(self):
        mock_lm = mock.MagicMock()
        mock_lm.totem_transport.return_value = "knet"

        mock_link = mock.MagicMock()
        mock_link.linknumber = 0
        mock_node = mock.MagicMock()
        mock_node.name = "node1"
        mock_node.addr = "192.168.0.3"
        mock_link.nodes = [mock_node]

        mock_lm.links.return_value = [mock_link]

        result = corosync_healthcheck.check_knet_link_network_interface("node1", mock_lm)
        self.assertEqual(result.returncode, 0)
        self.assertIsNone(result.result_description)

    @mock.patch("crmsh.sh.LocalShell.get_stdout_or_raise_error")
    def test_check_knet_link_network_interface_success(self, mock_get_stdout):
        mock_lm = mock.MagicMock()
        mock_lm.totem_transport.return_value = "knet"

        mock_link1 = mock.MagicMock()
        mock_link1.linknumber = 0
        mock_node1 = mock.MagicMock()
        mock_node1.name = "node1"
        mock_node1.addr = "192.168.0.3"
        mock_link1.nodes = [mock_node1]

        mock_link2 = mock.MagicMock()
        mock_link2.linknumber = 1
        mock_node2 = mock.MagicMock()
        mock_node2.name = "node1"
        mock_node2.addr = "192.168.1.3"
        mock_link2.nodes = [mock_node2]

        mock_lm.links.return_value = [mock_link1, mock_link2]

        mock_get_stdout.return_value = """[
            {
                "ifname": "eth0",
                "flags": ["UP"],
                "addr_info": [
                    {
                        "local": "192.168.0.3",
                        "prefixlen": 24
                    }
                ]
            },
            {
                "ifname": "eth1",
                "flags": ["UP"],
                "addr_info": [
                    {
                        "local": "192.168.1.3",
                        "prefixlen": 24
                    }
                ]
            }
        ]"""

        result = corosync_healthcheck.check_knet_link_network_interface("node1", mock_lm)
        self.assertEqual(result.returncode, 0)
        self.assertIsNone(result.result_description)

    @mock.patch("crmsh.sh.LocalShell.get_stdout_or_raise_error")
    def test_check_knet_link_network_interface_conflict(self, mock_get_stdout):
        mock_lm = mock.MagicMock()
        mock_lm.totem_transport.return_value = "knet"

        mock_link1 = mock.MagicMock()
        mock_link1.linknumber = 0
        mock_node1 = mock.MagicMock()
        mock_node1.name = "node1"
        mock_node1.addr = "192.168.0.3"
        mock_link1.nodes = [mock_node1]

        mock_link2 = mock.MagicMock()
        mock_link2.linknumber = 1
        mock_node2 = mock.MagicMock()
        mock_node2.name = "node1"
        mock_node2.addr = "192.168.0.4"
        mock_link2.nodes = [mock_node2]

        mock_lm.links.return_value = [mock_link1, mock_link2]

        mock_get_stdout.return_value = """[
            {
                "ifname": "eth0",
                "flags": ["UP"],
                "addr_info": [
                    {
                        "local": "192.168.0.3",
                        "prefixlen": 24
                    },
                    {
                        "local": "192.168.0.4",
                        "prefixlen": 24
                    }
                ]
            }
        ]"""

        result = corosync_healthcheck.check_knet_link_network_interface("node1", mock_lm)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Multiple knet links are configured on the same network interface:", result.result_description)
        self.assertIn("eth0", result.result_description)
        self.assertIn("0, 1", result.result_description)

    @mock.patch("crmsh.sh.LocalShell.get_stdout_or_raise_error")
    def test_check_knet_link_network_interface_conflict_different_subnets(self, mock_get_stdout):
        mock_lm = mock.MagicMock()
        mock_lm.totem_transport.return_value = "knet"

        mock_link1 = mock.MagicMock()
        mock_link1.linknumber = 0
        mock_node1 = mock.MagicMock()
        mock_node1.name = "node1"
        mock_node1.addr = "192.168.0.3"
        mock_link1.nodes = [mock_node1]

        mock_link2 = mock.MagicMock()
        mock_link2.linknumber = 1
        mock_node2 = mock.MagicMock()
        mock_node2.name = "node1"
        mock_node2.addr = "192.168.10.3"
        mock_link2.nodes = [mock_node2]

        mock_lm.links.return_value = [mock_link1, mock_link2]

        mock_get_stdout.return_value = """[
            {
                "ifname": "eth0",
                "flags": ["UP"],
                "addr_info": [
                    {
                        "local": "192.168.0.3",
                        "prefixlen": 24
                    },
                    {
                        "local": "192.168.10.3",
                        "prefixlen": 24
                    }
                ]
            }
        ]"""

        result = corosync_healthcheck.check_knet_link_network_interface("node1", mock_lm)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Multiple knet links are configured on the same network interface:", result.result_description)
        self.assertIn("eth0", result.result_description)
        self.assertIn("0, 1", result.result_description)

    @mock.patch("crmsh.sh.LocalShell.get_stdout_or_raise_error")
    def test_check_knet_link_network_interface_conflict_mixed_interfaces(self, mock_get_stdout):
        mock_lm = mock.MagicMock()
        mock_lm.totem_transport.return_value = "knet"

        mock_link1 = mock.MagicMock()
        mock_link1.linknumber = 0
        mock_node1 = mock.MagicMock()
        mock_node1.name = "node1"
        mock_node1.addr = "192.168.0.3"
        mock_link1.nodes = [mock_node1]

        mock_link2 = mock.MagicMock()
        mock_link2.linknumber = 1
        mock_node2 = mock.MagicMock()
        mock_node2.name = "node1"
        mock_node2.addr = "192.168.10.3"
        mock_link2.nodes = [mock_node2]

        mock_link3 = mock.MagicMock()
        mock_link3.linknumber = 2
        mock_node3 = mock.MagicMock()
        mock_node3.name = "node1"
        mock_node3.addr = "192.168.20.3"
        mock_link3.nodes = [mock_node3]

        mock_lm.links.return_value = [mock_link1, mock_link2, mock_link3]

        mock_get_stdout.return_value = """[
            {
                "ifname": "eth0",
                "flags": ["UP"],
                "addr_info": [
                    {
                        "local": "192.168.0.3",
                        "prefixlen": 24
                    },
                    {
                        "local": "192.168.10.3",
                        "prefixlen": 24
                    }
                ]
            },
            {
                "ifname": "eth1",
                "flags": ["UP"],
                "addr_info": [
                    {
                        "local": "192.168.20.3",
                        "prefixlen": 24
                    }
                ]
            }
        ]"""

        result = corosync_healthcheck.check_knet_link_network_interface("node1", mock_lm)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Multiple knet links are configured on the same network interface:", result.result_description)
        self.assertIn("eth0", result.result_description)
        self.assertIn("0, 1", result.result_description)
        self.assertNotIn("eth1", result.result_description)

    @mock.patch("crmsh.sh.LocalShell.get_stdout_or_raise_error")
    def test_check_knet_link_network_interface_shell_error(self, mock_get_stdout):
        mock_lm = mock.MagicMock()
        mock_lm.totem_transport.return_value = "knet"

        mock_link1 = mock.MagicMock()
        mock_link1.linknumber = 0
        mock_node1 = mock.MagicMock()
        mock_node1.name = "node1"
        mock_node1.addr = "192.168.0.3"
        mock_link1.nodes = [mock_node1]

        mock_link2 = mock.MagicMock()
        mock_link2.linknumber = 1
        mock_node2 = mock.MagicMock()
        mock_node2.name = "node1"
        mock_node2.addr = "192.168.1.3"
        mock_link2.nodes = [mock_node2]

        mock_lm.links.return_value = [mock_link1, mock_link2]

        mock_get_stdout.side_effect = ValueError("ip command not found")

        result = corosync_healthcheck.check_knet_link_network_interface("node1", mock_lm)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Failed to load local network interfaces", result.result_description)

    @mock.patch("crmsh.sh.LocalShell.get_stdout_or_raise_error")
    def test_check_knet_link_network_interface_other_node_ip(self, mock_get_stdout):
        # Even if the link configuration doesn't specify node1's IP or node1 is missing from node.addr,
        # we check the subnet using any node's IP configured on the link.
        mock_lm = mock.MagicMock()
        mock_lm.totem_transport.return_value = "knet"

        mock_link1 = mock.MagicMock()
        mock_link1.linknumber = 0
        mock_node_other1 = mock.MagicMock()
        mock_node_other1.name = "node2"
        mock_node_other1.addr = "192.168.0.4"
        mock_link1.nodes = [mock_node_other1]

        mock_link2 = mock.MagicMock()
        mock_link2.linknumber = 1
        mock_node_other2 = mock.MagicMock()
        mock_node_other2.name = "node2"
        mock_node_other2.addr = "192.168.1.4"
        mock_link2.nodes = [mock_node_other2]

        mock_lm.links.return_value = [mock_link1, mock_link2]

        mock_get_stdout.return_value = """[
            {
                "ifname": "eth0",
                "flags": ["UP"],
                "addr_info": [
                    {
                        "local": "192.168.0.3",
                        "prefixlen": 24
                    }
                ]
            },
            {
                "ifname": "eth1",
                "flags": ["UP"],
                "addr_info": [
                    {
                        "local": "192.168.1.3",
                        "prefixlen": 24
                    }
                ]
            }
        ]"""

        result = corosync_healthcheck.check_knet_link_network_interface("node1", mock_lm)
        self.assertEqual(result.returncode, 0)
        self.assertIsNone(result.result_description)

