import dataclasses
import functools
import ipaddress
import json
import logging
import re
import shlex
import subprocess
import typing

from io import StringIO

import lxml.etree

from . import corosync
from . import cibquery
from . import constants
from . import iproute2
from .prun import prun
from . import sh


logger = logging.getLogger(__name__)


@dataclasses.dataclass
class CheckResult:
    check_name: str
    checked_nodes: list[str]
    returncode: int
    result_description: typing.Optional[str]
    recommended_action: typing.Optional[str]


def validate_config_file_consistency(nodes: list[str]) -> CheckResult:
    assert nodes
    CHECK_NAME = 'Validate Corosync Configuration File Consistency'
    config_file_path = corosync.conf()
    result = prun.prun({node: f'sha256sum {shlex.quote(config_file_path)}' for node in nodes})
    ssh_errors = {k: v for k, v in result.items() if isinstance(v, prun.SSHError)}
    if ssh_errors:
        for node, error in ssh_errors.items():
            logger.error("%s", error)
        return CheckResult(
            CHECK_NAME,
            list(ssh_errors.keys()),
            255,
            "ssh error",
            None,
        )
    command_errors = {k: v for k, v in result.items() if v.returncode != 0}
    if command_errors:
        for node, process_result in command_errors.items():
            logger.error("%s: %s", node, process_result.stderr)
        return CheckResult(
            CHECK_NAME,
            list(command_errors.keys()),
            functools.reduce(lambda a, b: a | b, (v.returncode for v in command_errors.values())),
            "sha256sum error",
            None,
        )
    prev = None
    for x in result.values():
        if prev is None or x.stdout == prev:
            prev = x.stdout
        else:
            result_description = StringIO()
            result_description.write(f"Corosync configuration file {config_file_path} is inconsistent across nodes:\n")
            for node_name, y in result.items():
                stdout_str = y.stdout.decode('utf-8', 'replace').strip()
                parts = stdout_str.split(maxsplit=1)
                if len(parts) == 2:
                    sha256_hash, _ = parts
                    result_description.write(f"  {sha256_hash}  {node_name}\n")
                else:
                    result_description.write(f"  {stdout_str}  {node_name}\n")
            result_description.flush()
            return CheckResult(
                CHECK_NAME,
                nodes,
                1,
                result_description.getvalue(),
                'Run "crm corosync diff" to inspect the differences, and then "crm corosync push" to synchronize the configuration across cluster nodes.',
            )
    return CheckResult(
        CHECK_NAME,
        nodes,
        0,
        None,
        None,
    )


def validate_config_file(node: str) -> CheckResult:
    result = sh.cluster_shell().subprocess_run_without_input(
        node, 'root',
        'corosync -t',
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    CHECK_NAME = 'Validate Corosync Configuration File'
    match result.returncode:
        case 0:
            return CheckResult(
                CHECK_NAME,
                [node],
                result.returncode,
                None,
                None,
            )
        case _:
            return CheckResult(
                CHECK_NAME,
                [node],
                result.returncode,
                result.stdout.decode('utf-8', 'replace').strip(),
                None,
            )


def check_quorum_status(local_node: str) -> CheckResult:
    command_args = ['corosync-quorumtool', '-s']
    result = subprocess.run(
        command_args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    CHECK_NAME = "Check Quorum Status"
    if result.returncode not in (
            0,
            2,  # not quorate
    ):
        return CheckResult(
            CHECK_NAME,
            [local_node],
            result.returncode,
            result.stdout.decode('utf-8', 'replace').strip(),
            "Check if the corosync service is running.",
        )
    try:
        quorum_info = _parse_quorum_status(result.stdout.decode('utf-8', 'replace'))
    except ValueError as e:
        return CheckResult(
            CHECK_NAME,
            [local_node],
            1,
            f"Failed to parse '{' '.join(command_args)}' output: {e}",
            None,
        )
    if not quorum_info.quorate:
        return CheckResult(
            CHECK_NAME,
            [local_node],
            1,
            f"The cluster is not quorate. Total votes: {quorum_info.total_votes}, Quorum: {quorum_info.quorum}",
            "Ensure that enough nodes are online and connected to form a quorum.",
        )
    if quorum_info.total_votes < quorum_info.expected_votes:
        return CheckResult(
            CHECK_NAME,
            [local_node],
            1,
            f"Total votes ({quorum_info.total_votes}) is less than expected votes ({quorum_info.expected_votes}).",
            "Check that all expected cluster nodes are online and connected.",
        )
    return CheckResult(
        CHECK_NAME,
        [local_node],
        0,
        None,
        None,
    )


@dataclasses.dataclass
class _QuorumInfo:
    expected_votes: int
    total_votes: int
    quorum: int
    quorate: bool


def _parse_quorum_status(output: str) -> _QuorumInfo:
    """
    Parses the output of 'corosync-quorumtool -s' to extract
    expected_votes, total_votes, quorum, and quorate status from Flags.
    """
    expected_votes = None
    total_votes = None
    quorum = None
    quorate = None
    for line in output.splitlines():
        line = line.strip()
        if ':' not in line:
            continue
        key, val = line.split(':', 1)
        key = key.strip()
        val = val.strip()
        parts = val.split()
        if not parts:
            continue
        if key == 'Expected votes':
            expected_votes = int(parts[0])
        elif key == 'Total votes':
            total_votes = int(parts[0])
        elif key == 'Quorum':
            quorum = int(parts[0])
        elif key == 'Flags':
            quorate = 'Quorate' in parts
    if expected_votes is None:
        raise ValueError("Missing 'Expected votes' in quorum status output")
    if total_votes is None:
        raise ValueError("Missing 'Total votes' in quorum status output")
    if quorum is None:
        raise ValueError("Missing 'Quorum' in quorum status output")
    if quorate is None:
        raise ValueError("Missing 'Flags' in quorum status output")
    return _QuorumInfo(
        expected_votes=expected_votes,
        total_votes=total_votes,
        quorum=quorum,
        quorate=quorate,
    )


def check_nodeid_to_nodename_mapping(local_node: str, lm: corosync.LinkManager) -> CheckResult:
    """
    Check against the mismatch of nodeid to nodename mapping between corosync.conf and CIB.
    """
    CHECK_NAME = 'Check Node ID to Node Name Mapping'
    rc, out, err = sh.ShellUtils().get_stdout_stderr(constants.CIB_QUERY)
    if rc != 0:
        return CheckResult(
            CHECK_NAME,
            [local_node],
            255,
            f"Failed to load CIB: {err}",
            None,
        )
    try:
        cib = lxml.etree.fromstring(out)
    except lxml.etree.ParseError as e:
        return CheckResult(
            CHECK_NAME,
            [local_node],
            255,
            f"Failed to parse CIB: {e}",
            None,
        )
    try:
        cib_nodes = cibquery.get_cluster_nodes(cib)
    except AssertionError as e:
        return CheckResult(
            CHECK_NAME,
            [local_node],
            255,
            f"Failed to extract cluster nodes from CIB: {e}",
            None,
        )

    try:
        config_nodelist = lm._config['nodelist']['node']
    except KeyError:
        config_nodelist = []
    if not isinstance(config_nodelist, list):
        config_nodelist = [config_nodelist]
    corosync_id_to_name = {}
    for node in config_nodelist:
        nodeid_str = node.get('nodeid')
        name = node.get('name')
        if nodeid_str is not None:
            try:
                nodeid = int(nodeid_str)
            except ValueError:
                continue
            if name is not None:
                corosync_id_to_name[nodeid] = name

    cib_id_to_name = {node.node_id: node.uname for node in cib_nodes}
    mismatches = []
    if corosync_id_to_name == cib_id_to_name:
        pass
    for nodeid, nodename in corosync_id_to_name.items():
        cib_name = cib_id_to_name.get(nodeid, None)
        if cib_name is None:
            mismatches.append(
                f"Node ID {nodeid} with name '{nodename}' in corosync.conf is not found in CIB."
            )
        elif cib_name != nodename:
            mismatches.append(
                f"Node ID {nodeid} is associated with name '{nodename}' in corosync.conf but '{cib_name}' in CIB."
            )
    for nodeid, nodename in cib_id_to_name.items():
        corosync_name = corosync_id_to_name.get(nodeid, None)
        if corosync_name is None:
            mismatches.append(
                f"Node ID {nodeid} with name '{nodename}' in CIB is not found in corosync.conf."
            )
    if mismatches:
        result_description = StringIO()
        result_description.write("Mismatches between corosync.conf and CIB found.")
        for x in mismatches:
            result_description.write('\n * ')
            result_description.write(x)
        return CheckResult(
            CHECK_NAME,
            [local_node],
            1,
            result_description.getvalue(),
            "Ensure nodeid and name mapping are consistent between corosync.conf and CIB.",
        )
    else:
        return CheckResult(
            CHECK_NAME,
            [local_node],
            0,
            None,
            None,
        )


def check_links_status(local_node: str) -> CheckResult:
    """
    Check if corosync links are operational.
    """
    command_args = ['corosync-cfgtool', '-s']
    result = subprocess.run(
        command_args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    CHECK_NAME = "Check Corosync Links Status"
    if result.returncode != 0:
        return CheckResult(
            CHECK_NAME,
            [local_node],
            result.returncode,
            result.stdout.decode('utf-8', 'replace').strip(),
            "Check if the corosync service is running.",
        )
    try:
        links_info = _parse_links_status(result.stdout.decode('utf-8', 'replace'))
    except ValueError as e:
        return CheckResult(
            CHECK_NAME,
            [local_node],
            1,
            f"Failed to parse '{' '.join(command_args)}' output: {e}",
            None,
        )
    disconnected_links = []
    for link_id, nodes in links_info.items():
        for node_id, status in nodes.items():
            if status not in ("localhost", "connected"):
                disconnected_links.append((link_id, node_id, status))
    if disconnected_links:
        disconnected_links.sort()
        msg_parts = []
        for link_id, node_id, status in disconnected_links:
            msg_parts.append(f"Link {link_id} to node {node_id} has status '{status}'.")
        result_description = "Corosync link(s) are not operational:\n" + "\n".join(msg_parts)
        return CheckResult(
            CHECK_NAME,
            [local_node],
            1,
            result_description,
            "Check network connectivity and corosync configuration/service on the affected nodes.",
        )
    return CheckResult(
        CHECK_NAME,
        [local_node],
        0,
        None,
        None,
    )


def _parse_links_status(output: str) -> dict[int, dict[int, str]]:
    """
    Parses the output of 'corosync-cfgtool -s' to extract
    link statuses per node.
    """
    links = {}
    current_link = None
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        link_match = re.match(r'^LINK ID\s+(\d+)', line)
        if link_match:
            current_link = int(link_match.group(1))
            links[current_link] = {}
            continue
        node_match = re.match(r'^nodeid:\s*(\d+):\s*(.*)', line)
        if node_match:
            if current_link is None:
                raise ValueError("Found node ID status before any LINK ID section")
            node_id = int(node_match.group(1))
            status = node_match.group(2).strip()
            links[current_link][node_id] = status
    if not links:
        raise ValueError("No corosync links found in output")
    return links


def check_deprecated_transport(local_node: str, lm: corosync.LinkManager) -> CheckResult:
    """
    Check if corosync transport is knet. Give a warning if non-knet transport is used.
    """
    CHECK_NAME = "Check Deprecated Corosync Transport"
    transport = lm.totem_transport()

    if transport != 'knet':
        return CheckResult(
            CHECK_NAME,
            [local_node],
            2,
            f'Corosync transport "{transport}" is deprecated. Please use knet.',
            "Upgrade corosync transport to knet.",
        )

    return CheckResult(
        CHECK_NAME,
        [local_node],
        0,
        None,
        None,
    )


def check_knet_link_network_interface(local_node: str, lm: corosync.LinkManager) -> CheckResult:
    """
    Check if multiple knet links are configured on different network interfaces.
    """
    CHECK_NAME = "Check Knet Link Network Interface"
    if lm.totem_transport() != 'knet':
        return CheckResult(
            CHECK_NAME,
            [local_node],
            0,
            None,
            None,
        )

    link_addrs: dict[int, str] = {}  # Maps link number to any configured node address on that link
    for link in lm.links():
        if link is None:
            continue
        for node in link.nodes:
            if node.addr:
                link_addrs[link.linknumber] = node.addr
                break

    if len(link_addrs) <= 1:
        return CheckResult(
            CHECK_NAME,
            [local_node],
            0,
            None,
            None,
        )

    try:
        ip_j_addr = sh.LocalShell().get_stdout_or_raise_error(None, 'ip -j addr')
        local_interfaces = iproute2.IPAddr(json.loads(ip_j_addr)).interfaces()
    except Exception as e:
        return CheckResult(
            CHECK_NAME,
            [local_node],
            1,
            f"Failed to load local network interfaces: {e}",
            None,
        )

    interface_to_links: dict[str, list[int]] = {}  # Maps local network interface name to configured link numbers
    for linknumber, addr_str in link_addrs.items():
        try:
            link_ip = ipaddress.ip_address(addr_str)
        except ValueError:
            continue

        found_iface = None
        for iface in local_interfaces:
            for addr_info in iface.addr_info:
                if link_ip in addr_info.network:
                    found_iface = iface.ifname
                    break
            if found_iface is not None:
                break

        if found_iface is not None:
            interface_to_links.setdefault(found_iface, []).append(linknumber)

    conflicts: dict[str, list[int]] = {
        iface: links for iface, links in interface_to_links.items() if len(links) > 1
    }  # Identifies interfaces hosting multiple knet links (non-redundant)

    if conflicts:
        result_description = StringIO()
        result_description.write("Multiple knet links are configured on the same network interface:\n")
        for iface, links in conflicts.items():
            result_description.write(f"  Interface '{iface}' hosts knet links: {', '.join(map(str, links))}\n")
        return CheckResult(
            CHECK_NAME,
            [local_node],
            1,
            result_description.getvalue().strip(),
            "To ensure network redundancy, configure multiple knet links on different network interfaces.",
        )

    return CheckResult(
        CHECK_NAME,
        [local_node],
        0,
        None,
        None,
    )



