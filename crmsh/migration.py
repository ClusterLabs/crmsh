import logging
import os
import re
import shutil
import tempfile
import typing

import lxml.etree

from crmsh import constants
from crmsh import corosync
from crmsh import corosync_config_format
from crmsh import parallax
from crmsh import service_manager
from crmsh import sh
from crmsh import utils

logger = logging.getLogger(__name__)


class MigrationFailure(Exception):
    pass


def migrate():
    try:
        check()
        logger.info('Starting migration...')
        migrate_corosync_conf()
        logger.info('Finished migration.')
        return 0
    except MigrationFailure as e:
        logger.error('%s', e)
        return 1


def check():
    has_problems = [False]
    def problem_handler(is_fatal: bool, title: str, detail: typing.Iterable[str]):
        has_problems[0] = True
        logger.error('%s', title)
        for line in detail:
            logger.info('  %s', line)
        if is_fatal:
            raise MigrationFailure('Unable to start migration.')
    check_dependency_version(problem_handler)
    check_service_status(problem_handler)
    check_unsupported_corosync_features(problem_handler)
    # TODO: run checks on all cluster nodes
    if has_problems[0]:
        raise MigrationFailure('Unable to start migration.')


def check_dependency_version(handler: typing.Callable[[bool, str, typing.Iterable[str]], None]):
    logger.info('Checking dependency version...')
    shell = sh.LocalShell()
    out = shell.get_stdout_or_raise_error(None, 'corosync -v')
    match = re.search(r"version\s+'((\d+)(?:\.\d+)*)'", out)
    if not match or match.group(2) != '3':
        handler(
            False, 'Corosync version not supported', [
                'Supported version: corosync >= 3',
                f'Actual version:    corosync == {match.group(1)}',
            ],
        )


def check_service_status(handler: typing.Callable[[bool, str, typing.Iterable[str]], None]):
    logger.info('Checking service status...')
    manager = service_manager.ServiceManager()
    active_services = [x for x in ['corosync', 'pacemaker'] if manager.service_is_active(x)]
    if active_services:
        handler(False, 'Cluster services are running', (f'* {x}' for x in active_services))


def check_unsupported_corosync_features(handler: typing.Callable[[bool, str, str], None]):
    pass


def migrate_corosync_conf():
    conf_path = corosync.conf()
    with open(conf_path, 'r', encoding='utf-8') as f:
        config = corosync_config_format.DomParser(f).dom()
    logger.info('Migrating corosync configuration...')
    migrate_corosync_conf_impl(config)
    shutil.copy(conf_path, conf_path + '.bak')
    with utils.open_atomic(conf_path, 'w', fsync=True, encoding='utf-8') as f:
        corosync_config_format.DomSerializer(config, f)
        os.fchmod(f.fileno(), 0o644)
    logger.info('Finish migrating corosync configuration.')
    # TODO: copy to all cluster nodes


def migrate_corosync_conf_impl(config):
    assert 'totem' in config
    assert 'quorum' in config
    corosync.ConfParser.transform_dom_with_list_schema(config)
    migrate_transport(config)
    migrate_crypto(config)
    migrate_rrp(config)
    # TODO: other migrations


def migrate_transport(dom):
    match dom['totem'].get('transport', None):
        case 'knet':
            return
        case 'udpu':
            migrate_udpu(dom)
        case 'udp':
            migrate_multicast(dom)
        case _:
            # corosync 2 defaults to "udp"
            try:
                dom['totem']['interface'][0]['bindnetaddr']
            except KeyError:
                # looks like a corosync 3 config
                pass
            if 'nodelist' not in dom:
                migrate_multicast(dom)
            else:
                # looks like a corosync 3 config
                pass


def migrate_udpu(dom):
    dom['totem']['transport'] = 'knet'
    dom['totem']['knet_compression_model'] = 'none'
    if 'interface' in dom['totem']:
        for interface in dom['totem']['interface']:
            # remove udp-only items
            interface.pop('mcastaddr', None)
            interface.pop('bindnetaddr', None)
            interface.pop('broadcast', None)
            interface.pop('ttl', None)
            ringnumber = interface.pop('ringnumber', None)
            if ringnumber is not None:
                interface['linknumber'] = ringnumber
    dom['quorum'].pop('expected_votes', None)
    logger.info("Upgrade totem.transport to knet.")


def migrate_multicast(dom):
    dom['totem']['transport'] = 'knet'
    dom['totem']['knet_compression_model'] = 'none'
    for interface in dom['totem']['interface']:
        # remove udp-only items
        interface.pop('mcastaddr', None)
        interface.pop('bindnetaddr', None)
        interface.pop('broadcast', None)
        interface.pop('ttl', None)
        ringnumber = interface.pop('ringnumber', None)
        if ringnumber is not None:
            interface['linknumber'] = ringnumber
    logger.info("Generating nodelist according to CIB...")
    with open(constants.CIB_RAW_FILE, 'rb') as f:
        cib = Cib(f)
    cib_nodes = cib.nodes()
    assert 'nodelist' not in dom
    nodelist = list()
    with tempfile.TemporaryDirectory(prefix='crmsh-migration-') as dir_name:
        node_configs = {
            x[0]: x[1]
            for x in parallax.parallax_slurp([x.uname for x in cib_nodes], dir_name, corosync.conf())
        }
        for node in cib_nodes:
            assert node.uname in node_configs
            with open(node_configs[node.uname], 'r', encoding='utf-8') as f:
                root = corosync_config_format.DomParser(f).dom()
                corosync.ConfParser.transform_dom_with_list_schema(root)
                interfaces = root['totem']['interface']
                addresses = {f'ring{i}_addr': x['bindnetaddr'] for i, x in enumerate(interfaces)}
                logger.info("Node %s: %s: %s", node.node_id, node.uname, addresses)
                nodelist.append({
                    'nodeid': node.node_id,
                    'name': node.uname,
                } | addresses)
    dom['nodelist'] = {'node': nodelist}
    dom['quorum'].pop('expected_votes', None)
    logger.info("Unset quorum.expected_votes.")
    logger.info("Upgrade totem.transport to knet.")


def migrate_crypto(dom):
    try:
        # corosync 3 change the default hash algorithm to sha256 when `secauth` is enabled
        if dom['totem'].get('crypto_hash', None) == 'sha1':
            dom['totem']['crypto_hash'] = 'sha256'
            logger.info('Upgrade totem.crypto_hash from "sha1" to "sha256".')
    except KeyError:
        dom['totem']['crypto_hash'] = 'sha256'


def migrate_rrp(dom):
    try:
        nodes = dom['nodelist']['node']
    except KeyError:
        return
    is_rrp = any('ring1_addr' in node for node in nodes)
    if not is_rrp:
        return
    try:
        rrp_mode = dom['totem']['rrp_mode']
        del dom['totem']['rrp_mode']
        if rrp_mode == 'active':
            dom['totem']['link_mode'] = 'active'
    except KeyError:
        pass
    assert all('nodeid' in node for node in nodes)
    if any('name' not in node for node in nodes):
        populate_node_name(nodes)


def populate_node_name(nodelist):
    # cannot use utils.list_cluster_nodes, as pacemaker is not running
    with open(constants.CIB_RAW_FILE, 'rb') as f:
        cib = Cib(f)
    cib_nodes = {node.node_id: node for node in cib.nodes()}
    for node in nodelist:
        node_id = int(node['nodeid'])
        node['name'] = cib_nodes[node_id].uname


class Cib:
    class Node:
        def __init__(self, node_id: int, uname: str):
            self.node_id = node_id
            self.uname = uname

    def __init__(self, f: typing.IO):
        self._dom = lxml.etree.parse(f)

    def nodes(self):
        result = list()
        for element in self._dom.xpath(constants.XML_NODE_PATH):
            if element.get('type') == 'remote':
                xpath = f"//primitive[@provider='pacemaker' and @type='remote']/instance_attributes/nvpair[@name='server' and @value='{name}']"
                if self._dom.xpath(xpath):
                    continue
            node_id = element.get('id')
            uname = element.get('uname')
            assert node_id
            assert uname
            result.append(Cib.Node(int(node_id), uname))
        return result
