import argparse
import dataclasses
import importlib.resources
import itertools
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import tempfile
import typing

import lxml.etree

from crmsh import cibquery
from crmsh import constants
from crmsh import corosync
from crmsh import corosync_config_format
from crmsh import parallax
from crmsh import service_manager
from crmsh import sh
from crmsh import utils
from crmsh import xmlutil
from crmsh.prun import prun

logger = logging.getLogger(__name__)


SAP_HANA_RESOURCE_AGENTS = {
    cibquery.ResourceAgent('ocf', 'suse', 'SAPHana'),
    cibquery.ResourceAgent('ocf', 'suse', 'SAPHanaController'),
    cibquery.ResourceAgent('ocf', 'suse', 'SAPHanaTopology'),
}


class MigrationFailure(Exception):
    pass


class CheckResultHandler:
    def log_info(self, fmt: str, *args):
        raise NotImplementedError

    def handle_tip(self, title: str, details: typing.Iterable[str]):
        raise NotImplementedError

    def handle_problem(self, is_fatal: bool, title: str, detail: typing.Iterable[str]):
        raise NotImplementedError

    def end(self):
        raise NotImplementedError


class CheckResultJsonHandler(CheckResultHandler):
    def __init__(self, indent: typing.Optional[int] = None):
        self._indent = indent
        self.json_result = {
            "pass": True,
            "problems": [],
            "tips": [],
        }
    def log_info(self, fmt: str, *args):
        logger.debug(fmt, *args)

    def handle_tip(self, title: str, details: typing.Iterable[str]):
        self.json_result["tips"].append({
            "title": title,
            "descriptions": details if isinstance(details, list) else list(details),
        })

    def handle_problem(self, is_fatal: bool, title: str, detail: typing.Iterable[str]):
        self.json_result["pass"] = False
        self.json_result["problems"].append({
            "is_fatal": is_fatal,
            "title": title,
            "descriptions": detail if isinstance(detail, list) else list(detail),
        })

    def end(self):
        json.dump(
            self.json_result,
            sys.stdout,
            ensure_ascii=False,
            indent=self._indent,
        )
        sys.stdout.write('\n')


class CheckResultInteractiveHandler(CheckResultHandler):
    def __init__(self):
        self.has_problems = False

    def log_info(self, fmt: str, *args):
        self.write_in_color(sys.stdout, constants.GREEN, '[INFO] ')
        print(fmt % args)

    def handle_problem(self, is_fatal: bool, title: str, details: typing.Iterable[str]):
        self.has_problems = True
        self.write_in_color(sys.stdout, constants.YELLOW, '[FAIL] ')
        print(title)
        for line in details:
            sys.stdout.write('       ')
            print(line)
        if is_fatal:
            raise MigrationFailure('Unable to start migration.')

    def handle_tip(self, title: str, details: typing.Iterable[str]):
        self.write_in_color(sys.stdout, constants.YELLOW, '[WARN] ')
        print(title)
        for line in details:
            sys.stdout.write('       ')
            print(line)

    @staticmethod
    def write_in_color(f, color: str, text: str):
        if f.isatty():
            f.write(color)
            f.write(text)
            f.write(constants.END)
        else:
            f.write(text)

    def end(self):
        if self.has_problems:
            self.write_in_color(sys.stdout, constants.RED, '[FAIL]\n\n')
        else:
            self.write_in_color(sys.stdout, constants.GREEN, '[PASS]\n\n')
        if not self.has_problems:
            self.write_in_color(sys.stdout, constants.GREEN, '[PASS]\n')


def migrate():
    try:
        if 0 != check(list()):
            raise MigrationFailure('Unable to start migration.')
        logger.info('Starting migration...')
        migrate_corosync_conf()
        logger.info('Finished migration.')
        return 0
    except MigrationFailure as e:
        logger.error('%s', e)
        return 1


def check(args: typing.Sequence[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--json', nargs='?', const='pretty', choices=['oneline', 'pretty'])
    parser.add_argument('--local', action='store_true')
    parsed_args = parser.parse_args(args)
    match parsed_args.json:
        case 'oneline':
            handler = CheckResultJsonHandler()
        case 'pretty':
            handler = CheckResultJsonHandler(indent=2)
        case _:
            handler = CheckResultInteractiveHandler()
    ret = 0
    if parsed_args.local or parsed_args.json:
        check_remote_yield = itertools.repeat(0)
        check_local(handler)
    else:
        check_remote_yield = check_remote()
        next(check_remote_yield)
        print('------ corosync @ localhost ------')
        check_local(handler)
        check_global(handler)
    handler.end()
    match handler:
        case CheckResultJsonHandler():
            ret = 0 if handler.json_result["pass"] else 1
        case CheckResultInteractiveHandler():
            if handler.has_problems:
                ret = 1
    if check_remote_yield:
        remote_ret = next(check_remote_yield)
        if remote_ret > ret:
            ret = remote_ret
    return ret


def check_local(handler: CheckResultHandler):
    check_dependency_version(handler)
    check_service_status(handler)
    check_unsupported_corosync_features(handler)


def check_remote():
    handler = CheckResultInteractiveHandler()
    class CheckRemoteThread(threading.Thread):
        def run(self):
            self.result = prun.prun({
                node: 'crm cluster health sles16 --local --json=oneline'
                for node in utils.list_cluster_nodes_except_me()
            })
    prun_thread = CheckRemoteThread()
    prun_thread.start()
    yield
    prun_thread.join()
    ret = 0
    for host, result in prun_thread.result.items():
        match result:
            case prun.SSHError() as e:
                handler.write_in_color(
                    sys.stdout, constants.YELLOW,
                    f'\n------ {host} ------\n',
                )
                handler.write_in_color(
                    sys.stdout, constants.YELLOW,
                    str(e)
                )
                sys.stdout.write('\n')
                ret = 255
            case prun.ProcessResult() as result:
                if result.returncode > 1:
                    handler.write_in_color(
                        sys.stdout, constants.YELLOW,
                        f'\n------ {host} ------\n',
                    )
                    print(result.stdout.decode('utf-8', 'backslashreplace'))
                    handler.write_in_color(
                        sys.stdout, constants.YELLOW,
                        result.stderr.decode('utf-8', 'backslashreplace')
                    )
                    sys.stdout.write('\n')
                    ret = result.returncode
                else:
                    try:
                        result = json.loads(result.stdout.decode('utf-8'))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        handler.write_in_color(
                            sys.stdout, constants.YELLOW,
                            f'\n------ {host} ------\n',
                        )
                        print(result.stdout.decode('utf-8', 'backslashreplace'))
                        handler.write_in_color(
                            sys.stdout, constants.YELLOW,
                            result.stdout.decode('utf-8', 'backslashreplace')
                        )
                        sys.stdout.write('\n')
                        ret = result.returncode
                    else:
                        passed = result.get("pass", False)
                        handler.write_in_color(
                            sys.stdout, constants.GREEN if passed else constants.YELLOW,
                            f'\n------ {host} ------\n',
                        )
                        handler = CheckResultInteractiveHandler()
                        for problem in result.get("problems", list()):
                            handler.handle_problem(False, problem.get("title", ""), problem.get("descriptions"))
                        for tip in result.get("tips", list()):
                            handler.handle_tip(tip.get("title", ""), tip.get("descriptions"))
                        handler.end()
                        if not passed:
                            ret = 1
    yield ret


def check_global(handler: CheckResultHandler):
    check_unsupported_resource_agents(handler)


def check_dependency_version(handler: CheckResultHandler):
    handler.log_info('Checking dependency version...')
    shell = sh.LocalShell()
    out = shell.get_stdout_or_raise_error(None, 'corosync -v')
    _check_version_range(
        handler,
        'Corosync', (3,),
        re.compile(r"version\s+'(\d+(?:\.\d+)*)'"),
        shell.get_stdout_or_raise_error(None, 'corosync -v'),
    )
    _check_version_range(
        handler,
        'Pacemaker', (3,),
        re.compile(r"^Pacemaker\s+(\d+(?:\.\d+)*)"),
        shell.get_stdout_or_raise_error(None, 'pacemakerd --version'),
    )


def _check_version_range(
        handler: CheckResultHandler, component_name: str,
        minimum: tuple,
        pattern,
        text: str,
):
    match = pattern.search(text)
    if not match:
        handler.handle_problem(
            False, f'{component_name} version not supported', [
                'Unknown version:',
                text,
            ],
        )
    else:
        version = tuple(int(x) for x in match.group(1).split('.'))
        if not minimum <= version:
            handler.handle_problem(
                False, f'{component_name} version not supported', [
                    'Supported version: {} <= {}'.format(
                        '.'.join(str(x) for x in minimum),
                        component_name,
                    ),
                    f'Actual version:    {component_name} == {match.group(1)}',
                ],
            )


def check_service_status(handler: CheckResultHandler):
    handler.log_info('Checking service status...')
    manager = service_manager.ServiceManager()
    active_services = [x for x in ['corosync', 'pacemaker'] if manager.service_is_active(x)]
    if active_services:
        handler.handle_problem(False, 'Cluster services are running', (f'* {x}' for x in active_services))


def check_unsupported_corosync_features(handler: CheckResultHandler):
    handler.log_info("Checking used corosync features...")
    conf_path = corosync.conf()
    with open(conf_path, 'r', encoding='utf-8') as f:
        config = corosync_config_format.DomParser(f).dom()
    if config['totem'].get('rrp_mode', None) in {'active', 'passive'}:
        handler.handle_tip('Corosync RRP will be deprecated in corosync 3.', [
            'Run "crm health sles16 --fix" to migrate it to knet multilink.',
        ])
    _check_unsupported_corosync_transport(handler, config)


def _check_unsupported_corosync_transport(handler: CheckResultHandler, dom):
    transport = dom['totem'].get('transport', None)
    if transport == 'knet':
        return
    if transport is None:
        try:
            dom['totem']['interface'][0]['bindnetaddr']
        except KeyError:
            # looks like a corosync 3 config
            return
    handler.handle_tip(f'Corosync transport "{transport}" will be deprecated in corosync 3.', [
        'Run "crm health sles16 --fix" to migrate it to transport "knet".',
    ])


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
    for host, result in prun.pcopy_to_remote(conf_path, utils.list_cluster_nodes_except_me(), conf_path).items():
        match result:
            case None:
                pass
            case prun.PRunError() as e:
                logger.error("Failed to copy crmsh.conf to host %s: %s", host, e)


def migrate_corosync_conf_impl(config):
    assert 'totem' in config
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
    if 'quorum' in dom:
        dom['quorum'].pop('expected_votes', None)
    logger.info("Upgrade totem.transport to knet.")


def migrate_multicast(dom):
    dom['totem']['transport'] = 'knet'
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
    if 'quorum' in dom:
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


def check_unsupported_resource_agents(handler: CheckResultHandler):
    handler.log_info("Checking used resource agents...")
    ocf_resource_agents = list()
    stonith_resource_agents = list()
    cib = xmlutil.text2elem(sh.LocalShell().get_stdout_or_raise_error(None, 'crm configure show xml'))
    for resource_agent in cibquery.get_configured_resource_agents(cib):
        if resource_agent.m_class == 'ocf':
            ocf_resource_agents.append(resource_agent)
        elif resource_agent.m_class == 'stonith':
            stonith_resource_agents.append(resource_agent)
        else:
            raise ValueError(f'Unrecognized resource agent {resource_agent}')
    _check_saphana_resource_agent(handler, ocf_resource_agents)
    class TitledCheckResourceHandler(CheckResultHandler):
        def __init__(self, parent: CheckResultHandler, title: str):
            self._parent = parent
            self._title= title
        def log_info(self, fmt: str, *args):
            return self._parent.log_info(fmt, *args)
        def handle_problem(self, is_fatal: bool, title: str, detail: typing.Iterable[str]):
            return self._parent.handle_problem(is_fatal, self._title, detail)
        def handle_tip(self, title: str, details: typing.Iterable[str]):
            return self._parent.handle_tip(self._title, details)
    supported_resource_agents = _load_supported_resource_agents()
    _check_removed_resource_agents(
        TitledCheckResourceHandler(handler, "The following resource agents will be removed in SLES 16."),
        supported_resource_agents,
        (agent for agent in ocf_resource_agents if agent not in SAP_HANA_RESOURCE_AGENTS),
    )
    _check_removed_resource_agents(
        TitledCheckResourceHandler(handler, "The following fence agents will be removed in SLES 16."),
        supported_resource_agents,
        stonith_resource_agents,
    )
    _check_ocfs2(handler, cib)


def _check_saphana_resource_agent(handler: CheckResultHandler, resource_agents: typing.Iterable[cibquery.ResourceAgent]):
    # "SAPHana" appears only in SAPHanaSR Classic
    has_sap_hana_sr_resources = any(agent in SAP_HANA_RESOURCE_AGENTS for agent in resource_agents)
    if has_sap_hana_sr_resources:
        if 0 != subprocess.run(
            ['rpm', '-q', 'SAPHanaSR-angi'],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode:
            handler.handle_problem(False, 'SAPHanaSR Classic will be removed in SLES 16.', [
                'Before migrating to SLES 16, replace it with SAPHanaSR-angi.',
            ])


def _load_supported_resource_agents() -> typing.Set[cibquery.ResourceAgent]:
    ret = set()
    with importlib.resources.files('crmsh').joinpath('migration-supported-resource-agents.txt').open(
            'r', encoding='ascii',
    ) as r:
        for line in r:
            parts = line.strip().split(':', 3)
            m_class = parts[0]
            m_provider = parts[1] if len(parts) == 3 else None
            m_type = parts[-1]
            ret.add(cibquery.ResourceAgent(m_class, m_provider, m_type))
    return ret



def _check_removed_resource_agents(
        handler: CheckResultHandler,
        supported_resource_agents: typing.Set[cibquery.ResourceAgent],
        resource_agents: typing.Iterable[cibquery.ResourceAgent],
):
    unsupported_resource_agents = [x for x in resource_agents if x not in supported_resource_agents]
    if unsupported_resource_agents:
        handler.handle_problem(False, '', [
            '* ' + ':'.join(x for x in dataclasses.astuple(resource_agent) if x is not None)
            for resource_agent in unsupported_resource_agents
        ])


def _check_ocfs2(handler: CheckResultHandler, cib: lxml.etree.Element):
    if cibquery.has_primitive_filesystem_ocfs2(cib):
       handler.handle_problem(False, 'OCFS2 is not supported in SLES 16.', [
           '* Before migrating to SLES 16, replace it with GFS2.',
       ])
