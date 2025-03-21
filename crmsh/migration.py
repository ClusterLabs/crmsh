import argparse
import dataclasses
import enum
import glob
import importlib.resources
import ipaddress
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
from crmsh import iproute2
from crmsh import parallax
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


class CheckReturnCode(enum.IntEnum):
    ALREADY_MIGRATED = 0
    PASS_NO_AUTO_FIX = 1
    PASS_NEED_AUTO_FIX = 2
    BLOCKED_NEED_MANUAL_FIX = 3
    SSH_ERROR = 255


class CheckResultHandler:
    LEVEL_ERROR = 1
    LEVEL_WARN = 2

    def log_info(self, fmt: str, *args):
        raise NotImplementedError

    def handle_problem(self, need_auto_fix: bool, is_blocker: bool, level: int, title: str, detail: typing.Iterable[str]):
        raise NotImplementedError

    def end(self):
        raise NotImplementedError

    def to_check_return_code(self) -> CheckReturnCode:
        raise NotImplementedError


class CheckResultJsonHandler(CheckResultHandler):
    def __init__(self, indent: typing.Optional[int] = None):
        self._indent = indent
        self.json_result = {
            "problems": [],
        }

    def log_info(self, fmt: str, *args):
        logger.debug(fmt, *args)

    def handle_problem(self, need_auto_fix: bool, is_blocker: bool, level: int, title: str, detail: typing.Iterable[str]):
        self.json_result["problems"].append({
            "need_auto_fix": need_auto_fix,
            "is_blocker": is_blocker,
            "level": level,
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

    def to_check_return_code(self) -> CheckReturnCode:
        ret = CheckReturnCode.ALREADY_MIGRATED
        for problem in self.json_result['problems']:
            if problem.get('is_blocker', False):
                ret = max(CheckReturnCode.BLOCKED_NEED_MANUAL_FIX, ret)
            elif problem.get('need_auto_fix'):
                ret = max(CheckReturnCode.PASS_NEED_AUTO_FIX, ret)
            else:
                ret = max(CheckReturnCode.PASS_NO_AUTO_FIX, ret)
        return ret


class CheckResultInteractiveHandler(CheckResultHandler):
    def __init__(self):
        self.block_migration = False
        self.has_problems = False
        self.need_auto_fix = False

    def log_info(self, fmt: str, *args):
        self.write_in_color(sys.stdout, constants.GREEN, '[INFO] ')
        print(fmt % args)

    def handle_problem(self, need_auto_fix: bool, is_blocker: bool, level:int, title: str, details: typing.Iterable[str]):
        self.has_problems = True
        self.block_migration = self.block_migration or is_blocker
        self.need_auto_fix = self.need_auto_fix or need_auto_fix
        match level:
            case self.LEVEL_ERROR:
                self.write_in_color(sys.stdout, constants.YELLOW, '[FAIL] ')
            case self.LEVEL_WARN:
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
        sys.stdout.write('\n')

    def to_check_return_code(self) -> CheckReturnCode:
        if self.block_migration:
            ret = CheckReturnCode.BLOCKED_NEED_MANUAL_FIX
        elif self.need_auto_fix:
            ret = CheckReturnCode.PASS_NEED_AUTO_FIX
        elif self.has_problems:
            ret = CheckReturnCode.PASS_NO_AUTO_FIX
        else:
            ret = CheckReturnCode.ALREADY_MIGRATED
        return ret


def migrate():
    try:
        match _check_impl(local=False, json='', summary=False):
            case CheckReturnCode.ALREADY_MIGRATED:
                logger.info("This cluster works on SLES 16. No migration is needed.")
                return 0
            case CheckReturnCode.PASS_NO_AUTO_FIX:
                logger.info("This cluster works on SLES 16 with some warnings. Please fix the remaining warnings manually.")
                return 0
            case CheckReturnCode.PASS_NEED_AUTO_FIX:
                logger.info('Starting migration...')
                migrate_corosync_conf()
                logger.info('Finished migration.')
                return 0
            case _:
                raise MigrationFailure('Unable to start migration.')
    except MigrationFailure as e:
        logger.error('%s', e)
        return 1


def check(args: typing.Sequence[str]) -> int:
    parser = argparse.ArgumentParser(args[0])
    parser.add_argument('--json', nargs='?', const='pretty', choices=['oneline', 'pretty'])
    parser.add_argument('--local', action='store_true')
    parsed_args = parser.parse_args(args[1:])
    ret = _check_impl(parsed_args.local or parsed_args.json is not None, parsed_args.json, parsed_args.json is None)
    if not parsed_args.json:
        print('****** summary ******')
        match ret:
            case CheckReturnCode.ALREADY_MIGRATED:
                CheckResultInteractiveHandler.write_in_color(sys.stdout, constants.GREEN, '[INFO]')
                sys.stdout.write(' This cluster works on SLES 16. No migration is needed.\n')
            case CheckReturnCode.PASS_NO_AUTO_FIX:
                CheckResultInteractiveHandler.write_in_color(sys.stdout, constants.GREEN, '[PASS]')
                sys.stdout.write(' This cluster works on SLES 16 with some warnings. Please fix the remaining warnings manually.\n')
            case CheckReturnCode.PASS_NEED_AUTO_FIX:
                CheckResultInteractiveHandler.write_in_color(sys.stdout, constants.GREEN, '[INFO]')
                sys.stdout.write(' Please run "crm cluster health sles16 --fix" on on any one of above nodes.\n')
                CheckResultInteractiveHandler.write_in_color(sys.stdout, constants.GREEN, '[PASS]')
                sys.stdout.write(' This cluster is good to migrate to SLES 16.\n')
            case _:
                CheckResultInteractiveHandler.write_in_color(sys.stdout, constants.RED, '[FAIL]')
                sys.stdout.write(' The pacemaker cluster stack can not migrate to SLES 16.\n')
    return ret


def _check_impl(local: bool, json: str, summary: bool) -> CheckReturnCode:
    assert not summary or not bool(json)
    assert local or not bool(json)
    if not local:
        check_remote_yield = check_remote()
        next(check_remote_yield)
    else:
        check_remote_yield = itertools.repeat(0)
    match json:
        case 'oneline':
            handler = CheckResultJsonHandler()
        case 'pretty':
            handler = CheckResultJsonHandler(indent=2)
        case _:
            handler = CheckResultInteractiveHandler()
    if local:
        check_remote_yield = itertools.repeat(0)
        check_local(handler)
    else:
        check_remote_yield = check_remote()
        next(check_remote_yield)
        print('------ node: localhost ------')
        check_local(handler)
        print('\n------ cib ------')
        check_global(handler)
    handler.end()
    ret = handler.to_check_return_code()
    if check_remote_yield:
        remote_ret = next(check_remote_yield)
        ret = max(remote_ret, ret)
    return ret


def check_local(handler: CheckResultHandler):
    check_dependency_version(handler)
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
    ret = CheckReturnCode.ALREADY_MIGRATED
    for host, result in prun_thread.result.items():
        sys.stdout.write(f'------ node: {host} ------\n')
        match result:
            case prun.SSHError() as e:
                handler.write_in_color(
                    sys.stdout, constants.YELLOW,
                    str(e)
                )
                sys.stdout.write('\n')
                ret = CheckReturnCode.SSH_ERROR
            case prun.ProcessResult() as result:
                try:
                    check_result = json.loads(result.stdout.decode('utf-8'))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    print(result.stdout.decode('utf-8', 'backslashreplace'))
                    handler.write_in_color(
                        sys.stderr, constants.YELLOW,
                        result.stderr.decode('utf-8', 'backslashreplace')
                    )
                    sys.stdout.write('\n')
                    # cannot pass the exit status through,
                    # as all failed exit status become 1 in ui_context.Context.run()
                    ret = CheckReturnCode.BLOCKED_NEED_MANUAL_FIX
                else:
                    handler = CheckResultInteractiveHandler()
                    problems = check_result.get("problems", list())
                    for problem in problems:
                        handler.handle_problem(
                            problem.get("need_auto_fix", False), problem.get("is_blocker", False),
                            problem.get("level", handler.LEVEL_ERROR),
                            problem.get("title", ""), problem.get("descriptions"),
                        )
                    handler.end()
                    ret = handler.to_check_return_code()
    yield ret


def check_global(handler: CheckResultHandler):
    cib = xmlutil.text2elem(sh.LocalShell().get_stdout_or_raise_error(None, 'crm configure show xml'))
    check_cib_schema_version(handler, cib)
    check_unsupported_resource_agents(handler, cib)


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


def _check_version_range(
        handler: CheckResultHandler, component_name: str,
        minimum: tuple,
        pattern,
        text: str,
):
    match = pattern.search(text)
    if not match:
        handler.handle_problem(
            True, True, handler.LEVEL_ERROR,
            f'{component_name} version not supported',
            [
                'Unknown version:',
                text,
            ],
        )
    else:
        version = tuple(int(x) for x in match.group(1).split('.'))
        if not minimum <= version:
            handler.handle_problem(
                True, True,  handler.LEVEL_ERROR,
                f'{component_name} version not supported', [
                    'Supported version: {} >= {}'.format(
                        component_name,
                        '.'.join(str(x) for x in minimum),
                    ),
                    f'Actual version:    {component_name} == {match.group(1)}',
                ],
            )


def check_unsupported_corosync_features(handler: CheckResultHandler):
    handler.log_info("Checking used corosync features...")
    conf_path = corosync.conf()
    with open(conf_path, 'r', encoding='utf-8') as f:
        config = corosync_config_format.DomParser(f).dom()
        corosync.ConfParser.transform_dom_with_list_schema(config)
    if config['totem'].get('rrp_mode', None) in {'active', 'passive'}:
        handler.handle_problem(
            True, False, handler.LEVEL_WARN,
            'Corosync RRP is deprecated in corosync 3.', [
                'Run "crm health sles16 --fix" to migrate it to knet multilink.',
            ],
        )
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
    handler.handle_problem(
        True, False, handler.LEVEL_WARN,
        f'Corosync transport "{transport}" is deprecated in corosync 3. Please use knet.', [],
    )


def migrate_corosync_conf():
    conf_path = corosync.conf()
    with open(conf_path, 'r', encoding='utf-8') as f:
        config = corosync_config_format.DomParser(f).dom()
        corosync.ConfParser.transform_dom_with_list_schema(config)
    logger.info('Migrating corosync configuration...')
    migrate_corosync_conf_impl(config)
    shutil.copy(conf_path, conf_path + '.bak')
    with utils.open_atomic(conf_path, 'w', fsync=True, encoding='utf-8') as f:
        corosync_config_format.DomSerializer(config, f)
        os.fchmod(f.fileno(), 0o644)
    logger.info(
        'Finish migrating corosync configuration. The original configuration is renamed to %s.bak',
        os.path.basename(conf_path),
    )
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
            _migrate_totem_interface(interface)
    if 'quorum' in dom:
        dom['quorum'].pop('expected_votes', None)
    logger.info("Upgrade totem.transport to knet.")


def migrate_multicast(dom):
    dom['totem']['transport'] = 'knet'
    for interface in dom['totem']['interface']:
        _migrate_totem_interface(interface)
    logger.info("Generating nodelist according to CIB...")
    with open(constants.CIB_RAW_FILE, 'rb') as f:
        cib = lxml.etree.parse(f)
    cib_nodes = cibquery.get_cluster_nodes(cib)
    assert 'nodelist' not in dom
    nodelist = list()
    node_interfaces = {
        x[0]: iproute2.IPAddr(json.loads(x[1][1]))
        for x in parallax.parallax_call([x.uname for x in cib_nodes], 'ip -j addr')
        if x[1][0] == 0
    }
    with tempfile.TemporaryDirectory(prefix='crmsh-migration-') as dir_name:
        node_configs = {
            x[0]: x[1]
            for x in parallax.parallax_slurp([x.uname for x in cib_nodes], dir_name, corosync.conf())
        }
        for node in cib_nodes:
            assert node.uname in node_configs
            bindnetaddr_fixer = _BindnetaddrFixer(node_interfaces[node.uname].interfaces())
            with open(node_configs[node.uname], 'r', encoding='utf-8') as f:
                root = corosync_config_format.DomParser(f).dom()
                corosync.ConfParser.transform_dom_with_list_schema(root)
                interfaces = root['totem']['interface']
                addresses = {f'ring{i}_addr': bindnetaddr_fixer.fix_bindnetaddr(x['bindnetaddr']) for i, x in enumerate(interfaces)}
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


def _migrate_totem_interface(interface):
    # remove udp-only items
    interface.pop('mcastaddr', None)
    interface.pop('bindnetaddr', None)
    interface.pop('broadcast', None)
    interface.pop('ttl', None)
    ringnumber = interface.pop('ringnumber', None)
    if ringnumber is not None:
        interface['linknumber'] = ringnumber


class _BindnetaddrFixer:
    # crmsh generates incorrect bindnetaddr when joining a corosync 2 multicast cluster
    def __init__(self, interfaces: typing.Iterable[iproute2.IPInterface]):
        self._interface_addresses = {addr_info for interface in interfaces for addr_info in interface.addr_info}

    def fix_bindnetaddr(self, bindnetaddr: str):
        bind_address = ipaddress.ip_address(bindnetaddr)
        for interface_address in self._interface_addresses:
            if bind_address in interface_address.network:
                return str(interface_address.ip)
        return bindnetaddr


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
        cib = lxml.etree.parse(f)
    cib_nodes = {node.node_id: node for node in cibquery.get_cluster_nodes(cib)}
    for node in nodelist:
        node_id = int(node['nodeid'])
        node['name'] = cib_nodes[node_id].uname


def check_unsupported_resource_agents(handler: CheckResultHandler, cib: lxml.etree.Element):
    handler.log_info("Checking used resource agents...")
    ocf_resource_agents = list()
    stonith_resource_agents = list()
    class_unsupported_resource_agents = list()
    for resource_agent in cibquery.get_configured_resource_agents(cib):
        if resource_agent.m_class == 'ocf':
            ocf_resource_agents.append(resource_agent)
        elif resource_agent.m_class == 'stonith':
            stonith_resource_agents.append(resource_agent)
        elif resource_agent.m_class in {'lsb', 'service'}:
            class_unsupported_resource_agents.append(resource_agent)
        else:
            logger.debug('Unrecognized resource agent class: %s', resource_agent)
    unsupported_resource_agents = UnsupportedResourceAgentDetector()
    _check_saphana_resource_agent(handler, ocf_resource_agents)
    _check_removed_resource_agents(
        handler,
        "resource agents",
        unsupported_resource_agents,
        (agent for agent in ocf_resource_agents if agent not in SAP_HANA_RESOURCE_AGENTS),
    )
    _check_removed_resource_agents(
        handler,
        "fence agents",
        unsupported_resource_agents,
        stonith_resource_agents,
    )
    if class_unsupported_resource_agents:
        handler.handle_problem(
            False, True, handler.LEVEL_ERROR,
            'The following resource agents from class "lsb" or "service" are not supported in SLES 16.',
            ('* ' + ':'.join(x for x in dataclasses.astuple(resource_agent) if x is not None) for resource_agent in class_unsupported_resource_agents)
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
            handler.handle_problem(
                False, True, handler.LEVEL_ERROR,
                'SAPHanaSR Classic is removed in SLES 16.', [
                    'Before migrating to SLES 16, replace it with SAPHanaSR-angi.',
                ],
            )


class UnsupportedResourceAgentDetector:
    @dataclasses.dataclass(frozen=True)
    class UnsupportedState:
        alternative: typing.Optional[cibquery.ResourceAgent]
        is_deprecated: bool

    def __init__(self):
        self._unsupported = dict()
        with importlib.resources.files('crmsh').joinpath('migration-unsupported-resource-agents.txt').open(
                'r', encoding='ascii',
        ) as r:
            for line in r:
                parts = line.strip().split(',', 3)
                parts.extend(itertools.repeat('', 2))
                unsupported = self.__resource_agent_from_str(parts[0])
                alternative = parts[1]
                is_deprecated = parts[2] == "deprecated"
                self._unsupported[unsupported] = self.UnsupportedState(
                    self.__resource_agent_from_str(alternative) if alternative != '' else None,
                    is_deprecated,
                )

    def get_unsupported_state(self, resource_agent):
        return self._unsupported.get(resource_agent)

    @staticmethod
    def __resource_agent_from_str(s: str):
        parts = s.split(':', 3)
        m_class = parts[0]
        m_provider = parts[1] if len(parts) == 3 else None
        m_type = parts[-1]
        return cibquery.ResourceAgent(m_class, m_provider, m_type)


def _check_removed_resource_agents(
        handler: CheckResultHandler,
        agent_type_message: str,
        unsupported_resource_agents: UnsupportedResourceAgentDetector,
        resource_agents: typing.Iterable[cibquery.ResourceAgent],
):
    unsupported: typing.List[
        typing.Tuple[cibquery.ResourceAgent, UnsupportedResourceAgentDetector.UnsupportedState]] = list()
    deprecated: typing.List[
        typing.Tuple[cibquery.ResourceAgent, UnsupportedResourceAgentDetector.UnsupportedState]] = list()
    for x in resource_agents:
        unsupported_state = unsupported_resource_agents.get_unsupported_state(x)
        if unsupported_state is None:
            pass
        elif unsupported_state.is_deprecated:
            deprecated.append((x, unsupported_state))
        else:
            unsupported.append((x, unsupported_state))
    if unsupported:
        handler.handle_problem(
            False, True, handler.LEVEL_ERROR,
            f'The following {agent_type_message} are removed in SLES 16.', [
                '* {}{}'.format(
                    ':'.join(x for x in dataclasses.astuple(resource_agent) if x is not None),
                    ': please replace it with {}'.format(
                        ':'.join(x for x in dataclasses.astuple(unsupported_state.alternative) if x is not None)
                ) if unsupported_state.alternative is not None else ''
            )
            for resource_agent, unsupported_state in unsupported
        ])
    if deprecated:
        handler.handle_problem(
            False, False, handler.LEVEL_WARN,
            f'The following {agent_type_message} are deprecated in SLES 16.', [
            '* {}{}'.format(
                ':'.join(x for x in dataclasses.astuple(resource_agent) if x is not None),
                ': please replace it with {}'.format(
                    ':'.join(x for x in dataclasses.astuple(unsupported_state.alternative) if x is not None)
                ) if unsupported_state.alternative is not None else ''
            )
            for resource_agent, unsupported_state in deprecated
        ])


def _check_ocfs2(handler: CheckResultHandler, cib: lxml.etree.Element):
    if cibquery.has_primitive_filesystem_with_fstype(cib, 'ocfs2'):
       handler.handle_problem(
           False, True, handler.LEVEL_ERROR,
           'OCFS2 is not supported in SLES 16. Please use GFS2.', [],
       )

def check_cib_schema_version(handler: CheckResultHandler, cib: lxml.etree.Element):
    schema_version = cib.get('validate-with')
    if schema_version is None:
        handler.handle_problem(
            False, False, handler.LEVEL_WARN,
            "The CIB is validated with unknown schema version.", []
        )
        return
    version_match = re.match(r'^pacemaker-(\d+)\.(\d+)$', schema_version)
    if version_match is None:
        handler.handle_problem(
            False, False, handler.LEVEL_WARN,
            f"The CIB is validated with unknown schema version {schema_version}", []
        )
        return
    version = tuple(int(x) for x in version_match.groups())
    latest_schema_version = _get_latest_cib_schema_version()
    if version != latest_schema_version:
        handler.handle_problem(
            False, False, handler.LEVEL_WARN,
            "The CIB is not validated with the latest schema version.", [
                f'* Latest version:  {".".join(str(i) for i in latest_schema_version)}',
                f'* Current version: {".".join(str(i) for i in version)}',
            ]
        )


def _get_latest_cib_schema_version() -> tuple[int, int]:
    return max(tuple(int(s) for s in x.groups()) for x in (
        re.match(r'^pacemaker-(\d+)\.(\d+)\.rng$', filename)
        for filename in glob.iglob('pacemaker-*.rng', root_dir='/usr/share/pacemaker')
    ) if x is not None)
