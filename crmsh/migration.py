import argparse
import json
import logging
import pkgutil
import re
import subprocess
import sys
import typing

import lxml.etree

from crmsh import cibquery
from crmsh import constants
from crmsh import corosync
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
        sys.stdout.write('\n')


def check(args: typing.Sequence[str]) -> int:
    parser = argparse.ArgumentParser(args[0])
    parser.add_argument('--json', nargs='?', const='pretty', choices=['oneline', 'pretty'])
    parser.add_argument('--local', action='store_true')
    parsed_args = parser.parse_args(args[1:])

    if 'oneline' ==  parsed_args.json:
        handler = CheckResultJsonHandler()
    elif 'pretty' == parsed_args.json:
        handler = CheckResultJsonHandler(indent=2)
    else:
        handler = CheckResultInteractiveHandler()

    ret = 0
    if not parsed_args.local and not parsed_args.json:
        remote_ret = check_remote()
        print('------ corosync @ localhost ------')
        check_local(handler)
        print('------ cib ------')
        check_global(handler)
    else:
        remote_ret = 0
        check_local(handler)
    handler.end()
    if isinstance(handler, CheckResultJsonHandler):
            ret = 0 if handler.json_result["pass"] else 1
    elif isinstance(handler, CheckResultInteractiveHandler):
            if handler.has_problems:
                ret = 1
    if remote_ret > ret:
            ret = remote_ret
    if not parsed_args.json:
        print('****** summary ******')
        if ret == 0:
            CheckResultInteractiveHandler.write_in_color(sys.stdout, constants.GREEN, '[INFO]')
            sys.stdout.write(' Please run "crm cluster health sles16 --fix" on on any one of above nodes, after migrating all the nodes to SLES 16.\n')
            CheckResultInteractiveHandler.write_in_color(sys.stdout, constants.GREEN, '[PASS]')
            sys.stdout.write(' This cluster is good to migrate to SLES 16.\n')
        else:
            CheckResultInteractiveHandler.write_in_color(sys.stdout, constants.RED, '[FAIL]')
            sys.stdout.write(' The pacemaker cluster stack can not migrate to SLES 16. Please fix all the "FAIL" problems above before migrating to SLES 16.\n')
    return ret


def check_local(handler: CheckResultHandler):
    check_dependency_version(handler)
    check_service_status(handler)
    check_unsupported_corosync_features(handler)


def check_remote():
    handler = CheckResultInteractiveHandler()
    result = prun.prun({
        node: 'crm cluster health sles16 --local --json=oneline'
        for node in utils.list_cluster_nodes_except_me()
    })
    ret = 0
    for host, result in result.items():
        sys.stdout.write(f'------ corosync @ {host} ------\n')
        if isinstance(result, prun.SSHError):
                handler.write_in_color(
                    sys.stdout, constants.YELLOW,
                    str(result)
                )
                sys.stdout.write('\n')
                ret = 255
        elif isinstance(result, prun.ProcessResult):
                if result.returncode > 1:
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
                        print(result.stdout.decode('utf-8', 'backslashreplace'))
                        handler.write_in_color(
                            sys.stdout, constants.YELLOW,
                            result.stdout.decode('utf-8', 'backslashreplace')
                        )
                        sys.stdout.write('\n')
                        ret = result.returncode
                    else:
                        passed = result.get("pass", False)
                        handler = CheckResultInteractiveHandler()
                        for problem in result.get("problems", list()):
                            handler.handle_problem(False, problem.get("title", ""), problem.get("descriptions"))
                        for tip in result.get("tips", list()):
                            handler.handle_tip(tip.get("title", ""), tip.get("descriptions"))
                        handler.end()
                        if not passed:
                            ret = 1
    return ret


def check_global(handler: CheckResultHandler):
    check_unsupported_resource_agents(handler)


def check_dependency_version(handler: CheckResultHandler):
    handler.log_info('Checking dependency version...')
    shell = sh.LocalShell()
    out = shell.get_stdout_or_raise_error(None, 'corosync -v')
    _check_version_range(
        handler,
        'Corosync', (2, 4, 6), (3,),
        re.compile(r"version\s+'(\d+(?:\.\d+)*)'"),
        shell.get_stdout_or_raise_error(None, 'corosync -v'),
    )
    _check_version_range(
        handler,
        'Pacemaker', (2, 1, 7), (3,),
        re.compile(r"^Pacemaker\s+(\d+(?:\.\d+)*)"),
        shell.get_stdout_or_raise_error(None, 'pacemakerd --version'),
    )


def _check_version_range(
        handler: CheckResultHandler, component_name: str,
        minimum: tuple, maximum: tuple,
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
        if not minimum <= version < maximum:
            handler.handle_problem(
                False, f'{component_name} version not supported', [
                    'Supported version: {} <= {} < {}'.format(
                        '.'.join(str(x) for x in minimum),
                        component_name,
                        '.'.join(str(x) for x in maximum)
                    ),
                    f'Actual version:    {component_name} == {match.group(1)}',
                ],
            )


def check_service_status(handler: CheckResultHandler):
    handler.log_info('Checking service status...')
    manager = service_manager.ServiceManager()
    inactive_services = [x for x in ['corosync', 'pacemaker'] if not manager.service_is_active(x)]
    if any(inactive_services):
        handler.handle_tip(
            'Cluster services are not running. Check results may be outdated or inaccurate.',
            (f'* {x}' for x in inactive_services),
        )


def check_unsupported_corosync_features(handler: CheckResultHandler):
    handler.log_info("Checking used corosync features...")
    transport = 'udpu' if corosync.is_unicast() else 'udp'
    handler.handle_tip(f'Corosync transport "{transport}" will be deprecated in corosync 3. Please use "knet".', [
    ])
    if corosync.get_value("totem.rrp_mode") in {'active', 'passive'}:
        handler.handle_tip(f'Corosync RRP will be deprecated in corosync 3.', [
            'After migrating to SLES 16, run "crm cluster health sles16 --fix" to migrate it to knet multilink.',
        ])


def check_unsupported_resource_agents(handler: CheckResultHandler):
    handler.log_info("Checking used resource agents...")
    ocf_resource_agents = list()
    stonith_resource_agents = list()
    cib = xmlutil.text2elem(sh.LocalShell().get_stdout_or_raise_error(None, 'crm configure show xml'))
    for resource_agent in cibquery.get_configured_resource_agents(cib):
        if resource_agent.m_class == 'ocf':
            ocf_resource_agents.append(resource_agent)
        elif resource_agent.m_class == 'stonith':
            if resource_agent.m_type == 'external/sbd':
                handler.handle_problem(
                    False,
                    'stonith:external/sbd will be removed in SLES 16.', [
                        'Before migrating to SLES 16, replace it with stonith:fence_sbd.',
                ])
            else:
                stonith_resource_agents.append(resource_agent)
        else:
            raise ValueError(f'Unrecognized resource agent {resource_agent}')
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
    _check_saphana_resource_agent(handler, ocf_resource_agents)
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
    for line in pkgutil.get_data(
        'crmsh', 'migration-supported-resource-agents.txt'
    ).decode('ascii').splitlines():
        parts = line.split(':', 3)
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
            '* ' + ':'.join(x for x in resource_agent if x is not None) for resource_agent in unsupported_resource_agents
        ])


def _check_ocfs2(handler: CheckResultHandler, cib: lxml.etree.Element):
    if cibquery.has_primitive_filesystem_with_fstype(cib, 'ocfs2'):
       handler.handle_problem(False, 'OCFS2 is not supported in SLES 16. Please use GFS2.', [
       ])
