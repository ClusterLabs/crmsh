import argparse
import itertools
import json
import logging
import re
import sys
import threading
import typing

from crmsh import constants
from crmsh import service_manager
from crmsh import sh
from crmsh import utils
from crmsh.prun import prun

logger = logging.getLogger(__name__)


class MigrationFailure(Exception):
    pass


class CheckResultHandler:
    def log_info(self, fmt: str, *args):
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
        }
    def log_info(self, fmt: str, *args):
        logger.debug(fmt, *args)

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

    @staticmethod
    def write_in_color(f, color: str, text: str):
        if f.isatty():
            f.write(color)
            f.write(text)
            f.write(constants.END)
        else:
            f.write(text)

    def end(self):
        if not self.has_problems:
            self.write_in_color(sys.stdout, constants.GREEN, '[PASS]\n\n')


def check(args: typing.Sequence[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--json', nargs='?', const='pretty', choices=['oneline', 'pretty'])
    parser.add_argument('--local', action='store_true')
    parsed_args = parser.parse_args(args)
    ret = 0
    if not parsed_args.local and not parsed_args.json:
        check_remote_yield = check_remote()
        next(check_remote_yield)
        print('------ localhost ------')
    else:
        check_remote_yield = itertools.repeat(0)
    match parsed_args.json:
        case 'oneline':
            handler = CheckResultJsonHandler()
        case 'pretty':
            handler = CheckResultJsonHandler(indent=2)
        case _:
            handler = CheckResultInteractiveHandler()
    check_local(handler)
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
    handler.end()


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
                    f'------ {host} ------\n',
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
                        f'------ {host} ------\n',
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
                            f'------ {host} ------\n',
                        )
                        handler = CheckResultInteractiveHandler()
                        for problem in result.get("problems", list()):
                            handler.handle_problem(False, problem.get("title", ""), problem.get("descriptions"))
                        handler.end()
                        if not passed:
                            ret = 1
    yield ret


def check_dependency_version(handler: CheckResultHandler):
    handler.log_info('Checking dependency version...')
    shell = sh.LocalShell()
    out = shell.get_stdout_or_raise_error(None, 'corosync -v')
    match = re.search(r"version\s+'((\d+)(?:\.\d+)*)'", out)
    if not match or match.group(2) != '3':
        handler.handle_problem(
            False, 'Corosync version not supported', [
                'Supported version: corosync >= 3',
                f'Actual version:    corosync == {match.group(1)}',
            ],
        )


def check_service_status(handler: CheckResultHandler):
    handler.log_info('Checking service status...')
    manager = service_manager.ServiceManager()
    active_services = [x for x in ['corosync', 'pacemaker'] if manager.service_is_active(x)]
    if active_services:
        handler.handle_problem(False, 'Cluster services are running', (f'* {x}' for x in active_services))


def check_unsupported_corosync_features(handler: CheckResultHandler):
    pass
