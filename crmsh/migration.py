import logging
import re
import typing

from crmsh import service_manager
from crmsh import sh

logger = logging.getLogger(__name__)


class MigrationFailure(Exception):
    pass


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
