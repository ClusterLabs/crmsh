# Copyright (C) 2019 Xin Liang <XLiang@suse.com>
# See COPYING for license information.
import typing

import crmsh.utils
from crmsh.prun import prun


Error = prun.PRunError


def parallax_call(nodes, cmd, *, timeout_seconds: int = -1):
    """
    Executes the given command on a set of hosts, collecting the output, and raise exception when error occurs
    nodes:       a set of hosts
    cmd:         command
    timeout_seconds:    the timeout in seconds.
    Returns [(host, (rc, stdout, stdin)), ...], or raises ValueError when any one of the rc != 0
    """
    results = prun.prun({node: cmd for node in nodes}, timeout_seconds=timeout_seconds)
    for node, result in results.items():
        if isinstance(result, prun.SSHError) and 'authentication failure' in str(result):
            raise ValueError(
                'Failed to run command {} on {}@{}: authentication failure. Please configure passwordless authenticaiton with "crm cluster init ssh" and "crm cluster join ssh".'.format(
                    cmd, result.user, result.host,
                )
            )
        elif isinstance(result, prun.PRunError):
            raise ValueError('Failed to run command {} on {}@{}: {}'.format(cmd, result.user, result.host, result))
        elif result.returncode != 0:
            raise ValueError("Failed on {}: {}".format(node, crmsh.utils.to_ascii(result.stderr)))
    return [(node, (result.returncode, result.stdout, result.stderr)) for node, result in results.items()]


def parallax_slurp(nodes: typing.Sequence[str], localdir, filename) -> typing.List[typing.Tuple[str, typing.Union[str, Error]]]:
    """
    Copies from the remote node to the local node
    nodes:       a set of hosts
    localdir:    localpath
    filename:    remote filename want to slurp
    Returns [(host, localpath), ...] or raises ValueError when any one of hosts fails.
    """
    results = prun.pfetch_from_remote(nodes, filename, localdir)
    for node, result in results.items():
        if isinstance(result, prun.SSHError) and 'authentication failure' in str(result):
            raise ValueError(
                'Failed on {}@{}: authentication failure. Please configure passwordless authentication with "crm cluster init ssh" and "crm cluster join ssh".'.format(
                    result.user, result.host,
                )
            )
        elif isinstance(result, prun.PRunError):
            raise ValueError("Failed on {}@{}: {}".format(result.user, node, result))
    return [(k, v) for k, v in results.items()]


def parallax_copy(nodes, src, dst, recursive=False, *, timeout_seconds: int = -1):
    """
    Copies from the local node to a set of remote hosts
    nodes:       a set of hosts
    src:         local path
    dst:         remote path
    recursive:   whether to copy directories recursively
    timeout_seconds:    the timeout in seconds.
    Returns None, or raises ValueError when any one of hosts fails.
    """
    results = prun.pcopy_to_remote(src, nodes, dst, recursive, timeout_seconds=timeout_seconds)
    for node, exc in results.items():
        if exc is not None:
            raise ValueError("Failed on {}@{}: {}".format(exc.user, node, exc))


def parallax_run(nodes, cmd):
    """
    Executes the given command on a set of hosts, collecting the output and any error
    nodes:       a set of hosts
    cmd:         command

    Returns [(host, (rc, stdout, stdin)), ...], or raises ValueError when any one of the hosts fails to start running
    the command.
    """
    results = prun.prun({node: cmd for node in nodes})
    for value in results.values():
        if isinstance(value, prun.SSHError) and 'authentication failure' in str(value):
            raise ValueError(
                'Failed to run command {} on {}@{}: authentication failure. Please configure passwordless authentication with "crm cluster init ssh" and "crm cluster join ssh".'.format(
                    cmd, value.user, value.host,
                )
            )
        elif isinstance(value, prun.PRunError):
            raise ValueError('Failed to run command {} on {}@{}: {}'.format(cmd, value.user, value.host, value))
    return {node: (result.returncode, result.stdout, result.stderr) for node, result in results.items()}
