# Copyright (C) 2019 Xin Liang <XLiang@suse.com>
# See COPYING for license information.
import typing

import crmsh.utils
from crmsh.prun import prun


Error = prun.PRunError


def parallax_call(nodes, cmd):
    """
    Executes the given command on a set of hosts, collecting the output, and raise exception when error occurs
    nodes:       a set of hosts
    cmd:         command
    Returns [(host, (rc, stdout, stdin)), ...] or ValueError exception
    """
    results = prun.prun({node: cmd for node in nodes})
    for node, result in results.items():
        if isinstance(result, prun.SSHError):
            raise ValueError("Failed on {}@{}: {}".format(result.user, node, result))
        elif result.returncode != 0:
            raise ValueError("Failed on {}: {}".format(node, crmsh.utils.to_ascii(result.stderr)))
    return [(node, (result.returncode, result.stdout, result.stderr)) for node, result in results.items()]


def parallax_slurp(nodes: typing.Sequence[str], localdir, filename, askpass=False, ssh_options=None, strict=True) -> typing.List[typing.Tuple[str, typing.Union[str, Error]]]:
    """
    Copies from the remote node to the local node
    nodes:       a set of hosts
    localdir:    localpath
    filename:    remote filename want to slurp
    askpass:     Ask for a password if passwordless not configured
    ssh_options: Extra options to pass to SSH
    Returns [(host, (rc, stdout, stdin, localpath)), ...] or ValueError exception
    """
    results = prun.pfetch_from_remote(nodes, filename, localdir)
    for node, result in results.items():
        if isinstance(result, prun.PRunError):
            raise ValueError("Failed on {}@{}: {}".format(result.user, node, result))
    return [(k, v) for k, v in results.items()]


def parallax_copy(nodes, src, dst, recursive=False):
    """
    Copies from the local node to a set of remote hosts
    nodes:       a set of hosts
    src:         local path
    dst:         remote path
    askpass:     Ask for a password if passwordless not configured
    ssh_options: Extra options to pass to SSH
    Returns [(host, (rc, stdout, stdin)), ...] or ValueError exception
    """
    results = prun.pcopy_to_remote(src, nodes, dst, recursive)
    for node, exc in results.items():
        if exc is not None:
            raise ValueError("Failed on {}@{}: {}".format(exc.user, node, exc))

def parallax_run(nodes, cmd):
    """
    Executes the given command on a set of hosts, collecting the output and any error
    nodes:       a set of hosts
    cmd:         command
    askpass:     Ask for a password if passwordless not configured
    ssh_options: Extra options to pass to SSH
    Returns [(host, (rc, stdout, stdin)), ...] or ValueError exception
    """
    results = prun.prun({node: cmd for node in nodes})
    return {node: (result.returncode, result.stdout, result.stderr) for node, result in results.items()}
