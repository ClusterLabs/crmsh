# Copyright (C) 2019 Xin Liang <XLiang@suse.com>
# See COPYING for license information.
import typing

import os

import parallax
import crmsh.utils
from crmsh import userdir
from crmsh.prun import prun

Error = parallax.Error


class Parallax(object):
    """
    # Parallax SSH API
    # call: Executes the given command on a set of hosts, collecting the output
    # copy: Copies files from the local machine to a set of remote hosts
    # slurp: Copies files from a set of remote hosts to local folders
    """
    def __init__(self, nodes, cmd=None, localdir=None, filename=None,
            src=None, dst=None, askpass=False, ssh_options=None, strict=True):
        self.nodes = nodes
        self.askpass = askpass
        self.ssh_options = ssh_options
        self._sudoer = None
        self.strict = strict

        # used for call
        self.cmd = cmd
        # used for slurp
        self.localdir = localdir
        self.filename = filename
        # used for copy
        self.src = src
        self.dst = dst

        self.opts = self.prepare()

    def prepare(self):
        opts = parallax.Options()
        if self.ssh_options is None:
            self.ssh_options = ['StrictHostKeyChecking=no',
                    'ConnectTimeout=10',
                    'LogLevel=error']
        sudoer, _ = crmsh.utils.user_pair_for_ssh(self.nodes[0])
        if sudoer is not None:
            # FIXME: this is really unreliable
            self.ssh_options.append('IdentityFile={}/.ssh/id_rsa'.format(userdir.gethomedir(sudoer)))
            self._sudoer = sudoer
        opts.ssh_options = self.ssh_options
        opts.askpass = self.askpass
        # warn_message will available from parallax-1.0.5
        if hasattr(opts, 'warn_message'):
            opts.warn_message = False
        opts.localdir = self.localdir
        return opts

    def handle(self, results):
        for host, result in results:
            if isinstance(result, parallax.Error) and self.strict:
                raise ValueError("Failed on {}: {}".format(host, result))
        return results

    def call(self):
        host_port_user = []
        for host in self.nodes:
            _, remote_user = crmsh.utils.user_pair_for_ssh(host)
            host_port_user.append([host, None, remote_user])
        # FIXME: this is really unreliable
        sudoer = userdir.get_sudoer()
        cmd = f'sudo bash -c "{self.cmd}"' if sudoer else self.cmd
        results = parallax.call(host_port_user, cmd, self.opts)
        return self.handle(list(results.items()))

    def slurp(self):
        dst = os.path.basename(self.filename)
        results = parallax.slurp(self.nodes, self.filename, dst, self.opts)
        return self.handle(list(results.items()))

    def copy(self):
        results = parallax.copy(self.nodes, self.src, self.dst, self.opts)
        return self.handle(list(results.items()))
    def run(self):
        sudoer = userdir.get_sudoer()
        cmd = f'sudo bash -c "{self.cmd}"' if sudoer else self.cmd
        host_port_user = []
        for host in self.nodes:
            _, remote_user = crmsh.utils.user_pair_for_ssh(host)
            host_port_user.append([host, None, remote_user])
        return parallax.run(host_port_user, cmd, self.opts)


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
