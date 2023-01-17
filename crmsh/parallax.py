# Copyright (C) 2019 Xin Liang <XLiang@suse.com>
# See COPYING for license information.


import os
import parallax
import crmsh.utils

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
            host_port_user.append([host, None, crmsh.utils.user_of(host)])
        results = parallax.call(host_port_user, self.cmd, self.opts)
        return self.handle(list(results.items()))

    def slurp(self):
        dst = os.path.basename(self.filename)
        results = parallax.slurp(self.nodes, self.filename, dst, self.opts)
        return self.handle(list(results.items()))

    def copy(self):
        results = parallax.copy(self.nodes, self.src, self.dst, self.opts)
        return self.handle(list(results.items()))
    def run(self):
        return parallax.run(
            [[node, None, crmsh.utils.user_of(node)] for node in self.nodes],
            self.cmd,
            self.opts,
        )


def parallax_call(nodes, cmd, askpass=False, ssh_options=None, strict=True):
    """
    Executes the given command on a set of hosts, collecting the output, and raise exception when error occurs
    nodes:       a set of hosts
    cmd:         command
    askpass:     Ask for a password if passwordless not configured
    ssh_options: Extra options to pass to SSH
    Returns [(host, (rc, stdout, stdin)), ...] or ValueError exception
    """
    p = Parallax(nodes, cmd=cmd, askpass=askpass, ssh_options=ssh_options, strict=strict)
    return p.call()


def parallax_slurp(nodes, localdir, filename, askpass=False, ssh_options=None, strict=True):
    """
    Copies from the remote node to the local node
    nodes:       a set of hosts
    localdir:    localpath
    filename:    remote filename want to slurp
    askpass:     Ask for a password if passwordless not configured
    ssh_options: Extra options to pass to SSH
    Returns [(host, (rc, stdout, stdin, localpath)), ...] or ValueError exception
    """
    p = Parallax(nodes, localdir=localdir, filename=filename,
            askpass=askpass, ssh_options=ssh_options, strict=strict)
    return p.slurp()


def parallax_copy(nodes, src, dst, askpass=False, ssh_options=None, strict=True):
    """
    Copies from the local node to a set of remote hosts
    nodes:       a set of hosts
    src:         local path
    dst:         remote path
    askpass:     Ask for a password if passwordless not configured
    ssh_options: Extra options to pass to SSH
    Returns [(host, (rc, stdout, stdin)), ...] or ValueError exception
    """
    p = Parallax(nodes, src=src, dst=dst, askpass=askpass, ssh_options=ssh_options, strict=strict)
    return p.copy()

def parallax_run(nodes, cmd, askpass=False, ssh_options=None, strict=True):
    """
    Executes the given command on a set of hosts, collecting the output and any error
    nodes:       a set of hosts
    cmd:         command
    askpass:     Ask for a password if passwordless not configured
    ssh_options: Extra options to pass to SSH
    Returns [(host, (rc, stdout, stdin)), ...] or ValueError exception
    """
    p = Parallax(nodes, cmd=cmd, askpass=askpass, ssh_options=ssh_options, strict=strict)
    return p.run()
