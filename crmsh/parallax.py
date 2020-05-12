# Copyright (C) 2019 Xin Liang <XLiang@suse.com>
# See COPYING for license information.


import os
import parallax


class Parallax(object):
    """
    # Parallax SSH API
    # call: Executes the given command on a set of hosts, collecting the output
    # copy: Copies files from the local machine to a set of remote hosts
    # slurp: Copies files from a set of remote hosts to local folders
    """
    def __init__(self, nodes, cmd=None, localdir=None, filename=None,
                 src=None, dst=None, askpass=False, ssh_options=None):
        self.nodes = nodes
        self.askpass = askpass
        self.ssh_options = ssh_options

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
            self.ssh_options = ['StrictHostKeyChecking=no', 'ConnectTimeout=10']
        opts.ssh_options = self.ssh_options
        opts.askpass = self.askpass
        # warn_message will available from parallax-1.0.5
        if hasattr(opts, 'warn_message'):
            opts.warn_message = False
        opts.localdir = self.localdir
        return opts

    def handle(self, results):
        for host, result in results:
            if isinstance(result, parallax.Error):
                raise ValueError("Failed on {}: {}".format(host, result))
        return results

    def call(self):
        results = parallax.call(self.nodes, self.cmd, self.opts)
        return self.handle(list(results.items()))

    def slurp(self):
        dst = os.path.basename(self.filename)
        results = parallax.slurp(self.nodes, self.filename, dst, self.opts)
        return self.handle(list(results.items()))

    def copy(self):
        results = parallax.copy(self.nodes, self.src, self.dst, self.opts)
        return self.handle(list(results.items()))


def parallax_call(nodes, cmd, askpass=False, ssh_options=None):
    """
    Executes the given command on a set of hosts, collecting the output
    nodes:       a set of hosts
    cmd:         command
    askpass:     Ask for a password if passwordless not configured
    ssh_options: Extra options to pass to SSH
    Returns [(host, (rc, stdout, stdin)), ...] or ValueError exception
    """
    p = Parallax(nodes, cmd=cmd, askpass=askpass, ssh_options=ssh_options)
    return p.call()


def parallax_slurp(nodes, localdir, filename, askpass=False, ssh_options=None):
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
                 askpass=askpass, ssh_options=ssh_options)
    return p.slurp()


def parallax_slurp_one(node, localdir, filename, askpass=False, ssh_options=None):
    """
    Copies from the remote node to the local node
    Unlike the parallax_slurp it doesn't create a folder for each node
    It simply copies the source file to the localdir
    node:        one host
    localdir:    localpath
    filename:    remote filename want to slurp
    askpass:     Ask for a password if passwordless not configured
    ssh_options: Extra options to pass to SSH
    Returns (host, (rc, stdout, stdin, localpath)) or ValueError exception
    """
    p = Parallax([node], localdir=localdir, filename=filename,
                 askpass=askpass, ssh_options=ssh_options)
    result = p.slurp()[0]
    dest = src = result[1][3]
    from_where = os.path.join(localdir, result[0])
    if from_where in dest:
        dest = dest.replace(from_where, '')
    while dest[0] == '/':
        dest = dest[1:]
    dest = os.path.join(localdir, dest)
    os.replace(src, dest)
    os.rmdir(from_where)
    return (result[0], (result[1][0], result[1][1], result[1][2], dest))

def parallax_copy(nodes, src, dst, askpass=False, ssh_options=None):
    """
    Copies from the local node to a set of remote hosts
    nodes:       a set of hosts
    src:         local path
    dst:         remote path
    askpass:     Ask for a password if passwordless not configured
    ssh_options: Extra options to pass to SSH
    Returns [(host, (rc, stdout, stdin)), ...] or ValueError exception
    """
    p = Parallax(nodes, src=src, dst=dst, askpass=askpass, ssh_options=ssh_options)
    return p.copy()
