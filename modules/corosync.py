# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
'''
Functions that abstract creating and editing the corosync.conf
configuration file, and also the corosync-* utilities.
'''

import os
import utils


def conf():
    return os.getenv('COROSYNC_MAIN_CONFIG_FILE', '/etc/corosync/corosync.conf')


def is_corosync_stack():
    return utils.cluster_stack() == 'corosync'


def cfgtool(*args):
    return utils.get_stdout(['corosync-cfgtool'] + list(args), shell=False)


def quorumtool(*args):
    return utils.get_stdout(['corosync-quorumtool'] + list(args), shell=False)


class CorosyncConf(object):
    def __init__(self):
        self._data = None

    def parse(self, data):
        '''
        Parse the corosync.conf data into this object
        '''
        self._data = data
        return True

    def to_string(self):
        '''
        Serialize data into file format
        '''
        return self._data


def load():
    cfgfile = conf()
    data = ''
    if os.path.isfile(cfgfile):
        f = open(conf(), 'r')
        data = f.read()
        f.close()
    cfg = CorosyncConf()
    if not cfg.parse(data):
        return None
    return cfg


def push_configuration(nodes):
    '''
    Push the local configuration to the list of remote nodes
    '''
    try:
        from psshlib import api as pssh
        _has_pssh = True
    except ImportError:
        _has_pssh = False

    if not _has_pssh:
        raise ValueError("PSSH is required to push")
    from msg import err_buf

    local_path = conf()

    opts = pssh.Options()
    opts.timeout = 60
    opts.ssh_options += ['ControlPersist=no']
    ok = True
    for host, result in pssh.copy(nodes,
                                  local_path,
                                  local_path, opts).iteritems():
        if isinstance(result, pssh.Error):
            err_buf.error("Failed to push configuration to %s: %s" % (host, result))
            ok = False
        else:
            err_buf.ok(host)
    return ok


def pull_configuration(from_node):
    '''
    Copy the configuration from the given node to this node
    '''
    import tmpfiles
    local_path = conf()
    fd, fname = tmpfiles.create()
    print "Retrieving %s:%s..." % (from_node, local_path)
    cmd = ['scp', '-qC',
           '-o', 'PasswordAuthentication=no',
           '-o', 'StrictHostKeyChecking=no',
           '%s:%s' % (from_node, local_path),
           fname]
    rc = utils.ext_cmd_nosudo(cmd, shell=False)
    if rc == 0:
        data = open(fname).read()
        newhash = hash(data)
        if os.path.isfile(local_path):
            oldata = open(local_path).read()
            oldhash = hash(oldata)
            if newhash == oldhash:
                print "No change."
                return
        print "Writing %s..."
        local_file = open(local_path, 'w')
        local_file.write(data)
        local_file.close()
    else:
        raise ValueError("Failed to retrieve %s from %s" % (local_path, from_node))


def diff_configuration(nodes, checksum=False):
    try:
        from psshlib import api as pssh
        _has_pssh = True
    except ImportError:
        _has_pssh = False

    if not _has_pssh:
        raise ValueError("PSSH is required to diff")

    import tmpfiles
    local_path = conf()

    this_node = utils.this_node()
    nodes = list(nodes)

    if checksum or len(nodes) > 2:
        tmpdir = tmpfiles.create_dir()
        opts = pssh.Options()
        opts.localdir = tmpdir
        to = os.path.basename(local_path)
        by_host = pssh.slurp(nodes, local_path, to, opts).items()
        for host, result in by_host:
            if isinstance(result, pssh.Error):
                raise ValueError(str(result))

        import hashlib

        print "%-16s  SHA1 checksum of %s" % ('Host', local_path)
        if this_node not in nodes:
            print "%-16s: %s" % (this_node, hashlib.sha1(open(local_path).read()).hexdigest())
        for host, result in by_host:
            rc, _, _, path = result
            print "%-16s: %s" % (host, hashlib.sha1(open(path).read()).hexdigest())
    elif len(nodes) == 1:
        tmpdir = tmpfiles.create_dir()
        opts = pssh.Options()
        opts.localdir = tmpdir
        to = os.path.basename(local_path)
        by_host = pssh.slurp(nodes, local_path, to, opts)
        for host, result in by_host.iteritems():
            if isinstance(result, pssh.Error):
                raise ValueError("Failed on %s: %s" % (host, str(result)))
            rc, _, _, path = result
            rc, s = utils.get_stdout("diff -U 0 -d -b --label %s --label %s %s %s" %
                                     (host, this_node, path, local_path))
            utils.page_string(s)
    elif this_node in nodes:
        nodes.remove(this_node)
        tmpdir = tmpfiles.create_dir()
        opts = pssh.Options()
        opts.localdir = tmpdir
        to = os.path.basename(local_path)
        by_host = pssh.slurp(nodes, local_path, to, opts)
        for host, result in by_host.iteritems():
            if isinstance(result, pssh.Error):
                raise ValueError("Failed on %s: %s" % (host, str(result)))
            rc, _, _, path = result
            rc, s = utils.get_stdout("diff -U 0 -d -b --label %s --label %s %s %s" %
                                     (host, this_node, path, local_path))
            utils.page_string(s)
    elif len(nodes):
        tmpdir = tmpfiles.create_dir()
        opts = pssh.Options()
        opts.localdir = tmpdir
        to = os.path.basename(local_path)
        by_host = pssh.slurp(nodes, local_path, to, opts).items()
        for host, result in by_host:
            if isinstance(result, pssh.Error):
                raise ValueError("Failed on %s: %s" % (host, str(result)))
        h1, r1 = by_host[0]
        h2, r2 = by_host[1]
        rc, s = utils.get_stdout("diff -U 0 -d -b --label %s --label %s %s %s" %
                                 (h1, h2, r1[3], r2[3]))
        utils.page_string(s)
