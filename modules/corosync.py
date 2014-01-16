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
import re
import utils
import tmpfiles
import socket
from msg import err_buf


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

    def get_logfile(self):
        '''
        Return corosync logfile (if set)
        '''
        m = re.search(r"^\s*logfile:\s*(.+)$", self._data, re.M)
        if m:
            return m.group(1)
        return None

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
    local_path = conf()
    _, fname = tmpfiles.create()
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


def _diff_slurp(pssh, nodes, filename):
    tmpdir = tmpfiles.create_dir()
    opts = pssh.Options()
    opts.localdir = tmpdir
    dst = os.path.basename(filename)
    return pssh.slurp(nodes, filename, dst, opts).items()


def _diff_this(pssh, local_path, nodes, this_node):
    by_host = _diff_slurp(pssh, nodes, local_path)
    for host, result in by_host:
        if isinstance(result, pssh.Error):
            raise ValueError("Failed on %s: %s" % (host, str(result)))
        _, _, _, path = result
        _, s = utils.get_stdout("diff -U 0 -d -b --label %s --label %s %s %s" %
                                (host, this_node, path, local_path))
        utils.page_string(s)


def _diff(pssh, local_path, nodes):
    by_host = _diff_slurp(pssh, nodes, local_path)
    for host, result in by_host:
        if isinstance(result, pssh.Error):
            raise ValueError("Failed on %s: %s" % (host, str(result)))
    h1, r1 = by_host[0]
    h2, r2 = by_host[1]
    _, s = utils.get_stdout("diff -U 0 -d -b --label %s --label %s %s %s" %
                            (h1, h2, r1[3], r2[3]))
    utils.page_string(s)


def _checksum(pssh, local_path, nodes, this_node):
    import hashlib

    by_host = _diff_slurp(pssh, nodes, local_path)
    for host, result in by_host:
        if isinstance(result, pssh.Error):
            raise ValueError(str(result))

    print "%-16s  SHA1 checksum of %s" % ('Host', local_path)
    if this_node not in nodes:
        print "%-16s: %s" % (this_node, hashlib.sha1(open(local_path).read()).hexdigest())
    for host, result in by_host:
        _, _, _, path = result
        print "%-16s: %s" % (host, hashlib.sha1(open(path).read()).hexdigest())


def diff_configuration(nodes, checksum=False):
    try:
        from psshlib import api as pssh
        _has_pssh = True
    except ImportError:
        _has_pssh = False
    if not _has_pssh:
        raise ValueError("PSSH is required to diff")

    local_path = conf()
    this_node = utils.this_node()
    nodes = list(nodes)
    if checksum or len(nodes) > 2:
        _checksum(pssh, local_path, nodes, this_node)
    elif len(nodes) == 1:
        _diff_this(pssh, local_path, nodes, this_node)
    elif this_node in nodes:
        nodes.remove(this_node)
        _diff_this(pssh, local_path, nodes, this_node)
    elif len(nodes):
        _diff(pssh, local_path, nodes)


def next_nodeid():
    f = open(conf()).read()
    p = re.compile(r"nodeid:\s*([0-9]+)")
    ids = [int(m) for m in p.findall(f)]
    if ids:
        return max(ids) + 1
    return 1


def insert_section(config, section, block):
    """
    In the section { ... }, insert the block
    Returns updated config
    """
    lines = config
    out = []
    in_section = False
    brackets = 0
    at = None
    found = False
    section_re = re.compile('%s\\s*{' % (section))
    for linenum in xrange(len(lines)):
        at = linenum
        line = lines[linenum]
        if not in_section and section_re.search(line):
            in_section = True
        if in_section:
            brackets += line.count('{')
            brackets -= line.count('}')
            if brackets == 0:
                found = True
                break
        out.append(line)
    if found:
        out += block.split('\n')
    else:
        out += ("\n%s {\n%s\n}\n" % (section, block)).split('\n')
    for line in lines[at:]:
        out.append(line)
    return out


def get_ip(node):
    try:
        return socket.gethostbyname(node)
    except:
        return None


def add_node(name):
    '''
    Add node to corosync.conf
    '''
    coronodes = None
    nodes = None
    coronodes = utils.list_corosync_nodes()
    try:
        nodes = utils.list_cluster_nodes()
    except Exception:
        nodes = []
    ipaddr = get_ip(name)
    if name in coronodes or (ipaddr and ipaddr in coronodes):
        err_buf.warning("%s already in corosync.conf" % (name))
        return
    if name in nodes:
        err_buf.warning("%s already in configuration" % (name))
        return

    node_addr = name
    node_id = next_nodeid()
    f = open(conf())
    lines = f.read().split('\n')
    f.close()
    block = """    node {
        ring0_addr: %s
        nodeid: %s
    }
""" % (node_addr, node_id)
    out = insert_section(lines, 'nodelist', block)

    f = open(conf(), 'w')
    f.write('\n'.join(out))
    f.close()

    # update running config (if any)
    if nodes:
        utils.ext_cmd(["corosync-cmapctl",
                       "-s", "nodelist.node.%s.nodeid" % (node_id - 1),
                       "u32", str(node_id)], shell=False)
        utils.ext_cmd(["corosync-cmapctl",
                       "-s", "nodelist.node.%s.ring0_addr" % (node_id - 1),
                       "str", node_addr], shell=False)
