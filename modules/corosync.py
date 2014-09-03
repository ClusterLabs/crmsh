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
from msg import err_buf, common_debug


def conf():
    return os.getenv('COROSYNC_MAIN_CONFIG_FILE', '/etc/corosync/corosync.conf')


def is_corosync_stack():
    return utils.cluster_stack() == 'corosync'


def cfgtool(*args):
    return utils.get_stdout(['corosync-cfgtool'] + list(args), shell=False)


def quorumtool(*args):
    return utils.get_stdout(['corosync-quorumtool'] + list(args), shell=False)

_tCOMMENT = 0
_tBEGIN = 1
_tEND = 2
_tVALUE = 3


class Token(object):
    def __init__(self, token, path, key=None, value=None):
        self.token = token
        self.path = '.'.join(path)
        self.key = key
        self.value = value

    def __repr__(self):
        if self.token == _tCOMMENT:
            return self.key
        elif self.token == _tBEGIN:
            return "%s {" % (self.key)
        elif self.token == _tEND:
            return '}'
        else:
            return '%s: %s' % (self.key, self.value)


def corosync_tokenizer(stream):
    """Parses the corosync config file into a token stream"""
    section_re = re.compile(r'(\w+)\s*{')
    value_re = re.compile(r'(\w+):\s*(\S+)')
    path = []
    while stream:
        stream = stream.lstrip()
        if not stream:
            break
        if stream[0] == '#':
            end = stream.find('\n')
            t = Token(_tCOMMENT, [], stream[:end])
            stream = stream[end:]
            yield t
            continue
        if stream[0] == '}':
            t = Token(_tEND, [])
            stream = stream[1:]
            yield t
            path = path[:-1]
            continue
        m = section_re.match(stream)
        if m:
            path.append(m.group(1))
            t = Token(_tBEGIN, path, m.group(1))
            stream = stream[m.end():]
            yield t
            continue
        m = value_re.match(stream)
        if m:
            t = Token(_tVALUE, path + [m.group(1)], m.group(1), m.group(2))
            stream = stream[m.end():]
            yield t
            continue
        raise ValueError("Parse error at [..%s..]" % (stream[:16]))


def make_section(path, contents=None):
    "Create a token sequence representing a section"
    if not contents:
        contents = []
    sp = path.split('.')
    name = sp[-1]
    for t in contents:
        if t.path and not t.path.startswith(path):
            raise ValueError("%s (%s) not in path %s" % (t.path, t.key, path))
    return [Token(_tBEGIN, sp, name)] + contents + [Token(_tEND, [])]


def make_value(path, value):
    "Create a token sequence representing a value"
    sp = path.split('.')
    name = sp[-1]
    return [Token(_tVALUE, sp, name, value)]


class Parser(object):
    def __init__(self, data):
        self._tokens = list(corosync_tokenizer(data))

    def find(self, name, start=0):
        """Gets the index of the element with the given path"""
        for i, t in enumerate(self._tokens[start:]):
            if t.path == name:
                return i + start
        return -1

    def find_bounds(self, name, start=0):
        """find the (start, end) of the next instance of name found at start"""
        i = self.find(name, start)
        if i < 0:
            return -1, -1
        if self._tokens[i].token != _tBEGIN:
            return i, i
        e = i + 1
        depth = 0
        while e < len(self._tokens):
            t = self._tokens[e]
            if t.token == _tBEGIN:
                depth += 1
            if t.token == _tEND:
                depth -= 1
            if depth < 0:
                break
            e += 1
        if e == len(self._tokens):
            raise ValueError("Unclosed section")
        return i, e

    def get(self, path):
        """Gets the value for the key (if any)"""
        for t in self._tokens:
            if t.token == _tVALUE and t.path == path:
                return t.value
        return None

    def get_all(self, path):
        """Returns all values matching path"""
        ret = []
        for t in self._tokens:
            if t.token == _tVALUE and t.path == path:
                ret.append(t.value)
        return ret

    def all_paths(self):
        """Returns all value paths"""
        ret = []
        for t in self._tokens:
            if t.token == _tVALUE:
                ret.append(t.path)
        return ret

    def count(self, path):
        """Returns the number of elements matching path"""
        n = 0
        for t in self._tokens:
            if t.path == path:
                n += 1
        return n

    def remove(self, path):
        """Removes the given section or value"""
        i, e = self.find_bounds(path)
        if i < 0:
            return
        self._tokens = self._tokens[:i] + self._tokens[(e+1):]

    def remove_section_where(self, path, key, value):
        """
        Remove section which contains key: value
        Used to remove node definitions
        """
        nth = -1
        start = 0
        keypath = '.'.join([path, key])
        while True:
            nth += 1
            i, e = self.find_bounds(path, start)
            start = e + 1
            if i < 0:
                break
            k = self.find(keypath, i)
            if k < 0 or k > e:
                continue
            vt = self._tokens[k]
            if vt.token == _tVALUE and vt.value == value:
                self._tokens = self._tokens[:i] + self._tokens[(e+1):]
                return nth
        return -1

    def add(self, path, tokens):
        """Adds tokens to a section"""
        common_debug("corosync.add (%s) (%s)" % (path, tokens))
        if not path:
            self._tokens += tokens
            return
        start = self.find(path)
        if start < 0:
            return None
        depth = 0
        end = None
        for i, t in enumerate(self._tokens[start + 1:]):
            if t.token == _tBEGIN:
                depth += 1
            elif t.token == _tEND:
                depth -= 1
            if depth < 0:
                end = start + i + 1
                break
        if end is None:
            raise ValueError("Unterminated section at %s" % (start))
        self._tokens = self._tokens[:end] + tokens + self._tokens[end:]

    def set(self, path, value):
        """Sets a key: value entry. sections are given
        via dot-notation."""
        i = self.find(path)
        if i < 0:
            spath = path.split('.')
            return self.add('.'.join(spath[:-1]),
                            make_value(path, value))
        if self._tokens[i].token != _tVALUE:
            raise ValueError("%s is not a value" % (path))
        self._tokens[i].value = value

    def to_string(self):
        '''
        Serialize tokens into the corosync.conf
        file format
        '''
        def joiner(tstream):
            indent = 0
            last = None
            while tstream:
                t = tstream[0]
                if indent and t.token == _tEND:
                    indent -= 1
                s = ''
                if t.token == _tCOMMENT and (last and last.token != _tCOMMENT):
                    s += '\n'
                s += ('\t'*indent) + str(t) + '\n'
                if t.token == _tEND:
                    s += '\n'
                yield s
                if t.token == _tBEGIN:
                    indent += 1
                last = t
                tstream = tstream[1:]
        return ''.join(joiner(self._tokens))


def logfile(conftext):
    '''
    Return corosync logfile (if set)
    '''
    return Parser(conftext).get('logging.logfile')


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


def next_nodeid(parser):
    ids = parser.get_all('nodelist.node.nodeid')
    if not ids:
        return 1
    return max([int(i) for i in ids]) + 1


def get_ip(node):
    try:
        return socket.gethostbyname(node)
    except:
        return None


def get_all_paths():
    f = open(conf()).read()
    p = Parser(f)
    return p.all_paths()


def get_value(path):
    f = open(conf()).read()
    p = Parser(f)
    return p.get(path)


def get_values(path):
    f = open(conf()).read()
    p = Parser(f)
    return p.get_all(path)


def set_value(path, value):
    f = open(conf()).read()
    p = Parser(f)
    p.set(path, value)
    f = open(conf(), 'w')
    f.write(p.to_string())
    f.close()


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

    f = open(conf()).read()
    p = Parser(f)

    node_addr = name
    node_id = next_nodeid(p)

    p.add('nodelist',
          make_section('nodelist.node',
                       make_value('nodelist.node.ring0_addr', node_addr) +
                       make_value('nodelist.node.nodeid', str(node_id))))

    num_nodes = p.count('nodelist.node')
    if num_nodes > 2:
        p.remove('quorum.two_node')

    f = open(conf(), 'w')
    f.write(p.to_string())
    f.close()

    # update running config (if any)
    if nodes:
        utils.ext_cmd(["corosync-cmapctl",
                       "-s", "nodelist.node.%s.nodeid" % (num_nodes - 1),
                       "u32", str(node_id)], shell=False)
        utils.ext_cmd(["corosync-cmapctl",
                       "-s", "nodelist.node.%s.ring0_addr" % (num_nodes - 1),
                       "str", node_addr], shell=False)


def del_node(addr):
    '''
    Remove node from corosync
    '''
    f = open(conf()).read()
    p = Parser(f)
    nth = p.remove_section_where('nodelist.node', 'ring0_addr', addr)
    if nth == -1:
        return

    if p.count('nodelist.node') <= 2:
        p.set('quorum.two_node', '1')

    f = open(conf(), 'w')
    f.write(p.to_string())
    f.close()

    # check for running config
    try:
        nodes = utils.list_cluster_nodes()
    except Exception:
        nodes = []
    if nodes:
        utils.ext_cmd(["corosync-cmapctl", "-D", "nodelist.node.%s.nodeid" % (nth)],
                      shell=False)
        utils.ext_cmd(["corosync-cmapctl", "-D", "nodelist.node.%s.ring0_addr" % (nth)],
                      shell=False)
