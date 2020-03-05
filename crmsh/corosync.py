# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.
'''
Functions that abstract creating and editing the corosync.conf
configuration file, and also the corosync-* utilities.
'''

import os
import re
import socket
from . import utils
from . import tmpfiles
from .msg import err_buf, common_debug


def conf():
    return os.getenv('COROSYNC_MAIN_CONFIG_FILE', '/etc/corosync/corosync.conf')


def is_corosync_stack():
    return utils.cluster_stack() == 'corosync'


def check_tools():
    return all(utils.is_program(p)
               for p in ['corosync-cfgtool', 'corosync-quorumtool', 'corosync-cmapctl'])


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
    return utils.cluster_copy_file(conf(), nodes)


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


def diff_configuration(nodes, checksum=False):
    local_path = conf()
    this_node = utils.this_node()
    nodes = list(nodes)
    if checksum:
        utils.remote_checksum(local_path, nodes, this_node)
    elif len(nodes) == 1:
        utils.remote_diff_this(local_path, nodes, this_node)
    elif this_node in nodes:
        nodes.remove(this_node)
        utils.remote_diff_this(local_path, nodes, this_node)
    elif len(nodes):
        utils.remote_diff(local_path, nodes)


def get_free_nodeid(parser):
    ids = parser.get_all('nodelist.node.nodeid')
    if not ids:
        return 1
    ids = [int(i) for i in ids]
    max_id = max(ids) + 1
    for i in xrange(1, max_id):
        if i not in ids:
            return i
    return max_id


def get_ip(node):
    try:
        return socket.gethostbyname(node)
    except socket.error:
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


class IPAlreadyConfiguredError(Exception):
    pass


def find_configured_ip(ip_list):
    """
    find if the same IP already configured
    If so, raise IPAlreadyConfiguredError
    """
    with open(conf()) as f:
        p = Parser(f.read())

    # get exist ip list from corosync.conf
    corosync_iplist = []
    for path in set(p.all_paths()):
        if re.search('nodelist.node.ring[0-9]*_addr', path):
            corosync_iplist.extend(p.get_all(path))

    # all_possible_ip is a ip set to check whether one of them already configured
    all_possible_ip = set(ip_list)
    # get local ip list
    is_ipv6 = utils.IP.is_ipv6(ip_list[0])
    local_ip_list = utils.InterfacesInfo.get_local_ip_list(is_ipv6)
    # extend all_possible_ip if ip_list contain local ip
    # to avoid this scenarios in join node:
    #   eth0's ip already configured in corosync.conf
    #   eth1's ip also want to add in nodelist
    # if this scenarios happened, raise IPAlreadyConfiguredError
    if bool(set(ip_list) & set(local_ip_list)):
        all_possible_ip |= set(local_ip_list)
    configured_ip = list(all_possible_ip & set(corosync_iplist))
    if configured_ip:
        raise IPAlreadyConfiguredError("IP {} was already configured".format(','.join(configured_ip)))


def add_node_ucast(ip_list, node_id=None):

    find_configured_ip(ip_list)

    with open(conf()) as f:
        p = Parser(f.read())

    if node_id is None:
        node_id = get_free_nodeid(p)
    node_value = []
    for i, addr in enumerate(ip_list):
        node_value += make_value('nodelist.node.ring{}_addr'.format(i), addr)
    node_value += make_value('nodelist.node.nodeid', str(node_id))

    p.add('nodelist', make_section('nodelist.node', node_value))

    num_nodes = p.count('nodelist.node')
    p.set('quorum.two_node', '1' if num_nodes == 2 else '0')

    with open(conf(), 'w') as f:
        f.write(p.to_string())


def add_node(addr, name=None):
    '''
    Add node to corosync.conf
    '''
    coronodes = None
    nodes = None
    nodenames = None
    coronodes = utils.list_corosync_nodes()
    nodenames = utils.list_corosync_node_names()
    try:
        nodes = utils.list_cluster_nodes()
    except Exception:
        nodes = []
    ipaddr = get_ip(addr)
    if addr in nodenames + coronodes or (ipaddr and ipaddr in coronodes):
        err_buf.warning("%s already in corosync.conf" % (addr))
        return
    if name and name in nodenames + coronodes:
        err_buf.warning("%s already in corosync.conf" % (name))
        return
    if addr in nodes:
        err_buf.warning("%s already in configuration" % (addr))
        return
    if name and name in nodes:
        err_buf.warning("%s already in configuration" % (name))
        return

    f = open(conf()).read()
    p = Parser(f)

    node_addr = addr
    node_id = get_free_nodeid(p)
    node_name = name
    node_value = (make_value('nodelist.node.ring0_addr', node_addr) +
                  make_value('nodelist.node.nodeid', str(node_id)))
    if node_name:
        node_value += make_value('nodelist.node.name', node_name)

    p.add('nodelist', make_section('nodelist.node', node_value))

    num_nodes = p.count('nodelist.node')
    p.set('quorum.two_node', '1' if num_nodes == 2 else '0')

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
        if node_name:
            utils.ext_cmd(["corosync-cmapctl",
                           "-s", "nodelist.node.%s.name" % (num_nodes - 1),
                           "str", node_name], shell=False)


def del_node(addr):
    '''
    Remove node from corosync
    '''
    f = open(conf()).read()
    p = Parser(f)
    nth = p.remove_section_where('nodelist.node', 'ring0_addr', addr)
    if nth == -1:
        return

    num_nodes = p.count('nodelist.node')
    p.set('quorum.two_node', '1' if num_nodes == 2 else '0')

    f = open(conf(), 'w')
    f.write(p.to_string())
    f.close()


_COROSYNC_CONF_TEMPLATE_HEAD = """# Please read the corosync.conf.5 manual page

totem {
    version:    2
    secauth:    on
    crypto_hash:    sha1
    crypto_cipher:  aes256
    cluster_name:   %(clustername)s
    clear_node_high_bit: yes

    token:      5000
    token_retransmits_before_loss_const: 10
    join:       60
    consensus:  6000
    max_messages:   20
"""
_COROSYNC_CONF_TEMPLATE_TAIL = """
    %(rrp_mode)s
    %(transport)s
    %(ipv6)s
    %(ipv6_nodeid)s
}

logging {
    fileline:   off
    to_stderr:  no
    to_logfile:     no
    logfile:    /var/log/cluster/corosync.log
    to_syslog:  yes
    debug:      off
    timestamp:  on
    logger_subsys {
        subsys:     QUORUM
        debug:  off
    }
}

%(nodelist)s
quorum {
    # Enable and configure quorum subsystem (default: off)
    # see also corosync.conf.5 and votequorum.5
    provider: corosync_votequorum
    expected_votes: 1
    two_node: 0
}
"""
_COROSYNC_CONF_TEMPLATE_RING = """
    interface {
        ringnumber: %(number)d
        %(bindnetaddr)s
%(mcast)s
        ttl: 1
    }
"""


def create_configuration(clustername="hacluster",
                         bindnetaddr=None,
                         mcastaddr=None,
                         mcastport=None,
                         ringXaddr=None,
                         transport=None,
                         ipv6=False,
                         nodeid=None,
                         two_rings=False):

    if transport == "udpu":
        ring_tmpl = ""
        for i in 0, 1:
            ring_tmpl += "        ring{}_addr: {}\n".format(i, ringXaddr[i])
            if not two_rings:
                break

        nodelist_tmpl = """nodelist {
    node {
%(ringaddr)s       
        nodeid: 1
    }
}
""" % {"ringaddr": ring_tmpl}
    else:
        nodelist_tmpl = ""

    transport_tmpl = ""
    if transport is not None:
        transport_tmpl = "transport: {}\n".format(transport)

    rrp_mode_tmp = ""
    if two_rings:
        rrp_mode_tmp = "rrp_mode:  passive"

    ipv6_tmpl = ""
    ipv6_nodeid = ""
    if ipv6:
        ipv6_tmpl = "ip_version:  ipv6"
        if transport != "udpu":
            ipv6_nodeid = "nodeid:  %d" % nodeid

    config_common = {
        "clustername": clustername,
        "nodelist": nodelist_tmpl,
        "ipv6": ipv6_tmpl,
        "ipv6_nodeid": ipv6_nodeid,
        "rrp_mode": rrp_mode_tmp,
        "transport": transport_tmpl
    }

    _COROSYNC_CONF_TEMPLATE_RING_ALL = ""
    mcast_tmp = []
    bindnetaddr_tmp = []
    config_ring = []
    for i in 0, 1:
        mcast_tmp.append("")
        if mcastaddr is not None:
            mcast_tmp[i] += "        mcastaddr:   {}\n".format(mcastaddr[i])
        if mcastport is not None:
            mcast_tmp[i] += "        mcastport:   {}".format(mcastport[i])

        bindnetaddr_tmp.append("")
        if bindnetaddr is None:
            bindnetaddr_tmp[i] = ""
        else:
            bindnetaddr_tmp[i] = "bindnetaddr: {}".format(bindnetaddr[i])

        config_ring.append("")
        config_ring[i] = {
            "bindnetaddr": bindnetaddr_tmp[i],
            "mcast": mcast_tmp[i],
            "number": i
        }
        _COROSYNC_CONF_TEMPLATE_RING_ALL += _COROSYNC_CONF_TEMPLATE_RING % config_ring[i]

        if not two_rings:
            break

    _COROSYNC_CONF_TEMPLATE = _COROSYNC_CONF_TEMPLATE_HEAD + \
                              _COROSYNC_CONF_TEMPLATE_RING_ALL + \
                              _COROSYNC_CONF_TEMPLATE_TAIL
    utils.str2file(_COROSYNC_CONF_TEMPLATE % config_common, conf())
