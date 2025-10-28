# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# See COPYING for license information.

import os
from tempfile import mkstemp
from lxml import etree
from . import tmpfiles
from . import xmlutil
from . import utils
from . import config
from . import log


logger = log.setup_logger(__name__)


def get_tag_by_id(node, tag, ident):
    "Find a doc node which matches tag and id."
    for n in node.xpath(".//%s" % tag):
        if n.get("id") == ident:
            return n
    return None


def get_status_node_id(n):
    try:
        n = n.getparent()
    except:
        return None
    if n.tag != "node_state":
        return get_status_node_id(n)
    return n.get("id")


def get_status_node(status_node, node):
    for n in status_node.iterchildren("node_state"):
        if n.get("id") == node:
            return n
    return None


def get_status_ops(status_node, rsc, op, interval, node=''):
    '''
    Find a doc node which matches the operation. interval set to
    "-1" means to lookup an operation with non-zero interval (for
    monitors). Empty interval means any interval is fine.
    '''
    l = []
    for n in status_node.iterchildren("node_state"):
        if node is not None and n.get("id") != node:
            continue
        for r in n.iterchildren("lrm_resource"):
            if r.get("id") != rsc:
                continue
            for o in r.iterchildren("lrm_rsc_op"):
                if o.get("operation") != op:
                    continue
                iv = o.get("interval")
                if iv == interval or (interval == "-1" and iv != "0"):
                    l.append(o)
    return l


def split_op(op):
    if op == "probe":
        return "monitor", "0"
    elif op == "monitor":
        return "monitor", "-1"
    elif op[0:8] == "monitor:":
        return "monitor", op[8:]
    return op, "0"


def cib_path(source):
    return source[0:7] == "shadow:" and xmlutil.shadowfile(source[7:]) or source


class CibStatus(object):
    '''
    CIB status management
    '''
    cmd_inject = "</dev/null >/dev/null 2>&1 crm_simulate -x %s -I %s"
    cmd_run = "2>&1 crm_simulate -R -x %s"
    cmd_simulate = "2>&1 crm_simulate -S -x %s"
    node_ops = {
        "online": "-u",
        "offline": "-d",
        "unclean": "-f",
    }
    ticket_ops = {
        "grant": "-g",
        "revoke": "-r",
        "standby": "-b",
        "activate": "-e",
    }

    def __init__(self):
        self.origin = ""
        self.backing_file = ""  # file to keep the live cib
        self.status_node = None
        self.cib = None
        self.reset_state()

    def _cib_path(self, source):
        if source[0:7] == "shadow:":
            return xmlutil.shadowfile(source[7:])
        else:
            return source

    def _load_cib(self, source):
        if source == "live":
            if not self.backing_file:
                self.backing_file = xmlutil.cibdump2tmp()
                if not self.backing_file:
                    return None
                tmpfiles.add(self.backing_file)
            else:
                xmlutil.cibdump2file(self.backing_file)
            f = self.backing_file
        else:
            f = cib_path(source)
        return xmlutil.read_cib(xmlutil.file2cib_elem, f)

    def _load(self, source):
        cib = self._load_cib(source)
        if cib is None:
            return False
        status = cib.find("status")
        if status is None:
            return False
        self.cib = cib
        self.status_node = status
        self.reset_state()
        return True

    def reset_state(self):
        self.modified = False
        self.quorum = ''
        self.node_changes = {}
        self.op_changes = {}
        self.ticket_changes = {}

    def initialize(self):
        src = utils.get_cib_in_use()
        if not src:
            src = "live"
        else:
            src = "shadow:" + src
        if self._load(src):
            self.origin = src

    def source_file(self):
        if self.origin == "live":
            return self.backing_file
        else:
            return cib_path(self.origin)

    def status_node_list(self):
        st = self.get_status()
        if st is None:
            return
        return [x.get("id") for x in st.xpath(".//node_state")]

    def status_rsc_list(self):
        st = self.get_status()
        if st is None:
            return
        rsc_list = [x.get("id") for x in st.xpath(".//lrm_resource")]
        # how to uniq?
        d = {}
        for e in rsc_list:
            d[e] = 0
        return list(d.keys())

    def load(self, source):
        '''
        Load the status section from the given source. The source
        may be cluster ("live"), shadow CIB, or CIB in a file.
        '''
        if self.backing_file:
            os.unlink(self.backing_file)
            self.backing_file = ""
        if not self._load(source):
            logger.error("the cib contains no status")
            return False
        self.origin = source
        return True

    def save(self, dest=None):
        '''
        Save the modified status section to a file/shadow. If the
        file exists, then it must be a cib file and the status
        section is replaced with our status section. If the file
        doesn't exist, then our section and some (?) configuration
        is saved.
        '''
        if not self.modified:
            logger.info("apparently you didn't modify status")
            return False
        if (not dest and self.origin == "live") or dest == "live":
            logger.warning("cannot save status to the cluster")
            return False
        cib = self.cib
        if dest:
            dest_path = cib_path(dest)
            if os.path.isfile(dest_path):
                cib = self._load_cib(dest)
                if cib is None:
                    logger.error("%s exists, but no cib inside", dest)
                    return False
        else:
            dest_path = cib_path(self.origin)
        if cib != self.cib:
            status = cib.find("status")
            xmlutil.rmnode(status)
            cib.append(self.status_node)
        xml = etree.tostring(cib)
        try:
            f = open(dest_path, "w")
        except IOError as msg:
            logger.error(msg)
            return False
        f.write(xml)
        f.close()
        return True

    def _crm_simulate(self, cmd, nograph, scores, utilization, verbosity):
        if not self.origin:
            self.initialize()
        if verbosity:
            cmd = "%s -%s" % (cmd, verbosity.upper())
        if scores:
            cmd = "%s -s" % cmd
        if utilization:
            cmd = "%s -U" % cmd
        if config.core.dotty and not nograph:
            fd, dotfile = mkstemp()
            cmd = "%s -D %s" % (cmd, dotfile)
        else:
            dotfile = None
        rc = utils.ext_cmd(cmd % self.source_file())
        if dotfile:
            utils.show_dot_graph(dotfile)
        return rc == 0

    # actions is ignored
    def run(self, nograph, scores, utilization, actions, verbosity):
        return self._crm_simulate(self.cmd_run,
                                  nograph, scores, utilization, verbosity)

    # actions is ignored
    def simulate(self, nograph, scores, utilization, actions, verbosity):
        return self._crm_simulate(self.cmd_simulate,
                                  nograph, scores, utilization, verbosity)

    def get_status(self):
        '''
        Return the status section node.
        '''
        if not self.origin:
            self.initialize()
        if (self.status_node is None or (self.origin == "live" and not self.modified)) and not self._load(self.origin):
            return None
        return self.status_node

    def list_changes(self):
        '''
        Dump a set of changes done.
        '''
        if not self.modified:
            return True
        for node in self.node_changes:
            print(node, self.node_changes[node])
        for op in self.op_changes:
            print(op, self.op_changes[op])
        for ticket in self.ticket_changes:
            print(ticket, self.ticket_changes[ticket])
        if self.quorum:
            print("quorum:", self.quorum)
        return True

    def show(self):
        '''
        Page the "pretty" XML of the status section.
        '''
        if self.get_status() is None:
            return False
        utils.page_string(xmlutil.xml_tostring(self.status_node, pretty_print=True))
        return True

    def inject(self, opts):
        return utils.ext_cmd("%s %s" %
                       (self.cmd_inject % (self.source_file(), self.source_file()), opts))

    def set_quorum(self, v):
        if not self.origin:
            self.initialize()
        rc = self.inject("--quorum=%s" % (v and "true" or "false"))
        if rc != 0:
            return False
        self._load(self.origin)
        self.quorum = v and "true" or "false"
        self.modified = True
        return True

    def edit_node(self, node, state):
        '''
        Modify crmd, expected, and join attributes of node_state
        to set the node's state to online, offline, or unclean.
        '''
        if self.get_status() is None:
            return False
        if state not in self.node_ops:
            logger.error("unknown state %s", state)
            return False
        node_node = get_tag_by_id(self.status_node, "node_state", node)
        if node_node is None:
            logger.info("node %s created", node)
            return False
        rc = self.inject("%s %s" % (self.node_ops[state], node))
        if rc != 0:
            return False
        self._load(self.origin)
        self.node_changes[node] = state
        self.modified = True
        return True

    def edit_ticket(self, ticket, subcmd):
        '''
        Modify ticket status.
        '''
        if self.get_status() is None:
            return False
        if subcmd not in self.ticket_ops:
            logger.error("unknown ticket command %s", subcmd)
            return False
        rc = self.inject("%s %s" % (self.ticket_ops[subcmd], ticket))
        if rc != 0:
            return False
        self._load(self.origin)
        self.ticket_changes[ticket] = subcmd
        self.modified = True
        return True

    def edit_op(self, op, rsc, rc_code, op_status, node=''):
        '''
        Set rc-code and op-status in the lrm_rsc_op status
        section element.
        '''
        if self.get_status() is None:
            return False
        l_op, l_int = split_op(op)
        op_nodes = get_status_ops(self.status_node, rsc, l_op, l_int, node)
        if l_int == "-1" and len(op_nodes) != 1:
            logger.error("need interval for the monitor op")
            return False
        if node == '' and len(op_nodes) != 1:
            if op_nodes:
                nodelist = [get_status_node_id(x) for x in op_nodes]
                logger.error("operation %s found at %s", op, ' '.join(nodelist))
            else:
                logger.error("operation %s not found", op)
            return False
        # either the op is fully specified (maybe not found)
        # or we found exactly one op_node
        if len(op_nodes) == 1:
            op_node = op_nodes[0]
            if not node:
                node = get_status_node_id(op_node)
            if not node:
                logger.error("node not found for the operation %s", op)
                return False
            if l_int == "-1":
                l_int = op_node.get("interval")
        op_op = op_status == "0" and "-i" or "-F"
        rc = self.inject("%s %s_%s_%s@%s=%s" %
                         (op_op, rsc, l_op, l_int, node, rc_code))
        if rc != 0:
            return False
        self.op_changes[node+":"+rsc+":"+op] = "rc="+rc_code
        if op_status:
            self.op_changes[node+":"+rsc+":"+op] += "," "op-status="+op_status
        self._load(self.origin)
        self.modified = True
        return True


cib_status = CibStatus()

# vim:ts=4:sw=4:et:
