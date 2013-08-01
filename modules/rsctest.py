# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
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

import os
import sys
from msg import common_err, common_debug, common_warn, common_info
from utils import rmdir_r
from xmlutil import get_topmost_rsc, get_op_timeout, get_child_nvset_node, is_ms, is_cloned


#
# Resource testing suite
#


class RADriver(object):
    '''
    Execute operations on resources.
    '''
    pfx = {
        "instance_attributes": "OCF_RESKEY_",
        "meta_attributes": "OCF_RESKEY_CRM_meta_",
    }
    undef = -200
    unused = -201

    def __init__(self, rsc_node, node_l):
        from tempfile import mkdtemp
        self.rscdef_node = rsc_node
        if rsc_node is not None:
            self.ra_class = rsc_node.get("class")
            self.ra_type = rsc_node.get("type")
            self.ra_provider = rsc_node.get("provider")
            self.id = rsc_node.get("id")
        else:
            self.ra_class = None
            self.ra_type = None
            self.ra_provider = None
            self.id = None
        self.node_l = node_l
        self.outdir = mkdtemp(prefix="crmsh_out.")
        self.errdir = mkdtemp(prefix="crmsh_err.")
        self.ec_l = {}
        self.ec_ok = self.unused
        self.ec_stopped = self.unused
        self.ec_master = self.unused
        self.last_op = None
        self.last_rec = {}
        self.timeout = 20000

    def __del__(self):
        rmdir_r(self.outdir)
        rmdir_r(self.errdir)

    def id_str(self):
        return self.last_op and "%s:%s" % (self.id, self.last_op) or self.id

    def err(self, s):
        common_err("%s: %s" % (self.id_str(), s))

    def warn(self, s):
        common_warn("%s: %s" % (self.id_str(), s))

    def info(self, s):
        common_info("%s: %s" % (self.id_str(), s))

    def debug(self, s):
        common_debug("%s: %s" % (self.id_str(), s))

    def is_ms(self):
        return is_ms(self.rscdef_node)

    def nvset2env(self, set_n):
        if not set_n:
            return
        try:
            pfx = self.pfx[set_n.tag]
        except:
            self.err("unknown attributes set: %s" % set_n.tag)
            return
        for nvpair in set_n.iterchildren():
            if nvpair.tag != "nvpair":
                continue
            n = nvpair.get("name")
            v = nvpair.get("value")
            self.rscenv["%s%s" % (pfx, n)] = v

    def set_rscenv(self, op):
        '''
        Setup the environment. Class specific.
        '''
        self.rscenv = {}
        n = self.rscdef_node
        self.timeout = get_op_timeout(n, op, "20s")
        self.rscenv["%stimeout" % self.pfx["meta_attributes"]] = str(self.timeout)
        if op == "monitor":
            self.rscenv["%sinterval" % self.pfx["meta_attributes"]] = "10000"
        if is_cloned(n):
            # some of the meta attributes for clones/ms are used
            # by resource agents
            cn = get_topmost_rsc(n)
            self.nvset2env(get_child_nvset_node(cn))

    def op_status(self, host):
        'Status of the last op.'
        try:
            return self.ec_l[host]
        except:
            return self.undef

    def explain_op_status(self, host):
        stat = self.op_status(host)
        if stat == -9:
            return "timed out"
        elif stat == self.undef:
            return "unknown reason (the RA couldn't run?)"
        else:
            return "exit code %d" % stat

    def is_ok(self, host):
        'Was last op successful?'
        return self.op_status(host) == self.ec_ok

    def is_master(self, host):
        'Only if last op was probe/monitor.'
        return self.op_status(host) == self.ec_master

    def is_stopped(self, host):
        'Only if last op was probe/monitor.'
        return self.op_status(host) == self.ec_stopped

    def show_log(self, host):
        '''
        Execute an operation.
        '''
        from crm_pssh import show_output
        sys.stderr.write("host %s (%s)\n" %
                         (host, self.explain_op_status(host)))
        show_output(self.errdir, (host,), "stderr")
        show_output(self.outdir, (host,), "stdout")

    def run_on_all(self, op):
        '''
        In case of cloned resources, it doesn't make sense to run
        (certain) operations on just one node. So, we run them
        everywhere instead.
        For instance, some clones require quorum.
        '''
        return is_cloned(self.rscdef_node) and op in ("start", "stop")

    def exec_cmd(self, op):
        '''defined in subclasses'''
        pass

    def runop(self, op, node_l=None):
        '''
        Execute an operation.
        '''
        from crm_pssh import do_pssh_cmd
        if not node_l or self.run_on_all(op):
            node_l = self.node_l
        self.last_op = op
        self.set_rscenv(op)
        real_op = (op == "probe" and "monitor" or op)
        cmd = self.exec_cmd(real_op)
        common_debug("running %s on %s" % (real_op, node_l))
        for attr in self.rscenv.keys():
            # shell doesn't allow "-" in var names
            envvar = attr.replace("-", "_")
            if "'" in self.rscenv[attr]:
                cmd = '%s="%s" %s' % (envvar, self.rscenv[attr], cmd)
            else:
                cmd = "%s='%s' %s" % (envvar, self.rscenv[attr], cmd)
        statuses = do_pssh_cmd(cmd, node_l, self.outdir, self.errdir, self.timeout)
        for i in range(len(node_l)):
            try:
                self.ec_l[node_l[i]] = statuses[i]
            except:
                self.ec_l[node_l[i]] = self.undef
        return


class RAOCF(RADriver):
    '''
    Execute operations on OCF resources.
    '''
    # OCF exit codes
    OCF_SUCCESS = 0
    OCF_ERR_GENERIC = 1
    OCF_ERR_ARGS = 2
    OCF_ERR_UNIMPLEMENTED = 3
    OCF_ERR_PERM = 4
    OCF_ERR_INSTALLED = 5
    OCF_ERR_CONFIGURED = 6
    OCF_NOT_RUNNING = 7
    OCF_RUNNING_MASTER = 8
    OCF_FAILED_MASTER = 9

    def __init__(self, *args):
        RADriver.__init__(self, *args)
        self.ec_ok = self.OCF_SUCCESS
        self.ec_stopped = self.OCF_NOT_RUNNING
        self.ec_master = self.OCF_RUNNING_MASTER

    def set_rscenv(self, op):
        RADriver.set_rscenv(self, op)
        self.nvset2env(get_child_nvset_node(self.rscdef_node, "instance_attributes"))
        self.rscenv["OCF_RESOURCE_INSTANCE"] = self.id
        self.rscenv["OCF_ROOT"] = os.environ["OCF_ROOT"]

    def exec_cmd(self, op):
        cmd = "%s/resource.d/%s/%s %s" % \
            (os.environ["OCF_ROOT"], self.ra_provider, self.ra_type, op)
        return cmd


class RALSB(RADriver):
    '''
    Execute operations on LSB resources (init scripts).
    '''

    # OCF exit codes
    LSB_OK = 0
    LSB_ERR_GENERIC = 1
    LSB_ERR_ARGS = 2
    LSB_ERR_UNIMPLEMENTED = 3
    LSB_ERR_PERM = 4
    LSB_ERR_INSTALLED = 5
    LSB_ERR_CONFIGURED = 6
    LSB_NOT_RUNNING = 7
    LSB_STATUS_DEAD_PID = 1
    LSB_STATUS_DEAD_LOCK = 2
    LSB_STATUS_NOT_RUNNING = 3
    LSB_STATUS_UNKNOWN = 4

    def __init__(self, *args):
        RADriver.__init__(self, *args)
        self.ec_ok = self.LSB_OK
        self.ec_stopped = self.LSB_STATUS_NOT_RUNNING
        self.ec_master = self.unused

    def set_rscenv(self, op):
        RADriver.set_rscenv(self, op)

    def exec_cmd(self, op):
        if self.ra_type.startswith("/"):
            prog = self.ra_type
        else:
            prog = "/etc/init.d/%s" % self.ra_type
        cmd = "%s %s" % (prog, op == "monitor" and "status" or op)
        return cmd


ra_driver = {
    "ocf": RAOCF,
    "lsb": RALSB,
}


def check_test_support(rsc_l):
    rc = True
    for r in rsc_l:
        id = r.get("id")
        ra_class = r.get("class")
        if not ra_class:
            common_warn("class attribute not found in %s" % id)
            rc = False
        elif ra_class not in ra_driver:
            common_warn("testing of class %s resources not supported" %
                        ra_class)
            rc = False
    return rc


def are_all_stopped(rsc_l, node_l):
    rc = True
    sys.stderr.write("Probing resources ")
    for r in rsc_l:
        ra_class = r.get("class")
        drv = ra_driver[ra_class](r, node_l)
        sys.stderr.write(".")
        drv.runop("probe")
        for i in range(len(node_l)):
            if not drv.is_stopped(node_l[i]):
                if drv.is_ok(node_l[i]):
                    drv.warn("resource running at %s" % node_l[i])
                elif drv.is_ms() and drv.is_master(node_l[i]):
                    drv.warn("resource is master at %s" % node_l[i])
                else:
                    drv.warn("resource not clean at %s" % node_l[i])
                    drv.show_log(node_l[i])
                rc = False
    sys.stderr.write("\n")
    return rc


def stop_all(started, node):
    'Stop all resources in started, in reverse order.'
    while started:
        drv = started.pop()
        if drv.is_ms():
            drv.runop("demote", (node,))
        drv.runop("stop", (node,))
        if not drv.is_ok(node):
            drv.err("resource failed to stop on %s, clean it up!" % node)
            drv.show_log(node)


def test_resources_1(rsc_l, node):
    started = []
    sys.stderr.write("testing on %s:" % node)
    for r in rsc_l:
        id = r.get("id")
        ra_class = r.get("class")
        drv = ra_driver[ra_class](r, (node,))
        sys.stderr.write(" %s" % id)
        drv.runop("start", (node,))
        if drv.is_ms() and drv.is_ok(node):
            drv.runop("promote", (node,))
        if drv.is_ok(node):
            started.append(drv)
        else:
            sys.stderr.write("\n")
            drv.show_log(node)
            stop_all(started, node)
            return False
    sys.stderr.write("\n")
    stop_all(started, node)
    return True


def test_resources(rsc_l, node_l, all_nodes_l):
    try:
        import crm_pssh
    except ImportError:
        common_err("pssh not installed, rsctest can not be executed")
        return False
    if not check_test_support(rsc_l):
        return False
    if not are_all_stopped(rsc_l, all_nodes_l):
        sys.stderr.write("Stop all resources before testing!\n")
        return False
    rc = True
    for node in node_l:
        rc |= test_resources_1(rsc_l, node)
    return rc

# vim:ts=4:sw=4:et:
