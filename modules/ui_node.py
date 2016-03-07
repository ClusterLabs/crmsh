# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
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

import config
import command
import completers as compl
import ui_utils
import utils
import xmlutil
from msg import common_err, syntax_err, no_prog_err, common_info, common_warn
from cliformat import cli_nvpairs, nvpairs2list
import term


def _oneline(s):
    'join s into a single line of space-separated tokens'
    return ' '.join(l.strip() for l in s.splitlines())


def unpack_node_xmldata(node, is_offline):
    """
    takes an XML element defining a node, and
    returns the data to pass to print_node
    is_offline: function(uname) -> offline?
    """
    type = uname = id = ""
    inst_attr = []
    other = {}
    for attr in node.keys():
        v = node.get(attr)
        if attr == "type":
            type = v
        elif attr == "uname":
            uname = v
        elif attr == "id":
            id = v
        else:
            other[attr] = v
    inst_attr = [cli_nvpairs(nvpairs2list(elem))
                 for elem in node.xpath('./instance_attributes')]
    return uname, id, type, other, inst_attr, is_offline(uname)


def print_node(uname, id, node_type, other, inst_attr, offline):
    """
    Try to pretty print a node from the cib. Sth like:
    uname(id): node_type
        attr1=v1
        attr2=v2
    """
    s_offline = offline and "(offline)" or ""
    if not node_type:
        node_type = "normal"
    if uname == id:
        print term.render("%s: %s%s" % (uname, node_type, s_offline))
    else:
        print term.render("%s(%s): %s%s" % (uname, id, node_type, s_offline))
    for a in other:
        print term.render("\t%s: %s" % (a, other[a]))
    for s in inst_attr:
        print term.render("\t%s" % (s))


class NodeMgmt(command.UI):
    '''
    Nodes management class
    '''
    name = "node"

    node_standby = "crm_attribute -t nodes -N '%s' -n standby -v '%s' %s"
    node_maint = "crm_attribute -t nodes -N '%s' -n maintenance -v '%s'"
    node_delete = """cibadmin -D -o nodes -X '<node uname="%s"/>'"""
    node_delete_status = """cibadmin -D -o status -X '<node_state uname="%s"/>'"""
    node_clear_state = _oneline("""cibadmin %s
      -o status --xml-text
      '<node_state id="%s"
                   uname="%s"
                   ha="active"
                   in_ccm="false"
                   crmd="offline"
                   join="member"
                   expected="down"
                   crm-debug-origin="manual_clear"
                   shutdown="0"
       />'""")
    node_clear_state_118 = "stonith_admin --confirm %s"
    hb_delnode = config.path.hb_delnode + " '%s'"
    crm_node = "crm_node"
    node_fence = "crm_attribute -t status -U '%s' -n terminate -v true"
    dc = "crmadmin -D"
    node_attr = {
        'set': "crm_attribute -t nodes -U '%s' -n '%s' -v '%s'",
        'delete': "crm_attribute -D -t nodes -U '%s' -n '%s'",
        'show': "crm_attribute -G -t nodes -U '%s' -n '%s'",
    }
    node_status = {
        'set': "crm_attribute -t status -U '%s' -n '%s' -v '%s'",
        'delete': "crm_attribute -D -t status -U '%s' -n '%s'",
        'show': "crm_attribute -G -t status -U '%s' -n '%s'",
    }
    node_utilization = {
        'set': "crm_attribute -z -t nodes -U '%s' -n '%s' -v '%s'",
        'delete': "crm_attribute -z -D -t nodes -U '%s' -n '%s'",
        'show': "crm_attribute -z -G -t nodes -U '%s' -n '%s'",
    }

    def requires(self):
        for p in ('cibadmin', 'crm_attribute'):
            if not utils.is_program(p):
                no_prog_err(p)
                return False
        return True

    @command.completers(compl.nodes)
    def do_status(self, context, node=None):
        'usage: status [<node>]'
        a = node and ('--xpath "//nodes/node[@uname=\'%s\']"' % node) or \
            '-o nodes'
        return utils.ext_cmd("%s %s" % (xmlutil.cib_dump, a)) == 0

    @command.alias('list')
    @command.completers(compl.nodes)
    def do_show(self, context, node=None):
        'usage: show [<node>]'
        cib_elem = xmlutil.cibdump2elem()
        if cib_elem is None:
            return False
        try:
            nodes_node = cib_elem.xpath("//configuration/nodes")[0]
            status = cib_elem.findall("status")[0]
            node_state = status.xpath(".//node_state")
        except:
            return False

        def is_offline(uname):
            for state in node_state:
                if state.get("uname") == uname and state.get("crmd") == "offline":
                    return True
            return False

        for c in nodes_node.iterchildren():
            if c.tag != "node" or (node is not None and c.get("uname") != node):
                continue
            print_node(*unpack_node_xmldata(c, is_offline))

    @command.wait
    @command.completers(compl.nodes)
    def do_standby(self, context, *args):
        'usage: standby [<node>] [<lifetime>]'
        argl = list(args)
        node = None
        lifetime = utils.fetch_lifetime_opt(argl, iso8601=False)
        if not argl:
            node = utils.this_node()
        elif len(argl) == 1:
            node = args[0]
            if not xmlutil.is_our_node(node):
                common_err("%s: node name not recognized" % node)
                return False
        else:
            syntax_err(args, context=context.get_command_name())
            return False
        opts = ''
        if lifetime:
            opts = "--lifetime='%s'" % lifetime
        else:
            opts = "--lifetime='forever'"
        return utils.ext_cmd(self.node_standby % (node, "on", opts)) == 0

    @command.wait
    @command.completers(compl.nodes)
    def do_online(self, context, node=None):
        'usage: online [<node>]'
        if not node:
            node = utils.this_node()
        if not utils.is_name_sane(node):
            return False
        return utils.ext_cmd(self.node_standby % (node, "off", "--lifetime='forever'")) == 0

    @command.wait
    @command.completers(compl.nodes)
    def do_maintenance(self, context, node=None):
        'usage: maintenance [<node>]'
        if not node:
            node = utils.this_node()
        if not utils.is_name_sane(node):
            return False
        return utils.ext_cmd(self.node_maint % (node, "on")) == 0

    @command.wait
    @command.completers(compl.nodes)
    def do_ready(self, context, node=None):
        'usage: ready [<node>]'
        if not node:
            node = utils.this_node()
        if not utils.is_name_sane(node):
            return False
        return utils.ext_cmd(self.node_maint % (node, "off")) == 0

    @command.wait
    @command.completers(compl.nodes)
    def do_fence(self, context, node):
        'usage: fence <node>'
        if not utils.is_name_sane(node):
            return False
        if not config.core.force and \
                not utils.ask("Do you really want to shoot %s?" % node):
            return False
        if utils.is_remote_node(node):
            return utils.ext_cmd("stonith_admin -F '%s'" % (node)) == 0
        else:
            return utils.ext_cmd(self.node_fence % (node)) == 0

    @command.wait
    @command.completers(compl.nodes)
    def do_clearstate(self, context, node=None):
        'usage: clearstate <node>'
        if not node:
            node = utils.this_node()
        if not utils.is_name_sane(node):
            return False
        if not config.core.force and \
                not utils.ask("Do you really want to drop state for node %s?" % node):
            return False
        if utils.is_pcmk_118():
            return utils.ext_cmd(self.node_clear_state_118 % node) == 0
        else:
            return utils.ext_cmd(self.node_clear_state % ("-M -c", node, node)) == 0 and \
                utils.ext_cmd(self.node_clear_state % ("-R", node, node)) == 0

    def _call_delnode(self, node):
        "Remove node (how depends on cluster stack)"
        rc = True
        if utils.cluster_stack() == "heartbeat":
            cmd = (self.hb_delnode % node)
        else:
            ec, s = utils.get_stdout("%s -p" % self.crm_node)
            if not s:
                common_err('%s -p could not list any nodes (rc=%d)' %
                           (self.crm_node, ec))
                rc = False
            else:
                partition_l = s.split()
                if node in partition_l:
                    common_err("according to %s, node %s is still active" %
                               (self.crm_node, node))
                    rc = False
            cmd = "%s --force -R %s" % (self.crm_node, node)
        if not rc:
            if config.core.force:
                common_info('proceeding with node %s removal' % node)
            else:
                return False
        ec = utils.ext_cmd(cmd)
        if ec != 0:
            common_warn('"%s" failed, rc=%d' % (cmd, ec))
            return False
        return True

    @command.completers(compl.nodes)
    def do_delete(self, context, node):
        'usage: delete <node>'
        if not utils.is_name_sane(node):
            return False
        if not xmlutil.is_our_node(node):
            common_err("node %s not found in the CIB" % node)
            return False
        if not self._call_delnode(node):
            return False
        if utils.ext_cmd(self.node_delete % node) != 0 or \
                utils.ext_cmd(self.node_delete_status % node) != 0:
            common_err("%s removed from membership, but not from CIB!" % node)
            return False
        common_info("node %s deleted" % node)
        return True

    @command.wait
    @command.completers(compl.nodes, compl.choice(['set', 'delete', 'show']), compl.resources)
    def do_attribute(self, context, node, cmd, rsc, value=None):
        """usage:
        attribute <node> set <rsc> <value>
        attribute <node> delete <rsc>
        attribute <node> show <rsc>"""
        return ui_utils.manage_attr(context.get_command_name(), self.node_attr,
                                    node, cmd, rsc, value)

    @command.wait
    @command.completers(compl.nodes, compl.choice(['set', 'delete', 'show']), compl.resources)
    def do_utilization(self, context, node, cmd, rsc, value=None):
        """usage:
        utilization <node> set <rsc> <value>
        utilization <node> delete <rsc>
        utilization <node> show <rsc>"""
        return ui_utils.manage_attr(context.get_command_name(), self.node_utilization,
                                    node, cmd, rsc, value)

    @command.wait
    @command.name('status-attr')
    @command.completers(compl.nodes, compl.choice(['set', 'delete', 'show']), compl.resources)
    def do_status_attr(self, context, node, cmd, rsc, value=None):
        """usage:
        status-attr <node> set <rsc> <value>
        status-attr <node> delete <rsc>
        status-attr <node> show <rsc>"""
        return ui_utils.manage_attr(context.get_command_name(), self.node_status,
                                    node, cmd, rsc, value)


# vim:ts=4:sw=4:et:
