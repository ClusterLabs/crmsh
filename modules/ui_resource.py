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

import command
import completers as compl
import vars
import config
import utils
import xmlutil
import ui_utils
import options

from msg import common_error, common_err, common_info, common_debug, common_warn
from msg import no_prog_err
from cibconfig import CibFactory


def rm_meta_attribute(node, attr, l, force_children=False):
    '''
    Build a list of nvpair nodes which contain attribute
    (recursively in all children resources)
    '''
    for c in node.iterchildren():
        if c.tag == "meta_attributes":
            nvpair = xmlutil.get_attr_in_set(c, attr)
            if nvpair is not None:
                l.append(nvpair)
        elif force_children or \
                (xmlutil.is_child_rsc(c) and not c.getparent().tag == "group"):
            rm_meta_attribute(c, attr, l, force_children=force_children)


def get_children_with_different_attr(node, attr, value):
    l = []
    for p in node.xpath(".//primitive"):
        diff_attr = False
        for meta_set in xmlutil.get_set_nodes(p, "meta_attributes", 0):
            p_value = xmlutil.get_attr_value(meta_set, attr)
            if p_value is not None and p_value != value:
                diff_attr = True
                break
        if diff_attr:
            l.append(p)
    return l


def set_deep_meta_attr_node(target_node, attr, value):
    nvpair_l = []
    if xmlutil.is_clone(target_node):
        for c in target_node.iterchildren():
            if xmlutil.is_child_rsc(c):
                rm_meta_attribute(c, attr, nvpair_l)
    if config.core.manage_children != "never" and \
            (xmlutil.is_group(target_node) or
             (xmlutil.is_clone(target_node) and xmlutil.cloned_el(target_node) == "group")):
        odd_children = get_children_with_different_attr(target_node, attr, value)
        for c in odd_children:
            if config.core.manage_children == "always" or \
                    (config.core.manage_children == "ask" and
                     utils.ask("Do you want to override %s for child resource %s?" %
                               (attr, c.get("id")))):
                common_debug("force remove meta attr %s from %s" %
                             (attr, c.get("id")))
                rm_meta_attribute(c, attr, nvpair_l, force_children=True)
    xmlutil.rmnodes(list(set(nvpair_l)))

    # work around issue with pcs interoperability
    # by finding exising nvpairs -- if there are any, just
    # set the value in those. Otherwise fall back to adding
    # to all meta_attributes tags
    nvpairs = target_node.xpath("//meta_attributes/nvpair[@name='%s']" % (attr))
    if len(nvpairs) > 0:
        for nvpair in nvpairs:
            nvpair.set("value", value)
    else:
        for n in xmlutil.get_set_nodes(target_node, "meta_attributes", 1):
            xmlutil.set_attr(n, attr, value)
    return xmlutil.commit_rsc(target_node)


def set_deep_meta_attr(attr, value, rsc_id):
    '''
    If the referenced rsc is a primitive that belongs to a group,
    then set its attribute.
    Otherwise, go up to the topmost resource which contains this
    resource and set the attribute there (i.e. if the resource is
    cloned).
    If it's a group then check its children. If any of them has
    the attribute set to a value different from the one given,
    then ask the user whether to reset them or not (exact
    behaviour depends on the value of config.core.manage_children).
    '''
    target_node = xmlutil.RscState().rsc2node(rsc_id)
    if target_node is None:
        common_error("resource %s does not exist" % rsc_id)
        return False
    if not (target_node.tag == "primitive" and
            target_node.getparent().tag == "group"):
        target_node = xmlutil.get_topmost_rsc(target_node)
    return set_deep_meta_attr_node(target_node, attr, value)


def cleanup_resource(rsc, node=''):
    if not utils.is_name_sane(rsc) or not utils.is_name_sane(node):
        return False
    if not node:
        rc = utils.ext_cmd(RscMgmt.rsc_cleanup_all % (rsc)) == 0
    else:
        rc = utils.ext_cmd(RscMgmt.rsc_cleanup % (rsc, node)) == 0
    return rc


_attrcmds = compl.choice(['delete', 'set', 'show'])
_raoperations = compl.choice(vars.ra_operations)


class RscMgmt(command.UI):
    '''
    Resources management class
    '''
    name = "resource"

    rsc_status_all = "crm_resource -L"
    rsc_status = "crm_resource -W -r '%s'"
    rsc_showxml = "crm_resource -q -r '%s'"
    rsc_setrole = "crm_resource --meta -r '%s' -p target-role -v '%s'"
    rsc_migrate = "crm_resource -M -r '%s' %s"
    rsc_unmigrate = "crm_resource -U -r '%s'"
    rsc_cleanup = "crm_resource -C -r '%s' -H '%s'"
    rsc_cleanup_all = "crm_resource -C -r '%s'"
    rsc_maintenance = "crm_resource -r '%s' --meta -p maintenance -v '%s'"
    rsc_param = {
        'set': "crm_resource -r '%s' -p '%s' -v '%s'",
        'delete': "crm_resource -r '%s' -d '%s'",
        'show': "crm_resource -r '%s' -g '%s'",
    }
    rsc_meta = {
        'set': "crm_resource --meta -r '%s' -p '%s' -v '%s'",
        'delete': "crm_resource --meta -r '%s' -d '%s'",
        'show': "crm_resource --meta -r '%s' -g '%s'",
    }
    rsc_failcount = {
        'set': "crm_attribute -t status -n 'fail-count-%s' -N '%s' -v '%s' -d 0",
        'delete': "crm_attribute -t status -n 'fail-count-%s' -N '%s' -D -d 0",
        'show': "crm_attribute -t status -n 'fail-count-%s' -N '%s' -G -d 0",
    }
    rsc_utilization = {
        'set': "crm_resource -z -r '%s' -p '%s' -v '%s'",
        'delete': "crm_resource -z -r '%s' -d '%s'",
        'show': "crm_resource -z -r '%s' -g '%s'",
    }
    rsc_secret = {
        'set': "cibsecret set '%s' '%s' '%s'",
        'stash': "cibsecret stash '%s' '%s'",
        'unstash': "cibsecret unstash '%s' '%s'",
        'delete': "cibsecret delete '%s' '%s'",
        'show': "cibsecret get '%s' '%s'",
        'check': "cibsecret check '%s' '%s'",
    }
    rsc_refresh = "crm_resource -R"
    rsc_refresh_node = "crm_resource -R -H '%s'"
    rsc_reprobe = "crm_resource -P"
    rsc_reprobe_node = "crm_resource -P -H '%s'"

    def requires(self):
        for program in ('crm_resource', 'crm_attribute'):
            if not utils.is_program(program):
                no_prog_err(program)
                return False
        return True

    @command.alias('show', 'list')
    @command.completers(compl.resources)
    def do_status(self, context, rsc=None):
        "usage: status [<rsc>]"
        if rsc:
            if not utils.is_name_sane(rsc):
                return False
            return utils.ext_cmd(self.rsc_status % rsc) == 0
        else:
            return utils.ext_cmd(self.rsc_status_all) == 0

    @command.wait
    @command.completers(compl.resources)
    def do_start(self, context, rsc):
        "usage: start <rsc>"
        if not utils.is_name_sane(rsc):
            return False
        return set_deep_meta_attr("target-role", "Started", rsc)

    @command.wait
    @command.completers(compl.resources)
    def do_restart(self, context, rsc):
        "usage: restart <rsc>"
        if not utils.is_name_sane(rsc):
            return False
        common_info("ordering %s to stop" % rsc)
        if not self.do_stop(context, rsc):
            return False
        if not utils.wait4dc("stop", not options.batch):
            return False
        common_info("ordering %s to start" % rsc)
        return self.do_start(context, rsc)

    @command.wait
    @command.completers(compl.resources)
    def do_stop(self, context, rsc):
        "usage: stop <rsc>"
        if not utils.is_name_sane(rsc):
            return False
        return set_deep_meta_attr("target-role", "Stopped", rsc)

    @command.wait
    @command.completers(compl.resources)
    def do_promote(self, context, rsc):
        "usage: promote <rsc>"
        if not utils.is_name_sane(rsc):
            return False
        if not xmlutil.RscState().is_ms(rsc):
            common_err("%s is not a master-slave resource" % rsc)
            return False
        return utils.ext_cmd(self.rsc_setrole % (rsc, "Master")) == 0

    def do_scores(self, context):
        "usage: scores"
        if utils.is_program('crm_simulate'):
            utils.ext_cmd('crm_simulate -sL')
        elif utils.is_program('ptest'):
            utils.ext_cmd('ptest -sL')
        else:
            context.fatal_error("Need crm_simulate or ptest in path to display scores")

    @command.wait
    @command.completers(compl.resources)
    def do_demote(self, context, rsc):
        "usage: demote <rsc>"
        if not utils.is_name_sane(rsc):
            return False
        if not xmlutil.RscState().is_ms(rsc):
            common_err("%s is not a master-slave resource" % rsc)
            return False
        return utils.ext_cmd(self.rsc_setrole % (rsc, "Slave")) == 0

    @command.completers(compl.resources)
    def do_manage(self, context, rsc):
        "usage: manage <rsc>"
        if not utils.is_name_sane(rsc):
            return False
        return set_deep_meta_attr("is-managed", "true", rsc)

    @command.completers(compl.resources)
    def do_unmanage(self, context, rsc):
        "usage: unmanage <rsc>"
        if not utils.is_name_sane(rsc):
            return False
        return set_deep_meta_attr("is-managed", "false", rsc)

    @command.alias('move')
    @command.skill_level('administrator')
    @command.completers_repeating(compl.resources, compl.nodes,
                                  compl.choice(['lifetime', 'force']))
    def do_migrate(self, context, *args):
        """usage: migrate <rsc> [<node>] [<lifetime>] [force]"""
        argl = list(args)
        rsc = argl[0]
        if not utils.is_name_sane(rsc):
            return False
        del argl[0]
        node = None
        opt_l = utils.fetch_opts(argl, ["force"])
        lifetime = utils.fetch_lifetime_opt(argl)
        if len(argl) == 1:
            if xmlutil.is_our_node(argl[0]):
                node = argl[0]
            else:
                context.fatal_error("Not our node: " + argl[0])
        opts = ''
        if node:
            opts = "--node='%s'" % node
        if lifetime:
            opts = "%s --lifetime='%s'" % (opts, lifetime)
        if "force" in opt_l or config.core.force:
            opts = "%s --force" % opts
        return utils.ext_cmd(self.rsc_migrate % (rsc, opts)) == 0

    @command.alias('unmove')
    @command.skill_level('administrator')
    @command.completers(compl.resources)
    def do_unmigrate(self, context, rsc):
        "usage: unmigrate <rsc>"
        if not utils.is_name_sane(rsc):
            return False
        return utils.ext_cmd(self.rsc_unmigrate % rsc) == 0

    @command.skill_level('administrator')
    @command.wait
    @command.completers(compl.resources, compl.nodes)
    def do_cleanup(self, context, resource, node=''):
        "usage: cleanup <rsc> [<node>]"
        # Cleanup a resource on a node. Omit node to cleanup on
        # all live nodes.
        return cleanup_resource(resource, node)

    @command.completers(compl.resources, _attrcmds, compl.nodes)
    def do_failcount(self, context, *args):
        """usage:
        failcount <rsc> set <node> <value>
        failcount <rsc> delete <node>
        failcount <rsc> show <node>"""
        return ui_utils.manage_attr(context.get_command_name(), self.rsc_failcount, args)

    @command.skill_level('administrator')
    @command.wait
    @command.completers(compl.resources, _attrcmds)
    def do_param(self, context, *args):
        """usage:
        param <rsc> set <param> <value>
        param <rsc> delete <param>
        param <rsc> show <param>"""
        return ui_utils.manage_attr(context.get_command_name(), self.rsc_param, args)

    @command.skill_level('administrator')
    @command.wait
    @command.completers(compl.resources,
                        compl.choice(['set', 'stash', 'unstash', 'delete', 'show', 'check']))
    def do_secret(self, context, *args):
        """usage:
        secret <rsc> set <param> <value>
        secret <rsc> stash <param>
        secret <rsc> unstash <param>
        secret <rsc> delete <param>
        secret <rsc> show <param>
        secret <rsc> check <param>"""
        return ui_utils.manage_attr(context.get_command_name(), self.rsc_secret, args)

    @command.skill_level('administrator')
    @command.wait
    @command.completers(compl.resources, _attrcmds)
    def do_meta(self, context, *args):
        """usage:
        meta <rsc> set <attr> <value>
        meta <rsc> delete <attr>
        meta <rsc> show <attr>"""
        return ui_utils.manage_attr(context.get_command_name(), self.rsc_meta, args)

    @command.skill_level('administrator')
    @command.wait
    @command.completers(compl.resources, _attrcmds)
    def do_utilization(self, context, *args):
        """usage:
        utilization <rsc> set <attr> <value>
        utilization <rsc> delete <attr>
        utilization <rsc> show <attr>"""
        return ui_utils.manage_attr(context.get_command_name(), self.rsc_utilization, args)

    @command.completers(compl.nodes)
    def do_refresh(self, context, *args):
        'usage: refresh [<node>]'
        if len(args) == 1:
            if not utils.is_name_sane(args[0]):
                return False
            return utils.ext_cmd(self.rsc_refresh_node % args[0]) == 0
        else:
            return utils.ext_cmd(self.rsc_refresh) == 0

    @command.wait
    @command.completers(compl.nodes)
    def do_reprobe(self, context, *args):
        'usage: reprobe [<node>]'
        if len(args) == 1:
            if not utils.is_name_sane(args[0]):
                return False
            return utils.ext_cmd(self.rsc_reprobe_node % args[0]) == 0
        else:
            return utils.ext_cmd(self.rsc_reprobe) == 0

    @command.wait
    @command.completers(compl.resources, compl.choice(['on', 'off', 'true', 'false']))
    def do_maintenance(self, context, resource, on_off='true'):
        'usage: maintenance <resource> [on|off|true|false]'
        on_off = on_off.lower()
        if on_off not in ('on', 'true', 'off', 'false'):
            context.fatal_error("Expected <resource> [on|off|true|false]")
        elif on_off in ('on', 'true'):
            on_off = 'true'
        else:
            on_off = 'false'
        return utils.ext_cmd(self.rsc_maintenance % (resource, on_off)) == 0

    def _get_trace_rsc(self, rsc_id):
        cib_factory.refresh()
        if not cib_factory.is_cib_sane():
            return None
        rsc = cib_factory.find_object(rsc_id)
        if not rsc:
            common_err("resource %s does not exist" % rsc_id)
            return None
        if rsc.obj_type != "primitive":
            common_err("element %s is not a primitive resource" % rsc_id)
            return None
        return rsc

    @command.wait
    @command.completers(compl.primitives, _raoperations)
    def do_trace(self, context, rsc_id, op, interval=None):
        'usage: trace <rsc> <op> [<interval>]'
        rsc = self._get_trace_rsc(rsc_id)
        if not rsc:
            return False
        if not interval:
            interval = op == "monitor" and "non-0" or "0"
        if op == "probe":
            op = "monitor"
        op_node = xmlutil.find_operation(rsc.node, op, interval)
        if op_node is None and utils.crm_msec(interval) != 0:
            common_err("not allowed to create non-0 interval operation %s" % op)
            return False
        if op_node is None:
            head_pl = ["op", []]
            head_pl[1].append(["name", op])
            head_pl[1].append(["interval", interval])
            head_pl[1].append([vars.trace_ra_attr, "1"])
            cli_list = []
            cli_list.append(head_pl)
            if not rsc.add_operation(cli_list):
                return False
        else:
            op_node = rsc.set_op_attr(op_node, vars.trace_ra_attr, "1")
        if not cib_factory.commit():
            return False
        if op == "monitor" and utils.crm_msec(interval) != 0:
            common_warn("please CLEANUP the RA trace directory %s regularly!" %
                        config.path.heartbeat_dir)
        else:
            common_info("restart %s to get the trace" % rsc_id)
        return True

    @command.wait
    @command.completers(compl.primitives, _raoperations)
    def do_untrace(self, context, rsc_id, op, interval=None):
        'usage: untrace <rsc> <op> [<interval>]'
        rsc = self._get_trace_rsc(rsc_id)
        if not rsc:
            return False
        if not interval:
            interval = op == "monitor" and "non-0" or "0"
        if op == "probe":
            op = "monitor"
        op_node = xmlutil.find_operation(rsc.node, op, interval)
        if op_node is None:
            common_err("operation %s does not exist in %s" % (op, rsc.obj_id))
            return False
        op_node = rsc.del_op_attr(op_node, vars.trace_ra_attr)
        if rsc.is_dummy_operation(op_node):
            rsc.del_operation(op_node)
        return cib_factory.commit()


cib_factory = CibFactory.getInstance()
