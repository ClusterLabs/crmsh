# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2013-2018 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

from . import command
from . import completers as compl
from . import constants
from . import config
from . import utils
from . import xmlutil
from . import ui_utils
from . import options
from .cibconfig import cib_factory
from . import log


logger = log.setup_logger(__name__)
logger_utils = log.LoggerUtils(logger)


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

def get_children_with_attr(node, attr):
    l = []
    for p in node.xpath(".//primitive"):
        diff_attr = False
        for meta_set in xmlutil.get_set_nodes(p, "meta_attributes", create=False):
            p_value = xmlutil.get_attr_value(meta_set, attr)
            if p_value is not None:
                diff_attr = True
                break
        if diff_attr:
            l.append(p)
    return l

def set_deep_meta_attr_node(target_node, attr, value):
    nvpair_l = []
    conflicting_attr = ''
    if 'maintenance' == attr:
        conflicting_attr = 'is-managed'
    if 'is-managed' == attr:
        conflicting_attr = 'maintenance'
    if xmlutil.is_clone(target_node):
        for c in target_node.iterchildren():
            if xmlutil.is_child_rsc(c):
                rm_meta_attribute(c, attr, nvpair_l)
    if config.core.manage_children != "never" and \
            (xmlutil.is_group(target_node) or
             (xmlutil.is_clone(target_node) and xmlutil.cloned_el(target_node) == "group")):
        # maintenance and is-managed attributes conflict,
        # ask the user if he wants to leave both.
        if '' != conflicting_attr:
            odd_children = get_children_with_attr(target_node, conflicting_attr)
            for c in odd_children:
                if config.core.manage_children == "always" or \
                        (config.core.manage_children == "ask" and
                        utils.ask("'%s' conflicts with '%s' attribute. Remove '%s' for child resource %s?" %
                                (attr, conflicting_attr, conflicting_attr, c.get("id")))):
                    logger.debug("force remove meta attr %s from %s", conflicting_attr, c.get("id"))
                    rm_meta_attribute(c, conflicting_attr, nvpair_l, force_children=True)
        # remove the same attributes from all children (if wanted)
        odd_children = get_children_with_attr(target_node, attr)
        for c in odd_children:
            if config.core.manage_children == "always" or \
                    (config.core.manage_children == "ask" and
                     utils.ask("Do you want to override '%s' for child resource %s?" %
                               (attr, c.get("id")))):
                logger.debug("force remove meta attr %s from %s", attr, c.get("id"))
                rm_meta_attribute(c, attr, nvpair_l, force_children=True)
    xmlutil.rmnodes(list(set(nvpair_l)))
    if '' != conflicting_attr:
        nvpairs = target_node.xpath("./meta_attributes/nvpair[@name='%s']" % (conflicting_attr))
        if len(nvpairs) > 0:
            if (utils.ask("'%s' conflicts with '%s' attribute. Remove '%s' for resource %s?" %
                        (attr, conflicting_attr, conflicting_attr, target_node.get("id")))):
                xmlutil.rmnodes(list(set(nvpairs)))
    xmlutil.xml_processnodes(target_node,
                             xmlutil.is_emptynvpairs, xmlutil.rmnodes)

    # work around issue with pcs interoperability
    # by finding exising nvpairs -- if there are any, just
    # set the value in those. Otherwise fall back to adding
    # to all meta_attributes tags
    nvpairs = target_node.xpath("./meta_attributes/nvpair[@name='%s']" % (attr))
    if len(nvpairs) > 0:
        for nvpair in nvpairs:
            nvpair.set("value", value)
    else:
        for n in xmlutil.get_set_nodes(target_node, "meta_attributes", create=True):
            xmlutil.set_attr(n, attr, value)
    return True


def set_deep_meta_attr(rsc, attr, value, commit=True):
    """
    If the referenced rsc is a primitive that belongs to a group,
    then set its attribute.
    Otherwise, go up to the topmost resource which contains this
    resource and set the attribute there (i.e. if the resource is
    cloned).
    If it's a group then check its children. If any of them has
    the attribute set to a value different from the one given,
    then ask the user whether to reset them or not (exact
    behaviour depends on the value of config.core.manage_children).
    """

    def update_obj(obj):
        """
        set the meta attribute in the given object
        """
        node = obj.node
        obj.set_updated()
        if not (node.tag == "primitive" and
                node.getparent().tag == "group"):
            node = xmlutil.get_topmost_rsc(node)
        return set_deep_meta_attr_node(node, attr, value)

    def flatten(objs):
        for obj in objs:
            if isinstance(obj, list):
                for subobj in obj:
                    yield subobj
            else:
                yield obj

    def resolve(obj):
        if obj.obj_type == 'tag':
            ret = [cib_factory.find_object(o) for o in obj.node.xpath('./obj_ref/@id')]
            ret = [r for r in ret if r is not None]
            return ret
        return obj

    def is_resource(obj):
        return xmlutil.is_resource(obj.node)

    objs = cib_factory.find_objects(rsc)
    if objs is None:
        logger.error("CIB is not valid!")
        return False
    while any(obj for obj in objs if obj.obj_type == 'tag'):
        objs = list(flatten(resolve(obj) for obj in objs))
    objs = list(filter(is_resource, objs))
    logger.debug("set_deep_meta_attr: %s", ', '.join([obj.obj_id for obj in objs]))
    if not objs:
        logger.error("Resource not found: %s", rsc)
        return False

    ok = all(update_obj(obj) for obj in objs)
    if not ok:
        logger.error("Failed to update meta attributes for %s", rsc)
        return False

    if not commit:
        return True

    ok = cib_factory.commit()
    if not ok:
        logger.error("Failed to commit updates to %s", rsc)
        return False
    return True


_attrcmds = compl.choice(['delete', 'set', 'show'])
_raoperations = compl.choice(constants.ra_operations)


class RscMgmt(command.UI):
    '''
    Resources management class
    '''
    name = "resource"

    rsc_status_all = "crm_resource --list"
    rsc_status = "crm_resource --locate --resource '%s'"
    rsc_showxml = "crm_resource --query-xml --resource '%s'"
    rsc_setrole = "crm_resource --meta --resource '%s' --set-parameter target-role --parameter-value '%s'"
    rsc_migrate = "crm_resource --quiet --move --resource '%s' %s"
    rsc_unmigrate = "crm_resource --quiet --clear --resource '%s'"
    rsc_ban = "crm_resource --ban --resource '%s' %s"
    rsc_maintenance = "crm_resource --resource '%s' --meta --set-parameter maintenance --parameter-value '%s'"
    rsc_param = {
        'set': "crm_resource --resource '%s' --set-parameter '%s' --parameter-value '%s'",
        'delete': "crm_resource --resource '%s' --delete-parameter '%s'",
        'show': "crm_resource --resource '%s' --get-parameter '%s'",
        'get': "crm_resource --resource '%s' --get-parameter '%s'",
    }
    rsc_meta = {
        'set': "crm_resource --meta --resource '%s' --set-parameter '%s' --parameter-value '%s'",
        'delete': "crm_resource --meta --resource '%s' --delete-parameter '%s'",
        'show': "crm_resource --meta --resource '%s' --get-parameter '%s'",
        'get': "crm_resource --meta --resource '%s' --get-parameter '%s'",
    }
    rsc_failcount = {
        'set': "crm_attribute -t status -n 'fail-count-%s' -N '%s' -v '%s'",
        'set_p': "crm_attribute -t status -P 'fail-count-%s' -N '%s' -v '%s'",
        'delete': "crm_failcount -D -r %s -N %s",
        'show': "crm_failcount -G -r %s -N %s",
        'get': "crm_failcount -G -r %s -N %s",
    }
    rsc_utilization = {
        'set': "crm_resource --utilization --resource '%s' --set-parameter '%s' --parameter-value '%s'",
        'delete': "crm_resource --utilization --resource '%s' --delete-parameter '%s'",
        'show': "crm_resource --utilization --resource '%s' --get-parameter '%s'",
        'get': "crm_resource --utilization --resource '%s' --get-parameter '%s'",
    }
    rsc_secret = {
        'set': "cibsecret set '%s' '%s' '%s'",
        'stash': "cibsecret stash '%s' '%s'",
        'unstash': "cibsecret unstash '%s' '%s'",
        'delete': "cibsecret delete '%s' '%s'",
        'show': "cibsecret get '%s' '%s'",
        'get': "cibsecret get '%s' '%s'",
        'check': "cibsecret check '%s' '%s'",
    }

    def _refresh_cleanup(self, action, rsc, node, force):
        """
        Implements the refresh and cleanup commands.
        """
        if rsc == "force":
            rsc, force = None, True
        if node == "force":
            node, force = None, True
        cmd = ["crm_resource", "--" + action]
        if rsc:
            if not utils.is_name_sane(rsc):
                return False
            cmd.append("--resource")
            cmd.append(rsc)
        if node:
            if not utils.is_name_sane(node):
                return False
            cmd.append("--node")
            cmd.append(node)
        if force:
            cmd.append("--force")
        return utils.ext_cmd(" ".join(cmd)) == 0

    def requires(self):
        for program in ('crm_resource', 'crm_attribute'):
            if not utils.is_program(program):
                logger_utils.no_prog_err(program)
                return False
        return True

    @command.alias('show', 'list')
    @command.completers(compl.resources)
    def do_status(self, context, *resources):
        "usage: status [<rsc> ...]"
        if len(resources) > 0:
            rc = True
            for rsc in resources:
                if not utils.is_name_sane(rsc):
                    return False
                rc = rc and (utils.ext_cmd(self.rsc_status % rsc) == 0)
            return rc
        else:
            return utils.ext_cmd(self.rsc_status_all) == 0

    def _commit_meta_attr(self, context, rsc, name, value):
        """
        Perform change to resource
        """
        if not utils.is_name_sane(rsc):
            return False
        commit = not cib_factory.has_cib_changed()
        if not commit:
            context.info("Currently editing the CIB, changes will not be committed")
        return set_deep_meta_attr(rsc, name, value, commit=commit)

    def _commit_meta_attrs(self, context, resources, name, value):
        """
        Perform change to list of resources
        """
        for rsc in resources:
            if not utils.is_name_sane(rsc):
                return False
        commit = not cib_factory.has_cib_changed()
        if not commit:
            context.info("Currently editing the CIB, changes will not be committed")

        rc = True
        for rsc in resources:
            rc = rc and set_deep_meta_attr(rsc, name, value, commit=False)
        if commit and rc:
            ok = cib_factory.commit()
            if not ok:
                logger.error("Failed to commit updates to %s", rsc)
            return ok
        return rc

    @command.wait
    @command.completers(compl.resources_stopped)
    def do_start(self, context, *resources):
        "usage: start <rsc> [<rsc> ...]"
        if len(resources) == 0:
            context.error("Expected at least one resource as argument")
        return self._commit_meta_attrs(context, resources, "target-role", "Started")

    @command.wait
    @command.completers(compl.resources_started)
    def do_stop(self, context, *resources):
        "usage: stop <rsc> [<rsc> ...]"
        if len(resources) == 0:
            context.error("Expected at least one resource as argument")
        return self._commit_meta_attrs(context, resources, "target-role", "Stopped")

    @command.wait
    @command.completers(compl.resources)
    def do_restart(self, context, *resources):
        "usage: restart <rsc> [<rsc> ...]"
        logger.info("ordering %s to stop", ", ".join(resources))
        if not self._commit_meta_attrs(context, resources, "target-role", "Stopped"):
            return False
        if not utils.wait4dc("stop", not options.batch):
            return False
        logger.info("ordering %s to start", ", ".join(resources))
        return self._commit_meta_attrs(context, resources, "target-role", "Started")

    @command.wait
    @command.completers(compl.resources)
    def do_promote(self, context, rsc):
        "usage: promote <rsc>"
        if not utils.is_name_sane(rsc):
            return False
        if not xmlutil.RscState().is_ms_or_promotable_clone(rsc):
            logger.error("%s is not a promotable resource", rsc)
            return False
        role = utils.handle_role_for_ocf_1_1(constants.RSC_ROLE_PROMOTED_LEGACY)
        return utils.ext_cmd(self.rsc_setrole % (rsc, role)) == 0

    def do_scores(self, context):
        "usage: scores"
        if utils.is_program('crm_simulate'):
            utils.ext_cmd('crm_simulate -sUL')
        elif utils.is_program('ptest'):
            utils.ext_cmd('ptest -sUL')
        else:
            context.fatal_error("Need crm_simulate or ptest in path to display scores")

    @command.completers(compl.resources)
    def do_locate(self, context, *resources):
        "usage: locate <rsc> [<rsc> ...]"
        if len(resources) == 0:
            context.error("Expected at least one resource as argument")
        for rsc in resources:
            utils.ext_cmd("crm_resource --resource '%s' --locate" % (rsc))

    @command.wait
    @command.completers(compl.resources)
    def do_demote(self, context, rsc):
        "usage: demote <rsc>"
        if not utils.is_name_sane(rsc):
            return False
        if not xmlutil.RscState().is_ms_or_promotable_clone(rsc):
            logger.error("%s is not a promotable resource", rsc)
            return False
        role = utils.handle_role_for_ocf_1_1(constants.RSC_ROLE_UNPROMOTED_LEGACY)
        return utils.ext_cmd(self.rsc_setrole % (rsc, role)) == 0

    @command.completers(compl.resources)
    def do_manage(self, context, rsc):
        "usage: manage <rsc>"
        return self._commit_meta_attr(context, rsc, "is-managed", "true")

    @command.completers(compl.resources)
    def do_unmanage(self, context, rsc):
        "usage: unmanage <rsc>"
        return self._commit_meta_attr(context, rsc, "is-managed", "false")

    def move_or_ban(self, context, rsc, *args):
        """
        Common codes for move or ban action
        """
        if not utils.is_name_sane(rsc):
            return False
        cmd_map_dict = {'move': self.rsc_migrate,
                'ban': self.rsc_ban}
        action = context.get_command_name()
        action_cap = action.capitalize()
        action_cmd = cmd_map_dict[action]
        usage = "usage: {} <rsc> [<node>] [<lifetime>] [force]".format(action)
        node = None
        lifetime = None

        argl = list(args)
        force = "force" in utils.fetch_opts(argl, ["force"]) or config.core.force
        if len(argl) >= 3:
            context.fatal_error(usage)
        if len(argl) == 2:  # must be <node> <lifetime>
            node = argl[0]
            if not xmlutil.is_our_node(node):
                context.fatal_error("Not our node: " + node)
            lifetime = utils.fetch_lifetime_opt(argl)
        elif len(argl) == 1: # could be <node> or <lifetime>
            if xmlutil.is_our_node(argl[0]):
                node = argl[0]
            else:
                lifetime = utils.fetch_lifetime_opt(argl)

        if action == "move" and not node and not force:
            context.fatal_error("No target node: {} requires either a target node or 'force'".format(action_cap))

        opts = ''
        if node:
            opts = "--node '%s'" % node
        if lifetime:
            opts = "%s --lifetime '%s'" % (opts, lifetime)
        if force or config.core.force:
            opts = "%s --force" % opts
        rc = utils.ext_cmd(action_cmd % (rsc, opts))
        if rc == 0:
            if node:
                logger.info("%s constraint created for %s to %s", action_cap, rsc, node)
            else:
                logger.info("%s constraint created for %s", action_cap, rsc)
            logger.info("Use `crm resource clear %s` to remove this constraint", rsc)
        return rc == 0

    @command.alias('migrate')
    @command.skill_level('administrator')
    @command.wait
    @command.completers_repeating(compl.resources, compl.nodes)
    def do_move(self, context, rsc, *args):
        """usage: move <rsc> [<node>] [<lifetime>] [force]"""
        return self.move_or_ban(context, rsc, *args)


    @command.skill_level('administrator')
    @command.wait
    @command.completers_repeating(compl.resources, compl.nodes)
    def do_ban(self, context, rsc, *args):
        """usage: ban <rsc> [<node>] [<lifetime>] [force]"""
        return self.move_or_ban(context, rsc, *args)

    @command.alias('unmove', 'unban', 'unmigrate')
    @command.skill_level('administrator')
    @command.wait
    @command.completers(compl.resources)
    def do_clear(self, context, rsc):
        "usage: clear <rsc>"
        if not utils.is_name_sane(rsc):
            return False
        rc = utils.ext_cmd(self.rsc_unmigrate % rsc)
        if rc == 0:
            logger.info("Removed migration constraints for %s", rsc)
        return rc == 0

    @command.skill_level('administrator')
    @command.wait
    @command.completers(compl.resources, compl.nodes)
    def do_cleanup(self, context, rsc=None, node=None, force=False):
        "usage: cleanup [<rsc>] [<node>] [force]"
        return self._refresh_cleanup("cleanup", rsc, node, force)

    @command.wait
    @command.completers(compl.resources, compl.nodes)
    def do_operations(self, context, resource=None, node=None):
        "usage: operations [<rsc>] [<node>]"
        cmd = "crm_resource -O"
        if resource is None:
            return utils.ext_cmd(cmd)
        if node is None:
            return utils.ext_cmd("%s -r '%s'" % (cmd, resource))
        return utils.ext_cmd("%s -r '%s' -N '%s'" % (cmd, resource, node))

    @command.wait
    @command.completers(compl.resources)
    def do_constraints(self, context, resource):
        "usage: constraints <rsc>"
        return utils.ext_cmd("crm_resource -a -r '%s'" % (resource))

    @command.wait
    @command.completers(compl.resources, _attrcmds, compl.nodes)
    def do_failcount(self, context, rsc, cmd, node, value=None, operation=None, interval=None):
        """usage:
        failcount <rsc> set <node> <value> [operation] [interval]
        failcount <rsc> delete <node>
        failcount <rsc> show <node>"""
        def sec_to_ms(s):
            return s + '000'

        def ms_to_sec(m):
            return m[:len(m)-3]

        if rsc not in compl.resources():
            context.warning("Resource {} not exists in this cluster".format(rsc))
            return
        valid_cmd_list = ["set", "delete", "show"]
        if cmd not in valid_cmd_list:
            context.fatal_error("{} is not valid command(should be one of {})".format(cmd, valid_cmd_list))
        nodeid = utils.get_nodeid_from_name(node)
        if nodeid is None:
            context.fatal_error("Node {} not in this cluster".format(node))

        if cmd == "set":
            # query the current failcount status
            query_cmd = "cibadmin -Ql --xpath '/cib/status/node_state[@id='{}']'".format(nodeid)
            rc, out, err = utils.get_stdout_stderr(query_cmd)
            if rc != 0:
                context.fatal_error(err)

            # try to get failcount dict {operation:interval}
            import re
            failcount_res = re.findall(r'fail-count-{}#(.*)_([0-9]+)'.format(rsc), out)
            if not failcount_res:
                return True if value and int(value) == 0 else False
            failcount_dict = dict(failcount_res)

            # validate for operation and interval
            if operation and operation not in failcount_dict.keys():
                context.fatal_error("Usage: failcount <rsc> set <node> <value> [operation] [interval]\n\
                           Should specify operation between \"{}\"".format(' '.join(failcount_dict.keys())))
            if (operation and interval) and (operation, sec_to_ms(interval)) not in failcount_res:
                context.fatal_error("Usage: failcount <rsc> set <node> <value> [operation] [interval]\n\
                           Should specify (operation, interval) between {}".\
                           format([(op, ms_to_sec(inter)) for op, inter in failcount_res]))

            # just one failcount entry
            if len(failcount_res) == 1:
                operation = failcount_res[0][0]
                interval = failcount_dict[operation]
                rsc = '{}#{}_{}'.format(rsc, operation, interval)

            # multiple failcount entries for this resource and node
            if len(failcount_res) > 1:
                if operation and interval:
                    rsc = '{}#{}_{}'.format(rsc, operation, sec_to_ms(interval))
                elif int(value) == 0:
                    # using '-P' option of 'crm_attribute' command
                    cmd = "set_p"
                    if operation:
                        op_interval_str = '|'.join(['{}_{}'.format(operation, inter) for op, inter in failcount_res if op==operation])
                    else:
                        op_interval_str = '|'.join(['{}_{}'.format(op, inter) for op, inter in failcount_res])
                    rsc = '{}#({})'.format(rsc, op_interval_str)
                else:
                    # value != 0
                    if operation and len([op for op, _ in failcount_res if op == operation]) == 1:
                        rsc = '{}#{}_{}'.format(rsc, operation, failcount_dict[operation])
                    else:
                        context.fatal_error("Should specify (operation, interval) between {}".
                                format([(op, ms_to_sec(inter)) for op, inter in failcount_res]))

        return ui_utils.manage_attr(context.get_command_name(), self.rsc_failcount,
                                    rsc, cmd, node, value)

    @command.skill_level('administrator')
    @command.wait
    @command.completers(compl.resources, _attrcmds)
    def do_param(self, context, rsc, cmd, param, value=None):
        """usage:
        param <rsc> set <param> <value>
        param <rsc> delete <param>
        param <rsc> show <param>"""
        return ui_utils.manage_attr(context.get_command_name(), self.rsc_param,
                                    rsc, cmd, param, value)

    @command.skill_level('administrator')
    @command.completers(compl.resources,
                        compl.choice(['set', 'stash', 'unstash', 'delete', 'show', 'check']))
    def do_secret(self, context, rsc, cmd, param, value=None):
        """usage:
        secret <rsc> set <param> <value>
        secret <rsc> stash <param>
        secret <rsc> unstash <param>
        secret <rsc> delete <param>
        secret <rsc> show <param>
        secret <rsc> check <param>"""
        return ui_utils.manage_attr(context.get_command_name(), self.rsc_secret,
                                    rsc, cmd, param, value)

    @command.skill_level('administrator')
    @command.wait
    @command.completers(compl.resources, _attrcmds)
    def do_meta(self, context, rsc, cmd, attr, value=None):
        """usage:
        meta <rsc> set <attr> <value>
        meta <rsc> delete <attr>
        meta <rsc> show <attr>"""
        return ui_utils.manage_attr(context.get_command_name(), self.rsc_meta,
                                    rsc, cmd, attr, value)

    @command.skill_level('administrator')
    @command.wait
    @command.completers(compl.resources, _attrcmds)
    def do_utilization(self, context, rsc, cmd, attr, value=None):
        """usage:
        utilization <rsc> set <attr> <value>
        utilization <rsc> delete <attr>
        utilization <rsc> show <attr>"""
        return ui_utils.manage_attr(context.get_command_name(), self.rsc_utilization,
                                    rsc, cmd, attr, value)

    @command.alias('reprobe')
    @command.completers(compl.resources, compl.nodes)
    def do_refresh(self, context, rsc=None, node=None, force=False):
        'usage: refresh [<rsc>] [<node>] [force]'
        return self._refresh_cleanup("refresh", rsc, node, force)

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
        return self._commit_meta_attr(context, resource, "maintenance", on_off)

    def _get_trace_rsc(self, rsc_id):
        if not cib_factory.refresh():
            return None
        rsc = cib_factory.find_object(rsc_id)
        if not rsc:
            logger.error("resource %s does not exist", rsc_id)
            return None
        if rsc.obj_type != "primitive":
            logger.error("element %s is not a primitive resource", rsc_id)
            return None
        return rsc

    def _add_trace_op(self, rsc, op, interval, dir):
        from lxml import etree
        n = etree.Element('op')
        n.set('name', op)
        n.set('interval', interval)
        n.set(constants.trace_ra_attr, '1')
        if dir is not None:
            n.set(constants.trace_dir_attr, dir)
        return rsc.add_operation(n)

    def _trace_resource(self, context, rsc_id, rsc, dir):
        """Enable RA tracing for a specified resource."""
        op_nodes = rsc.node.xpath('operations/op')

        def trace(name):
            for o in op_nodes:
                if o.get('name') == name:
                    return
            if not self._add_trace_op(rsc, name, '0', dir):
                context.fatal_error("Failed to add trace for %s:%s" % (rsc_id, name))
        trace('start')
        trace('stop')
        if xmlutil.is_ms_or_promotable_clone(rsc.node):
            trace('promote')
            trace('demote')
        for op_node in op_nodes:
            op_node = rsc.set_op_attr(op_node, constants.trace_ra_attr, "1")
            if dir is not None:
                rsc.set_op_attr(op_node, constants.trace_dir_attr, dir)

    def _trace_op(self, context, rsc_id, rsc, op, dir):
        """Enable RA tracing for a specified operation."""
        op_nodes = rsc.node.xpath('operations/op[@name="%s"]' % (op))
        if not op_nodes:
            if op == 'monitor':
                context.fatal_error("No monitor operation configured for %s" % (rsc_id))
            if not self._add_trace_op(rsc, op, '0', dir):
                context.fatal_error("Failed to add trace for %s:%s" % (rsc_id, op))
        for op_node in op_nodes:
            op_node = rsc.set_op_attr(op_node, constants.trace_ra_attr, "1")
            if dir is not None:
                rsc.set_op_attr(op_node, constants.trace_dir_attr, dir)

    def _trace_op_interval(self, context, rsc_id, rsc, op, interval, dir):
        """Enable RA tracing for an operation with the exact interval."""
        op_node = xmlutil.find_operation(rsc.node, op, interval)
        if op_node is None and utils.crm_msec(interval) != 0:
            context.fatal_error("Operation %s with interval %s not found in %s" % (op, interval, rsc_id))
        if op_node is None:
            if not self._add_trace_op(rsc, op, interval, dir):
                context.fatal_error("Failed to add trace for %s:%s" % (rsc_id, op))
        else:
            op_node = rsc.set_op_attr(op_node, constants.trace_ra_attr, "1")
            if dir is not None:
                rsc.set_op_attr(op_node, constants.trace_dir_attr, dir)

    @command.completers(compl.primitives, _raoperations)
    def do_trace(self, context, rsc_id, *args):
        'usage: trace <rsc> [<op>] [<interval>] [<log-dir>]'
        usage='usage: trace <rsc> [<op>] [<interval>] [<log-dir>]'
        rsc = self._get_trace_rsc(rsc_id)
        if not rsc:
            return False

        argl = list(args)
        force = "force" in utils.fetch_opts(argl, ["force"]) or config.core.force
        if len(argl) > 3:
            context.fatal_error(usage)
        op=None
        interval=None
        dir=None
        for arg in argl:
            if arg[0] == '/':
                if dir is not None:
                    context.fatal_error(usage)
                dir = arg
            elif arg.isnumeric():
                if interval is not None:
                    context.fatal_error(usage)
                interval = arg
            else:
                if op is not None:
                    context.fatal_error(usage)
                op = arg

        if op == "probe":
            op = "monitor"
            if interval is None:
                interval = "0"
        if op is None:
            self._trace_resource(context, rsc_id, rsc, dir)
        elif interval is None:
            self._trace_op(context, rsc_id, rsc, op, dir)
        else:
            self._trace_op_interval(context, rsc_id, rsc, op, interval, dir)
        if not cib_factory.commit():
            return False
        rsc_type = rsc.node.get("type")
        trace_dir = "{}/{}".format(dir, rsc_type) if dir else "{}/trace_ra/{}".format(config.path.heartbeat_dir, rsc_type)
        logger.info("Trace for %s%s is written to %s", rsc_id, ":"+op if op else "", trace_dir)
        if op is not None and op != "monitor":
            logger.info("Trace set, restart %s to trace the %s operation", rsc_id, op)
        else:
            logger.info("Trace set, restart %s to trace non-monitor operations", rsc_id)
        return True

    def _remove_trace(self, rsc, op_node):
        logger.debug("op_node: %s", xmlutil.xml_tostring(op_node))
        op_node = rsc.del_op_attr(op_node, constants.trace_ra_attr)
        op_node = rsc.del_op_attr(op_node, constants.trace_dir_attr)
        if rsc.is_dummy_operation(op_node):
            rsc.del_operation(op_node)

    def _untrace_resource(self, context, rsc_id, rsc):
        """Disable RA tracing for a specified resource."""
        op_nodes = rsc.node.xpath(
            'operations/op[instance_attributes/nvpair[@name="%s"]]' %
            (constants.trace_ra_attr))
        for op_node in op_nodes:
            self._remove_trace(rsc, op_node)

    def _untrace_op(self, context, rsc_id, rsc, op):
        """Disable RA tracing for a specified operation."""
        op_nodes = rsc.node.xpath('operations/op[@name="%s"]' % (op))
        if not op_nodes:
            context.fatal_error("Operation %s not found in %s" % (op, rsc_id))
        for op_node in op_nodes:
            self._remove_trace(rsc, op_node)

    def _untrace_op_interval(self, context, rsc_id, rsc, op, interval):
        """Disable RA tracing for an operation with the exact interval."""
        op_node = xmlutil.find_operation(rsc.node, op, interval)
        if op_node is None:
            context.fatal_error(
                "Operation %s with interval %s not found in %s" %
                (op, interval, rsc_id))
        self._remove_trace(rsc, op_node)

    @command.completers(compl.primitives, _raoperations)
    def do_untrace(self, context, rsc_id, op=None, interval=None):
        'usage: untrace <rsc> [<op>] [<interval>]'
        rsc = self._get_trace_rsc(rsc_id)
        if not rsc:
            return False
        if op == "probe":
            op = "monitor"
            if interval is None:
                interval = "0"
        if op is None:
            self._untrace_resource(context, rsc_id, rsc)
        elif interval is None:
            self._untrace_op(context, rsc_id, rsc, op)
        else:
            self._untrace_op_interval(context, rsc_id, rsc, op, interval)
        if not cib_factory.commit():
            return False
        logger.info("Stop tracing %s%s", rsc_id, " for operation "+op if op else "")
        return True
