# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import re
import copy
import subprocess
from argparse import ArgumentParser, RawDescriptionHelpFormatter

from . import config
from . import command
from . import completers as compl
from . import constants
from . import ui_utils
from . import utils
from . import xmlutil
from .cliformat import cli_nvpairs, nvpairs2list
from . import term
from .cibconfig import cib_factory
from .sh import ShellUtils
from . import log


logger = log.setup_logger(__name__)
logger_utils = log.LoggerUtils(logger)


def remove_redundant_attrs(objs, attributes_tag, attr, conflicting_attr = None):
    """
    Remove attr from all resources_tags in the cib.xml
    """
    field2show = "id" # if attributes_tag == "meta_attributes"
    # By default the id of the object should be shown
    # The id of nodes is simply an integer number => show its uname field
    if "instance_attributes" == attributes_tag:
        field2show = "uname"
    # Override the resources on the node
    for r in objs:
        for meta_set in xmlutil.get_set_nodes(r, attributes_tag, create=False):
            a = xmlutil.get_attr_in_set(meta_set, attr)
            if a is not None and \
                (config.core.manage_children == "always" or \
                (config.core.manage_children == "ask" and
                utils.ask("'%s' attribute already exists in %s. Remove it?" %
                        (attr, r.get(field2show))))):
                logger.debug("force remove meta attr %s from %s", attr, r.get(field2show))
                xmlutil.rmnode(a)
                xmlutil.xml_processnodes(r, xmlutil.is_emptynvpairs, xmlutil.rmnodes)
            if conflicting_attr is not None:
                a = xmlutil.get_attr_in_set(meta_set, conflicting_attr)
                if a is not None and \
                    (config.core.manage_children == "always" or \
                    (config.core.manage_children == "ask" and
                    utils.ask("'%s' conflicts with '%s' in %s. Remove it?" %
                            (conflicting_attr, attr, r.get(field2show))))):
                    logger.debug("force remove meta attr %s from %s", conflicting_attr, r.get(field2show))
                    xmlutil.rmnode(a)
                    xmlutil.xml_processnodes(r, xmlutil.is_emptynvpairs, xmlutil.rmnodes)

def get_resources_on_nodes(nodes, resources_tags):
    prefix = "cli-prefer-"
    exclude = [str(x.node.get("id")).replace(prefix,"") for x in cib_factory.cib_objects
        if x.obj_type  == "location" and x.node.get("node") not in nodes]

    resources = [x.node for x in cib_factory.cib_objects
        if x.obj_type in resources_tags and x.obj_id not in exclude]
    return resources

def update_xml_node(cluster_node_name, attr, value):
    '''
    xml_node.attr := value

    Besides, it asks the user if he wants to
    1) remove both the attr and conflicting_attr
    in primitives, groups and clones
    2) remove the conflicting attribute in the node itself
    '''

    node_obj = cib_factory.find_node(cluster_node_name)
    if node_obj is None:
        logger.error("CIB is not valid!")
        return False

    logger.debug("update_xml_node: %s", node_obj.obj_id)

    xml_node = node_obj.node
    node_obj.set_updated()

    conflicting_attr = ''
    if 'maintenance' == attr:
        conflicting_attr = 'is-managed'
    if 'is-managed' == attr:
        conflicting_attr = 'maintenance'

    # Get all primitive, group and clone resources currently running on the cluster_node_name
    objs = get_resources_on_nodes([cluster_node_name], [ "primitive", "group", "clone"])

    # Ask the user to remove the 'attr' attributes on those primitives, groups and clones
    remove_redundant_attrs(objs, "meta_attributes", attr, conflicting_attr)

    # Remove the node conflicting attribute
    nvpairs = xml_node.xpath("./instance_attributes/nvpair[@name='%s']" % (conflicting_attr))
    if len(nvpairs) > 0 and \
        utils.ask("'%s' conflicts with '%s' in %s. Remove it?" %
                        (conflicting_attr, attr, xml_node.get("uname"))):
        for nvpair in nvpairs:
            xmlutil.rmnode(nvpair)
            xmlutil.xml_processnodes(xml_node, xmlutil.is_emptynvpairs, xmlutil.rmnodes)

    # Set the node attribute
    nvpairs = xml_node.xpath("./instance_attributes/nvpair[@name='%s']" % (attr))
    if len(nvpairs) > 0:
        for nvpair in nvpairs:
            nvpair.set("value", value)
    else:
        for n in xmlutil.get_set_instace_attributes(xml_node, create=True):
            xmlutil.set_attr(n, attr, value)
    return True

def set_node_attr(cluster_node_name, attr_name, value, commit=True):
    """
    Set an attribute for a node
    """
    if not update_xml_node(cluster_node_name, attr_name, value):
        logger.error("Failed to update node attributes for %s", cluster_node_name)
        return False

    if not commit:
        return True

    if not cib_factory.commit():
        logger.error("Failed to commit updates to %s", cluster_node_name)
        return False
    return True

def _oneline(s):
    'join s into a single line of space-separated tokens'
    return ' '.join(l.strip() for l in s.splitlines())


def unpack_node_xmldata(node, is_offline):
    """
    takes an XML element defining a node, and
    returns the data to pass to print_node
    is_offline: true|false
    """
    typ = uname = ident = ""
    inst_attr = []
    other = {}
    for attr in list(node.keys()):
        v = node.get(attr)
        if attr == "type":
            typ = v
        elif attr == "uname":
            uname = v
        elif attr == "id":
            ident = v
        else:
            other[attr] = v
    inst_attr = [cli_nvpairs(nvpairs2list(elem))
                 for elem in node.xpath('./instance_attributes')]
    return uname, ident, typ, other, inst_attr, is_offline


def _find_attr(args):
    """
    complete utilization/attribute/status-attr attrs
    """
    if not len(args) >= 2:
        return []
    cib = xmlutil.cibdump2elem()
    if cib is None:
        return []

    res = []
    if args[0] == "utilization":
        xpath = "//nodes/node[@uname='%s']/utilization/nvpair" % args[1]
    if args[0] == "attribute":
        xpath = "//nodes/node[@uname='%s']/instance_attributes/nvpair" % args[1]
    if args[0] == "status-attr":
        xpath = "//status/node_state[@uname='%s']/\
        transient_attributes/instance_attributes/nvpair" % args[1]
    node_attr = cib.xpath(xpath)
    for item in node_attr:
        res.append(item.get("name"))
    return res


def print_node(uname, ident, node_type, other, inst_attr, offline):
    """
    Try to pretty print a node from the cib. Sth like:
    uname(id): node_type
        attr1=v1
        attr2=v2
    """
    s_offline = offline and "(offline)" or ""
    if not node_type:
        node_type = "member"
    if uname == ident:
        print(term.render("%s: %s%s" % (uname, node_type, s_offline)))
    else:
        print(term.render("%s(%s): %s%s" % (uname, ident, node_type, s_offline)))
    for a in other:
        print(term.render("\t%s: %s" % (a, other[a])))
    for s in inst_attr:
        print(term.render("\t%s" % (s)))


def parse_option_for_nodes(context, *args):
    """
    Parse option for nodes
    Return a node list
    """
    action_type = context.get_command_name()
    action_target = "node" if action_type in ["standby", "online"] else "cluster service"
    action = "{} {}".format(action_type, action_target)
    usage_template = """
Specify node(s) on which to {action}.
If no nodes are specified, {action} on the local node.
If --all is specified, {action} on all nodes."""
    addtion_usage = ""
    if action_type == "standby":
        usage_template += """
\n\nAdditionally, you may specify a lifetime for the standby---if set to
"reboot", the node will be back online once it reboots. "forever" will
keep the node in standby after reboot. The life time defaults to
"forever"."""
        addtion_usage = " [lifetime]"

    parser = ArgumentParser(description=usage_template.format(action=action),
                       usage="{} [--all | <node>... ]{}".format(action_type, addtion_usage),
                       add_help=False,
                       formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument("-h", "--help", action="store_true", dest="help", help="Show this help message")
    parser.add_argument("--all", help="To {} on all nodes".format(action), action="store_true", dest="all")

    options, args = parser.parse_known_args(args)
    if options.help:
        parser.print_help()
        raise utils.TerminateSubCommand
    if options is None or args is None:
        raise utils.TerminateSubCommand
    if options.all and args:
        context.fatal_error("Should either use --all or specific node(s)")

    # return local node
    if (not options.all and not args) or (len(args) == 1 and args[0] == utils.this_node()):
        return [utils.this_node()]
    member_list = utils.list_cluster_nodes()
    if not member_list:
        context.fatal_error("Cannot get the node list from cluster")

    node_list = member_list if options.all else args
    for node in node_list:
        try:
            utils.ping_node(node)
        except ValueError as err:
            logger.warning(str(err))
            node_list.remove(node)
    return node_list


class NodeMgmt(command.UI):
    '''
    Nodes management class
    '''
    name = "node"

    node_standby = "crm_attribute -t nodes -N '%s' -n standby -v '%s' %s"
    node_maint = "crm_attribute -t nodes -N '%s' -n maintenance -v '%s'"
    node_delete = """cibadmin -D -o nodes -X '<node uname="%s"/>'"""
    node_delete_status = """cibadmin -D -o status -X '<node_state uname="%s"/>'"""
    node_cleanup_resources = "crm_resource --cleanup --node '%s'"
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
    node_fence = "crm_attribute -t status -N '%s' -n terminate -v true"
    dc = "crmadmin -D"
    node_attr = {
        'set': "crm_attribute -t nodes -N '%s' -n '%s' -v '%s'",
        'delete': "crm_attribute -D -t nodes -N '%s' -n '%s'",
        'show': "crm_attribute -G -t nodes -N '%s' -n '%s'",
    }
    node_status = {
        'set': "crm_attribute -t status -N '%s' -n '%s' -v '%s'",
        'delete': "crm_attribute -D -t status -N '%s' -n '%s'",
        'show': "crm_attribute -G -t status -N '%s' -n '%s'",
    }
    node_utilization = {
        'set': "crm_attribute -z -t nodes -N '%s' -n '%s' -v '%s'",
        'delete': "crm_attribute -z -D -t nodes -N '%s' -n '%s'",
        'show': "crm_attribute -z -G -t nodes -N '%s' -n '%s'",
    }

    def requires(self):
        for p in ('cibadmin', 'crm_attribute'):
            if not utils.is_program(p):
                logger_utils.no_prog_err(p)
                return False
        return True

    @command.alias('list')
    @command.completers(compl.nodes)
    def do_show(self, context, node=None):
        'usage: show [<node>]'
        cib = xmlutil.cibdump2elem()
        if cib is None:
            return False

        cfg_nodes = cib.xpath('/cib/configuration/nodes/node')
        node_states = cib.xpath('/cib/status/node_state')

        def find(it, lst):
            for n in lst:
                if n.get("uname") == it:
                    return n
            return None

        def do_print(uname):
            xml = find(uname, cfg_nodes)
            state = find(uname, node_states)
            if xml is not None or state is not None:
                is_offline = state is not None and \
                    (state.get("crmd") == "offline" or \
                        (state.get("crmd").isdigit() and int(state.get("crmd")) == 0))
                print_node(*unpack_node_xmldata(xml if xml is not None else state, is_offline))

        if node is not None:
            do_print(node)
        else:
            all_nodes = set([n.get("uname") for n in cfg_nodes + node_states])
            for uname in sorted(all_nodes):
                do_print(uname)
        return True

    @command.wait
    @command.completers(compl.online_nodes)
    def do_standby(self, context, *args):
        """
        usage: standby [<node>] [<lifetime>]
        To avoid race condition for --all option, melt all standby values into one cib replace session
        """
        # Parse lifetime option
        lifetime_opt = "forever"
        lifetime = utils.fetch_lifetime_opt(list(args), iso8601=False)
        if lifetime:
            lifetime_opt = lifetime
            args = args[:-1]

        # Parse node option
        node_list = parse_option_for_nodes(context, *args)
        if not node_list:
            return

        # For default "forever" lifetime, under "nodes" section
        xml_path = constants.XML_NODE_PATH
        xml_query_path = constants.XML_NODE_QUERY_STANDBY_PATH
        xml_query_path_oppsite = constants.XML_STATUS_QUERY_STANDBY_PATH
        # For "reboot" lifetime, under "status" section
        if lifetime_opt == "reboot":
            xml_path = constants.XML_STATUS_PATH
            xml_query_path = constants.XML_STATUS_QUERY_STANDBY_PATH
            xml_query_path_oppsite = constants.XML_NODE_QUERY_STANDBY_PATH

        cib = xmlutil.cibdump2elem()
        # IMPORTANT:
        # Do NOT call cibdump2elem twice, or you risk a race where the
        # resulting diff will contain more changes than the values for
        # "standby", potentially rolling back the effect of other operations.
        # Really use the same xml as "original" and basis for the changes.
        # Thus the "deepcopy" here.
        #
        # Possible optimization: instead of deepcopy here and xml_tostring
        # below and str2tmp in diff_and_patch you probably want to change
        # diff_and_patch to accept a file (as well), then
        # from . import tmpfiles
        # orig_cib_tmpfile = xmlutil.cibdump2tmp()
        # tmpfiles.add(orig_cib_tmpfile)
        # cib = xmlutil.file2cib_elem(orig_cib_tmpfile)
        # ...
        # diff_and_patch(orig_file=orig_cib_tmpfile, new_str=xmlutil.xml_tostring(cib))
        orig_cib = copy.deepcopy(cib)

        xml_item_list = cib.xpath(xml_path)
        for xml_item in xml_item_list:
            if xml_item.get("uname") in node_list:
                node_id = xml_item.get('id')
                # Remove possible oppsite lifetime standby nvpair
                item_to_del = cib.xpath(xml_query_path_oppsite.format(node_id=node_id))
                if item_to_del:
                    xmlutil.rmnodes(item_to_del)
                # If the standby nvpair already exists, set and continue
                item = cib.xpath(xml_query_path.format(node_id=node_id))
                if item and item[0].get("value") != "on":
                    item[0].set("value", "on")
                    continue
                # Create standby nvpair
                interface_item = xml_item
                if lifetime_opt == "reboot":
                    res_item = xmlutil.get_set_nodes(xml_item, "transient_attributes", create=True)
                    interface_item = res_item[0]
                res_item = xmlutil.get_set_nodes(interface_item, "instance_attributes", create=True)
                xmlutil.set_attr(res_item[0], "standby", "on")

        rc = utils.diff_and_patch(xmlutil.xml_tostring(orig_cib), xmlutil.xml_tostring(cib))
        if not rc:
            return False
        for node in node_list:
            logger.info("standby node %s", node)

    @command.wait
    @command.completers(compl.standby_nodes)
    def do_online(self, context, *args):
        """
        usage: online [<node>]
        To avoid race condition for --all option, melt all online values into one cib replace session
        """
        # Parse node option
        node_list = parse_option_for_nodes(context, *args)
        if not node_list:
            return

        cib = xmlutil.cibdump2elem()
        # IMPORTANT: Do NOT call cibdump2elem twice, or you risk a race.
        # Really use the same xml as "original" and basis for the changes.
        # Thus the "deepcopy" here; see also do_standby().
        orig_cib = copy.deepcopy(cib)
        for node in node_list:
            node_id = utils.get_nodeid_from_name(node)
            for query_path in [constants.XML_NODE_QUERY_STANDBY_PATH, constants.XML_STATUS_QUERY_STANDBY_PATH]:
                item = cib.xpath(query_path.format(node_id=node_id))
                if item and item[0].get("value") != "off":
                    item[0].set("value", "off")

        rc = utils.diff_and_patch(xmlutil.xml_tostring(orig_cib), xmlutil.xml_tostring(cib))
        if not rc:
            return False
        for node in node_list:
            logger.info("online node %s", node)

    @command.wait
    @command.completers(compl.nodes)
    def do_maintenance(self, context, node=None):
        'usage: maintenance [<node>]'
        if not node:
            node = utils.this_node()
        if not utils.is_name_sane(node):
            return False
        return self._commit_node_attr(context, node, "maintenance", "true")


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
                not utils.ask("Fencing %s will shut down the node and migrate any resources that are running on it! Do you want to fence %s?" % (node, node)):
            return False
        if xmlutil.is_remote_node(node):
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
        if utils.is_larger_than_pcmk_118():
            cib_elem = xmlutil.cibdump2elem()
            if cib_elem is None:
                return False
            crmd = cib_elem.xpath("//node_state[@uname=\"%s\"]/@crmd" % node)
            if crmd == ["online"] or (crmd[0].isdigit() and int(crmd[0]) != 0):
                return utils.ext_cmd(self.node_cleanup_resources % node) == 0
            in_ccm = cib_elem.xpath("//node_state[@uname=\"%s\"]/@in_ccm" % node)
            if in_ccm == ["true"] or (in_ccm[0].isdigit() and int(in_ccm[0]) != 0):
                logger.warning("Node is offline according to Pacemaker, but online according to corosync. First shut down node '%s'", node)
                return False
            return utils.ext_cmd(self.node_clear_state_118 % node) == 0
        else:
            return utils.ext_cmd(self.node_clear_state % ("-M -c", node, node)) == 0 and \
                utils.ext_cmd(self.node_clear_state % ("-R", node, node)) == 0

    @classmethod
    def call_delnode(cls, node):
        "Remove node (how depends on cluster stack)"
        rc = True
        ec, s = ShellUtils().get_stdout("%s -p" % cls.crm_node)
        if not s:
            logger.error('%s -p could not list any nodes (rc=%d)', cls.crm_node, ec)
            rc = False
        else:
            partition_l = s.split()
            if node in partition_l:
                logger.error("according to %s, node %s is still active", cls.crm_node, node)
                rc = False
        cmd = "%s --force -R %s" % (cls.crm_node, node)
        if not rc:
            if config.core.force:
                logger.info('proceeding with node %s removal', node)
            else:
                return False
        ec = utils.ext_cmd(cmd)
        if ec != 0:
            node_xpath = "//nodes/node[@uname='{}']".format(node)
            cmd = 'cibadmin --delete-all --force --xpath "{}"'.format(node_xpath)
            rc, _, err = ShellUtils().get_stdout_stderr(cmd)
            if rc != 0:
                logger.error('"%s" failed, rc=%d, %s', cmd, rc, err)
                return False
        if utils.ext_cmd(cls.node_delete % node) != 0 or \
                utils.ext_cmd(cls.node_delete_status % node) != 0:
            logger.error("%s removed from membership, but not from CIB!", node)
            return False
        return True

    @command.completers(compl.nodes)
    def do_delete(self, context, node):
        'usage: delete <node>'
        logger.warning('`crm node delete` is deprecated and will very likely be dropped in the near future. It is auto-replaced as `crm cluster remove -c {}`.'.format(node))
        if config.core.force:
            rc = subprocess.call(['crm', 'cluster', 'remove', '-F', '-c', node])
        else:
            rc = subprocess.call(['crm', 'cluster', 'remove', '-c', node])
        return rc == 0

    @command.wait
    @command.completers(compl.nodes, compl.choice(['set', 'delete', 'show']), _find_attr)
    def do_attribute(self, context, node, cmd, attr, value=None):
        """usage:
        attribute <node> set <attr> <value>
        attribute <node> delete <attr>
        attribute <node> show <attr>"""
        return ui_utils.manage_attr(context.get_command_name(), self.node_attr,
                                    node, cmd, attr, value)

    @command.wait
    @command.completers(compl.nodes, compl.choice(['set', 'delete', 'show']), _find_attr)
    def do_utilization(self, context, node, cmd, attr, value=None):
        """usage:
        utilization <node> set <attr> <value>
        utilization <node> delete <attr>
        utilization <node> show <attr>"""
        return ui_utils.manage_attr(context.get_command_name(), self.node_utilization,
                                    node, cmd, attr, value)

    @command.wait
    @command.name('status-attr')
    @command.completers(compl.nodes, compl.choice(['set', 'delete', 'show']), _find_attr)
    def do_status_attr(self, context, node, cmd, attr, value=None):
        """usage:
        status-attr <node> set <attr> <value>
        status-attr <node> delete <attr>
        status-attr <node> show <attr>"""
        return ui_utils.manage_attr(context.get_command_name(), self.node_status,
                                    node, cmd, attr, value)

    def _commit_node_attr(self, context, node_name, attr_name, value):
        """
        Perform change to resource
        """
        if not utils.is_name_sane(node_name):
            return False
        commit = not cib_factory.has_cib_changed()
        if not commit:
            context.info("Currently editing the CIB, changes will not be committed")
        return set_node_attr(node_name, attr_name, value, commit=commit)

    def do_server(self, context, *nodes):
        """
        usage:
        server -- print server hostname / address for each node
        server <node> ... -- print server hostname / address for node
        """
        cib = xmlutil.cibdump2elem()
        if cib is None:
            return False
        for node in cib.xpath('/cib/configuration/nodes/node'):
            if nodes and node not in nodes:
                continue
            name = node.get('uname') or node.get('id')
            if node.get('type') == 'remote':
                srv = cib.xpath("//primitive[@id='%s']/instance_attributes/nvpair[@name='server']" % (name))
                if srv:
                    print(srv[0].get('value'))
                    continue
            print(name)

# vim:ts=4:sw=4:et:
