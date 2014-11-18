# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#

import os
import subprocess
from lxml import etree, doctestcompare
import copy
import bz2

from schema import Schema
from userprefs import UserPrefs
from vars import Vars, getuser, gethomedir
from msg import common_err, common_error, common_debug, cib_parse_err, err_buf
from utils import add_sudo, str2file, str2tmp, pipe_string, get_boolean
from utils import get_stdout, stdout2list, crm_msec, crm_time_cmp
from utils import olist


def xmlparse(f):
    try:
        cib_elem = etree.parse(f).getroot()
    except Exception, msg:
        common_err("cannot parse xml: %s" % msg)
        return None
    return cib_elem


def file2cib_elem(s):
    try:
        f = open(s, 'r')
    except IOError, msg:
        common_err(msg)
        return None
    cib_elem = xmlparse(f)
    f.close()
    return cib_elem


cib_dump = "cibadmin -Ql"


def cibdump2file(fname):
    cmd = add_sudo(cib_dump)
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    try:
        s = ''.join(p.stdout)
        p.wait()
    except IOError, msg:
        common_err(msg)
        return None
    return str2file(s, fname)


def cibdump2tmp():
    cmd = add_sudo(cib_dump)
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    try:
        tmpf = str2tmp(''.join(p.stdout))
        p.wait()
    except IOError, msg:
        common_err(msg)
        return None
    return tmpf


def cibdump2elem(section=None):
    if section:
        cmd = "%s -o %s" % (cib_dump, section)
    else:
        cmd = cib_dump
    cmd = add_sudo(cmd)
    p = subprocess.Popen(cmd,
                         shell=True,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    try:
        (outp, err_outp) = p.communicate()
        p.wait()
        rc = p.returncode
    except IOError, msg:
        common_err("running %s: %s" % (cmd, msg))
        return None
    if rc == 0:
        try:
            return etree.fromstring(outp)
        except Exception, msg:
            cib_parse_err(msg, outp)
            return None
    elif rc == vars.cib_no_section_rc:
        return None
    else:
        common_error("running %s: %s" % (cmd, err_outp))
        return None

cib_piped = "cibadmin -p"


def commit_rsc(node):
    "Replace a resource definition using cibadmin -R or cibadmin -P (if available)"
    from utils import cibadmin_can_patch, filter_string

    xml_processnodes(node, is_emptynvpairs, rmnodes)
    xml_processnodes(node, is_emptyops, rmnodes)

    if cibadmin_can_patch():
        nid = node.get('id')
        current_cib = read_cib(cibdump2elem)
        oldnode = current_cib.xpath('//configuration//%s[@id="%s"]' % (node.tag, nid))
        if len(oldnode) != 1:
            common_err("Resource to modify not found in CIB")
            return False
        oldnode = oldnode[0]

        new_cib = copy.deepcopy(current_cib)
        # bump epoch
        if 'epoch' in new_cib.attrib:
            new_cib.set('epoch', str(int(new_cib.get('epoch')) + 1))
        else:
            new_cib.set('epoch', 1)
        new_node = new_cib.xpath('//configuration//%s[@id="%s"]' % (node.tag, nid))[0]

        new_node.getparent().replace(new_node, node)

        oldcib_s = etree.tostring(current_cib)
        newcib_s = etree.tostring(new_cib)

        tmpf = str2tmp(oldcib_s, suffix=".xml")
        if not tmpf:
            common_err("Failed to create temporary file")
            return False
        vars.tmpfiles.append(tmpf)
        rc, diff = filter_string("crm_diff -o %s -n -" % (tmpf), newcib_s)
        if not diff:
            common_err("crm_diff failed to produce a diff (rc=%d)" % rc)
            return False
        rc = pipe_string("%s --patch" % (cib_piped), diff)
    else:
        rc = pipe_string("%s -R -o %s" % (cib_piped, "resources"),
                         etree.tostring(node))
    return rc == 0


def read_cib(fun, params=None):
    cib_elem = fun(params)
    if cib_elem is None or cib_elem.tag != "cib":
        return None
    return cib_elem


def sanity_check_nvpairs(id, node, attr_list):
    rc = 0
    for nvpair in node.iterchildren("nvpair"):
        n = nvpair.get("name")
        if n and not n in attr_list:
            common_err("%s: attribute %s does not exist" % (id, n))
            rc |= user_prefs.get_check_rc()
    return rc


def sanity_check_meta(id, node, attr_list):
    rc = 0
    if node is None or not attr_list:
        return rc
    for c in node.iterchildren():
        if c.tag == "meta_attributes":
            rc |= sanity_check_nvpairs(id, c, attr_list)
    return rc


def get_interesting_nodes(node, nodes_l):
    '''
    All nodes which can be represented as CIB objects.
    '''
    for c in node.iterchildren():
        if is_cib_element(c):
            nodes_l.append(c)
        get_interesting_nodes(c, nodes_l)
    return nodes_l


def get_top_cib_nodes(node, nodes_l):
    '''
    All nodes which can be represented as CIB objects, but not
    nodes which are children of other CIB objects.
    '''
    for c in node.iterchildren():
        if is_cib_element(c):
            nodes_l.append(c)
        else:
            get_top_cib_nodes(c, nodes_l)
    return nodes_l


class RscState(object):
    '''
    Get the resource status and some other relevant bits.
    In particular, this class should allow for a bit of caching
    of cibadmin -Q -o resources output in case we need to check
    more than one resource in a row.
    '''

    rsc_status = "crm_resource -W -r '%s'"

    def __init__(self):
        self.current_cib = None
        self.rsc_elem = None
        self.prop_elem = None
        self.rsc_dflt_elem = None

    def _init_cib(self):
        self.current_cib = cibdump2elem("configuration")
        self.rsc_elem = \
            get_first_conf_elem(self.current_cib, "resources")
        self.prop_elem = \
            get_first_conf_elem(self.current_cib, "crm_config/cluster_property_set")
        self.rsc_dflt_elem = \
            get_first_conf_elem(self.current_cib, "rsc_defaults/meta_attributes")

    def rsc2node(self, id):
        '''
        Get a resource XML element given the id.
        NB: this is called from almost all other methods.
        Hence we initialize the cib here. CIB reading is
        expensive.
        '''
        if self.rsc_elem is None:
            self._init_cib()
        if self.rsc_elem is None:
            return None
        # does this need to be optimized?
        expr = './/*[@id="%s"]' % id
        try:
            return self.rsc_elem.xpath(expr)[0]
        except (IndexError, AttributeError):
            return None

    def is_ms(self, id):
        '''
        Test if the resource is master-slave.
        '''
        rsc_node = self.rsc2node(id)
        if rsc_node is None:
            return False
        return is_ms(rsc_node)

    def rsc_clone(self, id):
        '''
        Return id of the clone/ms containing this resource
        or None if it's not cloned.
        '''
        rsc_node = self.rsc2node(id)
        if rsc_node is None:
            return None
        pnode = rsc_node.getparent()
        if pnode is None:
            return None
        if is_group(pnode):
            pnode = pnode.getparent()
        if is_clonems(pnode):
            return pnode.get("id")
        return None

    def is_managed(self, id):
        '''
        Is this resource managed?
        '''
        rsc_node = self.rsc2node(id)
        if rsc_node is None:
            return False
        # maintenance-mode, if true, overrides all
        attr = get_attr_value(self.prop_elem, "maintenance-mode")
        if attr and is_xs_boolean_true(attr):
            return False
        # then check the rsc is-managed meta attribute
        rsc_meta_node = get_rsc_meta_node(rsc_node)
        attr = get_attr_value(rsc_meta_node, "is-managed")
        if attr:
            return is_xs_boolean_true(attr)
        # then rsc_defaults is-managed attribute
        attr = get_attr_value(self.rsc_dflt_elem, "is-managed")
        if attr:
            return is_xs_boolean_true(attr)
        # finally the is-managed-default property
        attr = get_attr_value(self.prop_elem, "is-managed-default")
        if attr:
            return is_xs_boolean_true(attr)
        return True

    def is_running(self, id):
        '''
        Is this resource running?
        '''
        if not is_live_cib():
            return False
        test_id = self.rsc_clone(id) or id
        rc, outp = get_stdout(self.rsc_status % test_id, stderr_on=False)
        return outp.find("running") > 0 and outp.find("NOT") == -1

    def can_delete(self, id):
        '''
        Can a resource be deleted?
        The order below is important!
        '''
        return not (self.is_running(id) and self.is_managed(id))


def resources_xml():
    return cibdump2elem("resources")


def is_normal_node(n):
    return n.tag == "node" and n.get("type") in (None, "normal", "member")


def mk_rsc_type(n):
    ra_type = n.get("type")
    ra_class = n.get("class")
    ra_provider = n.get("provider")
    s1 = s2 = ''
    if ra_class:
        s1 = "%s:" % ra_class
    if ra_provider:
        s2 = "%s:" % ra_provider
    return ''.join((s1, s2, ra_type))


def listnodes():
    nodes_elem = cibdump2elem("nodes")
    if nodes_elem is None:
        return []
    return [x.get("uname") for x in nodes_elem.iterchildren("node")
            if is_normal_node(x)]


def is_our_node(s):
    '''
    Check if s is in a list of our nodes (ignore case).
    This is not fast, perhaps should be cached.
    '''
    for n in listnodes():
        if n.lower() == s.lower():
            return True
    return False


def is_live_cib():
    '''We working with the live cluster?'''
    return not vars.cib_in_use and not os.getenv("CIB_file")


def is_crmuser():
    return (user_prefs.user in ("root", vars.crm_daemon_user)
            or getuser() in ("root", vars.crm_daemon_user))


def cib_shadow_dir():
    if os.getenv("CIB_shadow_dir"):
        return os.getenv("CIB_shadow_dir")
    if is_crmuser():
        return vars.crm_conf_dir
    home = gethomedir(user_prefs.user)
    if home and home.startswith(os.path.sep):
        return os.path.join(home, ".cib")
    return os.getenv("TMPDIR") or "/tmp"


def listshadows():
    dir = cib_shadow_dir()
    if not os.path.isdir(dir):
        return []
    rc, l = stdout2list("ls %s | fgrep shadow. | sed 's/^shadow\.//'" % dir)
    return l


def shadowfile(name):
    return "%s/shadow.%s" % (cib_shadow_dir(), name)


def pe2shadow(pe_file, name):
    '''Copy a PE file (or any CIB file) to a shadow.'''
    try:
        f = open(pe_file)
    except IOError, msg:
        common_err("open: %s" % msg)
        return False
    s = ''.join(f)
    f.close()
    # decompresed if it ends with .bz2
    if pe_file.endswith(".bz2"):
        s = bz2.decompress(s)
    # copy input to the shadow
    try:
        f = open(shadowfile(name), "w")
    except IOError, msg:
        common_err("open: %s" % msg)
        return False
    f.write(s)
    f.close()
    return True


def is_xs_boolean_true(bool):
    return bool.lower() in ("true", "1")


def cloned_el(node):
    for c in node.iterchildren():
        if is_resource(c):
            return c.tag


def get_topmost_rsc(node):
    '''
    Return a topmost node which is a resource and contains this resource
    '''
    if is_container(node.getparent()):
        return get_topmost_rsc(node.getparent())
    return node


attr_defaults_missing = {
}


def add_missing_attr(node):
    try:
        for defaults in attr_defaults_missing[node.tag]:
            if defaults[0] not in node.attrib:
                node.set(defaults[0], defaults[1])
    except:
        pass


attr_defaults = {
    "rule": (("boolean-op", "and"),),
    "expression": (("type", "string"),),
}


def drop_attr_defaults(node, ts=0):
    try:
        for defaults in attr_defaults[node.tag]:
            if node.get(defaults[0]) == defaults[1]:
                del node.attrib[defaults[0]]
    except:
        pass


def nameandid(e, level):
    if e.tag:
        print level*' ', e.tag, e.get("id"), e.get("name")


def xmltraverse(e, fun, ts=0):
    for c in e.iterchildren():
        fun(c, ts)
        xmltraverse(c, fun, ts+1)


def xmltraverse_thin(e, fun, ts=0):
    '''
    Skip elements which may be resources themselves.
    NB: Call this only on resource (or constraint) nodes, but
    never on cib or configuration!
    '''
    for c in e.iterchildren():
        if not c.tag in ('primitive', 'group'):
            xmltraverse_thin(c, fun, ts+1)
    fun(e, ts)


def xml_processnodes(e, node_filter, proc):
    '''
    Process with proc all nodes that match filter.
    '''
    node_list = []
    for child in e.iterchildren():
        if node_filter(child):
            node_list.append(child)
        if len(child) > 0:
            xml_processnodes(child, node_filter, proc)
    if node_list:
        proc(node_list)


# filter the cib
def true(e):
    'Just return True.'
    return True


def is_entity(e):
    return e.tag == etree.Entity


def is_comment(e):
    return e.tag == etree.Comment


def is_status_node(e):
    return e.tag == "status"


def is_emptyelem(node, tag_l):
    if node.tag in tag_l:
        for a in vars.precious_attrs:
            if node.get(a):
                return False
        for n in node.iterchildren():
            return False
        return True
    else:
        return False


def is_emptynvpairs(node):
    return is_emptyelem(node, vars.nvpairs_tags)


def is_emptyops(node):
    return is_emptyelem(node, ("operations",))


def is_cib_element(node):
    return node.tag in vars.cib_cli_map


def is_group(node):
    return node.tag == "group"


def is_ms(node):
    return node.tag in ("master", "ms")


def is_clone(node):
    return node.tag == "clone"


def is_clonems(node):
    return node.tag in vars.clonems_tags


def is_cloned(node):
    return (node.getparent().tag in vars.clonems_tags or
            (node.getparent().tag == "group" and
             node.getparent().getparent().tag in vars.clonems_tags))


def is_container(node):
    return node.tag in vars.container_tags


def is_primitive(node):
    return node.tag == "primitive"


def is_resource(node):
    return node.tag in vars.resource_tags


def is_template(node):
    return node.tag == "template"


def is_child_rsc(node):
    return node.tag in vars.children_tags


def is_constraint(node):
    return node.tag in vars.constraint_tags


def is_defaults(node):
    return node.tag in vars.defaults_tags


def rsc_constraint(rsc_id, con_elem):
    for attr in con_elem.keys():
        if attr in vars.constraint_rsc_refs \
                and rsc_id == con_elem.get(attr):
            return True
    for rref in con_elem.xpath("resource_set/resource_ref"):
        if rsc_id == rref.get("id"):
            return True
    return False


def sort_container_children(e_list):
    '''
    Make sure that attributes's nodes are first, followed by the
    elements (primitive/group). The order of elements is not
    disturbed, they are just shifted to end!
    '''
    for node in e_list:
        children = [x for x in node.iterchildren()
                    if x.tag in vars.children_tags]
        for c in children:
            node.remove(c)
        for c in children:
            node.append(c)


def rmnode(e):
    if e is not None and e.getparent() is not None:
        e.getparent().remove(e)


def rmnodes(e_list):
    for e in e_list:
        rmnode(e)


def printid(e_list):
    for e in e_list:
        id = e.get("id")
        if id:
            print "element id:", id


def remove_dflt_attrs(e_list):
    '''
    Drop optional attributes which are already set to default
    '''
    for e in e_list:
        try:
            d = vars.attr_defaults[e.tag]
            for a in d.keys():
                if e.get(a) == d[a]:
                    del e.attrib[a]
        except:
            pass


def remove_text(e_list):
    for e in e_list:
        if not is_comment(e):
            e.text = None
            e.tail = None


def sanitize_cib(doc):
    xml_processnodes(doc, is_status_node, rmnodes)
    #xml_processnodes(doc, true, printid)
    xml_processnodes(doc, is_emptynvpairs, rmnodes)
    xml_processnodes(doc, is_emptyops, rmnodes)
    xml_processnodes(doc, is_entity, rmnodes)
    #xml_processnodes(doc, is_comment, rmnodes)
    xml_processnodes(doc, is_container, sort_container_children)
    xml_processnodes(doc, true, remove_dflt_attrs)
    xml_processnodes(doc, true, remove_text)
    xmltraverse(doc, drop_attr_defaults)


def is_simpleconstraint(node):
    return len(node.xpath("resource_set/resource_ref")) == 0


match_list = {
    "node": ("uname",),
    "crm_config": (),
    "rsc_defaults": (),
    "op_defaults": (),
    "cluster_property_set": (),
    "instance_attributes": (),
    "meta_attributes": (),
    "utilization": (),
    "operations": (),
    "nvpair": ("name",),
    "op": ("name", "interval"),
    "rule": ("score", "score-attribute", "role"),
    "expression": ("attribute", "operation", "value"),
    "fencing-level": ("target", "devices"),
}


def add_comment(e, s):
    '''
    Add comment s to e from doc.
    '''
    if e is None or not s:
        return
    comm_elem = etree.Comment(s)
    firstelem_idx = 0
    for c in e.iterchildren():
        firstelem_idx = e.index(c)
        break
    e.insert(firstelem_idx, comm_elem)


def stuff_comments(node, comments):
    if not comments:
        return
    for s in reversed(comments):
        add_comment(node, s)


def fix_comments(e):
    'Make sure that comments start with #'
    celems = [x for x in e.iterchildren() if is_comment(x)]
    for c in celems:
        c.text = c.text.strip()
        if not c.text.startswith("#"):
            c.text = "# %s" % c.text


def set_id_used_attr(e):
    e.set("__id_used", "Yes")


def is_id_used_attr(e):
    return e.get("__id_used") == "Yes"


def remove_id_used_attr(e, lvl):
    if is_id_used_attr(e):
        del e.attrib["__id_used"]


def remove_id_used_attributes(e):
    if e is not None:
        xmltraverse(e, remove_id_used_attr)


def lookup_node(node, oldnode, location_only=False, ignore_id=False):
    '''
    Find a child of oldnode which matches node.
    This is used to "harvest" existing ids in order to prevent
    irrelevant changes to the XML code.
    The list of attributes to match is in the dictionary
    match_list.
    The "id" attribute is treated differently. In case the new node
    (the first parameter here) contains the id, then the "id"
    attribute is added to the match list.
    '''
    #print "lookup:", node.tag, node.get("id")
    if oldnode is None:
        return None
    #print "  in:", oldnode.tag, oldnode.get("id")
    try:
        attr_list = list(match_list[node.tag])
    except KeyError:
        attr_list = []
    if not ignore_id and node.get("id"):
        #print "  add id attribute"
        attr_list.append("id")
    for c in oldnode.iterchildren():
        if not location_only and is_id_used_attr(c):
            continue
        #print "  checking:", c.tag, c.get("id")
        if node.tag == c.tag:
            failed = False
            for a in attr_list:
                if node.get(a) != c.get(a):
                    failed = True
                    break
            if not failed:
                #print "  found:", c.tag, c.get("id")
                return c
    return None


def find_operation(rsc_node, name, interval="0"):
    '''
    Setting interval to "non-0" means get the first op with interval
    different from 0.
    '''
    op_node_l = rsc_node.findall("operations")
    for ops in op_node_l:
        for c in ops.iterchildren("op"):
            if c.get("name") != name:
                continue
            if (interval == "non-0" and
                    crm_msec(c.get("interval")) > 0) or \
                    crm_time_cmp(c.get("interval"), interval) == 0:
                return c


def get_op_timeout(rsc_node, op, default_timeout):
    interval = (op == "monitor" and "non-0" or "0")
    op_n = find_operation(rsc_node, op == "probe" and "monitor" or op, interval)
    timeout = op_n is not None and op_n.get("timeout") or default_timeout
    return crm_msec(timeout)


def op2list(node):
    pl = []
    action = ""
    for name in node.keys():
        if name == "name":
            action = node.get(name)
        elif name != "id":  # skip the id
            pl.append([name, node.get(name)])
    if not action:
        common_err("op is invalid (no name)")
    return action, pl


def get_rsc_operations(rsc_node):
    actions = []
    for c in rsc_node.iterchildren():
        if c.tag == "operations":
            for c2 in c.iterchildren():
                if c2.tag == "op":
                    op, pl = op2list(c2)
                    if op:
                        actions.append([op, pl])
    return actions


def filter_on_tag(nl, tag):
    return [node for node in nl if node.tag == tag]


def nodes(node_list):
    return filter_on_tag(node_list, "node")


def primitives(node_list):
    return filter_on_tag(node_list, "primitive")


def groups(node_list):
    return filter_on_tag(node_list, "group")


def clones(node_list):
    return filter_on_tag(node_list, "clone")


def mss(node_list):
    return filter_on_tag(node_list, "master")


def templates(node_list):
    return filter_on_tag(node_list, "template")


def constraints(node_list):
    return filter_on_tag(node_list, "rsc_location") \
        + filter_on_tag(node_list, "rsc_colocation") \
        + filter_on_tag(node_list, "rsc_order") \
        + filter_on_tag(node_list, "rsc_ticket")


def properties(node_list):
    return filter_on_tag(node_list, "cluster_property_set") \
        + filter_on_tag(node_list, "rsc_defaults") \
        + filter_on_tag(node_list, "op_defaults")


def acls(node_list):
    return filter_on_tag(node_list, "acl_role") \
        + filter_on_tag(node_list, "acl_user")


def fencing_topology(node_list):
    return filter_on_tag(node_list, "fencing-topology")


def processing_sort(nl):
    '''
    It's usually important to process cib objects in this order,
    i.e. simple objects first.
    '''
    return nodes(nl) + templates(nl) + primitives(nl) + groups(nl) + mss(nl) + clones(nl) \
        + constraints(nl) + fencing_topology(nl) + properties(nl) + acls(nl)


def obj_cmp(obj1, obj2):
    return cmp(obj1.obj_id, obj2.obj_id)


def filter_on_type(cl, obj_type):
    if type(cl[0]) == type([]):
        l = [cli_list for cli_list in cl if cli_list[0][0] == obj_type]
        if user_prefs.sort_elements:
            l.sort(cmp=cmp)
    else:
        l = [obj for obj in cl if obj.obj_type == obj_type]
        if user_prefs.sort_elements:
            l.sort(cmp=obj_cmp)
    return l


def nodes_cli(cl):
    return filter_on_type(cl, "node")


def primitives_cli(cl):
    return filter_on_type(cl, "primitive")


def groups_cli(cl):
    return filter_on_type(cl, "group")


def clones_cli(cl):
    return filter_on_type(cl, "clone")


def mss_cli(cl):
    return filter_on_type(cl, "ms") + filter_on_type(cl, "master")


def templates_cli(cl):
    return filter_on_type(cl, "rsc_template")


def constraints_cli(node_list):
    return filter_on_type(node_list, "location") \
        + filter_on_type(node_list, "colocation") \
        + filter_on_type(node_list, "collocation") \
        + filter_on_type(node_list, "order") \
        + filter_on_type(node_list, "rsc_ticket")


def properties_cli(cl):
    return filter_on_type(cl, "property") \
        + filter_on_type(cl, "rsc_defaults") \
        + filter_on_type(cl, "op_defaults")


def fencing_topology_cli(cl):
    return filter_on_type(cl, "fencing_topology")


def acls_cli(cl):
    return filter_on_type(cl, "role") \
        + filter_on_type(cl, "user")


def ops_cli(cl):
    return filter_on_type(cl, "op")


def processing_sort_cli(cl):
    '''
    Return the given list in this order:
    nodes, primitives, groups, ms, clones, constraints, rest
    Both a list of objects (CibObject) and list of cli
    representations accepted.
    '''
    if not cl:
        return []
    return nodes_cli(cl) + templates_cli(cl) + primitives_cli(cl) + groups_cli(cl) + mss_cli(cl) + clones_cli(cl) \
        + constraints_cli(cl) + fencing_topology_cli(cl) + properties_cli(cl) \
        + ops_cli(cl) + acls_cli(cl)


def is_resource_cli(s):
    return s in olist(vars.resource_cli_names)


def is_constraint_cli(s):
    return s in olist(vars.constraint_cli_names)


def referenced_resources(node):
    if not is_constraint(node):
        return []
    xml_obj_type = node.tag
    if xml_obj_type == "rsc_location":
        rsc_list = [node.get("rsc")]
    elif node.xpath("resource_set/resource_ref"):
        # resource sets
        rsc_list = [x.get("id")
                    for x in node.xpath("resource_set/resource_ref")]
    elif xml_obj_type == "rsc_colocation":
        rsc_list = [node.get("rsc"), node.get("with-rsc")]
    elif xml_obj_type == "rsc_order":
        rsc_list = [node.get("first"), node.get("then")]
    elif xml_obj_type == "rsc_ticket":
        rsc_list = [node.get("rsc")]
    return rsc_list


def rename_id(node, old_id, new_id):
    if node.get("id") == old_id:
        node.set("id", new_id)


def rename_rscref_simple(c_obj, old_id, new_id):
    c_modified = False
    for attr in c_obj.node.keys():
        if attr in vars.constraint_rsc_refs and \
                c_obj.node.get(attr) == old_id:
            c_obj.node.set(attr, new_id)
            c_obj.updated = True
            c_modified = True
    return c_modified


def delete_rscref_simple(c_obj, rsc_id):
    c_modified = False
    for attr in c_obj.node.keys():
        if attr in vars.constraint_rsc_refs and \
                c_obj.node.get(attr) == rsc_id:
            del c_obj.node.attrib[attr]
            c_obj.updated = True
            c_modified = True
    return c_modified


def rset_uniq(c_obj, d):
    '''
    Drop duplicate resource references.
    '''
    l = []
    for rref in c_obj.node.xpath("resource_set/resource_ref"):
        rsc_id = rref.get("id")
        if d[rsc_id] > 1:
            # drop one
            l.append(rref)
            d[rsc_id] -= 1
    rmnodes(l)


def delete_rscref_rset(c_obj, rsc_id):
    '''
    Drop all reference to rsc_id.
    '''
    c_modified = False
    l = []
    for rref in c_obj.node.xpath("resource_set/resource_ref"):
        if rsc_id == rref.get("id"):
            l.append(rref)
            c_obj.updated = True
            c_modified = True
    rmnodes(l)
    l = []
    cnt = 0
    nonseq_rset = False
    for rset in c_obj.node.findall("resource_set"):
        rref_cnt = len(rset.findall("resource_ref"))
        if rref_cnt == 0:
            l.append(rset)
            c_obj.updated = True
            c_modified = True
        elif not get_boolean(rset.get("sequential"), True) and rref_cnt > 1:
            nonseq_rset = True
        cnt += rref_cnt
    rmnodes(l)
    if not nonseq_rset and cnt == 2:
        rset_convert(c_obj)
    return c_modified


def rset_convert(c_obj):
    l = c_obj.node.xpath("resource_set/resource_ref")
    if len(l) != 2:
        return  # eh?
    rsetcnt = 0
    for rset in c_obj.node.findall("resource_set"):
        # in case there are multiple non-sequential sets
        if rset.get("sequential"):
            del rset.attrib["sequential"]
        rsetcnt += 1
    c_obj.modified = True
    cli = c_obj.repr_cli(format=-1)
    cli = cli.replace("_rsc_set_ ", "")
    newnode = c_obj.cli2node(cli)
    if newnode is not None:
        c_obj.node.getparent().replace(c_obj.node, newnode)
        c_obj.node = newnode
        if rsetcnt == 1 and c_obj.obj_type == "colocation":
            # exchange the elements in colocations
            rsc = newnode.get("rsc")
            with_rsc = newnode.get("with-rsc")
            newnode.set("rsc", with_rsc)
            newnode.set("with-rsc", rsc)


def rename_rscref_rset(c_obj, old_id, new_id):
    c_modified = False
    d = {}
    for rref in c_obj.node.xpath("resource_set/resource_ref"):
        rsc_id = rref.get("id")
        if rsc_id == old_id:
            rref.set("id", new_id)
            rsc_id = new_id
            c_obj.updated = True
            c_modified = True
        if not rsc_id in d:
            d[rsc_id] = 1
        else:
            d[rsc_id] += 1
    rset_uniq(c_obj, d)
    # if only two resource references remained then, to preserve
    # sanity, convert it to a simple constraint (sigh)
    cnt = 0
    for key in d:
        cnt += d[key]
    if cnt == 2:
        rset_convert(c_obj)
    return c_modified


def rename_rscref(c_obj, old_id, new_id):
    if rename_rscref_simple(c_obj, old_id, new_id) or \
            rename_rscref_rset(c_obj, old_id, new_id):
        err_buf.info("resource references in %s updated" % str(c_obj))


def delete_rscref(c_obj, rsc_id):
    return delete_rscref_simple(c_obj, rsc_id) or \
        delete_rscref_rset(c_obj, rsc_id)


def silly_constraint(c_node, rsc_id):
    '''
    Remove a constraint from rsc_id to rsc_id.
    Or an invalid one.
    '''
    if c_node.xpath("resource_set/resource_ref"):
        # it's a resource set
        # the resource sets have already been uniq-ed
        return len(c_node.xpath("resource_set/resource_ref")) <= 1
    cnt = 0  # total count of referenced resources have to be at least two
    rsc_cnt = 0
    for attr in c_node.keys():
        if attr in vars.constraint_rsc_refs:
            cnt += 1
            if c_node.get(attr) == rsc_id:
                rsc_cnt += 1
    if c_node.tag in ("rsc_location", "rsc_ticket"):  # locations and tickets are never silly
        return cnt < 1
    else:
        return rsc_cnt == 2 or cnt < 2


def is_climove_location(node):
    'Figure out if the location was created by crm resource move.'
    rule_l = node.findall("rule")
    expr_l = node.xpath(".//expression")
    return len(rule_l) == 1 and len(expr_l) == 1 and \
        node.get("id").startswith("cli-") and \
        expr_l[0].get("attribute") == "#uname" and \
        expr_l[0].get("operation") == "eq"


def is_pref_location(node):
    'Figure out if the location is a node preference.'
    rule_l = node.findall("rule")
    expr_l = node.xpath(".//expression")
    return len(rule_l) == 1 and len(expr_l) == 1 and \
        expr_l[0].get("attribute") == "#uname" and \
        expr_l[0].get("operation") == "eq"


def get_rsc_ref_ids(node):
    return [x.get("id")
            for x in node.xpath("./resource_ref")]


def get_rsc_children_ids(node):
    return [x.get("id")
            for x in node.iterchildren() if is_child_rsc(x)]


def get_prim_children_ids(node):
    l = [x for x in node.iterchildren() if is_child_rsc(x)]
    if len(l) and l[0].tag == "group":
        l = [x for x in l[0].iterchildren() if is_child_rsc(x)]
    return [x.get("id") for x in l]


def get_child_nvset_node(node, attr_set="meta_attributes"):
    if node is None:
        return None
    for c in node.iterchildren():
        if c.tag != attr_set:
            continue
        return c
    return None


def get_rscop_defaults_meta_node(node):
    return get_child_nvset_node(node)


def get_rsc_meta_node(node):
    return get_child_nvset_node(node)


def get_properties_node(node):
    return get_child_nvset_node(node, attr_set="cluster_property_set")


def new_cib():
    cib_elem = etree.Element("cib")
    conf_elem = etree.SubElement(cib_elem, "configuration")
    for name in schema.get('sub', "configuration", 'r'):
        etree.SubElement(conf_elem, name)
    return cib_elem


def get_conf_elems(cib_elem, path):
    '''
    Get a list of configuration elements. All elements are within
    /configuration
    '''
    if cib_elem is None:
        return None
    return cib_elem.xpath("//configuration/%s" % path)


def get_first_conf_elem(cib_elem, path):
    try:
        return get_conf_elems(cib_elem, path)[0]
    except IndexError:
        return None


def get_topnode(cib_elem, tag):
    "Get configuration element or create/append if there's none."
    conf_elem = cib_elem.find("configuration")
    if conf_elem is None:
        common_err("no configuration element found!")
        return None
    if tag == "configuration":
        return conf_elem
    e = cib_elem.find("configuration/%s" % tag)
    if e is None:
        common_debug("create configuration section %s" % tag)
        e = etree.SubElement(conf_elem, tag)
    return e


def get_attr_in_set(e, attr):
    if e is None:
        return None
    for c in e.iterchildren("nvpair"):
        if c.get("name") == attr:
            return c
    return None


def get_attr_value(e, attr):
    try:
        return get_attr_in_set(e, attr).get("value")
    except:
        return None


def set_attr(e, attr, value):
    '''
    Set an attribute in the attribute set.
    '''
    nvpair = get_attr_in_set(e, attr)
    if nvpair is None:
        from idmgmt import IdMgmt
        id_store = IdMgmt.getInstance()
        nvpair = etree.SubElement(e, "nvpair")
        nvpair.set("id", "temp")
        nvpair.set("name", attr)
        nvpair.set("id", id_store.new(nvpair, e.get("id")))
        nvpair.set("value", value)
    else:
        nvpair.set("name", attr)
        nvpair.set("value", value)


def get_set_nodes(e, setname, create=0):
    'Return the attributes set nodes (create one if requested)'
    l = [c for c in e.iterchildren(setname)]
    if l:
        return l
    if create:
        from idmgmt import IdMgmt
        id_store = IdMgmt.getInstance()
        elem = etree.SubElement(e, setname)
        elem.set("id", id_store.new(elem, e.get("id")))
        l.append(elem)
    return l


def xml_noorder_hash(n):
    return sorted([hash(etree.tostring(x))
                   for x in n.iterchildren()])

xml_hash_d = {
    "fencing-topology": xml_noorder_hash,
}

checker = doctestcompare.LXMLOutputChecker()


def xml_cmp(n, m, show=False):
    if n.tag in xml_hash_d:
        n_hash_l = xml_hash_d[n.tag](n)
        m_hash_l = xml_hash_d[n.tag](m)
        rc = len(n_hash_l) == len(m_hash_l)
        for i in range(len(n_hash_l)):
            if not rc:
                break
            if n_hash_l[i] != m_hash_l[i]:
                rc = False
    else:
        rc = checker.compare_docs(n, m)
    if not rc and show and user_prefs.debug:
        # somewhat strange, but that's how this works
        from doctest import Example
        example = Example("etree.tostring(n)", etree.tostring(n))
        got = etree.tostring(m)
        print checker.output_difference(example, got, 0)
    return rc


def merge_attributes(dnode, snode, tag):
    rc = False
    add_children = []
    for sc in snode.iterchildren(tag):
        dc = lookup_node(sc, dnode, ignore_id=True)
        if dc is not None:
            for a, v in sc.items():
                if a == "id":
                    continue
                if v != dc.get(a):
                    dc.set(a, v)
                    rc = True
        else:
            add_children.append(sc)
            rc = True
    for c in add_children:
        dnode.append(copy.deepcopy(c))
    return rc


def merge_nodes(dnode, snode):
    '''
    Import elements from snode into dnode.
    If an element is attributes set (vars.nvpairs_tags) or
    "operations", then merge attributes in the children.
    Otherwise, replace the whole element. (TBD)
    '''
    rc = False  # any changes done?
    if dnode is None or snode is None:
        return rc
    add_children = []
    for sc in snode.iterchildren():
        dc = lookup_node(sc, dnode, ignore_id=True)
        if dc is None:
            if sc.tag in vars.nvpairs_tags or sc.tag == "operations":
                add_children.append(sc)
                rc = True
        elif dc.tag in vars.nvpairs_tags:
            rc = merge_attributes(dc, sc, "nvpair") or rc
        elif dc.tag == "operations":
            rc = merge_attributes(dc, sc, "op") or rc
    for c in add_children:
        dnode.append(copy.deepcopy(c))
    return rc


def merge_tmpl_into_prim(prim_node, tmpl_node):
    '''
    Create a new primitive element which is a merge of a
    rsc_template and a primitive which references it.
    '''
    dnode = etree.Element(prim_node.tag)
    merge_nodes(dnode, tmpl_node)
    merge_nodes(dnode, prim_node)
    # the resulting node should inherit all primitives attributes
    for a, v in prim_node.items():
        dnode.set(a, v)
    # but class/provider/type are coming from the template
    # savannah#41410: stonith resources do not have the provider
    # attribute
    for a in ("class", "provider", "type"):
        v = tmpl_node.get(a)
        if v is not None:
            dnode.set(a, v)
    return dnode


user_prefs = UserPrefs.getInstance()
vars = Vars.getInstance()
schema = Schema.getInstance()
# vim:ts=4:sw=4:et:
