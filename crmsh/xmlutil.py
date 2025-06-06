# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2016 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import os
import subprocess
import typing

from lxml import etree, doctestcompare
import copy
import bz2
from collections import defaultdict
from tempfile import mktemp

from . import config, sh
from . import options
from . import schema
from . import constants
from . import userdir
from .sh import ShellUtils
from . import utils
from . import log


logger = log.setup_logger(__name__)
logger_utils = log.LoggerUtils(logger)


def xmlparse(f: typing.IO[typing.AnyStr]) -> etree.Element:
    try:
        cib_elem = etree.parse(f).getroot()
    except Exception as msg:
        logger.error("cannot parse xml: %s", msg)
        return None
    return cib_elem


def file2cib_elem(s):
    cib_tmp_copy = ''
    try:
        f = open(s, 'r')
    except IOError as msg:
        logger.debug("{} tried to read cib.xml, but : {}".format(userdir.getuser(), msg))
        cib_tmp_copy = mktemp(suffix=".cib.xml")

    if cib_tmp_copy != '':
        logger.debug("{} gonna try it with sudo".format(userdir.getuser()))
        # Actually it's not trying to open the file with sudo,
        # but copying the file with sudo. We do copy,
        # because xmlparse function requires the function descriptor not the plain text
        # and this would be so much work to redo it.
        # It's not too bad, but it's still a workaround and better be refactored, so FIXME!
        utils.copy_local_file(s, cib_tmp_copy)
        f = open(cib_tmp_copy, 'r')
        logger.debug("{} successfully read the cib.xml".format(userdir.getuser()))

    cib_elem = xmlparse(f)
    f.close()
    if cib_tmp_copy != '':
        utils.rmfile(cib_tmp_copy)
    if options.regression_tests and cib_elem is None:
        print("Failed to read CIB from file: %s" % (s))
    return cib_elem


def compressed_file_to_cib(s):
    try:
        if s.endswith('.bz2'):
            f = bz2.BZ2File(s)
        elif s.endswith('.gz'):
            import gzip
            f = gzip.open(s)
        else:
            f = open(s)
    except IOError as msg:
        logger.error(msg)
        return None
    cib_elem = xmlparse(f)
    if options.regression_tests and cib_elem is None:
        print("Failed to read CIB from file %s" % (s))
        f.seek(0)
        print(f.read())
    f.close()
    return cib_elem


cib_dump = "cibadmin -Ql"


def sudocall(cmd):
    cmd = utils.add_sudo(cmd)
    if options.regression_tests:
        print(".EXT", cmd)
    p = subprocess.Popen(
        cmd, shell=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=os.environ,  # bsc#1205925
    )
    try:
        outp, errp = p.communicate()
        p.wait()
        return p.returncode, utils.to_ascii(outp), utils.to_ascii(errp)
    except IOError as msg:
        logger.error("running %s: %s", cmd, msg)
        return None, None, None


def cibdump2file(fname):
    _, outp, _ = sudocall(cib_dump)
    if outp is not None:
        return utils.str2file(outp, fname)
    return None


def cibdump2tmp():
    try:
        _, outp, _ = sudocall(cib_dump)
        if outp is not None:
            return utils.str2tmp(outp)
    except IOError as msg:
        logger.error(msg)
    return None


def text2elem(text: str) -> etree.Element:
    """
    Convert a text format CIB to
    an XML tree.
    """
    try:
        return etree.fromstring(text)
    except Exception as err:
        logger_utils.text_xml_parse_err(err, text)
        return None


def cibdump2elem(section=None, no_side_effects=False):
    if section:
        cmd = "%s -o %s" % (cib_dump, section)
    else:
        cmd = cib_dump
    rc, outp, errp = sudocall(cmd)
    if rc == 0:
        return text2elem(outp)
    elif not no_side_effects:
        logger.error("running %s: %s", cmd, errp)
    return None


def read_cib(fun, params=None):
    cib_elem = fun(params)
    if cib_elem is None or cib_elem.tag != "cib":
        return None
    return cib_elem


def sanity_check_nvpairs(ident, node, attr_list):
    rc = utils.VerifyResult.SUCCESS
    for nvpair in node.iterchildren("nvpair"):
        n = nvpair.get("name")
        if n and n not in attr_list:
            logger.warning("%s: unknown attribute '%s'", ident, n)
            rc |= utils.VerifyResult.WARNING
    return rc


def sanity_check_meta(ident, node, attr_list):
    rc = utils.VerifyResult.SUCCESS
    if node is None or not attr_list:
        return rc
    for c in node.iterchildren():
        if c.tag == "meta_attributes":
            rc |= sanity_check_nvpairs(ident, c, attr_list)
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
        cib = cibdump2elem("configuration")
        self.current_cib = cib
        self.rsc_elem = get_first_conf_elem(cib, "resources")
        self.prop_elem = get_first_conf_elem(cib, "crm_config/cluster_property_set")
        self.rsc_dflt_elem = get_first_conf_elem(cib, "rsc_defaults/meta_attributes")

    def rsc2node(self, ident):
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
        expr = './/*[@id="%s"]' % ident
        try:
            return self.rsc_elem.xpath(expr)[0]
        except (IndexError, AttributeError):
            return None

    def is_ms_or_promotable_clone(self, ident):
        '''
        Test if the resource is master-slave.
        '''
        rsc_node = self.rsc2node(ident)
        if rsc_node is None:
            return False
        return is_ms_or_promotable_clone(rsc_node)

    def rsc_clone(self, ident):
        '''
        Return id of the clone/ms containing this resource
        or None if it's not cloned.
        '''
        rsc_node = self.rsc2node(ident)
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

    def is_managed(self, ident):
        '''
        Is this resource managed?
        '''
        rsc_node = self.rsc2node(ident)
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

    def is_running(self, ident):
        '''
        Is this resource running?
        '''
        if not is_live_cib():
            return False
        test_id = self.rsc_clone(ident) or ident
        rc, outp = ShellUtils().get_stdout(self.rsc_status % test_id, stderr_on=False)
        return outp.find("running") > 0 and outp.find("NOT") == -1

    def is_group(self, ident):
        '''
        Test if the resource is a group
        '''
        rsc_node = self.rsc2node(ident)
        if rsc_node is None:
            return False
        return is_group(rsc_node)

    def can_delete(self, ident):
        '''
        Can a resource be deleted?
        The order below is important!
        '''
        return not (self.is_running(ident) and not self.is_group(ident) and self.is_managed(ident))


def resources_xml():
    return cibdump2elem("resources")


def is_member_node(n):
    return n.tag == "node" and (n.get("type") in (None, "member", ""))


def unique_ra(typ, klass, provider):
    """
    Unique:
    * it's explicitly ocf:heartbeat:
    * no explicit class or provider
    * only one provider (heartbeat counts as one provider)
    Not unique:
    * class is not ocf
    * multiple providers
    """
    if klass is None and provider is None:
        return True
    return klass == 'ocf' and provider is None or provider == 'heartbeat'


def mk_rsc_type(n):
    """
    Returns prefixless for unique RAs
    """
    ra_type = n.get("type")
    ra_class = n.get("class")
    ra_provider = n.get("provider")
    if unique_ra(ra_type, ra_class, ra_provider):
        ra_class = None
        ra_provider = None
    s1 = s2 = ''
    if ra_class:
        s1 = "%s:" % ra_class
    if ra_provider:
        s2 = "%s:" % ra_provider
    return ''.join((s1, s2, ra_type))


def listnodes(include_remote_nodes=True):
    cib = cibdump2elem()
    if cib is None:
        return []
    local_nodes = cib.xpath('/cib/configuration/nodes/node/@uname')
    if include_remote_nodes:
        remote_nodes = cib.xpath('/cib/status/node_state[@remote_node="true"]/@uname')
    else:
        remote_nodes = []
    return list(set([n for n in local_nodes + remote_nodes if n]))


def is_our_node(s):
    '''
    Check if s is in a list of our nodes (ignore case).
    This is not fast, perhaps should be cached.

    Includes remote nodes as well
    '''
    for n in listnodes():
        if n.lower() == s.lower():
            return True
    return False


def is_remote_node(n):
    cib = cibdump2elem()
    if cib is None:
        return False
    remote_nodes = cib.xpath('/cib/status/node_state[@remote_node="true"]/@uname')
    return any(n == r for r in remote_nodes if r)


def is_live_cib():
    '''We working with the live cluster?'''
    return not utils.get_cib_in_use() and not os.getenv("CIB_file")


def is_crmuser():
    crmusers = ("root", config.path.crm_daemon_user)
    return config.core.user in crmusers or userdir.getuser() in crmusers


def cib_shadow_dir():
    if os.getenv("CIB_shadow_dir"):
        return os.getenv("CIB_shadow_dir")
    if is_crmuser():
        return config.path.crm_config
    home = userdir.gethomedir(config.core.user)
    if home and home.startswith(os.path.sep):
        return os.path.join(home, ".cib")
    return utils.get_tempdir()


def listshadows():
    d = cib_shadow_dir()
    if not os.path.isdir(d):
        return []
    rc, l = utils.stdout2list("ls %s | fgrep shadow. | sed 's/^shadow\\.//'" % d)
    return l


def shadowfile(name):
    return "%s/shadow.%s" % (cib_shadow_dir(), name)


def pe2shadow(pe_file, name):
    '''Copy a PE file (or any CIB file) to a shadow.'''
    try:
        bits = open(pe_file, 'rb').read()
    except IOError as msg:
        logger.error("open: %s", msg)
        return False
    # decompresed if it ends with .bz2
    if pe_file.endswith(".bz2"):
        bits = bz2.decompress(bits)
    # copy input to the shadow
    try:
        open(shadowfile(name), "wb").write(bits)
    except IOError as msg:
        logger.error("open: %s", msg)
        return False
    return True


def is_xs_boolean_true(b):
    return b.lower() in ("true", "1")


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
        print(level*' ', e.tag, e.get("id"), e.get("name"))


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
        if c.tag not in ('primitive', 'group'):
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
        for a in constants.precious_attrs:
            if node.get(a):
                return False
        for n in node.iterchildren():
            return False
        return True
    else:
        return False


def is_emptynvpairs(node):
    return is_emptyelem(node, constants.nvpairs_tags)


def is_emptyops(node):
    return is_emptyelem(node, ("operations",))


def is_cib_element(node):
    return node.tag in constants.cib_cli_map


def is_group(node):
    return node.tag == "group"


def is_attr_set(node, attr):
    return get_attr_value(get_child_nvset_node(node), attr) is not None


def is_ms_or_promotable_clone(node):
    is_promotable_type = utils.is_boolean_true(is_attr_set(node, "promotable"))
    is_ms_type = node.tag in ("master", "ms")
    return is_ms_type or is_promotable_type


def is_clone(node):
    return node.tag == "clone"


def is_clonems(node):
    return node.tag in constants.clonems_tags


def is_cloned(node):
    return (node.getparent().tag in constants.clonems_tags or
            (node.getparent().tag == "group" and
             node.getparent().getparent().tag in constants.clonems_tags))


def is_container(node):
    return node.tag in constants.container_tags


def is_primitive(node):
    return node.tag == "primitive"


def is_resource(node):
    return node.tag in constants.resource_tags


def is_template(node):
    return node.tag == "template"


def is_child_rsc(node):
    return node.tag in constants.children_tags


def is_constraint(node):
    return node.tag in constants.constraint_tags


def is_defaults(node):
    return node.tag in constants.defaults_tags


def rsc_constraint(rsc_id, con_elem):
    for attr in list(con_elem.keys()):
        if attr in constants.constraint_rsc_refs \
                and rsc_id == con_elem.get(attr):
            return True
    for rref in con_elem.xpath("resource_set/resource_ref"):
        if rsc_id == rref.get("id"):
            return True
    return False


def is_related(rsc_id, node):
    """
    checks if the given node is an element
    that has a direct relation to rsc_id. That is,
    if it contains it, if it references it...
    """
    if is_constraint(node) and rsc_constraint(rsc_id, node):
        return True
    if node.tag == 'tag':
        if len(node.xpath('.//obj_ref[@id="%s"]' % (rsc_id))) > 0:
            return True
        return False
    if is_container(node):
        for tag in ('primitive', 'group', 'clone', 'master'):
            if len(node.xpath('.//%s[@id="%s"]' % (tag, rsc_id))) > 0:
                return True
        return False
    return False


def sort_container_children(e_list):
    '''
    Make sure that attributes's nodes are first, followed by the
    elements (primitive/group). The order of elements is not
    disturbed, they are just shifted to end!
    '''
    for node in e_list:
        children = [x for x in node.iterchildren()
                    if x.tag in constants.children_tags]
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
        ident = e.get("id")
        if ident:
            print("element id:", ident)


def remove_dflt_attrs(e_list):
    '''
    Drop optional attributes which are already set to default
    '''
    for e in e_list:
        try:
            d = constants.attr_defaults[e.tag]
            for a in list(d.keys()):
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
    # xml_processnodes(doc, true, printid)
    # xml_processnodes(doc, is_emptynvpairs, rmnodes)
    # xml_processnodes(doc, is_emptyops, rmnodes)
    xml_processnodes(doc, is_entity, rmnodes)
    # xml_processnodes(doc, is_comment, rmnodes)
    xml_processnodes(doc, is_container, sort_container_children)
    xml_processnodes(doc, true, remove_dflt_attrs)
    xml_processnodes(doc, true, remove_text)
    xmltraverse(doc, drop_attr_defaults)

def sanitize_cib_for_patching(doc):
    """
    Custom version of sanitize_cib which
    doesn't sort container children, to use
    for processing the original CIB when
    generating a patch to apply using crm_diff.
    """
    xml_processnodes(doc, is_status_node, rmnodes)
    xml_processnodes(doc, is_entity, rmnodes)
    xml_processnodes(doc, true, remove_dflt_attrs)
    xml_processnodes(doc, true, remove_text)

def is_simpleconstraint(node):
    return len(node.xpath("resource_set/resource_ref")) == 0


match_list = defaultdict(tuple,
                         {"node": ("uname",),
                          "nvpair": ("name",),
                          "op": ("name", "interval"),
                          "rule": ("score", "score-attribute", "role"),
                          "expression": ("attribute", "operation", "value"),
                          "fencing-level": ("target", "devices"),
                          "alert": ("path",),
                          "recipient": ("value",)})


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
    if oldnode is None:
        return None
    attr_list = list(match_list[node.tag])
    if not ignore_id and node.get("id"):
        attr_list.append("id")
    for c in oldnode.iterchildren():
        if not location_only and is_id_used_attr(c):
            continue
        if node.tag == c.tag:
            for a in attr_list:
                if node.get(a) != c.get(a):
                    break
            else:
                return c
    return None


def find_operation(rsc_node, name, interval=None):
    '''
    Setting interval to "non-0" means get the first op with interval
    different from 0.
    Not setting interval at all means get the only matching op, or the
    0 op (if any)
    '''
    matching_name = []
    for ops in rsc_node.findall("operations"):
        matching_name.extend([op for op in ops.iterchildren("op")
                              if op.get("name") == name])
    if interval is None and len(matching_name) == 1:
        return matching_name[0]
    interval = interval or "0"
    for op in matching_name:
        opint = op.get("interval")
        if interval == "non-0" and utils.crm_msec(opint) > 0:
            return op
        if utils.crm_time_cmp(opint, interval) == 0:
            return op
    return None


def get_op_timeout(rsc_node, op, default_timeout):
    interval = (op == "monitor" and "non-0" or "0")
    op_n = find_operation(rsc_node, op == "probe" and "monitor" or op, interval)
    timeout = op_n is not None and op_n.get("timeout") or default_timeout
    return utils.crm_msec(timeout)


def op2list(node):
    pl = []
    action = ""
    for name in list(node.keys()):
        if name == "name":
            action = node.get(name)
        elif name != "id":  # skip the id
            pl.append([name, node.get(name)])
    if not action:
        logger.error("op is invalid (no name)")
    return action, pl


def get_rsc_operations(rsc_node):
    actions = [op2list(op) for op in rsc_node.xpath('.//operations/op')]
    actions = [[op, pl] for op, pl in actions if op]
    return actions


# lower score = earlier sort
def make_sort_map(*order):
    m = {}
    for i, o in enumerate(order):
        if isinstance(o, str):
            m[o] = i
        else:
            for k in o:
                m[k] = i
    return m


_sort_xml_order = make_sort_map('node',
                                'template', 'primitive', 'bundle', 'group', 'master', 'clone', 'op',
                                'tag',
                                ['rsc_location', 'rsc_colocation', 'rsc_order'],
                                ['rsc_ticket', 'fencing-topology'],
                                'cluster_property_set', 'rsc_defaults', 'op_defaults',
                                'acl_role', ['acl_target', 'acl_group', 'acl_user'],
                                'alert')

_sort_cli_order = make_sort_map('node',
                                'rsc_template', 'primitive', 'bundle', 'group',
                                ['ms', 'master'], 'clone', 'op',
                                'tag',
                                ['location', 'colocation', 'collocation', 'order'],
                                ['rsc_ticket', 'fencing_topology'],
                                'property', 'rsc_defaults', 'op_defaults',
                                'role', ['acl_target', 'acl_group', 'user'],
                                'alert')

_SORT_LAST = 1000


def processing_sort(nl):
    '''
    It's usually important to process cib objects in this order,
    i.e. simple objects first.

    TODO: if sort_elements is disabled, only sort to resolve inter-dependencies.
    '''
    def sort_elements(k):
        return _sort_xml_order.get(k.tag, _SORT_LAST)

    def sort_type(k):
        return _sort_xml_order.get(k.tag, _SORT_LAST)

    return sorted(nl, key=sort_elements if config.core.sort_elements else sort_type)


def processing_sort_cli(nl):
    '''
    nl: list of objects (CibObject)
    Returns the given list in order

    TODO: if sort_elements is disabled, only sort to resolve inter-dependencies.
    '''
    def sort_elements(k):
        return _sort_cli_order.get(k.obj_type, _SORT_LAST), k.obj_id

    def sort_type(k):
        return _sort_cli_order.get(k.obj_type, _SORT_LAST)

    return sorted(nl, key=sort_elements if config.core.sort_elements else sort_type)


def is_resource_cli(s):
    return s in utils.olist(constants.resource_cli_names)


def is_constraint_cli(s):
    return s in utils.olist(constants.constraint_cli_names)


def referenced_resources(node):
    if not is_constraint(node):
        return []
    xml_obj_type = node.tag
    rsc_list = []
    if xml_obj_type == "rsc_location" and node.get("rsc"):
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
    return [rsc for rsc in rsc_list if rsc is not None]


def rename_id(node, old_id, new_id):
    if node.get("id") == old_id:
        node.set("id", new_id)


def rename_rscref_simple(c_obj, old_id, new_id):
    c_modified = False
    for attr in list(c_obj.node.keys()):
        if attr in constants.constraint_rsc_refs and \
                c_obj.node.get(attr) == old_id:
            c_obj.node.set(attr, new_id)
            c_obj.updated = True
            c_modified = True
    return c_modified


def delete_rscref_simple(c_obj, rsc_id):
    c_modified = False
    for attr in list(c_obj.node.keys()):
        if attr in constants.constraint_rsc_refs and \
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
        elif not utils.get_boolean(rset.get("sequential"), True) and rref_cnt > 1:
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
    cli = c_obj.repr_cli(format_mode=-1)
    cli = cli.replace("_rsc_set_ ", "")
    newnode = c_obj.cli2node(cli)
    if newnode is not None:
        c_obj.node.getparent().replace(c_obj.node, newnode)
        c_obj.node = newnode
        if rsetcnt == 1 and c_obj.obj_type == "colocation":
            # exchange the elements in colocations
            rsc = newnode.get("rsc")
            with_rsc = newnode.get("with-rsc")
            if with_rsc is not None:
                newnode.set("rsc", with_rsc)
            if rsc is not None:
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
        if rsc_id not in d:
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
        logger.info("modified %s from %s to %s", str(c_obj), old_id, new_id)


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
        cnt = len(c_node.xpath("resource_set/resource_ref"))
        if c_node.tag in ("rsc_location", "rsc_ticket"):  # locations and tickets are never silly
            return cnt < 1
        return cnt <= 1
    cnt = 0  # total count of referenced resources have to be at least two
    rsc_cnt = 0
    for attr in list(c_node.keys()):
        if attr in constants.constraint_rsc_refs:
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
        elems = get_conf_elems(cib_elem, path)
        return elems[0] if elems else None
    except IndexError:
        return None


def get_topnode(cib_elem, tag):
    "Get configuration element or create/append if there's none."
    conf_elem = cib_elem.find("configuration")
    if conf_elem is None:
        logger.error("no configuration element found!")
        return None
    if tag == "configuration":
        return conf_elem
    e = cib_elem.find("configuration/%s" % tag)
    if e is None:
        logger.debug("create configuration section %s", tag)
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
    nvp = get_attr_in_set(e, attr)
    if nvp is None:
        from . import idmgmt
        nvp = etree.SubElement(e, "nvpair", id="", name=attr, value=value)
        nvp.set("id", idmgmt.new(nvp, e.get("id")))
    else:
        nvp.set("name", attr)
        nvp.set("value", value)


def get_set_nodes(e, setname, create=False):
    """Return the attributes set nodes (create one if requested)
    setname can for example be meta_attributes
    """
    l = [c for c in e.iterchildren(setname)]
    if l:
        return l
    if create:
        from . import idmgmt
        elem = etree.SubElement(e, setname, id="")
        elem.set("id", idmgmt.new(elem, e.get("id")))
        l.append(elem)
    return l

def get_set_instace_attributes(e, create=False):
    '''
    Return instance attributes set nodes (create one if requested)
    '''
    l = [c for c in e.iterchildren("instance_attributes")]
    if l:
        return l
    if create:
        from . import idmgmt
        elem = etree.SubElement(e, "instance_attributes", id="")
        elem.set("id", "nodes-"+e.attrib["id"])
        l.append(elem)
    return l


_checker = doctestcompare.LXMLOutputChecker()


def xml_equals_unordered(a, b):
    """
    used by xml_equals to compare xml trees without ordering.
    NOTE: resource_set children SHOULD be compared with ordering.
    """
    def fail(msg):
        logger.debug("%s!=%s: %s", a.tag, b.tag, msg)
        return False

    def tagflat(x):
        return isinstance(x.tag, str) and x.tag or x.text

    def sortby(v):
        if v.tag == 'primitive':
            return v.tag
        return tagflat(v) + ''.join(sorted(list(v.attrib.keys()) + list(v.attrib.values())))

    def safe_strip(text):
        return text is not None and text.strip() or ''

    if a.tag != b.tag:
        return fail("tags differ: %s != %s" % (a.tag, b.tag))
    elif a.attrib != b.attrib:
        return fail("attributes differ: %s != %s" % (a.attrib, b.attrib))
    elif safe_strip(a.text) != safe_strip(b.text):
        return fail("text differ %s != %s" % (repr(a.text), repr(b.text)))
    elif safe_strip(a.tail) != safe_strip(b.tail):
        return fail("tails differ: %s != %s" % (a.tail, b.tail))
    elif len(a) != len(b):
        return fail("number of children differ")
    elif len(a) == 0:
        return True

    # order matters here, but in a strange way:
    # all primitive tags should sort the same..
    if a.tag == 'resource_set':
        return all(xml_equals_unordered(a, b) for a, b in zip(a, b))
    else:
        sorted_children = list(zip(sorted(a, key=sortby), sorted(b, key=sortby)))
        return all(xml_equals_unordered(a, b) for a, b in sorted_children)


def xml_equals(n, m, show=False):
    rc = xml_equals_unordered(n, m)
    if not rc and show and config.core.debug:
        # somewhat strange, but that's how this works
        from doctest import Example
        example = Example("etree.tostring(n)", xml_tostring(n))
        got = xml_tostring(m)
        print(_checker.output_difference(example, got, 0))
    return rc


def xml_tostring(*args, **kwargs):
    """
    Python 2/3 conversion utility:
    etree.tostring returns a bytestring, but
    we need actual Python strings.
    """
    return etree.tostring(*args, **kwargs).decode('utf-8')


def merge_attributes(dnode, snode, tag):
    rc = False
    add_children = []
    for sc in snode.iterchildren(tag):
        dc = lookup_node(sc, dnode, ignore_id=True)
        if dc is not None:
            for a, v in list(sc.items()):
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
    If an element is attributes set (constants.nvpairs_tags) or
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
            if sc.tag in constants.nvpairs_tags or sc.tag == "operations":
                add_children.append(sc)
                rc = True
        elif dc.tag in constants.nvpairs_tags:
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
    for a, v in list(prim_node.items()):
        dnode.set(a, v)
    # but class/provider/type are coming from the template
    # savannah#41410: stonith resources do not have the provider
    # attribute
    for a in ("class", "provider", "type"):
        v = tmpl_node.get(a)
        if v is not None:
            dnode.set(a, v)
    return dnode


def check_id_ref(elem, id_ref):
    target = elem.xpath('.//*[@id="%s"]' % (id_ref))
    if len(target) == 0:
        logger.error("Reference not found: %s", id_ref)
    elif len(target) > 1:
        logger.error("Ambiguous reference to %s", id_ref)


def new(tag, **attributes):
    """
    <tag/>
    """
    return etree.Element(tag, **attributes)


def child(parent, tag, **attributes):
    """append new tag to parent.
    Use append() in case parent is a list and not an element.
    """
    e = etree.Element(tag, **attributes)
    parent.append(e)
    return e


def tostring(n):
    return etree.tostring(n, pretty_print=True)


def maybe_set(node, key, value):
    if value:
        node.set(key, value)
    return node


def nvpair(name, value):
    """
    <nvpair name="" value="" />
    """
    value = utils.handle_role_for_ocf_1_1(value, name=name)
    return new("nvpair", name=name, value=value)


def nvpair_id(nvpairid, name, value):
    """
    <nvpair id="" name="" value="" />
    """
    if name is None:
        name = nvpairid
    return new("nvpair", id=nvpairid, name=name, value=value)


def nvpair_ref(idref, name=None):
    """
    <nvpair id-ref=<idref> [name=<name>]/>
    """
    nvp = new("nvpair")
    nvp.set('id-ref', idref)
    if name is not None:
        nvp.set('name', name)
    return nvp


def set_date_expression(expr, tag, values):
    """
    Fill in date_expression tag for date_spec/in_range operations
    expr: <date_expression/>
    values: [nvpair...]
    """
    if set(nvp.get('name') for nvp in values) == set(constants.in_range_attrs):
        for nvp in values:
            expr.set(nvp.get('name'), nvp.get('value'))
        return expr
    subtag = child(expr, tag)
    for nvp in values:
        if nvp.get('name') in constants.in_range_attrs:
            expr.set(nvp.get('name'), nvp.get('value'))
        else:
            subtag.set(nvp.get('name'), nvp.get('value'))
    return expr


def attributes(typename, rules, values, xmlid=None, score=None):
    """
    Represents a set of name-value pairs, tagged with
    a container typename and an optional xml id.
    The container can also hold rule expressions, passed
    in the rules parameter.

    returns an xml object containing the data
    example:
    <instance_attributes id="foo">
    <nvpair name="thing" value="yes"/>
    </instance_attributes>
    """
    e = new(typename)
    if xmlid:
        e.set("id", xmlid)
    if score:
        e.set("score", score)
    for rule in rules:
        e.append(rule)
    for nvp in values:
        e.append(nvp)
    return e


class CrmMonXmlParser(object):
    """
    Class to parse xml output of crm_mon
    """
    def __init__(self, peer=None):
        """
        Init function
        when peer set, parse peer node's results
        """
        self.peer = peer
        self.xml_elem = self._load()

    def _load(self):
        """
        Load xml output of crm_mon
        """
        _, output, _ = sh.cluster_shell().get_rc_stdout_stderr_without_input(self.peer, constants.CRM_MON_XML_OUTPUT)
        return text2elem(output)

    def is_node_online(self, node):
        """
        Check if a node is online
        """
        xpath = f'//node[@name="{node}" and @online="true"]'
        return bool(self.xml_elem.xpath(xpath))

    def get_node_list(self, online=True, standby=False, exclude_remote=True) -> typing.List[str]:
        """
        Get a list of nodes based on the given attribute
        """
        xpath_str = '//nodes/node'
        conditions = []
        online_value = "true" if online else "false"
        conditions.append(f'@online="{online_value}"')
        standby_value = "true" if standby else "false"
        conditions.append(f'@standby="{standby_value}"')
        if exclude_remote:
            conditions.append('@type="member"')
        xpath_str += '[' + ' and '.join(conditions) + ']'
        return [elem.get('name') for elem in self.xml_elem.xpath(xpath_str)]

    def is_resource_configured(self, ra_type):
        """
        Check if the RA is configured
        """
        xpath = f'//resource[@resource_agent="{ra_type}"]'
        return bool(self.xml_elem.xpath(xpath))

    def is_any_resource_running(self):
        """
        Check if any RA is running
        """
        xpath = '//resource[@active="true"]'
        return bool(self.xml_elem.xpath(xpath))

    def is_resource_started(self, ra):
        """
        Check if the RA started(in all clone instances if configured as clone)

        @ra could be resource id or resource type
        """
        xpath = f'//resource[(@id="{ra}" or @resource_agent="{ra}") and @active="true" and @role="Started"]'
        return bool(self.xml_elem.xpath(xpath))

    def get_resource_id_list_via_type(self, ra_type):
        """
        Given configured ra type, get the ra id list
        """
        xpath = f'//resource[@resource_agent="{ra_type}"]'
        return [elem.get('id') for elem in self.xml_elem.xpath(xpath)]
# vim:ts=4:sw=4:et:
