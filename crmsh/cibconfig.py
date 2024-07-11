# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# See COPYING for license information.

import copy
import os
import sys
import re
import fnmatch
import time
import collections
from lxml import etree
from . import config
from . import options
from . import constants
from . import tmpfiles
from . import clidisplay
from . import idmgmt
from . import schema
from . import utils
from . import cibverify
from . import parse
from . import ordereddict
from . import orderedset
from . import cibstatus
from . import crm_gv
from . import ui_utils
from . import userdir
from .ra import get_ra, get_properties_list, get_pe_meta, get_properties_meta, RAInfo
from .utils import ext_cmd, safe_open_w, pipe_string, safe_close_w, crm_msec
from .utils import ask, lines2cli, olist
from .utils import page_string, str2tmp, ensure_sudo_readable
from .utils import run_ptest, is_id_valid, edit_file, get_boolean, filter_string
from .xmlutil import is_child_rsc, rsc_constraint, sanitize_cib, rename_id, get_interesting_nodes
from .xmlutil import is_pref_location, get_topnode, new_cib, get_rscop_defaults_meta_node
from .xmlutil import rename_rscref, is_ms_or_promotable_clone, silly_constraint, is_container, fix_comments
from .xmlutil import sanity_check_nvpairs, merge_nodes, op2list, mk_rsc_type, is_resource
from .xmlutil import stuff_comments, is_comment, is_constraint, read_cib, processing_sort_cli
from .xmlutil import find_operation, get_rsc_children_ids, is_primitive, referenced_resources
from .xmlutil import cibdump2elem, processing_sort, get_rsc_ref_ids, merge_tmpl_into_prim
from .xmlutil import remove_id_used_attributes, get_top_cib_nodes
from .xmlutil import merge_attributes, is_cib_element, sanity_check_meta
from .xmlutil import is_simpleconstraint, is_template, rmnode, is_defaults, is_live_cib
from .xmlutil import get_rsc_operations, delete_rscref, xml_equals, lookup_node, RscState
from .xmlutil import text2elem, is_related, check_id_ref, xml_tostring
from .xmlutil import sanitize_cib_for_patching, is_attr_set, get_set_nodes, set_attr
from .cliformat import get_score, nvpairs2list, abs_pos_score, cli_acl_roleref, nvpair_format
from .cliformat import cli_nvpair, cli_acl_rule, rsc_set_constraint, get_kind, head_id_format
from .cliformat import simple_rsc_constraint, cli_rule, cli_format
from .cliformat import cli_acl_role, cli_acl_permission, cli_path
from . import log


logger = log.setup_logger(__name__)
logger_utils = log.LoggerUtils(logger)


def show_unrecognized_elems(cib_elem):
    try:
        conf = cib_elem.findall("configuration")[0]
    except IndexError:
        logger.warning("CIB has no configuration element")
        return False
    rc = True
    for topnode in conf.iterchildren():
        if is_defaults(topnode) or topnode.tag == "fencing-topology":
            continue
        for c in topnode.iterchildren():
            if c.tag not in cib_object_map:
                logger.warning("unrecognized CIB element %s", c.tag)
                rc = False
    return rc


#
# object sets (enables operations on sets of elements)
#
def mkset_obj(*args):
    if not cib_factory.is_cib_sane():
        raise ValueError("CIB is not valid")
    if args and args[0] == "xml":
        return CibObjectSetRaw(*args[1:])
    return CibObjectSetCli(*args)


def set_graph_attrs(gv_obj, obj_type):
    try:
        for attr, attr_v in constants.graph['*'].items():
            gv_obj.new_graph_attr(attr, attr_v)
    except KeyError:
        pass
    try:
        for attr, attr_v in constants.graph[obj_type].items():
            gv_obj.new_graph_attr(attr, attr_v)
    except KeyError:
        pass


def set_obj_attrs(gv_obj, obj_id, obj_type):
    try:
        for attr, attr_v in constants.graph['*'].items():
            gv_obj.new_attr(obj_id, attr, attr_v)
    except KeyError:
        pass
    try:
        for attr, attr_v in constants.graph[obj_type].items():
            gv_obj.new_attr(obj_id, attr, attr_v)
    except KeyError:
        pass


def set_edge_attrs(gv_obj, edge_id, obj_type):
    try:
        for attr, attr_v in constants.graph[obj_type].items():
            gv_obj.new_edge_attr(edge_id, attr, attr_v)
    except KeyError:
        pass


def fill_nvpairs(name, node, attrs, id_hint):
    '''
    Fill the container node with attrs:
    name: name of container
    node: container Element
    attrs: dict containing values
    id_hint: used to generate unique ids for nvpairs
    '''
    subpfx = constants.subpfx_list.get(name, '')
    subpfx = "%s_%s" % (id_hint, subpfx) if subpfx else id_hint
    nvpair_pfx = node.get("id") or subpfx
    for n, v in attrs.items():
        nvpair = etree.SubElement(node, "nvpair", name=n)
        if v is not None:
            nvpair.set("value", v)
        idmgmt.set_id(nvpair, None, nvpair_pfx)
    return node


def mkxmlnvpairs(name, attrs, id_hint):
    '''
    name: Name of the element.
    attrs: dict containing a set of nvpairs.
    hint: Used to generate ids.

    Example: instance_attributes, {name: value...}, <hint>

    Notes:

      Other tags not containing nvpairs are fine if the dict is empty.

      cluster_property_set and defaults have nvpairs as direct children.
      In that case, use the id_hint directly as id.
      This is important in case there are multiple sets.

    '''
    xml_node_type = "meta_attributes" if name in constants.defaults_tags else name
    node = etree.Element(xml_node_type)
    notops = name != "operations"

    if (name == "cluster_property_set" or name in constants.defaults_tags) and id_hint:
        node.set("id", id_hint)
    id_ref = attrs.get("$id-ref")
    if id_ref:
        id_ref_2 = cib_factory.resolve_id_ref(name, id_ref)
        node.set("id-ref", id_ref_2)
        if notops:
            return node  # id_ref is the only attribute (if not operations)
        if '$id-ref' in attrs:
            del attrs['$id-ref']
    v = attrs.get('$id')
    if v:
        node.set("id", v)
        del attrs['$id']
    elif name in constants.nvset_cli_names:
        node.set("id", id_hint)
    else:
        # operations don't need no id
        idmgmt.set_id(node, None, id_hint, id_required=notops)
    return fill_nvpairs(name, node, attrs, id_hint)


def copy_nvpair(nvpairs, nvp, id_hint=None):
    """
    Copies the given nvpair into the given tag containing nvpairs
    """
    logger.debug("copy_nvpair: %s", xml_tostring(nvp))
    if 'value' not in nvp.attrib:
        nvpairs.append(copy.deepcopy(nvp))
        return
    n = nvp.get('name')
    if id_hint is None:
        id_hint = n
    for nvp2 in nvpairs:
        if nvp2.get('name') == n:
            nvp2.set('value', nvp.get('value'))
            break
    else:
        m = copy.deepcopy(nvp)
        nvpairs.append(m)
        if 'id' not in m.attrib:
            m.set('id', idmgmt.new(m, id_hint))


def copy_nvpairs(tonode, fromnode):
    """
    copy nvpairs from fromnode to tonode.
    things to copy can be nvpairs, comments or rules.
    """
    def copy_comment(cnode):
        for nvp2 in tonode:
            if is_comment(nvp2) and nvp2.text == cnode.text:
                break  # no need to copy
        else:
            tonode.append(copy.deepcopy(cnode))

    def copy_id(node):
        nid = node.get('id')
        for nvp2 in tonode:
            if nvp2.get('id') == nid:
                tonode.replace(nvp2, copy.deepcopy(node))
                break
        else:
            tonode.append(copy.deepcopy(node))

    logger.debug("copy_nvpairs: %s -> %s", xml_tostring(fromnode), xml_tostring(tonode))
    id_hint = tonode.get('id')
    for c in fromnode:
        if is_comment(c):
            copy_comment(c)
        elif c.tag == "nvpair":
            copy_nvpair(tonode, c, id_hint=id_hint)
        elif 'id' in c.attrib:  # ok, it has an id, we can work with this
            copy_id(c)
        else:  # no idea what this is, just copy it
            tonode.append(copy.deepcopy(c))


class CibObjectSet(object):
    '''
    Edit or display a set of cib objects.
    repr() for objects representation and
    save() used to store objects into internal structures
    are defined in subclasses.
    '''
    def __init__(self, *args):
        self.args = args
        self._initialize()

    def _initialize(self):
        rc, self.obj_set = cib_factory.mkobj_set(*self.args)
        self.search_rc = rc
        self.all_set = cib_factory.get_all_obj_set()
        self.obj_ids = orderedset.oset([o.obj_id for o in self.obj_set])
        self.all_ids = orderedset.oset([o.obj_id for o in self.all_set])
        self.locked_ids = self.all_ids - self.obj_ids

    def _open_url(self, src):
        if src == "-":
            return sys.stdin
        import urllib.request
        import urllib.error
        import urllib.parse
        try:
            ret = urllib.request.urlopen(src)
            return ret
        except (urllib.error.URLError, ValueError):
            pass
        try:
            ret = open(src)
            return ret
        except IOError as e:
            logger.error("could not open %s: %s", src, e)
        return False

    def _pre_edit(self, s):
        '''Extra processing of the string to be editted'''
        return s

    def _post_edit(self, s):
        '''Extra processing after editing'''
        return s

    def _edit_save(self, s):
        '''
        Save string s to a tmp file. Invoke editor to edit it.
        Parse/save the resulting file. In case of syntax error,
        allow user to reedit.
        If no changes are done, return silently.
        '''
        rc = False
        try:
            s = self._pre_edit(s)
            filehash = hash(s)
            tmp = str2tmp(s)
            if not tmp:
                return False
            while not rc:
                if edit_file(tmp) != 0:
                    break
                s = open(tmp).read()
                if hash(s) != filehash:
                    ok = self.save(self._post_edit(s))
                    if not ok and config.core.force:
                        logger.error("Save failed and --force is set, aborting edit to avoid infinite loop")
                    elif not ok and ask("Edit or discard changes (yes to edit, no to discard)?"):
                        continue
                rc = True
            os.unlink(tmp)
        except OSError as e:
            logger.error("unlink(%s) failure: %s", tmp, e)
        except IOError as msg:
            logger.error(msg)
        return rc

    def edit(self):
        if options.batch:
            logger.info("edit not allowed in batch mode")
            return False
        with clidisplay.nopretty():
            s = self.repr()
        # don't allow edit if one or more elements were not
        # found
        if not self.search_rc:
            return self.search_rc
        return self._edit_save(s)

    def _filter_save(self, fltr, s):
        '''
        Pipe string s through a filter. Parse/save the output.
        If no changes are done, return silently.
        '''
        rc, outp = filter_string(fltr, s)
        if rc != 0:
            return False
        if hash(outp) == hash(s):
            return True
        return self.save(outp)

    def filter(self, fltr):
        with clidisplay.nopretty():
            s = self.repr(format_mode=-1)
        # don't allow filter if one or more elements were not
        # found
        if not self.search_rc:
            return self.search_rc
        return self._filter_save(fltr, s)

    def save_to_file(self, fname):
        f = safe_open_w(fname)
        if not f:
            return False
        rc = True
        with clidisplay.nopretty():
            s = self.repr()
        if s:
            f.write(s)
            f.write('\n')
        elif self.obj_set:
            rc = False
        safe_close_w(f)
        return rc

    def _get_gv_obj(self, gtype):
        if not self.obj_set:
            return True, None
        if gtype not in crm_gv.gv_types:
            logger.error("graphviz type %s is not supported", gtype)
            return False, None
        gv_obj = crm_gv.gv_types[gtype]()
        set_graph_attrs(gv_obj, ".")
        return True, gv_obj

    def _graph_repr(self, gv_obj):
        '''Let CIB elements produce graph elements.
        '''
        for obj in processing_sort_cli(list(self.obj_set)):
            obj.repr_gv(gv_obj, from_grp=False)

    def query_graph(self, *args):
        "usage: graph <pe> [<gtype> [<file> [<img_format>]]]"
        rc, gtype, outf, ftype = ui_utils.graph_args(args)
        if not rc:
            return None
        rc, d = utils.load_graphviz_file(userdir.GRAPHVIZ_USER_FILE)
        if rc and d:
            constants.graph = d
        if outf is None:
            return self.show_graph(gtype)
        elif gtype == ftype:
            rc = self.save_graph(gtype, outf)
        else:
            rc = self.graph_img(gtype, outf, ftype)
        return rc

    def show_graph(self, gtype):
        '''Display graph using dotty'''
        rc, gv_obj = self._get_gv_obj(gtype)
        if not rc or not gv_obj:
            return rc
        self._graph_repr(gv_obj)
        return gv_obj.display()

    def graph_img(self, gtype, outf, img_type):
        '''Render graph to image and save it to a file (done by
        dot(1))'''
        rc, gv_obj = self._get_gv_obj(gtype)
        if not rc or not gv_obj:
            return rc
        self._graph_repr(gv_obj)
        return gv_obj.image(img_type, outf)

    def save_graph(self, gtype, outf):
        '''Save graph to a file'''
        rc, gv_obj = self._get_gv_obj(gtype)
        if not rc or not gv_obj:
            return rc
        self._graph_repr(gv_obj)
        return gv_obj.save(outf)

    def show(self):
        s = self.repr()
        if s:
            page_string(s)
        return self.search_rc

    def import_file(self, method, fname):
        '''
        method: update or replace or push
        '''
        if not cib_factory.is_cib_sane():
            return False
        f = self._open_url(fname)
        if not f:
            return False
        s = f.read()
        if f != sys.stdin:
            f.close()
        if method == 'push':
            return self.save(s, remove=True, method='update')
        else:
            return self.save(s, remove=False, method=method)

    def repr(self, format_mode=0):
        '''
        Return a string with objects's representations (either
        CLI or XML).
        '''
        return ''

    def save(self, s, remove=True, method='replace'):
        '''
        For each object:
            - try to find a corresponding object in obj_set
            - if (update and not found) or found:
              replace the object in the obj_set with
              the new object
            - if not found: create new
        See below for specific implementations.
        '''
        pass

    def _check_unique_clash(self, set_obj_all):
        'Check whether resource parameters with attribute "unique" clash'
        def process_primitive(prim, clash_dict):
            '''
            Update dict clash_dict with
            (ra_class, ra_provider, ra_type, name, value) -> [ resourcename ]
            if parameter "name" should be unique
            '''
            ra_id = prim.get("id")
            r_node = reduce_primitive(prim)
            if r_node is None:
                return  # template not defined yet
            ra_type = node.get("type")
            ra_class = node.get("class")
            ra_provider = node.get("provider")
            ra = get_ra(r_node)
            if ra.mk_ra_node() is None:  # no RA found?
                return
            ra_params = ra.params()
            for p in r_node.xpath("./instance_attributes/nvpair"):
                name, value = p.get("name"), p.get("value")
                if value is None:
                    continue
                # don't fail if the meta-data doesn't contain the
                # expected attributes
                if name in ra_params and ra_params[name].get("unique") == "1":
                    clash_dict[(ra_class, ra_provider, ra_type, name, value)].append(ra_id)
            return
        # we check the whole CIB for clashes as a clash may originate between
        # an object already committed and a new one
        check_set = set([o.obj_id
                         for o in self.obj_set
                         if o.obj_type == "primitive"])
        if not check_set:
            return 0
        clash_dict = collections.defaultdict(list)
        for obj in set_obj_all.obj_set:
            node = obj.node
            if is_primitive(node):
                process_primitive(node, clash_dict)
        # but we only warn if a 'new' object is involved
        rc = 0
        for param, resources in list(clash_dict.items()):
            # at least one new object must be involved
            if len(resources) > 1 and len(set(resources) & check_set) > 0:
                rc = 2
                msg = 'Resources %s violate uniqueness for parameter "%s": "%s"' % (
                    ",".join(sorted(resources)), param[3], param[4])
                logger.warning(msg)
        return rc

    def semantic_check(self, set_obj_all):
        '''
        Test objects for sanity. This is about semantics.
        '''
        rc = self._check_unique_clash(set_obj_all)
        for obj in sorted(self.obj_set, key=lambda x: x.obj_id):
            rc |= obj.check_sanity()
        return rc


class CibObjectSetCli(CibObjectSet):
    '''
    Edit or display a set of cib objects (using cli notation).
    '''
    vim_stx_str = "# vim: set filetype=pcmk:\n"

    def __init__(self, *args):
        CibObjectSet.__init__(self, *args)

    def repr_nopretty(self, format_mode=1):
        with clidisplay.nopretty():
            return self.repr(format_mode=format_mode)

    def repr(self, format_mode=1):
        "Return a string containing cli format of all objects."
        if not self.obj_set:
            return ''
        return '\n'.join(obj.repr_cli(format_mode=format_mode)
                         for obj in processing_sort_cli(list(self.obj_set)))

    def _pre_edit(self, s):
        '''Extra processing of the string to be edited'''
        if config.core.editor.startswith("vi"):
            return "%s\n%s" % (s, self.vim_stx_str)
        return s

    def _post_edit(self, s):
        if config.core.editor.startswith("vi"):
            return s.replace(self.vim_stx_str, "")
        return s

    def _get_id(self, node):
        '''
        Get the id from a CLI representation. Normally, it should
        be value of the id attribute, but sometimes the
        attribute is missing.
        '''
        if node.tag == 'fencing-topology':
            return 'fencing_topology'
        if node.tag in constants.defaults_tags:
            return node[0].get('id')
        return node.get('id')

    def save(self, s, remove=True, method='replace'):
        '''
        Save a user supplied cli format configuration.
        On errors user is typically asked to review the
        configuration (for instance on editting).

        On errors, the user is asked to edit again (if we're
        coming from edit). The original CIB is preserved and no
        changes are made.
        '''
        diff = CibDiff(self)
        rc = True
        comments = []
        with logger_utils.line_number():
            for cli_text in lines2cli(s):
                logger_utils.incr_lineno()
                node = parse.parse(cli_text, comments=comments)
                if node not in (False, None):
                    rc = rc and diff.add(node)
                elif node is False:
                    rc = False

        # we can't proceed if there was a syntax error, but we
        # can ask the user to fix problems
        if not rc:
            return rc

        rc = diff.apply(cib_factory, mode='cli', remove=remove, method=method)
        if not rc:
            self._initialize()
        return rc


class CibObjectSetRaw(CibObjectSet):
    '''
    Edit or display one or more CIB objects (XML).
    '''
    def __init__(self, *args):
        CibObjectSet.__init__(self, *args)

    def repr(self, format_mode="ignored"):
        "Return a string containing xml of all objects."
        cib_elem = cib_factory.obj_set2cib(self.obj_set)

        from .utils import obscured
        for nvp in cib_elem.xpath('//nvpair'):
            if 'value' in nvp.attrib:
                nvp.set('value', obscured(nvp.get('name'), nvp.get('value')))

        s = xml_tostring(cib_elem, pretty_print=True)
        return '<?xml version="1.0" ?>\n' + s

    def _get_id(self, node):
        if node.tag == "fencing-topology":
            return "fencing_topology"
        return node.get("id")

    def save(self, s, remove=True, method='replace'):
        try:
            cib_elem = etree.fromstring(s)
        except etree.ParseError as msg:
            logger_utils.text_xml_parse_err(msg, s)
            return False
        sanitize_cib(cib_elem)
        if not show_unrecognized_elems(cib_elem):
            return False
        rc = True
        diff = CibDiff(self)
        for node in get_top_cib_nodes(cib_elem, []):
            rc = diff.add(node)
        if not rc:
            return rc
        rc = diff.apply(cib_factory, mode='xml', remove=remove, method=method)
        if not rc:
            self._initialize()
        return rc

    def verify(self):
        if not self.obj_set:
            return True
        with clidisplay.nopretty():
            cib = self.repr(format_mode=-1)
        rc = cibverify.verify(cib)

        if rc not in (0, 1):
            logger.debug("verify (rc=%s): %s", rc, cib)
        return rc in (0, 1)

    def ptest(self, nograph, scores, utilization, actions, verbosity):
        if not cib_factory.is_cib_sane():
            return False
        cib_elem = cib_factory.obj_set2cib(self.obj_set)
        status = cibstatus.cib_status.get_status()
        if status is None:
            logger.error("no status section found")
            return False
        cib_elem.append(copy.deepcopy(status))
        graph_s = etree.tostring(cib_elem)
        return run_ptest(graph_s, nograph, scores, utilization, actions, verbosity)


def find_comment_nodes(node):
    return [c for c in node.iterchildren() if is_comment(c)]


def fix_node_ids(node, oldnode):
    """
    Fills in missing ids, getting ids from oldnode
    as much as possible. Tries to generate reasonable
    ids as well.
    """
    hint_map = {
        'node': 'node',
        'primitive': 'rsc',
        'template': 'rsc',
        'master': 'grp',
        'group': 'grp',
        'clone': 'grp',
        'rsc_location': 'location',
        'fencing-topology': 'fencing',
        'tags': 'tag',
        'alerts': 'alert',
        }

    idless = set([
        'operations', 'fencing-topology', 'network', 'docker', 'podman', 'rkt',
        'storage', 'select', 'select_attributes', 'select_fencing',
        'select_nodes', 'select_resources'
    ])
    isref = set(['resource_ref', 'obj_ref', 'crmsh-ref'])

    def needs_id(node):
        a = node.attrib
        if node.tag in isref:
            return False
        return 'id-ref' not in a and node.tag not in idless

    def next_prefix(node, refnode, prefix):
        if node.tag == 'node' and 'uname' in node.attrib:
            return node.get('uname')
        if 'id' in node.attrib:
            return node.get('id')
        return prefix

    def recurse(node, oldnode, prefix):
        refnode = lookup_node(node, oldnode)
        if needs_id(node):
            idmgmt.set_id(node, refnode, prefix, id_required=(node.tag not in idless))
        prefix = next_prefix(node, refnode, prefix)
        for c in node.iterchildren():
            if not is_comment(c):
                recurse(c, refnode if refnode is not None else oldnode, prefix)

    recurse(node, oldnode, hint_map.get(node.tag, ''))


def resolve_idref(node):
    """
    resolve id-ref references that refer
    to object ids, not attribute lists
    """
    id_ref = node.get('id-ref')
    attr_list_type = node.tag
    obj = cib_factory.find_object(id_ref)
    if obj:
        nodes = obj.node.xpath(".//%s" % attr_list_type)
        if len(nodes) > 1:
            logger.warning("%s contains more than one %s, using first", obj.obj_id, attr_list_type)
        if len(nodes) > 0:
            node_id = nodes[0].get("id")
            if node_id:
                return node_id
    check_id_ref(cib_factory.get_cib(), id_ref)
    return id_ref


def resolve_references(node):
    """
    In the output from parse(), there are
    possible references to other nodes in
    the CIB. This resolves those references.
    """
    idrefnodes = node.xpath('.//*[@id-ref]')
    if 'id-ref' in node.attrib:
        idrefnodes += [node]
    for ref in idrefnodes:
        ref.set('id-ref', resolve_idref(ref))
    for ref in node.iterchildren('crmsh-ref'):
        child_id = ref.get('id')
        # TODO: This always refers to a resource ATM.
        # Handle case where it may refer to a node name?
        obj = cib_factory.find_resource(child_id)
        logger.debug("resolve_references: %s -> %s", child_id, obj)
        if obj is not None:
            newnode = copy.deepcopy(obj.node)
            node.replace(ref, newnode)
        else:
            node.remove(ref)
            logger.error("%s refers to missing object %s", node.get('id'), child_id)


def id_for_node(node, id_hint=None):
    "find id for unprocessed node"
    root = node
    if node.tag in constants.defaults_tags:
        node = node[0]
    if node.tag == 'fencing-topology':
        obj_id = 'fencing_topology'
    else:
        obj_id = node.get('id') or node.get('uname')
    if obj_id is None:
        if node.tag == 'op':
            if id_hint is None:
                id_hint = node.get("rsc")
            idmgmt.set_id(node, None, id_hint)
            obj_id = node.get('id')
        else:
            defid = default_id_for_tag(root.tag)
            if defid is not None:
                try:
                    node.set('id', defid)
                except TypeError as e:
                    raise ValueError('Internal error: %s (%s)' % (e, xml_tostring(node)))
                obj_id = node.get('id')
                idmgmt.save(obj_id)
    if root.tag != "node" and obj_id and not is_id_valid(obj_id):
        logger_utils.invalid_id_err(obj_id)
        return None
    return obj_id


def postprocess_cli(node, oldnode=None, id_hint=None, complete_advised=False):
    """
    input: unprocessed but parsed XML
    output: XML, obj_type, obj_id
    """
    if node.tag == 'op':
        obj_type = 'op'
    else:
        obj_type = cib_object_map[node.tag][0]
    obj_id = id_for_node(node, id_hint=id_hint)
    if obj_id is None:
        if obj_type == 'op':
            # In this case, we need to delay postprocessing
            # until we know where to insert the op
            return node, obj_type, None
        logger.error("No ID found for %s: %s", obj_type, xml_tostring(node))
        return None, None, None
    if node.tag in constants.defaults_tags:
        node = node[0]
    fix_node_ids(node, oldnode)
    resolve_references(node)
    if oldnode is not None:
        remove_id_used_attributes(oldnode)
    if complete_advised:
        complete_advised_meta(node)
    return node, obj_type, obj_id


def complete_advised_meta(node):
    """
    Complete advised meta attributes
    """
    if node.tag != "clone":
        return
    primitive_list = node.xpath('primitive')
    if not primitive_list:
        return
    set_list = []
    for meta_item in ["promotable", "interleave"]:
        if not is_attr_set(node, meta_item):
            set_list.append(meta_item)
    if not set_list:
        return

    meta_node = get_set_nodes(node, "meta_attributes", create=True)[0]
    p = primitive_list[0]
    ra_inst = RAInfo(p.get('class'), p.get('type'), p.get('provider'))
    ra_actions_dict = ra_inst.actions()
    if ra_actions_dict and "promote" in ra_actions_dict and "demote" in ra_actions_dict:
        for item in set_list:
            set_attr(meta_node, item, "true")
    # Add interleave=true as long as it's not set, no matter if it's promotable clone or not
    elif "interleave" in set_list:
        set_attr(meta_node, "interleave", "true")


def parse_cli_to_xml(cli, oldnode=None):
    """
    input: CLI text
    output: XML, obj_type, obj_id
    """
    node = None
    complete = False
    comments = []
    if isinstance(cli, str):
        utils.auto_convert_role = False
        for s in lines2cli(cli):
            node = parse.parse(s, comments=comments)
    else:  # should be a pre-tokenized list
        utils.auto_convert_role = True
        complete = True
        node = parse.parse(cli, comments=comments, ignore_empty=False, complete_advised=complete)
    if node is False:
        return None, None, None
    elif node is None:
        return None, None, None
    return postprocess_cli(node, oldnode, complete_advised=complete)

#
# cib element classes (CibObject the parent class)
#
class CibObject(object):
    '''
    The top level object of the CIB. Resources and constraints.
    '''
    state_fmt = "%16s %-8s%-8s%-8s%-4s"
    set_names = {}

    def __init__(self, xml_obj_type):
        if xml_obj_type not in cib_object_map:
            logger_utils.unsupported_err(xml_obj_type)
            return
        self.obj_type = cib_object_map[xml_obj_type][0]
        self.parent_type = cib_object_map[xml_obj_type][2]
        self.xml_obj_type = xml_obj_type
        self.origin = ""        # where did it originally come from?
        self.nocli = False      # we don't support this one
        self.nocli_warn = True  # don't issue warnings all the time
        self.updated = False    # was the object updated
        self.parent = None      # object superior (group/clone/ms)
        self.children = []      # objects inferior
        self.obj_id = None
        self.node = None

    def __str__(self):
        return "%s:%s" % (self.obj_type, self.obj_id)

    def set_updated(self):
        self.updated = True
        self.propagate_updated()

    def dump_state(self):
        'Print object status'
        print(self.state_fmt % (self.obj_id,
                                self.origin,
                                self.updated,
                                self.parent and self.parent.obj_id or "",
                                len(self.children)))

    def _repr_cli_xml(self, format_mode):
        with clidisplay.nopretty(format_mode < 0):
            h = clidisplay.keyword("xml")
            l = xml_tostring(self.node, pretty_print=True).split('\n')
            l = [x for x in l if x]  # drop empty lines
            return "%s %s" % (h, cli_format(l, break_lines=(format_mode > 0), xml=True))

    def _gv_rsc_id(self):
        if self.parent and self.parent.obj_type in constants.clonems_tags:
            return "%s:%s" % (self.parent.obj_type, self.obj_id)
        return self.obj_id

    def _set_gv_attrs(self, gv_obj, obj_type=None):
        if not obj_type:
            obj_type = self.obj_type
        obj_id = self.node.get("uname") or self.obj_id
        set_obj_attrs(gv_obj, obj_id, obj_type)

    def _set_sg_attrs(self, sg_obj, obj_type=None):
        if not obj_type:
            obj_type = self.obj_type
        set_graph_attrs(sg_obj, obj_type)

    def _set_edge_attrs(self, gv_obj, e_id, obj_type=None):
        if not obj_type:
            obj_type = self.obj_type
        set_edge_attrs(gv_obj, e_id, obj_type)

    def repr_gv(self, gv_obj, from_grp=False):
        '''
        Add some graphviz elements to gv_obj.
        '''
        pass

    def normalize_parameters(self):
        pass

    def _repr_cli_head(self, format_mode):
        'implemented in subclasses'
        pass

    def repr_cli(self, format_mode=1):
        '''
        CLI representation for the node.
        _repr_cli_head and _repr_cli_child in subclasess.
        '''
        if self.nocli:
            return self._repr_cli_xml(format_mode)
        l = []
        with clidisplay.nopretty(format_mode < 0):
            head_s = self._repr_cli_head(format_mode)
            # everybody must have a head
            if not head_s:
                return None
            comments = []
            l.append(head_s)
            desc = self.node.get("description")
            if desc:
                l.append(nvpair_format("description", desc))
            for c in self.node.iterchildren():
                if is_comment(c):
                    comments.append(c.text)
                    continue
                s = self._repr_cli_child(c, format_mode)
                if s:
                    l.append(s)
            return self._cli_format_and_comment(l, comments, format_mode=format_mode)

    def _attr_set_str(self, node):
        '''
        Add $id=<id> if the set id is referenced by another
        element.

        also show rule expressions if found
        '''

        # has_nvpairs = len(node.xpath('.//nvpair')) > 0
        idref = node.get('id-ref')

        # don't skip empty sets: skipping these breaks
        # patching
        # empty set
        # if not (has_nvpairs or idref is not None):
        #    return ''

        ret = "%s " % (clidisplay.keyword(self.set_names[node.tag]))
        node_id = node.get("id")
        if node_id is not None and cib_factory.is_id_refd(node.tag, node_id):
            ret += "%s " % (nvpair_format("$id", node_id))
        elif idref is not None:
            ret += "%s " % (nvpair_format("$id-ref", idref))

        ret += self._attr_set_bundle_str(node)

        score = node.get("score")
        if score:
            ret += "%s: " % (clidisplay.score(score))

        for c in node.iterchildren():
            if c.tag == "rule":
                ret += "%s %s " % (clidisplay.keyword("rule"), cli_rule(c))
        for c in node.iterchildren():
            if c.tag == "nvpair":
                ret += "%s " % (cli_nvpair(c))
        if ret[-1] == ' ':
            ret = ret[:-1]
        return ret

    def _attr_set_bundle_str(self, node):
        ret = ""
        prefix = "\\\n\t\t"

        if node.tag in constants.container_type:
            if "image" not in node.keys():
                logger.error("%s requires 'image' attribute", node.tag)
                return ret
            ret += f"{nvpair_format('image', node.get('image'))} "
            for item in node.keys():
                if item != "image":
                    ret += f"{prefix}{nvpair_format(item, node.get(item))} "

        if node.tag in ("network", "storage"):
            for item in node.keys():
                ret += f"{nvpair_format(item, node.get(item))} "
            for _type in ("port-mapping", "storage-mapping"):
                for c in node.iterchildren(_type):
                    ret += f"{prefix}{_type} "
                    for item in c.keys():
                        if item != "id":
                            ret += f"{nvpair_format(item, c.get(item))} "

        if node.tag == "primitive":
            ret += node.get('id')

        return ret

    def _repr_cli_child(self, c, format_mode):
        if c.tag in self.set_names:
            return self._attr_set_str(c)

    def _get_oldnode(self):
        '''
        Used to retrieve sub id's.
        '''
        if self.obj_type == "property":
            return get_topnode(cib_factory.get_cib(), self.parent_type)
        elif self.obj_type in constants.defaults_tags:
            return self.node.getparent()
        return self.node

    def set_id(self, obj_id=None):
        if obj_id is None and self.node is not None:
            obj_id = self.node.get("id") or self.node.get('uname')
            if obj_id is None:
                m = cib_object_map.get(self.node.tag)
                if m and len(m) > 3:
                    obj_id = m[3]
        self.obj_id = obj_id

    def set_nodeid(self):
        if self.node is not None and self.obj_id:
            self.node.set("id", self.obj_id)

    def cli2node(self, cli):
        '''
        Convert CLI representation to a DOM node.
        '''
        oldnode = self._get_oldnode()
        node, obj_type, obj_id = parse_cli_to_xml(cli, oldnode)
        return node

    def set_node(self, node, oldnode=None):
        self.node = node
        self.set_id()
        return self.node

    def _cli_format_and_comment(self, l, comments, format_mode):
        '''
        Format and add comment (if any).
        '''
        s = cli_format(l, break_lines=(format_mode > 0))
        cs = '\n'.join(comments)
        if len(comments) and format_mode >= 0:
            return '\n'.join([cs, s])
        return s

    def move_comments(self):
        '''
        Move comments to the top of the node.
        '''
        l = []
        firstelem = None
        for n in self.node.iterchildren():
            if is_comment(n):
                if firstelem:
                    l.append(n)
            else:
                if not firstelem:
                    firstelem = self.node.index(n)
        for comm_node in l:
            self.node.remove(comm_node)
            self.node.insert(firstelem, comm_node)
            firstelem += 1

    def mknode(self, obj_id):
        if self.xml_obj_type in constants.defaults_tags:
            tag = "meta_attributes"
        else:
            tag = self.xml_obj_type
        self.node = etree.Element(tag)
        self.set_id(obj_id)
        self.set_nodeid()
        self.origin = "user"
        return True

    def can_be_renamed(self):
        '''
        Return False if this object can't be renamed.
        '''
        if self.obj_id is None:
            return False
        rscstat = RscState()
        if not rscstat.can_delete(self.obj_id):
            logger.error("cannot rename a running resource (%s)", self.obj_id)
            return False
        if not is_live_cib() and self.node.tag == "node":
            logger.error("cannot rename nodes")
            return False
        return True

    def cli_use_validate(self):
        '''
        Check validity of the object, as we know it. It may
        happen that we don't recognize a construct, but that the
        object is still valid for the CRM. In that case, the
        object is marked as "CLI read only", i.e. we will neither
        convert it to CLI nor try to edit it in that format.

        The validation procedure:
        we convert xml to cli and then back to xml. If the two
        xml representations match then we can understand the xml.

        Complication:
        There are valid variations of the XML where the CLI syntax
        cannot express the difference. For example, sub-tags in a
        <primitive> are not ordered, but the CLI syntax can only express
        one specific ordering.

        This is usually not a problem unless mixing pcs and crmsh.
        '''
        if self.node is None:
            return True
        with clidisplay.nopretty():
            cli_text = self.repr_cli(format_mode=0)
        if not cli_text:
            logger.debug("validation failed: %s", xml_tostring(self.node))
            return False
        xml2 = self.cli2node(cli_text)
        if xml2 is None:
            logger.debug("validation failed: %s -> %s", xml_tostring(self.node), cli_text)
            return False
        if not xml_equals(self.node, xml2, show=True):
            logger.debug("validation failed: %s -> %s -> %s", xml_tostring(self.node), cli_text, xml_tostring(xml2))
            return False
        return True

    def _verify_op_attributes(self, op_node):
        '''
        Check if all operation attributes are supported by the
        schema.
        '''
        rc = 0
        op_id = op_node.get("name")
        for name in list(op_node.keys()):
            vals = schema.rng_attr_values(op_node.tag, name)
            if not vals:
                continue
            v = op_node.get(name)
            if v not in vals:
                logger.warning("%s: op '%s' attribute '%s' value '%s' not recognized", self.obj_id, op_id, name, v)
                rc = 1
        return rc

    def _check_ops_attributes(self):
        '''
        Check if operation attributes settings are valid.
        '''
        rc = 0
        if self.node is None:
            return rc
        for op_node in self.node.xpath("operations/op"):
            rc |= self._verify_op_attributes(op_node)
        return rc

    def check_sanity(self):
        '''
        Right now, this is only for primitives.
        And groups/clones/ms and cluster properties.
        '''
        return 0

    def reset_updated(self):
        self.updated = False
        for child in self.children:
            child.reset_updated()

    def propagate_updated(self):
        if self.parent:
            self.parent.updated = self.updated
            self.parent.propagate_updated()

    def top_parent(self):
        '''Return the top parent or self'''
        if self.parent:
            return self.parent.top_parent()
        else:
            return self

    def meta_attributes(self, name):
        "Returns all meta attribute values with the given name"
        v = self.node.xpath('./meta_attributes/nvpair[@name="%s"]/@value' % (name))
        return v

    def find_child_in_node(self, child):
        for c in self.node.iterchildren():
            if c.tag == child.node.tag and \
                    c.get("id") == child.obj_id:
                return c
        return None


def gv_first_prim(node):
    if node.tag != "primitive":
        for c in node.iterchildren():
            if is_child_rsc(c):
                return gv_first_prim(c)
    return node.get("id")


def gv_first_rsc(rsc_id):
    rsc_obj = cib_factory.find_object(rsc_id)
    if not rsc_obj:
        return rsc_id
    return gv_first_prim(rsc_obj.node)


def gv_last_prim(node):
    if node.tag != "primitive":
        for c in node.iterchildren(reversed=True):
            if is_child_rsc(c):
                return gv_last_prim(c)
    return node.get("id")


def gv_last_rsc(rsc_id):
    rsc_obj = cib_factory.find_object(rsc_id)
    if not rsc_obj:
        return rsc_id
    return gv_last_prim(rsc_obj.node)


def gv_edge_score_label(gv_obj, e_id, node):
    score = get_score(node) or get_kind(node)
    if abs_pos_score(score):
        gv_obj.new_edge_attr(e_id, 'style', 'solid')
        return
    elif re.match("-?([0-9]+|inf)$", score):
        lbl = score
    elif score in schema.rng_attr_values('rsc_order', 'kind'):
        lbl = score
    elif not score:
        lbl = 'Adv'
    else:
        lbl = "attr:%s" % score
    gv_obj.new_edge_attr(e_id, 'label', lbl)


class CibNode(CibObject):
    '''
    Node and node's attributes.
    '''
    set_names = {
        "instance_attributes": "attributes",
        "utilization": "utilization",
    }

    def _repr_cli_head(self, format_mode):
        uname = self.node.get("uname")
        s = clidisplay.keyword(self.obj_type)
        if self.obj_id != uname:
            if utils.noquotes(self.obj_id):
                s = "%s %s:" % (s, self.obj_id)
            else:
                s = '%s $id="%s"' % (s, self.obj_id)
        s = '%s %s' % (s, clidisplay.ident(uname))
        node_type = self.node.get("type")
        if node_type and node_type != constants.node_default_type:
            s = '%s:%s' % (s, node_type)
        return s

    def repr_gv(self, gv_obj, from_grp=False):
        '''
        Create a gv node. The label consists of the ID.
        Nodes are square.
        '''
        uname = self.node.get("uname")
        if not uname:
            uname = self.obj_id
        gv_obj.new_node(uname, top_node=True)
        gv_obj.new_attr(uname, 'label', uname)
        self._set_gv_attrs(gv_obj)


def reduce_primitive(node):
    '''
    A primitive may reference template. If so, put the two
    together.
    Returns:
        - if no template reference, node itself
        - if template reference, but no template found, None
        - return merged primitive node into template node
    '''
    template = node.get("template")
    if not template:
        return node
    template_obj = cib_factory.find_object(template)
    if not template_obj:
        return None
    return merge_tmpl_into_prim(node, template_obj.node)


class Op(object):
    '''
    Operations.
    '''
    elem_type = "op"

    def __init__(self, op_name, prim, node=None):
        self.prim = prim
        self.node = node
        self.attr_d = ordereddict.odict()
        self.attr_d["name"] = op_name
        if self.node is not None:
            self.xml2dict()

    def set_attr(self, n, v):
        self.attr_d[n] = v

    def get_attr(self, n):
        try:
            return self.attr_d[n]
        except KeyError:
            return None

    def del_attr(self, n):
        try:
            del self.attr_d[n]
        except KeyError:
            pass

    def xml2dict(self):
        for name in list(self.node.keys()):
            if name != "id":  # skip the id
                self.set_attr(name, self.node.get(name))
        for p in self.node.xpath("instance_attributes/nvpair"):
            n = p.get("name")
            v = p.get("value")
            if n is not None and v is not None:
                self.set_attr(n, v)

    def mkxml(self):
        # create an xml node
        if self.node is not None:
            if self.node.getparent() is not None:
                self.node.getparent().remove(self.node)
            idmgmt.remove_xml(self.node)
        self.node = etree.Element(self.elem_type)
        inst_attr = {}
        valid_attrs = olist(schema.get('attr', 'op', 'a'))
        for n, v in self.attr_d.items():
            if n in valid_attrs:
                self.node.set(n, v)
            else:
                inst_attr[n] = v
        idmgmt.set_id(self.node, None, self.prim)
        if inst_attr:
            nia = mkxmlnvpairs("instance_attributes", inst_attr, self.node.get("id"))
            self.node.append(nia)
        return self.node


class CibOp(CibObject):
    '''
    Operations
    '''

    set_names = {
        "instance_attributes": "op_params",
        "meta_attributes": "op_meta"
    }

    def _repr_cli_head(self, format_mode):
        action, pl = op2list(self.node)
        if not action:
            return ""
        ret = ["%s %s" % (clidisplay.keyword("op"), action)]
        ret += [nvpair_format(n, v) for n, v in pl]
        return ' '.join(ret)


class CibPrimitive(CibObject):
    '''
    Primitives.
    '''

    set_names = {
        "instance_attributes": "params",
        "meta_attributes": "meta",
        "utilization": "utilization",
    }

    def _repr_cli_head(self, format_mode):
        if self.obj_type == "primitive":
            template_ref = self.node.get("template")
        else:
            template_ref = None
        if template_ref:
            rsc_spec = "@%s" % clidisplay.idref(template_ref)
        else:
            rsc_spec = mk_rsc_type(self.node)
        s = clidisplay.keyword(self.obj_type)
        ident = clidisplay.ident(self.obj_id)
        return "%s %s %s" % (s, ident, rsc_spec)

    def _repr_cli_child(self, c, format_mode):
        if c.tag in self.set_names:
            return self._attr_set_str(c)
        elif c.tag == "operations":
            l = []
            s = ''
            c_id = c.get("id")
            if c_id:
                s = nvpair_format('$id', c_id)
            idref = c.get("id-ref")
            if idref:
                s = '%s %s' % (s, nvpair_format('$id-ref', idref))
            if s:
                l.append("%s %s" % (clidisplay.keyword("operations"), s))
            for op_node in c.iterchildren():
                op_obj = cib_object_map[op_node.tag][1](op_node.tag)
                op_obj.set_node(op_node)
                l.append(op_obj.repr_cli(format_mode > 0))
            return cli_format(l, break_lines=(format_mode > 0))

    def _append_op(self, op_node):
        try:
            ops_node = self.node.findall("operations")[0]
        except IndexError:
            ops_node = etree.SubElement(self.node, "operations")
        ops_node.append(op_node)

    def add_operation(self, node):
        # check if there is already an op with the same interval
        name = node.get("name")
        interval = node.get("interval")
        if find_operation(self.node, name, interval) is not None:
            logger.error("%s already has a %s op with interval %s", self.obj_id, name, interval)
            return None
        # create an xml node
        if 'id' not in node.attrib:
            idmgmt.set_id(node, None, self.obj_id)
        valid_attrs = olist(schema.get('attr', 'op', 'a'))
        inst_attr = {}
        for attr in list(node.attrib.keys()):
            if attr not in valid_attrs:
                inst_attr[attr] = node.attrib[attr]
                del node.attrib[attr]
        if inst_attr:
            attr_nodes = node.xpath('./instance_attributes')
            if len(attr_nodes) == 1:
                fill_nvpairs("instance_attributes", attr_nodes[0], inst_attr, node.get("id"))
            else:
                nia = mkxmlnvpairs("instance_attributes", inst_attr, node.get("id"))
                node.append(nia)

        self._append_op(node)
        comments = find_comment_nodes(node)
        for comment in comments:
            node.remove(comment)
        if comments and self.node is not None:
            stuff_comments(self.node, [c.text for c in comments])
        self.set_updated()
        return self

    def del_operation(self, op_node):
        if op_node.getparent() is None:
            return
        ops_node = op_node.getparent()
        op_node.getparent().remove(op_node)
        idmgmt.remove_xml(op_node)
        if len(ops_node) == 0:
            rmnode(ops_node)
        self.set_updated()

    def is_dummy_operation(self, op_node):
        '''If the op has just name, id, and interval=0, then it's
        not of much use.'''
        interval = op_node.get("interval")
        if len(op_node) == 0 and crm_msec(interval) == 0:
            attr_names = set(op_node.keys())
            basic_attr_names = set(["id", "name", "interval"])
            if len(attr_names ^ basic_attr_names) == 0:
                return True
        return False

    def set_op_attr(self, op_node, attr_n, attr_v):
        name = op_node.get("name")
        op_obj = Op(name, self.obj_id, op_node)
        op_obj.set_attr(attr_n, attr_v)
        new_op_node = op_obj.mkxml()
        self._append_op(new_op_node)
        # the resource is updated
        self.set_updated()
        return new_op_node

    def del_op_attr(self, op_node, attr_n):
        name = op_node.get("name")
        op_obj = Op(name, self.obj_id, op_node)
        op_obj.del_attr(attr_n)
        new_op_node = op_obj.mkxml()
        self._append_op(new_op_node)
        self.set_updated()
        return new_op_node

    def normalize_parameters(self):
        """
        Normalize parameter names:
        If a parameter "foo-bar" is set but the
        agent doesn't have a parameter "foo-bar",
        and instead has a parameter "foo_bar", then
        change the name to set the value of "foo_bar"
        instead.
        """
        r_node = self.node
        if self.obj_type == "primitive":
            r_node = reduce_primitive(self.node)
        if r_node is None:
            return
        ra = get_ra(r_node)
        ra.normalize_parameters(r_node)

    def check_sanity(self):
        '''
        Check operation timeouts and if all required parameters
        are defined.
        '''
        if self.node is None:  # eh?
            logger.error("%s: no xml (strange)", self.obj_id)
            return utils.get_check_rc()
        rc3 = sanity_check_meta(self.obj_id, self.node, constants.rsc_meta_attributes)
        if self.obj_type == "primitive":
            r_node = reduce_primitive(self.node)
            if r_node is None:
                logger.error("%s: no such resource template", self.node.get("template"))
                return utils.get_check_rc()
        else:
            r_node = self.node
        ra = get_ra(r_node)
        if ra.mk_ra_node() is None:  # no RA found?
            if cib_factory.is_asymm_cluster():
                return rc3
            if config.core.ignore_missing_metadata:
                return rc3
            ra.error("no such resource agent")
            return utils.get_check_rc()
        actions = get_rsc_operations(r_node)
        default_timeout = get_default_timeout()
        rc2 = ra.sanity_check_ops(self.obj_id, actions, default_timeout)
        rc4 = self._check_ops_attributes()
        params = []
        for c in r_node.iterchildren("instance_attributes"):
            params += nvpairs2list(c)
        rc1 = ra.sanity_check_params(self.obj_id,
                                     params,
                                     existence_only=(self.obj_type != "primitive"))
        return rc1 | rc2 | rc3 | rc4

    def repr_gv(self, gv_obj, from_grp=False):
        '''
        Create a gv node. The label consists of the ID and the
        RA type.
        '''
        if self.obj_type == "primitive":
            # if we belong to a group, but were not called with
            # from_grp=True, then skip
            if not from_grp and self.parent and self.parent.obj_type == "group":
                return
            n = reduce_primitive(self.node)
            if n is None:
                raise ValueError("Referenced template not found")
            ra_class = n.get("class")
            ra_type = n.get("type")
            lbl_top = self._gv_rsc_id()
            if ra_class in ("ocf", "stonith"):
                lbl_bottom = ra_type
            else:
                lbl_bottom = "%s:%s" % (ra_class, ra_type)
            gv_obj.new_node(self.obj_id, norank=(ra_class == "stonith"))
            gv_obj.new_attr(self.obj_id, 'label', '%s\\n%s' % (lbl_top, lbl_bottom))
            self._set_gv_attrs(gv_obj)
            self._set_gv_attrs(gv_obj, "class:%s" % ra_class)
            # if it's clone/ms, then get parent graph attributes
            if self.parent and self.parent.obj_type in constants.clonems_tags:
                self._set_gv_attrs(gv_obj, self.parent.obj_type)

            template_ref = self.node.get("template")
            if template_ref:
                e = [template_ref, self.obj_id]
                e_id = gv_obj.new_edge(e)
                self._set_edge_attrs(gv_obj, e_id, 'template:edge')

        elif self.obj_type == "rsc_template":
            n = reduce_primitive(self.node)
            if n is None:
                raise ValueError("Referenced template not found")
            ra_class = n.get("class")
            ra_type = n.get("type")
            lbl_top = self._gv_rsc_id()
            if ra_class in ("ocf", "stonith"):
                lbl_bottom = ra_type
            else:
                lbl_bottom = "%s:%s" % (ra_class, ra_type)
            gv_obj.new_node(self.obj_id, norank=(ra_class == "stonith"))
            gv_obj.new_attr(self.obj_id, 'label', '%s\\n%s' % (lbl_top, lbl_bottom))
            self._set_gv_attrs(gv_obj)
            self._set_gv_attrs(gv_obj, "class:%s" % ra_class)
            # if it's clone/ms, then get parent graph attributes
            if self.parent and self.parent.obj_type in constants.clonems_tags:
                self._set_gv_attrs(gv_obj, self.parent.obj_type)


class CibContainer(CibObject):
    '''
    Groups and clones and ms.
    '''
    set_names = {
        "instance_attributes": "params",
        "meta_attributes": "meta",
    }

    def _repr_cli_head(self, format_mode):
        children = []
        for c in self.node.iterchildren():
            if (self.obj_type == "group" and is_primitive(c)) or \
                    is_child_rsc(c):
                children.append(clidisplay.rscref(c.get("id")))
            elif self.obj_type in constants.clonems_tags and is_child_rsc(c):
                children.append(clidisplay.rscref(c.get("id")))
        s = clidisplay.keyword(self.obj_type)
        ident = clidisplay.ident(self.obj_id)
        return "%s %s %s" % (s, ident, ' '.join(children))

    def check_sanity(self):
        '''
        Check meta attributes.
        '''
        if self.node is None:  # eh?
            logger.error("%s: no xml (strange)", self.obj_id)
            return utils.get_check_rc()
        l = constants.rsc_meta_attributes
        if self.obj_type == "clone":
            l += constants.clone_meta_attributes
        elif self.obj_type == "ms":
            l += constants.clone_meta_attributes + constants.ms_meta_attributes
        elif self.obj_type == "group":
            l += constants.group_meta_attributes
        rc = sanity_check_meta(self.obj_id, self.node, l)
        return rc

    def repr_gv(self, gv_obj, from_grp=False):
        '''
        A group is a subgraph.
        Clones and ms just get different attributes.
        '''
        if self.obj_type != "group":
            return
        sg_obj = gv_obj.group([x.obj_id for x in self.children],
                              "cluster_%s" % self.obj_id)
        sg_obj.new_graph_attr('label', self._gv_rsc_id())
        self._set_sg_attrs(sg_obj, self.obj_type)
        if self.parent and self.parent.obj_type in constants.clonems_tags:
            self._set_sg_attrs(sg_obj, self.parent.obj_type)
        for child_rsc in self.children:
            child_rsc.repr_gv(sg_obj, from_grp=True)


class CibBundle(CibObject):
    '''
    bundle type resource
    '''
    set_names = {
        "instance_attributes": "params",
        "meta_attributes": "meta",
        "docker": "docker",
        "podman": "podman",
        "rkt": "rkt",
        "network": "network",
        "storage": "storage",
        "primitive": "primitive",
        "meta": "meta"
    }

    def _repr_cli_head(self, format_mode):
        s = clidisplay.keyword(self.obj_type)
        ident = clidisplay.ident(self.obj_id)
        return "%s %s" % (s, ident)

    def _repr_cli_child(self, c, format_mode):
        return self._attr_set_str(c)


def _check_if_constraint_ref_is_child(obj):
    """
    Used by check_sanity for constraints to verify
    that referenced resources are not children in
    a container.
    """
    rc = 0
    for rscid in obj.referenced_resources():
        tgt = cib_factory.find_object(rscid)
        if not tgt:
            logger.warning("%s: resource %s does not exist", obj.obj_id, rscid)
            rc = 1
        elif tgt.parent and tgt.parent.obj_type == "group":
            if obj.obj_type == "colocation":
                logger.warning("%s: resource %s is grouped, constraints should apply to the group", obj.obj_id, rscid)
                rc = 1
        elif tgt.parent and tgt.parent.obj_type in constants.container_tags:
            logger.warning("%s: resource %s ambiguous, apply constraints to container", obj.obj_id, rscid)
            rc = 1
    return rc


class CibLocation(CibObject):
    '''
    Location constraint.
    '''

    def _repr_cli_head(self, format_mode):
        rsc = None
        if "rsc" in list(self.node.keys()):
            rsc = self.node.get("rsc")
        elif "rsc-pattern" in list(self.node.keys()):
            rsc = '/%s/' % (self.node.get("rsc-pattern"))
        if rsc is not None:
            rsc = clidisplay.rscref(rsc)
        elif self.node.find("resource_set") is not None:
            rsc = '{ %s }' % (' '.join(rsc_set_constraint(self.node, self.obj_type)))
        else:
            logger.error("%s: unknown rsc_location format", self.obj_id)
            return None
        s = clidisplay.keyword(self.obj_type)
        ident = clidisplay.ident(self.obj_id)
        s = "%s %s %s" % (s, ident, rsc)

        known_attrs = ['role', 'resource-discovery']
        for attr in known_attrs:
            val = self.node.get(attr)
            if val is not None:
                s += " %s=%s" % (attr, val)

        pref_node = self.node.get("node")
        score = clidisplay.score(get_score(self.node))
        if pref_node is not None:
            s = "%s %s: %s" % (s, score, pref_node)
        return s

    def _repr_cli_child(self, c, format_mode):
        if c.tag == "rule":
            return "%s %s" % \
                (clidisplay.keyword("rule"), cli_rule(c))

    def check_sanity(self):
        '''
        Check if node references match existing nodes.
        '''
        if self.node is None:  # eh?
            logger.error("%s: no xml (strange)", self.obj_id)
            return utils.get_check_rc()
        rc = 0
        uname = self.node.get("node")
        if uname and uname.lower() not in [ident.lower() for ident in cib_factory.node_id_list()]:
            logger.warning("%s: referenced node %s does not exist", self.obj_id, uname)
            rc = 1
        pattern = self.node.get("rsc-pattern")
        if pattern:
            try:
                re.compile(pattern)
            except IndexError as e:
                logger.warning("%s: '%s' may not be a valid regular expression (%s)", self.obj_id, pattern, e)
                rc = 1
            except re.error as e:
                logger.warning("%s: '%s' may not be a valid regular expression (%s)", self.obj_id, pattern, e)
                rc = 1
        for enode in self.node.xpath("rule/expression"):
            if enode.get("attribute") == "#uname":
                uname = enode.get("value")
                ids = [i.lower() for i in cib_factory.node_id_list()]
                if uname and uname.lower() not in ids:
                    logger.warning("%s: referenced node %s does not exist", self.obj_id, uname)
                    rc = 1
        rc2 = _check_if_constraint_ref_is_child(self)
        if rc2 > rc:
            rc = rc2
        return rc

    def referenced_resources(self):
        ret = self.node.xpath('.//resource_set/resource_ref/@id')
        return ret or [self.node.get("rsc")]

    def repr_gv(self, gv_obj, from_grp=False):
        '''
        What to do with the location constraint?
        '''
        pref_node = self.node.get("node")
        if pref_node is not None:
            score_n = self.node
            # otherwise, it's too complex to render
        elif is_pref_location(self.node):
            score_n = self.node.findall("rule")[0]
            exp = self.node.xpath("rule/expression")[0]
            pref_node = exp.get("value")
        if pref_node is None:
            return
        rsc_id = gv_first_rsc(self.node.get("rsc"))
        if rsc_id is not None:
            e = [pref_node, rsc_id]
            e_id = gv_obj.new_edge(e)
            self._set_edge_attrs(gv_obj, e_id)
            gv_edge_score_label(gv_obj, e_id, score_n)


def _opt_set_name(n):
    return "cluster%s" % n.get("id")


def rsc_set_gv_edges(node, gv_obj):
    def traverse_set(cum, st):
        e = []
        for i, elem in enumerate(cum):
            if isinstance(elem, list):
                for rsc in elem:
                    cum2 = copy.copy(cum)
                    cum2[i] = rsc
                    traverse_set(cum2, st)
                return
            else:
                e.append(elem)
        st.append(e)

    cum = []
    for n in node.iterchildren("resource_set"):
        sequential = get_boolean(n.get("sequential"), True)
        require_all = get_boolean(n.get("require-all"), True)
        l = get_rsc_ref_ids(n)
        if not require_all and len(l) > 1:
            sg_name = _opt_set_name(n)
            cum.append('[%s]%s' % (sg_name, l[0]))
        elif not sequential and len(l) > 1:
            cum.append(l)
        else:
            cum += l
    st = []
    # deliver only 2-edges
    for i, lvl in enumerate(cum):
        if i == len(cum)-1:
            break
        traverse_set([cum[i], cum[i+1]], st)
    return st


class CibSimpleConstraint(CibObject):
    '''
    Colocation and order constraints.
    '''

    def _repr_cli_head(self, format_mode):
        s = clidisplay.keyword(self.obj_type)
        ident = clidisplay.ident(self.obj_id)
        score = get_score(self.node) or get_kind(self.node)
        if self.node.find("resource_set") is not None:
            col = rsc_set_constraint(self.node, self.obj_type)
        else:
            col = simple_rsc_constraint(self.node, self.obj_type)
        if not col:
            return None
        if self.obj_type == "order":
            symm = self.node.get("symmetrical")
            if symm:
                col.append("symmetrical=%s" % symm)
        elif self.obj_type == "colocation":
            node_attr = self.node.get("node-attribute")
            if node_attr:
                col.append("node-attribute=%s" % node_attr)
        s = "%s %s " % (s, ident)
        if score != '':
            s += "%s: " % (clidisplay.score(score))
        return s + ' '.join(col)

    def _mk_optional_set(self, gv_obj, n):
        '''
        Put optional resource set in a box.
        '''
        members = get_rsc_ref_ids(n)
        sg_name = _opt_set_name(n)
        sg_obj = gv_obj.optional_set(members, sg_name)
        self._set_sg_attrs(sg_obj, "optional_set")

    def _mk_one_edge(self, gv_obj, e):
        '''
        Create an edge between two resources (used for resource
        sets). If the first resource name starts with '[', it's
        an optional resource set which is later put into a subgraph.
        The edge then goes from the subgraph to the resource
        which follows. An expensive exception.
        '''
        optional_rsc = False
        r = re.match(r'\[(.*)\]', e[0])
        if r:
            optional_rsc = True
            sg_name = r.group(1)
        e = [re.sub(r'\[(.*)\]', '', x) for x in e]
        e = [gv_last_rsc(e[0]), gv_first_rsc(e[1])]
        e_id = gv_obj.new_edge(e)
        gv_edge_score_label(gv_obj, e_id, self.node)
        if optional_rsc:
            self._set_edge_attrs(gv_obj, e_id, 'optional_set')
            gv_obj.new_edge_attr(e_id, 'ltail', gv_obj.gv_id(sg_name))

    def repr_gv(self, gv_obj, from_grp=False):
        '''
        What to do with the collocation constraint?
        '''
        if self.obj_type != "order":
            return
        if self.node.find("resource_set") is not None:
            for e in rsc_set_gv_edges(self.node, gv_obj):
                self._mk_one_edge(gv_obj, e)
            for n in self.node.iterchildren("resource_set"):
                if not get_boolean(n.get("require-all"), True):
                    self._mk_optional_set(gv_obj, n)
        else:
            self._mk_one_edge(gv_obj, [
                self.node.get("first"),
                self.node.get("then")])

    def referenced_resources(self):
        ret = self.node.xpath('.//resource_set/resource_ref/@id')
        if ret:
            return ret
        if self.obj_type == "order":
            return [self.node.get("first"), self.node.get("then")]
        elif self.obj_type == "colocation":
            return [self.node.get("rsc"), self.node.get("with-rsc")]
        elif self.node.get("rsc"):
            return [self.node.get("rsc")]

    def check_sanity(self):
        if self.node is None:
            logger.error("%s: no xml (strange)", self.obj_id)
            return utils.get_check_rc()
        return _check_if_constraint_ref_is_child(self)


class CibRscTicket(CibSimpleConstraint):
    '''
    rsc_ticket constraint.
    '''

    def _repr_cli_head(self, format_mode):
        s = clidisplay.keyword(self.obj_type)
        ident = clidisplay.ident(self.obj_id)
        ticket = clidisplay.ticket(self.node.get("ticket"))
        if self.node.find("resource_set") is not None:
            col = rsc_set_constraint(self.node, self.obj_type)
        else:
            col = simple_rsc_constraint(self.node, self.obj_type)
        if not col:
            return None
        a = self.node.get("loss-policy")
        if a:
            col.append("loss-policy=%s" % a)
        return "%s %s %s: %s" % (s, ident, ticket, ' '.join(col))


class CibProperty(CibObject):
    '''
    Cluster properties.
    '''

    def _repr_cli_head(self, format_mode):
        return "%s %s" % (clidisplay.keyword(self.obj_type),
                          head_id_format(self.obj_id))

    def _repr_cli_child(self, c, format_mode):
        if c.tag == "rule":
            return ' '.join((clidisplay.keyword("rule"),
                             cli_rule(c)))
        elif c.tag == "nvpair":
            return cli_nvpair(c)
        else:
            return ''

    def check_sanity(self):
        '''
        Match properties with PE metadata.
        '''
        if self.node is None:  # eh?
            logger.error("%s: no xml (strange)", self.obj_id)
            return utils.get_check_rc()
        l = []
        if self.obj_type == "property":
            # don't check property sets which are not
            # "cib-bootstrap-options", they are probably used by
            # some resource agents such as mysql to store RA
            # specific state
            if self.obj_id != cib_object_map[self.xml_obj_type][3]:
                return 0
            l = get_properties_list()
            l += constants.extra_cluster_properties
        elif self.obj_type == "op_defaults":
            l = schema.get('attr', 'op', 'a')
        elif self.obj_type == "rsc_defaults":
            l = constants.rsc_meta_attributes
        rc = sanity_check_nvpairs(self.obj_id, self.node, l)
        return rc


def is_stonith_rsc(xmlnode):
    '''
    True if resource is stonith or derived from stonith template.
    '''
    xmlnode = reduce_primitive(xmlnode)
    if xmlnode is None:
        return False
    return xmlnode.get('class') == 'stonith'


class CibFencingOrder(CibObject):
    '''
    Fencing order (fencing-topology).
    '''

    def set_id(self, obj_id=None):
        self.obj_id = "fencing_topology"

    def set_nodeid(self):
        '''This id is not part of attributes'''
        pass

    def __str__(self):
        return self.obj_id

    def can_be_renamed(self):
        ''' Cannot rename this one. '''
        return False

    def _repr_cli_head(self, format_mode):
        s = clidisplay.keyword(self.obj_type)
        d = ordereddict.odict()
        for c in self.node.iterchildren("fencing-level"):
            if "target-pattern" in c.attrib:
                target = (None, c.get("target-pattern"))
            elif "target-attribute" in c.attrib:
                target = (c.get("target-attribute"), c.get("target-value"))
            else:
                target = c.get("target")
            if target not in d:
                d[target] = {}
            d[target][c.get("index")] = c.get("devices")
        dd = ordereddict.odict()
        for target in list(d.keys()):
            sorted_keys = sorted([int(i) for i in list(d[target].keys())])
            dd[target] = [d[target][str(x)] for x in sorted_keys]
        d2 = {}
        for target in list(dd.keys()):
            devs_s = ' '.join(dd[target])
            d2[devs_s] = 1
        if len(d2) == 1 and len(d) == len(cib_factory.node_id_list()):
            return "%s %s" % (s, devs_s)

        def fmt_target(tgt):
            if isinstance(tgt, tuple):
                if tgt[0] is None:
                    return "pattern:%s" % (tgt[1])
                return "attr:%s=%s" % tgt
            return tgt + ":"
        return cli_format([s] + ["%s %s" % (fmt_target(x), ' '.join(dd[x]))
                                 for x in list(dd.keys())],
                          break_lines=(format_mode > 0))

    def _repr_cli_child(self, c, format_mode):
        pass  # no children here

    def check_sanity(self):
        '''
        Targets are nodes and resource are stonith resources.
        '''
        if self.node is None:  # eh?
            logger.error("%s: no xml (strange)", self.obj_id)
            return utils.get_check_rc()
        rc = 0
        nl = self.node.findall("fencing-level")
        for target in [x.get("target") for x in nl if x.get("target") is not None]:
            if target.lower() not in [ident.lower() for ident in cib_factory.node_id_list()]:
                logger.warning("%s: target %s not a node", self.obj_id, target)
                rc = 1
        stonith_rsc_l = [x.obj_id for x in
                         cib_factory.get_elems_on_type("type:primitive")
                         if is_stonith_rsc(x.node)]
        for devices in [x.get("devices") for x in nl]:
            for dev in devices.split(","):
                if not cib_factory.find_object(dev):
                    logger.warning("%s: resource %s does not exist", self.obj_id, dev)
                    rc = 1
                elif dev not in stonith_rsc_l:
                    logger.warning("%s: %s not a stonith resource", self.obj_id, dev)
                    rc = 1
        return rc


class CibAcl(CibObject):
    '''
    User and role ACL.

    Now with support for 1.1.12 style ACL rules.

    '''

    def _repr_cli_head(self, format_mode):
        s = clidisplay.keyword(self.obj_type)
        ident = clidisplay.ident(self.obj_id)
        return "%s %s" % (s, ident)

    def _repr_cli_child(self, c, format_mode):
        if c.tag in constants.acl_rule_names:
            return cli_acl_rule(c, format_mode)
        elif c.tag == "role_ref":
            return cli_acl_roleref(c, format_mode)
        elif c.tag == "role":
            return cli_acl_role(c)
        elif c.tag == "acl_permission":
            return cli_acl_permission(c)


class CibTag(CibObject):
    '''
    Tag objects

    TODO: check_sanity, repr_gv

    '''

    def _repr_cli_head(self, fmt):
        return ' '.join([clidisplay.keyword(self.obj_type),
                         clidisplay.ident(self.obj_id)] +
                        [clidisplay.rscref(c.get('id'))
                         for c in self.node.iterchildren() if not is_comment(c)])


class CibAlert(CibObject):
    '''
    Alert objects

    TODO: check_sanity, repr_gv

    FIXME: display instance / meta attributes, description

    '''
    set_names = {
        "instance_attributes": "attributes",
        "meta_attributes": "meta",
    }

    def _repr_cli_head(self, fmt):
        ret = [clidisplay.keyword(self.obj_type),
               clidisplay.ident(self.obj_id),
               cli_path(self.node.get('path'))]
        return ' '.join(ret)

    def _repr_cli_child(self, c, format_mode):
        if c.tag in self.set_names:
            return self._attr_set_str(c)
        elif c.tag == "select":
            r = ["select"]
            for sel in c.iterchildren():
                if not sel.tag.startswith('select_'):
                    continue
                r.append(sel.tag.lstrip('select_'))
                if sel.tag == 'select_attributes':
                    r.append('{')
                    r.extend(sel.xpath('attribute/@name'))
                    r.append('}')
            return ' '.join(r)
        elif c.tag == "recipient":
            r = ["to"]
            is_complex = self._is_complex()
            if is_complex:
                r.append('{')
            r.append(cli_path(c.get('value')))
            for subset in c.xpath('instance_attributes|meta_attributes'):
                r.append(self._attr_set_str(subset))
            if is_complex:
                r.append('}')
            return ' '.join(r)

    def _is_complex(self):
        '''
        True if this alert is ambiguous wrt meta attributes in recipient tags
        '''
        children = [c.tag for c in self.node.xpath('recipient|instance_attributes|meta_attributes')]
        ri = children.index('recipient')
        if ri < 0:
            return False
        children = children[ri+1:]
        return 'instance_attributes' in children or 'meta_attributes' in children


#
################################################################


#
# cib factory
#
cib_piped = "cibadmin -p"


def get_default_timeout():
    t = cib_factory.get_op_default("timeout")
    if t is not None:
        return t


# xml -> cli translations (and classes)
cib_object_map = {
    # xml_tag: ( cli_name, element class, parent element tag, id hint )
    "node": ("node", CibNode, "nodes"),
    "op": ("op", CibOp, "operations"),
    "primitive": ("primitive", CibPrimitive, "resources"),
    "group": ("group", CibContainer, "resources"),
    "clone": ("clone", CibContainer, "resources"),
    "master": ("ms", CibContainer, "resources"),
    "template": ("rsc_template", CibPrimitive, "resources"),
    "bundle": ("bundle", CibBundle, "resources"),
    "rsc_location": ("location", CibLocation, "constraints"),
    "rsc_colocation": ("colocation", CibSimpleConstraint, "constraints"),
    "rsc_order": ("order", CibSimpleConstraint, "constraints"),
    "rsc_ticket": ("rsc_ticket", CibRscTicket, "constraints"),
    "cluster_property_set": ("property", CibProperty, "crm_config", "cib-bootstrap-options"),
    "rsc_defaults": ("rsc_defaults", CibProperty, "rsc_defaults", "rsc-options"),
    "op_defaults": ("op_defaults", CibProperty, "op_defaults", "op-options"),
    "fencing-topology": ("fencing_topology", CibFencingOrder, "configuration"),
    "acl_role": ("role", CibAcl, "acls"),
    "acl_user": ("user", CibAcl, "acls"),
    "acl_target": ("acl_target", CibAcl, "acls"),
    "acl_group": ("acl_group", CibAcl, "acls"),
    "tag": ("tag", CibTag, "tags"),
    "alert": ("alert", CibAlert, "alerts"),
}


# generate a translation cli -> tag
backtrans = ordereddict.odict((item[0], key) for key, item in cib_object_map.items())


def default_id_for_tag(tag):
    "Get default id for XML tag"
    m = cib_object_map.get(tag, tuple())
    return m[3] if len(m) > 3 else None


def default_id_for_obj(obj_type):
    "Get default id for object type"
    return default_id_for_tag(backtrans.get(obj_type))


def can_migrate(node):
    return 'true' in node.xpath('.//nvpair[@name="allow-migrate"]/@value')


class CibDiff(object):
    '''
    Represents a cib edit order.
    Is complicated by the fact that
    nodes and resources can have
    colliding ids.

    Can carry changes either as CLI objects
    or as XML statements.
    '''
    def __init__(self, objset):
        self.objset = objset
        self._node_set = orderedset.oset()
        self._nodes = {}
        self._rsc_set = orderedset.oset()
        self._resources = {}

    def add(self, item):
        obj_id = id_for_node(item)
        is_node = item.tag == 'node'
        if obj_id is None:
            logger.error("element %s has no id!", xml_tostring(item, pretty_print=True))
            return False
        elif is_node and obj_id in self._node_set:
            logger.error("Duplicate node: %s", obj_id)
            return False
        elif not is_node and obj_id in self._rsc_set:
            logger.error("Duplicate resource: %s", obj_id)
            return False
        elif is_node:
            self._node_set.add(obj_id)
            self._nodes[obj_id] = item
        else:
            self._rsc_set.add(obj_id)
            self._resources[obj_id] = item
        return True

    def _obj_type(self, nid):
        for obj in self.objset.all_set:
            if obj.obj_id == nid:
                return obj.obj_type
        return None

    def _is_node(self, nid):
        for obj in self.objset.all_set:
            if obj.obj_id == nid and obj.obj_type == 'node':
                return True
        return False

    def _is_resource(self, nid):
        for obj in self.objset.all_set:
            if obj.obj_id == nid and obj.obj_type != 'node':
                return True
        return False

    def _obj_nodes(self):
        return orderedset.oset([n for n in self.objset.obj_ids
                                if self._is_node(n)])

    def _obj_resources(self):
        return orderedset.oset([n for n in self.objset.obj_ids
                                if self._is_resource(n)])

    def _is_edit_valid(self, id_set, existing):
        '''
        1. Cannot name any elements as those which exist but
        were not picked for editing.
        2. Cannot remove running resources.
        '''
        rc = True
        not_allowed = id_set & self.objset.locked_ids
        rscstat = RscState()
        if not_allowed:
            logger.error("Elements %s already exist", ', '.join(list(not_allowed)))
            rc = False
        delete_set = existing - id_set
        cannot_delete = [x for x in delete_set
                         if not rscstat.can_delete(x)]
        if cannot_delete:
            logger.error("Cannot delete running resources: %s", ', '.join(cannot_delete))
            rc = False
        return rc

    def apply(self, factory, mode='cli', remove=True, method='replace'):
        rc = True

        edited_nodes = self._nodes.copy()
        edited_resources = self._resources.copy()

        def calc_sets(input_set, existing):
            rc = True
            if remove:
                rc = self._is_edit_valid(input_set, existing)
                del_set = existing - (input_set)
            else:
                del_set = orderedset.oset()
            mk_set = (input_set) - existing
            upd_set = (input_set) & existing
            return rc, mk_set, upd_set, del_set

        if not rc:
            return rc

        for e, s, existing in ((edited_nodes, self._node_set, self._obj_nodes()),
                               (edited_resources, self._rsc_set, self._obj_resources())):
            rc, mk, upd, rm = calc_sets(s, existing)
            if not rc:
                return rc
            rc = cib_factory.set_update(e, mk, upd, rm, upd_type=mode, method=method)
            if not rc:
                return rc
        return rc


class CibFactory(object):
    '''
    Juggle with CIB objects.
    See check_structure below for details on the internal cib
    representation.
    '''

    def __init__(self):
        self._init_vars()
        self.regtest = options.regression_tests
        self.last_commit_time = 0
        # internal (just not to produce silly messages)
        self._no_constraint_rm_msg = False
        self._crm_diff_cmd = "crm_diff --no-version"

    def is_cib_sane(self):
        # try to initialize
        if self.cib_elem is None:
            self.initialize()
            if self.cib_elem is None:
                logger_utils.empty_cib_err()
                return False
        return True

    def get_cib(self):
        if not self.is_cib_sane():
            return None
        return self.cib_elem
    #
    # check internal structures
    #

    def _check_parent(self, obj, parent):
        if obj not in parent.children:
            logger.error("object %s does not reference its child %s", parent.obj_id, obj.obj_id)
            return False
        if parent.node != obj.node.getparent():
            if obj.node.getparent() is None:
                logger.error("object %s node is not a child of its parent %s", obj.obj_id, parent.obj_id)
            else:
                logger.error("object %s node is not a child of its parent %s, but %s:%s",
                        obj.obj_id, parent.obj_id, obj.node.getparent().tag, obj.node.getparent().get("id"))
            return False
        return True

    def check_structure(self):
        if not self.is_cib_sane():
            return False
        rc = True
        for obj in self.cib_objects:
            if obj.parent:
                if not self._check_parent(obj, obj.parent):
                    logger.debug("check_parent failed: %s %s", obj.obj_id, obj.parent)
                    rc = False
            for child in obj.children:
                if not child.parent:
                    logger.error("child %s does not reference its parent %s", child.obj_id, obj.obj_id)
                    rc = False
        return rc

    def regression_testing(self, param):
        # provide some help for regression testing
        # in particular by trying to provide output which is
        # easier to predict
        if param == "off":
            self.regtest = False
        elif param == "on":
            self.regtest = True
        else:
            logger.warning("bad parameter for regtest: %s", param)

    def get_schema(self):
        return self.cib_attrs["validate-with"]

    def change_schema(self, schema_st):
        'Use another schema'
        if schema_st == self.get_schema():
            logger.info("already using schema %s", schema_st)
            return True
        if not schema.is_supported(schema_st):
            logger.warning("schema %s is not supported by the shell", schema_st)
        self.cib_elem.set("validate-with", schema_st)
        if not schema.test_schema(self.cib_elem):
            self.cib_elem.set("validate-with", self.get_schema())
            logger.error("schema %s does not exist", schema_st)
            return False
        schema.init_schema(self.cib_elem)
        rc = True
        for obj in self.cib_objects:
            if schema.get('sub', obj.node.tag, 'a') is None:
                logger.error("Element '%s' is not supported by the RNG schema %s", obj.node.tag, schema_st)
                logger.debug("Offending object: %s", xml_tostring(obj.node))
                rc = False
        if not rc:
            # revert, as some elements won't validate
            self.cib_elem.set("validate-with", self.get_schema())
            schema.init_schema(self.cib_elem)
            logger.error("Schema %s conflicts with current configuration", schema_st)
            return 4
        self.cib_attrs["validate-with"] = schema_st
        self.new_schema = True
        return 0

    def is_elem_supported(self, obj_type):
        'Do we support this element?'
        try:
            if schema.get('sub', backtrans[obj_type], 'a') is None:
                return False
        except KeyError:
            pass
        return True

    def is_cib_supported(self):
        'Do we support this CIB?'
        req = self.cib_elem.get("crm_feature_set")
        validator = self.cib_elem.get("validate-with")
        # if no schema is configured, just assume that it validates
        if not validator or schema.is_supported(validator):
            return True
        logger_utils.cib_ver_unsupported_err(validator, req)
        return False

    def upgrade_validate_with(self, force=False):
        """Upgrade the CIB.

        Requires the force argument to be set if
        validate-with is configured to anything other than
        0.6.
        """
        if not self.is_cib_sane():
            return False
        validator = self.cib_elem.get("validate-with")
        if force or not validator or re.match("0[.]6", validator):
            return ext_cmd("cibadmin --upgrade --force") == 0

    def _import_cib(self, cib_elem):
        'Parse the current CIB (from cibadmin -Q).'
        self.cib_elem = cib_elem
        if self.cib_elem is None:
            return False
        if not self.is_cib_supported():
            logger.warning("CIB schema is not supported by the shell")
        self._get_cib_attributes(self.cib_elem)
        schema.init_schema(self.cib_elem)
        return True

    def _get_cib_attributes(self, cib):
        for attr in list(cib.keys()):
            self.cib_attrs[attr] = cib.get(attr)

    def _set_cib_attributes(self, cib):
        for attr in self.cib_attrs:
            cib.set(attr, self.cib_attrs[attr])

    def _copy_cib_attributes(self, src_cib, cib):
        """
        Copy CIB attributes from src_cib to cib.
        Also updates self.cib_attrs.
        Preserves attributes that may be modified by
        the user (for example validate-with).
        """
        attrs = ((attr, src_cib.get(attr))
                 for attr in self.cib_attrs
                 if attr not in constants.cib_user_attrs)
        for attr, value in attrs:
            self.cib_attrs[attr] = value
            cib.set(attr, value)

    def obj_set2cib(self, obj_set, obj_filter=None):
        '''
        Return document containing objects in obj_set.
        Must remove all children from the object list, because
        printing xml of parents will include them.
        Optional filter to sieve objects.
        '''
        cib_elem = new_cib()
        # get only top parents for the objects in the list
        # e.g. if we get a primitive which is part of a clone,
        # then the clone gets in, not the primitive
        # dict will weed out duplicates
        d = {}
        for obj in obj_set:
            if obj_filter and not obj_filter(obj):
                continue
            d[obj.top_parent()] = 1
        for obj in d:
            get_topnode(cib_elem, obj.parent_type).append(copy.deepcopy(obj.node))
        self._set_cib_attributes(cib_elem)
        return cib_elem

    #
    # commit changed objects to the CIB
    #
    def _attr_match(self, c, a):
        'Does attribute match?'
        return c.get(a) == self.cib_attrs.get(a)

    def is_current_cib_equal(self, silent=False):
        cib_elem = read_cib(cibdump2elem)
        if cib_elem is None:
            return False
        rc = self._attr_match(cib_elem, 'epoch') and \
            self._attr_match(cib_elem, 'admin_epoch')
        if not silent and not rc:
            logger.warning("CIB changed in the meantime: won't touch it!")
        return rc

    def _state_header(self):
        'Print object status header'
        print(CibObject.state_fmt % \
            ("", "origin", "updated", "parent", "children"))

    def showobjects(self):
        self._state_header()
        for obj in self.cib_objects:
            obj.dump_state()
        if self.remove_queue:
            print("Remove queue:")
            for obj in self.remove_queue:
                obj.dump_state()

    def commit(self, force=False, replace=False):
        'Commit the configuration to the CIB.'
        if not self.is_cib_sane():
            return False
        if not replace:
            rc = self._patch_cib(force)
        else:
            rc = self._replace_cib(force)
        if rc:
            # reload the cib!
            t = time.time()
            logger.debug("CIB commit successful at %s", t)
            if is_live_cib():
                self.last_commit_time = t
            self.refresh()

            utils.check_no_quorum_policy_with_dlm()
        return rc

    def _update_schema(self):
        '''
        Set the validate-with, if the schema changed.
        '''
        s = '<cib validate-with="%s"/>' % self.cib_attrs["validate-with"]
        rc = pipe_string("%s -U" % cib_piped, s)
        if rc != 0:
            logger_utils.update_err("cib", "-U", s, rc)
            return False
        self.new_schema = False
        return True

    def _replace_cib(self, force):
        try:
            conf_el = self.cib_elem.findall("configuration")[0]
        except IndexError:
            logger.error("cannot find the configuration element")
            return False
        if self.new_schema and not self._update_schema():
            return False
        cibadmin_opts = force and "-R --force" or "-R"
        rc = pipe_string("%s %s" % (cib_piped, cibadmin_opts), etree.tostring(conf_el))
        if rc != 0:
            logger_utils.update_err("cib", cibadmin_opts, xml_tostring(conf_el), rc)
            return False
        return True

    def _patch_cib(self, force):
        # copy the epoch from the current cib to both the target
        # cib and the original one (otherwise cibadmin won't want
        # to apply the patch)
        current_cib = read_cib(cibdump2elem)
        if current_cib is None:
            return False

        self._copy_cib_attributes(current_cib, self.cib_orig)
        current_cib = None  # don't need that anymore
        self._set_cib_attributes(self.cib_elem)
        cib_s = xml_tostring(self.cib_orig, pretty_print=True)
        tmpf = str2tmp(cib_s, suffix=".xml")
        if not tmpf or not ensure_sudo_readable(tmpf):
            return False
        tmpfiles.add(tmpf)
        cibadmin_opts = force and "-P --force" or "-P"

        # produce a diff:
        # dump_new_conf | crm_diff -o self.cib_orig -n -

        logger.debug("Basis: %s", open(tmpf).read())
        logger.debug("Input: %s", xml_tostring(self.cib_elem))
        rc, cib_diff = filter_string("%s -o %s -n -" %
                                     (self._crm_diff_cmd, tmpf),
                                     etree.tostring(self.cib_elem))
        if not cib_diff and (rc == 0):
            # no diff = no action
            return True
        elif not cib_diff:
            logger.error("crm_diff apparently failed to produce the diff (rc=%d)", rc)
            return False

        # for v1 diffs, fall back to non-patching if
        # any containers are modified, else strip the digest
        if "<diff" in cib_diff and "digest=" in cib_diff:
            if not self.can_patch_v1():
                return self._replace_cib(force)
            e = etree.fromstring(cib_diff)
            for tag in e.xpath("/diff"):
                if "digest" in tag.attrib:
                    del tag.attrib["digest"]
            cib_diff = xml_tostring(e)
        logger.debug("Diff: %s", cib_diff)
        rc = pipe_string("%s %s" % (cib_piped, cibadmin_opts),
                         cib_diff.encode('utf-8'))
        if rc != 0:
            logger_utils.update_err("cib", cibadmin_opts, cib_diff, rc)
            return False
        return True

    def can_patch_v1(self):
        """
        The v1 patch format cannot handle reordering,
        so if there are any changes to any containers
        or acl tags, don't patch.
        """
        def group_changed():
            for obj in self.cib_objects:
                if not obj.updated:
                    continue
                if obj.obj_type in constants.container_tags:
                    return True
                if obj.obj_type in ('user', 'role', 'acl_target', 'acl_group'):
                    return True
            return False
        return not group_changed()

    #
    # initialize cib_objects from CIB
    #
    def _create_object_from_cib(self, node, pnode=None):
        '''
        Need pnode (parent node) acrobacy because cluster
        properties and rsc/op_defaults hold stuff in a
        meta_attributes child.
        '''
        assert node is not None
        if pnode is None:
            pnode = node
        obj = cib_object_map[pnode.tag][1](pnode.tag)
        obj.origin = "cib"
        obj.node = node
        obj.set_id()
        self.cib_objects.append(obj)
        return obj

    def _populate(self):
        "Walk the cib and collect cib objects."
        all_nodes = get_interesting_nodes(self.cib_elem, [])
        if not all_nodes:
            return
        for node in processing_sort(all_nodes):
            if is_defaults(node):
                for c in node.xpath("./meta_attributes"):
                    self._create_object_from_cib(c, node)
            else:
                self._create_object_from_cib(node)
        for obj in self.cib_objects:
            obj.move_comments()
            fix_comments(obj.node)
        self.cli_use_validate_all()
        for obj in self.cib_objects:
            self._update_links(obj)

    def cli_use_validate_all(self):
        for obj in self.cib_objects:
            if not obj.cli_use_validate():
                obj.nocli = True
                obj.nocli_warn = False
                # no need to warn, user can see the object displayed as XML
                logger.debug("object %s cannot be represented in the CLI notation", obj.obj_id)

    def initialize(self, cib=None, no_side_effects=False):
        if self.cib_elem is not None:
            return True
        if cib is None:
            cib_element = read_cib(lambda x: cibdump2elem(x, no_side_effects=no_side_effects))
            if cib_element is None and no_side_effects:
                return False
        elif isinstance(cib, str):
            cib_element = text2elem(cib)
        else:
            cib_element = cib
        if not self._import_cib(cib_element):
            return False
        self.cib_orig = copy.deepcopy(self.cib_elem)
        sanitize_cib_for_patching(self.cib_orig)
        sanitize_cib(self.cib_elem)
        show_unrecognized_elems(self.cib_elem)
        self._populate()
        return self.check_structure()

    def _init_vars(self):
        self.cib_elem = None     # the cib
        self.cib_orig = None     # the CIB which we loaded
        self.cib_attrs = {}      # cib version dictionary
        self.cib_objects = []    # a list of cib objects
        self.remove_queue = []   # a list of cib objects to be removed
        self.id_refs = {}        # dict of id-refs
        self.new_schema = False  # schema changed
        self._state = []

    def _push_state(self):
        '''
        A rudimentary instance state backup. Just make copies of
        all important variables.
        idmgmt has to be backed up too.
        '''
        self._state.append([copy.deepcopy(x)
                            for x in (self.cib_elem,
                                      self.cib_attrs,
                                      self.cib_objects,
                                      self.remove_queue,
                                      self.id_refs)])
        idmgmt.push_state()

    def _pop_state(self):
        try:
            logger.debug("performing rollback from %s", self.cib_objects)
            self.cib_elem, \
                self.cib_attrs, self.cib_objects, \
                self.remove_queue, self.id_refs = self._state.pop()
        except KeyError:
            return False
        # need to get addresses of all new objects created by
        # deepcopy
        for obj in self.cib_objects:
            obj.node = self.find_xml_node(obj.xml_obj_type, obj.obj_id)
            self._update_links(obj)
        idmgmt.pop_state()
        return self.check_structure()

    def _drop_state(self):
        try:
            self._state.pop()
        except KeyError:
            pass
        idmgmt.drop_state()

    def _clean_state(self):
        self._state = []
        idmgmt.clean_state()

    def reset(self):
        if self.cib_elem is None:
            return
        self.cib_elem = None
        self.cib_orig = None
        self._init_vars()
        self._clean_state()
        idmgmt.clear()

    def find_objects(self, obj_id):
        "Find objects for id (can be a wildcard-glob)."
        def matchfn(x):
            return x and fnmatch.fnmatch(x, obj_id)
        if not self.is_cib_sane() or obj_id is None:
            return None
        objs = []
        for obj in self.cib_objects:
            if matchfn(obj.obj_id):
                objs.append(obj)
            # special case for Heartbeat nodes which have id
            # different from uname
            elif obj.obj_type == "node" and matchfn(obj.node.get("uname")):
                objs.append(obj)
        return objs

    def find_object(self, obj_id):
        if not self.is_cib_sane():
            return None
        objs = self.find_objects(obj_id)
        if objs is None:
            return None
        if objs:
            for obj in objs:
                if obj.obj_type != 'node':
                    return obj
            return objs[0]
        return None

    def find_resource(self, obj_id):
        if not self.is_cib_sane():
            return None
        objs = self.find_objects(obj_id)
        if objs is None:
            return None
        for obj in objs:
            if obj.obj_type != 'node':
                return obj
        return None

    def find_node(self, obj_id):
        if not self.is_cib_sane():
            return None
        objs = self.find_objects(obj_id)
        if objs is None:
            return None
        for obj in objs:
            if obj.obj_type == 'node':
                return obj
        return None

    #
    # tab completion functions
    #
    def id_list(self):
        "List of ids (for completion)."
        return [x.obj_id for x in self.cib_objects]

    def type_list(self):
        "List of object types (for completion)"
        return list(set([x.obj_type for x in self.cib_objects]))

    def tag_list(self):
        "List of tags (for completion)"
        return list(set([x.obj_id for x in self.cib_objects if x.obj_type == "tag"]))

    def prim_id_list(self):
        "List of primitives ids (for group completion)."
        return [x.obj_id for x in self.cib_objects if x.obj_type == "primitive"]

    def fence_id_list(self):
        """
        List all configured fence agent's id
        """
        return [x.obj_id for x in self.cib_objects if x.node.get('class') == "stonith"]

    def fence_id_list_with_pcmk_delay(self):
        """
        List all fence agent's id which configured pcmk_delay_max
        """
        id_list = []
        for x in self.cib_objects:
            if x.node.get("class") != "stonith":
                continue
            for c in x.node.xpath('.//nvpair'):
                if c.get("name") == "pcmk_delay_max" and utils.crm_msec(c.get("value")) > 0:
                    id_list.append(x.obj_id)
                    break
        return id_list

    def fence_id_list_without_pcmk_delay(self):
        """
        List all fence agent's id which not configured pcmk_delay_max
        """
        return [_id for _id in self.fence_id_list() if _id not in self.fence_id_list_with_pcmk_delay()]

    def children_id_list(self):
        "List of child ids (for clone/master completion)."
        return [x.obj_id for x in self.cib_objects if x.obj_type in constants.children_tags]

    def rsc_id_list(self):
        "List of all resource ids."
        return [x.obj_id for x in self.cib_objects
                if x.obj_type in constants.resource_tags]

    def top_rsc_id_list(self):
        "List of top resource ids (for constraint completion)."
        return [x.obj_id for x in self.cib_objects
                if x.obj_type in constants.resource_tags and not x.parent]

    def node_id_list(self):
        "List of node ids."
        return sorted([x.node.get("uname") for x in self.cib_objects
                       if x.obj_type == "node"])

    def f_prim_free_id_list(self):
        "List of possible primitives ids (for group completion)."
        return [x.obj_id for x in self.cib_objects
                if x.obj_type == "primitive" and not x.parent]

    def f_prim_list_in_group(self, gname):
        "List resources in a group"
        return [x.obj_id for x in self.cib_objects
                if x.obj_type == "primitive" and x.parent and \
                x.parent.obj_id == gname]

    def f_group_id_list(self):
        "List of group ids."
        return [x.obj_id for x in self.cib_objects
                if x.obj_type == "group"]

    def rsc_template_list(self):
        "List of templates."
        return [x.obj_id for x in self.cib_objects
                if x.obj_type == "rsc_template"]

    def f_children_id_list(self):
        "List of possible child ids (for clone/master completion)."
        return [x.obj_id for x in self.cib_objects
                if x.obj_type in constants.children_tags and not x.parent]

    #
    # a few helper functions
    #
    def find_container_child(self, node):
        "Find an object which may be the child in a container."
        for obj in reversed(self.cib_objects):
            if node.tag == "fencing-topology" and obj.xml_obj_type == "fencing-topology":
                return obj
            if node.tag == obj.node.tag and node.get("id") == obj.obj_id:
                return obj
        return None

    def find_xml_node(self, tag, ident, strict=True):
        "Find a xml node of this type with this id."
        try:
            if tag in constants.defaults_tags:
                expr = '//%s/meta_attributes[@id="%s"]' % (tag, ident)
            elif tag == 'fencing-topology':
                expr = '//fencing-topology'
            else:
                expr = '//%s[@id="%s"]' % (tag, ident)
            return self.cib_elem.xpath(expr)[0]
        except IndexError:
            if strict:
                logger.warning("strange, %s element %s not found", tag, ident)
            return None

    #
    # Element editing stuff.
    #
    def default_timeouts(self, *args):
        '''
        Set timeouts for operations from the defaults provided in
        the meta-data.
        '''
        implied_actions = ["start", "stop"]
        implied_ms_actions = ["promote", "demote"]
        implied_migrate_actions = ["migrate_to", "migrate_from"]
        other_actions = ("monitor",)
        if not self.is_cib_sane():
            return False
        rc = True
        for obj_id in args:
            obj = self.find_resource(obj_id)
            if not obj:
                logger_utils.no_object_err(obj_id)
                rc = False
                continue
            if obj.obj_type != "primitive":
                logger.warning("element %s is not a primitive", obj_id)
                rc = False
                continue
            r_node = reduce_primitive(obj.node)
            if r_node is None:
                # cannot do anything without template defined
                logger.warning("template for %s not defined", obj_id)
                rc = False
                continue
            ra = get_ra(r_node)
            if ra.mk_ra_node() is None:  # no RA found?
                if not self.is_asymm_cluster():
                    ra.error("no resource agent found for %s" % obj_id)
                continue
            obj_modified = False
            for c in r_node.iterchildren():
                if c.tag == "operations":
                    for c2 in c.iterchildren():
                        if not c2.tag == "op":
                            continue
                        op, pl = op2list(c2)
                        if not op:
                            continue
                        if op in implied_actions:
                            implied_actions.remove(op)
                        elif can_migrate(r_node) and op in implied_migrate_actions:
                            implied_migrate_actions.remove(op)
                        elif is_ms_or_promotable_clone(obj.node.getparent()) and op in implied_ms_actions:
                            implied_ms_actions.remove(op)
                        elif op not in other_actions:
                            continue
                        adv_timeout = None
                        role = c2.get('role')
                        depth = c2.get('depth')
                        adv_timeout = ra.get_op_attr_value(op, "timeout", role=role, depth=depth)
                        if adv_timeout:
                            c2.set("timeout", adv_timeout)
                            obj_modified = True
            l = implied_actions
            if can_migrate(r_node):
                l += implied_migrate_actions
            if is_ms_or_promotable_clone(obj.node.getparent()):
                l += implied_ms_actions
            for op in l:
                adv_timeout = ra.get_op_attr_value(op, "timeout")
                if not adv_timeout:
                    continue
                n = etree.Element('op')
                n.set('name', op)
                n.set('timeout', adv_timeout)
                n.set('interval', '0')
                if not obj.add_operation(n):
                    rc = False
                else:
                    obj_modified = True
            if obj_modified:
                obj.set_updated()
        return rc

    def is_id_refd(self, attr_list_type, ident):
        '''
        Is this ID referenced anywhere?
        Used from cliformat
        '''
        try:
            return self.id_refs[ident] == attr_list_type
        except KeyError:
            return False

    def resolve_id_ref(self, attr_list_type, id_ref):
        '''
        User is allowed to specify id_ref either as a an object
        id or as attributes id. Here we try to figure out which
        one, i.e. if the former is the case to find the right
        id to reference.
        '''
        self.id_refs[id_ref] = attr_list_type
        obj = self.find_resource(id_ref)
        if obj:
            nodes = obj.node.xpath(".//%s" % attr_list_type)
            numnodes = len(nodes)
            if numnodes > 1:
                logger.warning("%s contains more than one %s, using first", obj.obj_id, attr_list_type)
            if numnodes > 0:
                node_id = nodes[0].get("id")
                if node_id:
                    return node_id
        check_id_ref(self.cib_elem, id_ref)
        return id_ref

    def _get_attr_value(self, obj_type, attr):
        if not self.is_cib_sane():
            return None
        for obj in self.cib_objects:
            if obj.obj_type == obj_type and obj.node is not None:
                for n in nvpairs2list(obj.node):
                    if n.get('name') == attr:
                        return n.get('value')
        return None

    def get_property(self, prop):
        '''
        Get the value of the given cluster property.
        '''
        return self._get_attr_value("property", prop)

    def get_property_w_default(self, prop):
        '''
        Get the value of the given property. If it is
        not set, return the default value.
        '''
        v = self.get_property(prop)
        if v is None:
            try:
                v = get_properties_meta().param_default(prop)
            except:
                pass
        return v

    def get_op_default(self, attr):
        '''
        Get the value of the attribute from op_defaults.
        '''
        return self._get_attr_value("op_defaults", attr)

    def is_asymm_cluster(self):
        symm = self.get_property("symmetric-cluster")
        return symm and symm != "true"

    def new_object(self, obj_type, obj_id):
        "Create a new object of type obj_type."
        logger.debug("new_object: %s:%s", obj_type, obj_id)
        existing = self.find_object(obj_id)
        if existing and [obj_type, existing.obj_type].count("node") != 1:
            logger.error("Cannot create %s with ID '%s': Found existing %s with same ID.", obj_type, obj_id, existing.obj_type)
            return None
        xml_obj_type = backtrans.get(obj_type)
        v = cib_object_map.get(xml_obj_type)
        if v is None:
            return None
        obj = v[1](xml_obj_type)
        obj.obj_type = obj_type
        obj.set_id(obj_id)
        obj.node = None
        obj.origin = "user"
        return obj

    def modified_elems(self):
        return [x for x in self.cib_objects
                if x.updated or x.origin == "user"]

    def get_elems_of_ra_partial_search(self, spec):
        """
        Get elements by given ra class:provider:type or class:type or only class/provider/type
        return [] if no results
        """
        def match_type(obj, tp):
            type_res = obj.node.get("type")
            return type_res and tp.lower() in type_res.lower()

        content_list = spec.split(':')[1:]
        if len(content_list) > 3:
            return []
        if len(content_list) == 3:
            cls, provider, tp = content_list
            return [x for x in self.cib_objects 
                    if match_type(x, tp)
                    and x.node.get("provider") == provider
                    and x.node.get("class") == cls]
        if len(content_list) == 2:
            cls, tp = content_list
            return [x for x in self.cib_objects 
                    if match_type(x, tp)
                    and x.node.get("class") == cls]
        if len(content_list) == 1:
            tp = content_list[0]
            if not tp:
                return []
            return [x for x in self.cib_objects
                    if match_type(x, tp) or
                    x.node.get("class") == tp or
                    x.node.get("provider") == tp]

    def get_elems_on_type(self, spec):
        if not spec.startswith("type:"):
            return []
        t = spec[5:]
        return [x for x in self.cib_objects if x.obj_type == t]

    def get_elems_on_tag(self, spec):
        if not spec.startswith("tag:"):
            return []
        t = spec[4:]
        matching_tags = [x for x in self.cib_objects if x.obj_type == 'tag' and x.obj_id == t]
        ret = []
        for mt in matching_tags:
            matches = [cib_factory.find_resource(o) for o in mt.node.xpath('./obj_ref/@id')]
            ret += [m for m in matches if m is not None]
        return ret

    def filter_objects(self, filters):
        """
        Filter out a set of objects given a list of filters.

        Complication: We want to refine selections, for example
        type:primitive tag:foo should give all primitives tagged foo,
        or type:node boo should give the node boo, but not the primitive boo.

        Add keywords and|or to influence selection?
        Default to "or" between matches (like now)

        type:primitive or type:group = all primitives and groups
        type:primitive and foo = primitives with id foo
        type:primitive and foo* = primitives that start with id foo
        type:primitive or foo* = all that start with id foo plus all primitives
        type:primitive and tag:foo

        Returns:
        True, set() on success
        false, err on failure
        """
        if not filters:
            return True, copy.copy(self.cib_objects)
        if filters[0] == 'NOOBJ':
            return True, orderedset.oset([])
        obj_set = orderedset.oset([])
        and_filter, and_set = False, None
        for spec in filters:
            if spec == "or":
                continue
            elif spec == "and":
                and_filter, and_set = True, obj_set
                obj_set = orderedset.oset([])
                continue
            if spec == "changed":
                obj_set |= orderedset.oset(self.modified_elems())
            elif spec.startswith("type:"):
                obj_set |= orderedset.oset(self.get_elems_on_type(spec))
            elif spec.startswith("tag:"):
                obj_set |= orderedset.oset(self.get_elems_on_tag(spec))
            elif spec.startswith("related:"):
                name = spec[len("related:"):]
                obj_set |= orderedset.oset(self.find_objects(name) or [])
                obj = self.find_object(name)
                if obj is not None:
                    obj_set |= orderedset.oset(self.related_elements(obj))
                obj_set |= orderedset.oset(self.get_elems_of_ra_partial_search(spec))
            else:
                objs = self.find_objects(spec) or []
                for obj in objs:
                    obj_set.add(obj)
                if not objs:
                    return False, spec
            if and_filter is True:
                and_filter, obj_set = False, obj_set.intersection(and_set)
        if and_filter is True:
            and_filter, obj_set = False, and_set
        return True, obj_set

    def mkobj_set(self, *args):
        rc, obj_set = self.filter_objects(args)
        if rc is False:
            logger_utils.no_object_err(obj_set)
            return False, orderedset.oset([])
        return rc, obj_set

    def get_all_obj_set(self):
        return set(self.cib_objects)

    def has_no_primitives(self):
        return not self.get_elems_on_type("type:primitive")

    def has_cib_changed(self):
        if self.cib_elem is None:
            # cib is not loaded, so it is also not changed
            return False
        elif not self.is_cib_sane():
            return False
        else:
            return self.modified_elems() or self.remove_queue

    def ensure_cib_updated(self):
        if options.interactive and not self.has_cib_changed():
            self.refresh()

    def _verify_constraints(self, node):
        '''
        Check if all resources referenced in a constraint exist
        '''
        rc = True
        constraint_id = node.get("id")
        for obj_id in referenced_resources(node):
            if not self.find_resource(obj_id):
                logger_utils.constraint_norefobj_err(constraint_id, obj_id)
                rc = False
        return rc

    def _verify_rsc_children(self, obj):
        '''
        Check prerequisites:
          a) all children must exist
          b) no child may have more than one parent
          c) there may not be duplicate children
        '''
        obj_id = obj.obj_id
        rc = True
        c_dict = {}
        for c in obj.node.iterchildren():
            if not is_cib_element(c):
                continue
            child_id = c.get("id")
            if not self._verify_child(child_id, obj.node.tag, obj_id):
                rc = False
            if child_id in c_dict:
                logger.error("in group %s child %s listed more than once", obj_id, child_id)
                rc = False
            c_dict[child_id] = 1
        for other in [x for x in self.cib_objects
                      if x != obj and is_container(x.node)]:
            shared_obj = set(obj.children) & set(other.children)
            if shared_obj:
                logger.error("%s contained in both %s and %s", ','.join([x.obj_id for x in shared_obj]), obj_id, other.obj_id)
                rc = False
        return rc

    def _verify_child(self, child_id, parent_tag, obj_id):
        'Check if child exists and obj_id is (or may become) its parent.'
        child = self.find_resource(child_id)
        if not child:
            logger_utils.no_object_err(child_id)
            return False
        if parent_tag == "group" and child.obj_type != "primitive":
            logger.error("a group may contain only primitives; %s is %s", child_id, child.obj_type)
            return False
        if child.parent and child.parent.obj_id != obj_id:
            logger.error("%s already in use at %s", child_id, child.parent.obj_id)
            return False
        if child.node.tag not in constants.children_tags:
            logger.error("%s may contain a primitive or a group; %s is %s", parent_tag, child_id, child.obj_type)
            return False
        return True

    def _verify_element(self, obj):
        '''
        Can we create this object given its CLI representation.
        This is not about syntax, we're past that, but about
        semantics.
        Right now we check if the children, if any, are fit for
        the parent. And if this is a constraint, if all
        referenced resources are present.
        '''
        rc = True
        node = obj.node
        obj_id = obj.obj_id
        try:
            cib_object_map[node.tag][0]
        except KeyError:
            logger.error("element %s (%s) not recognized", node.tag, obj_id)
            return False
        if is_container(node):
            rc &= self._verify_rsc_children(obj)
        elif is_constraint(node):
            rc &= self._verify_constraints(node)
        return rc

    def create_object(self, *args):
        if not self.is_cib_sane():
            return False
        return self.create_from_cli(list(args)) is not None

    def set_property_cli(self, obj_type, node):
        pset_id = node.get('id') or default_id_for_obj(obj_type)
        obj = self.find_object(pset_id)
        # If id is the default, use any existing set rather create another one.
        if not obj and pset_id == default_id_for_obj(obj_type):
            objs = self.get_elems_on_type("type:%s" %obj_type)
            if objs and len(objs) > 0:
                obj = objs[-1]
        if not obj:
            if not is_id_valid(pset_id):
                logger_utils.invalid_id_err(pset_id)
                return None
            obj = self.new_object(obj_type, pset_id)
            if not obj:
                return None
            topnode = get_topnode(self.cib_elem, obj.parent_type)
            obj.node = etree.SubElement(topnode, node.tag)
            obj.origin = "user"
            obj.node.set('id', pset_id)
            topnode.append(obj.node)
            self.cib_objects.append(obj)
        copy_nvpairs(obj.node, node)
        obj.normalize_parameters()
        obj.set_updated()
        return obj

    def add_op(self, node):
        '''Add an op to a primitive.'''
        # does the referenced primitive exist
        rsc_id = node.get('rsc')
        rsc_obj = self.find_resource(rsc_id)
        if not rsc_obj:
            logger_utils.no_object_err(rsc_id)
            return None
        if rsc_obj.obj_type != "primitive":
            logger.error("%s is not a primitive", rsc_id)
            return None

        # the given node is not postprocessed
        node, obj_type, obj_id = postprocess_cli(node, id_hint=rsc_obj.obj_id)

        del node.attrib['rsc']
        return rsc_obj.add_operation(node)

    def create_from_cli(self, cli):
        'Create a new cib object from the cli representation.'
        if not self.is_cib_sane():
            logger.debug("create_from_cli (%s): is_cib_sane() failed", cli)
            return None
        if isinstance(cli, (list, str)):
            elem, obj_type, obj_id = parse_cli_to_xml(cli)
        else:
            elem, obj_type, obj_id = postprocess_cli(cli)
        if elem is None:
            # FIXME: raise error?
            logger.debug("create_from_cli (%s): failed", cli)
            return None
        logger.debug("create_from_cli: %s, %s, %s", xml_tostring(elem), obj_type, obj_id)
        if obj_type in olist(constants.nvset_cli_names):
            return self.set_property_cli(obj_type, elem)
        if obj_type == "op":
            return self.add_op(elem)
        if obj_type == "node":
            obj = self.find_node(obj_id)
            # make an exception and allow updating nodes
            if obj:
                self.merge_from_cli(obj, elem)
                return obj
        obj = self.new_object(obj_type, obj_id)
        if not obj:
            return None
        return self._add_element(obj, elem)

    def update_from_cli(self, obj, node, method):
        '''
        Replace element from the cli intermediate.
        If this is an update and the element is properties, then
        the new properties should be merged with the old.
        Otherwise, users may be surprised.
        '''
        if method == 'update' and obj.obj_type in constants.nvset_cli_names:
            return self.merge_from_cli(obj, node)
        return self.update_element(obj, node)

    def update_from_node(self, obj, node):
        'Update element from a doc node.'
        idmgmt.replace_xml(obj.node, node)
        return self.update_element(obj, node)

    def update_element(self, obj, newnode):
        'Update element from a doc node.'
        if newnode is None:
            return False
        if not self.is_cib_sane():
            idmgmt.replace_xml(newnode, obj.node)
            return False
        oldnode = obj.node
        if xml_equals(oldnode, newnode):
            if newnode.getparent() is not None:
                newnode.getparent().remove(newnode)
            return True  # the new and the old versions are equal
        obj.node = newnode
        logger.debug("update CIB element: %s", str(obj))
        if oldnode.getparent() is not None:
            oldnode.getparent().replace(oldnode, newnode)
        obj.nocli = False  # try again after update
        if not self._adjust_children(obj):
            return False
        if not obj.cli_use_validate():
            logger.debug("update_element: validation failed (%s, %s)", obj, xml_tostring(newnode))
            obj.nocli_warn = True
            obj.nocli = True
        obj.set_updated()
        return True

    def merge_from_cli(self, obj, node):
        logger.debug("merge_from_cli: %s %s", obj.obj_type, xml_tostring(node))
        if obj.obj_type in constants.nvset_cli_names:
            rc = merge_attributes(obj.node, node, "nvpair")
        else:
            rc = merge_nodes(obj.node, node)
        if rc:
            obj.set_updated()
        return True

    def _cli_set_update(self, edit_d, mk_set, upd_set, del_set, method):
        '''
        Create/update/remove elements.
        edit_d is a dict with id keys and parsed xml values.
        mk_set is a set of ids to be created.
        upd_set is a set of ids to be updated (replaced).
        del_set is a set to be removed.
        method is either replace or update.
        '''
        logger.debug("_cli_set_update: mk=%s, upd=%s, del=%s", mk_set, upd_set, del_set)
        test_l = []

        def obj_is_container(x):
            obj = self.find_resource(x)
            return obj and is_container(obj.node)

        def obj_is_constraint(x):
            obj = self.find_resource(x)
            return obj and is_constraint(obj.node)

        del_constraints = []
        del_containers = []
        del_objs = []
        for x in del_set:
            if obj_is_constraint(x):
                del_constraints.append(x)
            elif obj_is_container(x):
                del_containers.append(x)
            else:
                del_objs.append(x)

        # delete constraints and containers first in case objects are moved elsewhere
        if not self.delete(*del_constraints):
            logger.debug("delete %s failed", list(del_set))
            return False
        if not self.delete(*del_containers):
            logger.debug("delete %s failed", list(del_set))
            return False

        for cli in processing_sort([edit_d[x] for x in mk_set]):
            obj = self.create_from_cli(cli)
            if not obj:
                logger.debug("create_from_cli '%s' failed", xml_tostring(cli, pretty_print=True))
                return False
            test_l.append(obj)

        for ident in upd_set:
            if edit_d[ident].tag == 'node':
                obj = self.find_node(ident)
            else:
                obj = self.find_resource(ident)
            if not obj:
                logger.debug("%s not found!", ident)
                return False
            node, _, _ = postprocess_cli(edit_d[ident], oldnode=obj.node)
            if node is None:
                logger.debug("postprocess_cli failed: %s", ident)
                return False
            if not self.update_from_cli(obj, node, method):
                logger.debug("update_from_cli failed: %s, %s, %s", obj, xml_tostring(node), method)
                return False
            test_l.append(obj)

        if not self.delete(*reversed(del_objs)):
            logger.debug("delete %s failed", list(del_set))
            return False
        rc = True
        for obj in test_l:
            if not self.test_element(obj):
                logger.debug("test_element failed for %s", obj)
                rc = False
        return rc & self.check_structure()

    def _xml_set_update(self, edit_d, mk_set, upd_set, del_set):
        '''
        Create/update/remove elements.
        node_l is a list of elementtree elements.
        mk_set is a set of ids to be created.
        upd_set is a set of ids to be updated (replaced).
        del_set is a set to be removed.
        '''
        logger.debug("_xml_set_update: %s, %s, %s", mk_set, upd_set, del_set)
        test_l = []
        for el in processing_sort([edit_d[x] for x in mk_set]):
            obj = self.create_from_node(el)
            if not obj:
                return False
            test_l.append(obj)
        for ident in upd_set:
            if edit_d[ident].tag == 'node':
                obj = self.find_node(ident)
            else:
                obj = self.find_resource(ident)
            if not obj:
                return False
            if not self.update_from_node(obj, edit_d[ident]):
                return False
            test_l.append(obj)
        if not self.delete(*list(del_set)):
            return False
        rc = True
        for obj in test_l:
            if not self.test_element(obj):
                rc = False
        return rc & self.check_structure()

    def _set_update(self, edit_d, mk_set, upd_set, del_set, upd_type, method):
        if upd_type == "xml":
            return self._xml_set_update(edit_d, mk_set, upd_set, del_set)
        return self._cli_set_update(edit_d, mk_set, upd_set, del_set, method)

    def set_update(self, edit_d, mk_set, upd_set, del_set, upd_type="cli", method='replace'):
        '''
        Just a wrapper for _set_update() to allow for a
        rollback.
        '''
        self._push_state()
        if not self._set_update(edit_d, mk_set, upd_set, del_set, upd_type, method):
            if not self._pop_state():
                raise RuntimeError("this should never happen!")
            return False
        self._drop_state()
        return True

    def _adjust_children(self, obj):
        '''
        All stuff children related: manage the nodes of children,
        update the list of children for the parent, update
        parents in the children.
        '''
        new_children_ids = get_rsc_children_ids(obj.node)
        if not new_children_ids:
            return True
        old_children = [x for x in obj.children if x.parent == obj]
        new_children = [self.find_resource(x) for x in new_children_ids]
        new_children = [c for c in new_children if c is not None]
        obj.children = new_children
        # relink orphans to top
        for child in set(old_children) - set(obj.children):
            logger.debug("relink child %s to top", str(child))
            self._relink_child_to_top(child)
        if not self._are_children_orphans(obj):
            return False
        return self._update_children(obj)

    def _relink_child_to_top(self, obj):
        'Relink a child to the top node.'
        get_topnode(self.cib_elem, obj.parent_type).append(obj.node)
        obj.parent = None

    def _are_children_orphans(self, obj):
        """
        Check if we're adding a container containing objects
        we've already added to a different container
        """
        for child in obj.children:
            if not child.parent:
                continue
            if child.parent == obj or child.parent.obj_id == obj.obj_id:
                continue
            if child.parent.obj_type in constants.container_tags:
                logger.error("Cannot create %s: Child %s already in %s", obj, child, child.parent)
                return False
        return True

    def _update_children(self, obj):
        '''For composite objects: update all children nodes.
        '''
        # unlink all and find them in the new node
        for child in obj.children:
            oldnode = child.node
            newnode = obj.find_child_in_node(child)
            if newnode is None:
                logger.error("Child found in children list but not in node: %s, %s", obj, child)
                return False
            child.node = newnode
            if child.children:  # and children of children
                if not self._update_children(child):
                    return False
            rmnode(oldnode)
            if child.parent:
                child.parent.updated = True
            child.parent = obj
        return True

    def test_element(self, obj):
        if obj.xml_obj_type not in constants.defaults_tags:
            if not self._verify_element(obj):
                return False
        if utils.is_check_always() and obj.check_sanity() > 1:
            return False
        return True

    def _update_links(self, obj):
        '''
        Update the structure links for the object (obj.children,
        obj.parent). Update also the XML, if necessary.
        '''
        obj.children = []
        if obj.obj_type not in constants.container_tags:
            return
        for c in obj.node.iterchildren():
            if is_child_rsc(c):
                child = self.find_container_child(c)
                if not child:
                    logger_utils.missing_obj_err(c)
                    continue
                child.parent = obj
                obj.children.append(child)
                if c != child.node:
                    rmnode(child.node)
                    child.node = c

    def _add_element(self, obj, node):
        assert node is not None
        obj.node = node
        obj.set_id()
        pnode = get_topnode(self.cib_elem, obj.parent_type)
        logger.debug("_add_element: append child %s to %s", obj.obj_id, pnode.tag)
        if not self._adjust_children(obj):
            return None
        pnode.append(node)
        self._redirect_children_constraints(obj)
        obj.normalize_parameters()
        if not obj.cli_use_validate():
            self.nocli_warn = True
            obj.nocli = True
        self._update_links(obj)
        obj.origin = "user"
        self.cib_objects.append(obj)
        return obj

    def _add_children(self, obj_type, node):
        """
        Called from create_from_node
        In case this is a clone/group/master create from XML,
        and the child node(s) haven't been added as a separate objects.
        """
        if obj_type not in constants.container_tags:
            return True

        # bsc#959895: also process cloned groups
        for c in node.iterchildren():
            if c.tag not in ('primitive', 'group'):
                continue
            pid = c.get('id')
            child_obj = self.find_resource(pid)
            if child_obj is None:
                child_obj = self.create_from_node(copy.deepcopy(c))
                if not child_obj:
                    return False
        return True

    def create_from_node(self, node):
        'Create a new cib object from a document node.'
        if node is None:
            logger.debug("create_from_node: got None")
            return None
        try:
            obj_type = cib_object_map[node.tag][0]
        except KeyError:
            logger.debug("create_from_node: keyerror (%s)", node.tag)
            return None
        if is_defaults(node):
            node = get_rscop_defaults_meta_node(node)
            if node is None:
                logger.debug("create_from_node: get_rscop_defaults_meta_node failed")
                return None

        if not self._add_children(obj_type, node):
            return None

        obj = self.new_object(obj_type, node.get("id"))
        if not obj:
            return None
        return self._add_element(obj, node)

    def _remove_obj(self, obj):
        "Remove a cib object."
        logger.debug("remove object %s", str(obj))
        for child in obj.children:
            # just relink, don't remove children
            self._relink_child_to_top(child)
        if obj.parent:  # remove obj from its parent, if any
            obj.parent.children.remove(obj)
        idmgmt.remove_xml(obj.node)
        rmnode(obj.node)
        self._add_to_remove_queue(obj)
        self.cib_objects.remove(obj)
        for tag in self.related_tags(obj):
            # remove self from tag
            # remove tag if self is last tagged object in tag
            selfies = [x for x in tag.node.iterchildren() if x.get('id') == obj.obj_id]
            for c in selfies:
                rmnode(c)
            if not tag.node.xpath('./obj_ref'):
                self._remove_obj(tag)
                if not self._no_constraint_rm_msg:
                    logger.info("hanging %s deleted", str(tag))
        for c_obj in self.related_constraints(obj):
            if is_simpleconstraint(c_obj.node) and obj.children:
                # the first child inherits constraints
                rename_rscref(c_obj, obj.obj_id, obj.children[0].obj_id)
            deleted = False
            if delete_rscref(c_obj, obj.obj_id):
                deleted = True
            if silly_constraint(c_obj.node, obj.obj_id):
                # remove invalid constraints
                self._remove_obj(c_obj)
                if not self._no_constraint_rm_msg:
                    logger.info("hanging %s deleted", str(c_obj))
            elif deleted:
                logger.info("constraint %s updated", str(c_obj))

    def related_tags(self, obj):
        def related_tag(tobj):
            if tobj.obj_type != 'tag':
                return False
            for c in tobj.node.iterchildren():
                if c.get('id') == obj.obj_id:
                    return True
            return False
        return [x for x in self.cib_objects if related_tag(x)]

    def related_constraints(self, obj):
        def related_constraint(obj2):
            return is_constraint(obj2.node) and rsc_constraint(obj.obj_id, obj2.node)
        if not is_resource(obj.node):
            return []
        return [x for x in self.cib_objects if related_constraint(x)]

    def related_elements(self, obj):
        "Both constraints, groups, tags, ..."
        if not is_resource(obj.node):
            return []
        return [x for x in self.cib_objects if is_related(obj.obj_id, x.node)]

    def _redirect_children_constraints(self, obj):
        '''
        Redirect constraints to the new parent
        '''
        for child in obj.children:
            for c_obj in self.related_constraints(child):
                rename_rscref(c_obj, child.obj_id, obj.obj_id)
        # drop useless constraints which may have been created above
        for c_obj in self.related_constraints(obj):
            if silly_constraint(c_obj.node, obj.obj_id):
                self._no_constraint_rm_msg = True
                self._remove_obj(c_obj)
                self._no_constraint_rm_msg = False

    def template_primitives(self, obj):
        if not is_template(obj.node):
            return []
        c_list = []
        for obj2 in self.cib_objects:
            if not is_primitive(obj2.node):
                continue
            if obj2.node.get("template") == obj.obj_id:
                c_list.append(obj2)
        return c_list

    def _check_running_primitives(self, prim_l):
        rscstat = RscState()
        for prim in prim_l:
            if not rscstat.can_delete(prim.obj_id):
                logger.error("resource %s is running, can't delete it", prim.obj_id)
                return False
        return True

    def _add_to_remove_queue(self, obj):
        if obj.origin == "cib":
            self.remove_queue.append(obj)

    def _delete_1(self, obj):
        '''
        Remove an object and its parent in case the object is the
        only child.
        '''
        if obj.parent and len(obj.parent.children) == 1:
            self._delete_1(obj.parent)
        if obj in self.cib_objects:  # don't remove parents twice
            self._remove_obj(obj)

    def delete(self, *args):
        'Delete a cib object.'
        if not self.is_cib_sane():
            return False
        rc = True
        l = []
        rscstat = RscState()
        for obj_id in args:
            obj = self.find_object(obj_id)
            if not obj:
                # If --force is set:
                # Unless something more serious goes wrong here,
                # don't return an error code if the object
                # to remove doesn't exist. This should help scripted
                # workflows without compromising an interactive
                # use.
                if not config.core.force:
                    logger_utils.no_object_err(obj_id)
                    rc = False
                continue
            if not rscstat.can_delete(obj_id):
                logger.error("resource %s is running, can't delete it", obj_id)
                rc = False
                continue
            if is_template(obj.node):
                prim_l = self.template_primitives(obj)
                prim_l = [x for x in prim_l
                          if x not in l and x.obj_id not in args]
                if not self._check_running_primitives(prim_l):
                    rc = False
                    continue
                for prim in prim_l:
                    logger.info("hanging %s deleted", str(prim))
                    l.append(prim)
            l.append(obj)
        if l:
            l = processing_sort_cli(l)
            for obj in reversed(l):
                self._delete_1(obj)
        return rc

    def rename(self, old_id, new_id):
        '''
        Rename a cib object.
        - check if the resource (if it's a resource) is stopped
        - check if the new id is not taken
        - find the object with old id
        - rename old id to new id in all related objects
          (constraints)
        - if the object came from the CIB, then it must be
          deleted and the one with the new name created
        - rename old id to new id in the object
        '''
        if not self.is_cib_sane() or not new_id:
            return False
        if idmgmt.id_in_use(new_id):
            return False
        obj = self.find_object(old_id)
        if not obj:
            logger_utils.no_object_err(old_id)
            return False
        if not obj.can_be_renamed():
            return False
        for c_obj in self.related_constraints(obj):
            rename_rscref(c_obj, old_id, new_id)
        rename_id(obj.node, old_id, new_id)
        obj.obj_id = new_id
        idmgmt.rename(old_id, new_id)
        # FIXME: (bnc#901543)
        # for each child node; if id starts with "%(old_id)s-" and
        # is not referenced by anything, change that id as well?
        # otherwise inner ids will resemble old name, not new
        obj.set_updated()

    def erase(self):
        "Remove all cib objects."
        # remove only bottom objects and no constraints
        # the rest will automatically follow
        if not self.is_cib_sane():
            return False
        erase_ok = True
        l = []
        rscstat = RscState()
        for obj in [obj for obj in self.cib_objects if not obj.children and not is_constraint(obj.node) and obj.obj_type != "node"]:
            if not rscstat.can_delete(obj.obj_id):
                logger.warning("resource %s is running, can't delete it", obj.obj_id)
                erase_ok = False
            else:
                l.append(obj)
        if not erase_ok:
            logger.error("CIB erase aborted (nothing was deleted)")
            return False
        self._no_constraint_rm_msg = True
        for obj in l:
            self.delete(obj.obj_id)
        self._no_constraint_rm_msg = False
        remaining = 0
        for obj in self.cib_objects:
            if obj.obj_type != "node":
                remaining += 1
        if remaining > 0:
            logger.error("strange, but these objects remained:")
            for obj in self.cib_objects:
                if obj.obj_type != "node":
                    print(str(obj), file=sys.stderr)
            self.cib_objects = []
        return True

    def erase_nodes(self):
        "Remove nodes only."
        if not self.is_cib_sane():
            return False
        l = [obj for obj in self.cib_objects if obj.obj_type == "node"]
        for obj in l:
            self.delete(obj.obj_id)

    def refresh(self):
        "Refresh from the CIB."
        self.reset()
        self.initialize()
        return self.is_cib_sane()


cib_factory = CibFactory()

# vim:ts=4:sw=4:et:
