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

import copy
from lxml import etree
import os
import sys
import re
import fnmatch
import time
import config
from singletonmixin import Singleton
import options
import vars
import tmpfiles
from parse import CliParser
from clidisplay import CliDisplay
from cibstatus import CibStatus
from idmgmt import IdMgmt
from ra import get_ra, get_properties_list, get_pe_meta
from schema import Schema, rng_attr_values, rng_attr_values_l
from crm_gv import gv_types
from msg import common_warn, common_err, common_debug, common_info, ErrorBuffer
from msg import common_error, constraint_norefobj_err, cib_parse_err, no_object_err
from msg import missing_obj_err, common_warning, update_err, unsupported_err, empty_cib_err
from msg import invalid_id_err, cib_ver_unsupported_err
import utils
from utils import ext_cmd, safe_open_w, pipe_string, safe_close_w, crm_msec
from utils import ask, lines2cli, cli_append_attr, cli_replace_attr, olist
from utils import keyword_cmp, page_string, cibadmin_can_patch, str2tmp
from utils import run_ptest, is_id_valid, edit_file, get_boolean, filter_string, find_value
from ordereddict import odict
from xmlutil import is_child_rsc, rsc_constraint, sanitize_cib, rename_id, get_interesting_nodes
from xmlutil import is_pref_location, get_topnode, new_cib, get_rscop_defaults_meta_node
from xmlutil import rename_rscref, is_ms, silly_constraint, is_container, fix_comments
from xmlutil import sanity_check_nvpairs, merge_nodes, op2list, mk_rsc_type, is_resource
from xmlutil import stuff_comments, is_comment, is_constraint, read_cib, processing_sort_cli
from xmlutil import find_operation, get_rsc_children_ids, is_primitive, referenced_resources
from xmlutil import cibdump2elem, processing_sort, get_rsc_ref_ids, merge_tmpl_into_prim
from xmlutil import remove_id_used_attributes, get_top_cib_nodes, set_id_used_attr
from xmlutil import merge_attributes, is_cib_element, sanity_check_meta, add_missing_attr
from xmlutil import is_simpleconstraint, is_template, rmnode, is_defaults, is_live_cib
from xmlutil import get_rsc_operations, delete_rscref, xml_equals, lookup_node, RscState
from xmlutil import cibtext2elem
from cliformat import get_score, nvpairs2list, abs_pos_score, cli_acl_roleref, nvpair_format
from cliformat import cli_acl_rule, cli_pairs, rsc_set_constraint, get_kind
from cliformat import cli_operations, simple_rsc_constraint, cli_rule, cli_format


def show_unrecognized_elems(cib_elem):
    try:
        conf = cib_elem.findall("configuration")[0]
    except IndexError:
        common_warn("CIB has no configuration element")
        return False
    rc = True
    for topnode in conf.iterchildren():
        if is_defaults(topnode) or topnode.tag == "fencing-topology":
            continue
        for c in topnode.iterchildren():
            if not c.tag in cib_object_map:
                common_warn("unrecognized CIB element %s" % c.tag)
                rc = False
    return rc


#
# object sets (enables operations on sets of elements)
#
def mkset_obj(*args):
    if args and args[0] == "xml":
        obj = lambda: CibObjectSetRaw(*args[1:])
    else:
        obj = lambda: CibObjectSetCli(*args)
    return obj()


def set_graph_attrs(gv_obj, obj_type):
    try:
        for attr, attr_v in vars.graph['*'].iteritems():
            gv_obj.new_graph_attr(attr, attr_v)
    except KeyError:
        pass
    try:
        for attr, attr_v in vars.graph[obj_type].iteritems():
            gv_obj.new_graph_attr(attr, attr_v)
    except KeyError:
        pass


def set_obj_attrs(gv_obj, obj_id, obj_type):
    try:
        for attr, attr_v in vars.graph['*'].iteritems():
            gv_obj.new_attr(obj_id, attr, attr_v)
    except KeyError:
        pass
    try:
        for attr, attr_v in vars.graph[obj_type].iteritems():
            gv_obj.new_attr(obj_id, attr, attr_v)
    except KeyError:
        pass


def set_edge_attrs(gv_obj, edge_id, obj_type):
    try:
        for attr, attr_v in vars.graph[obj_type].iteritems():
            gv_obj.new_edge_attr(edge_id, attr, attr_v)
    except KeyError:
        pass


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
        self.obj_ids = set([o.obj_id for o in self.obj_set])
        self.all_ids = set([o.obj_id for o in self.all_set])
        self.locked_ids = self.all_ids - self.obj_ids

    def _open_url(self, src):
        if src == "-":
            return sys.stdin
        import urllib
        try:
            return urllib.urlopen(src)
        except:
            pass
        try:
            return open(src)
        except:
            pass
        common_err("could not open %s" % src)
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
        s = self._pre_edit(s)
        tmp = str2tmp(s)
        if not tmp:
            return False
        filehash = hash(s)
        rc = False
        while True:
            if edit_file(tmp) != 0:
                break
            try:
                f = open(tmp, 'r')
            except IOError, msg:
                common_err(msg)
                break
            s = ''.join(f)
            f.close()
            if hash(s) == filehash:  # file unchanged
                rc = True
                break
            if not self.save(self._post_edit(s)):
                if ask("Do you want to edit again?"):
                    continue
            rc = True
            break
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return rc

    def edit(self):
        if options.batch:
            common_info("edit not allowed in batch mode")
            return False
        cli_display.set_no_pretty()
        s = self.repr()
        cli_display.reset_no_pretty()
        # don't allow edit if one or more elements were not
        # found
        if not self.search_rc:
            return self.search_rc
        return self._edit_save(s)

    def _filter_save(self, filter, s):
        '''
        Pipe string s through a filter. Parse/save the output.
        If no changes are done, return silently.
        '''
        rc, outp = filter_string(filter, s)
        if rc != 0:
            return False
        if hash(outp) == hash(s):
            return True
        return self.save(outp)

    def filter(self, filter):
        cli_display.set_no_pretty()
        s = self.repr(format=-1)
        cli_display.reset_no_pretty()
        # don't allow filter if one or more elements were not
        # found
        if not self.search_rc:
            return self.search_rc
        return self._filter_save(filter, s)

    def save_to_file(self, fname):
        f = safe_open_w(fname)
        if not f:
            return False
        rc = True
        cli_display.set_no_pretty()
        s = self.repr()
        cli_display.reset_no_pretty()
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
        if gtype not in gv_types:
            common_err("graphviz type %s is not supported" % gtype)
            return False, None
        gv_obj = gv_types[gtype]()
        set_graph_attrs(gv_obj, ".")
        return True, gv_obj

    def _graph_repr(self, gv_obj):
        '''Let CIB elements produce graph elements.
        '''
        for obj in processing_sort_cli(list(self.obj_set)):
            obj.repr_gv(gv_obj, from_grp=False)

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
        if not s:
            return self.search_rc
        page_string(s)
        return self.search_rc

    def import_file(self, method, fname):
        '''
        method: update or replace
        '''
        if not cib_factory.is_cib_sane():
            return False
        f = self._open_url(fname)
        if not f:
            return False
        s = ''.join(f)
        if f != sys.stdin:
            f.close()
        return self.save(s, no_remove=True, method=method)

    def repr(self, format=format):
        '''
        Return a string with objects's representations (either
        CLI or XML).
        '''
        return ''

    def save(self, s, no_remove=False, method='replace'):
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

    def __check_unique_clash(self, set_obj_all):
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
            for a in r_node.iterchildren("instance_attributes"):
                for p in a.iterchildren("nvpair"):
                    name = p.get("name")
                    # don't fail if the meta-data doesn't contain the
                    # expected attributes
                    try:
                        if ra_params[name].get("unique") == "1":
                            value = p.get("value")
                            k = (ra_class, ra_provider, ra_type, name, value)
                            try:
                                clash_dict[k].append(ra_id)
                            except KeyError:
                                clash_dict[k] = [ra_id]
                    except KeyError:
                        pass
            return
        # we check the whole CIB for clashes as a clash may originate between
        # an object already committed and a new one
        check_set = set([o.obj_id
                         for o in self.obj_set
                         if o.obj_type == "primitive"])
        if not check_set:
            return 0
        clash_dict = {}
        for obj in set_obj_all.obj_set:
            node = obj.node
            if is_primitive(node):
                process_primitive(node, clash_dict)
        # but we only warn if a 'new' object is involved
        rc = 0
        for param, resources in clash_dict.items():
            # at least one new object must be involved
            if len(resources) > 1 and len(set(resources) & check_set) > 0:
                rc = 2
                msg = 'Resources %s violate uniqueness for parameter "%s": "%s"' % (
                    ",".join(sorted(resources)), param[3], param[4])
                common_warning(msg)
        return rc

    def semantic_check(self, set_obj_all):
        '''
        Test objects for sanity. This is about semantics.
        '''
        rc = self.__check_unique_clash(set_obj_all)
        for obj in self.obj_set:
            rc |= obj.check_sanity()
        return rc

    def is_edit_valid(self, id_set):
        '''
        1. Cannot name any elements as those which exist but
        were not picked for editing.
        2. Cannot remove running resources.
        '''
        rc = True
        not_allowed = id_set & self.locked_ids
        rscstat = RscState()
        if not_allowed:
            common_err("Elements %s already exist" %
                       ', '.join(list(not_allowed)))
            rc = False
        delete_set = self.obj_ids - id_set
        cannot_delete = [x for x in delete_set
                         if not rscstat.can_delete(x)]
        if cannot_delete:
            common_err("Cannot delete running resources: %s" %
                       ', '.join(cannot_delete))
            rc = False
        return rc


def get_comments(cli_list):
    if not cli_list:
        return []
    last = cli_list[len(cli_list)-1]
    try:
        if last[0] == "comments":
            cli_list.pop()
            return last[1]
    except IndexError:
        pass
    return []


class CibObjectSetCli(CibObjectSet):
    '''
    Edit or display a set of cib objects (using cli notation).
    '''
    vim_stx_str = "#vim:set syntax=pcmk\n"

    def __init__(self, *args):
        CibObjectSet.__init__(self, *args)

    def repr_nopretty(self, format=1):
        cli_display.set_no_pretty()
        s = self.repr(format=format)
        cli_display.reset_no_pretty()
        return s

    def repr(self, format=1):
        "Return a string containing cli format of all objects."
        if not self.obj_set:
            return ''
        return '\n'.join(obj.repr_cli(format=format)
                         for obj in processing_sort_cli(list(self.obj_set)))

    def _pre_edit(self, s):
        '''Extra processing of the string to be editted'''
        if config.core.editor.startswith("vi"):
            return "%s\n%s" % (s, self.vim_stx_str)
        return s

    def _post_edit(self, s):
        if config.core.editor.startswith("vi"):
            return s.replace(self.vim_stx_str, "")
        return s

    def _get_id(self, cli_list):
        '''
        Get the id from a CLI representation. Normally, it should
        be value of the id attribute, but sometimes the
        attribute is missing.
        '''
        id = find_value(cli_list[0][1], "id") or find_value(cli_list[0][1], "$id")
        if not id:
            type = cli_list[0][0]
            if type in vars.nvset_cli_names:
                # some elements have default ids
                # (property, *_defaults)
                id = cib_object_map[backtrans[type]][3]
            else:
                # some are unique and have no ids,
                # i.e. fencing-topology
                id = type
        return id

    def save(self, s, no_remove=False, method='replace'):
        '''
        Save a user supplied cli format configuration.
        On errors user is typically asked to review the
        configuration (for instance on editting).

        On errors, the user is asked to edit again (if we're
        coming from edit). The original CIB is preserved and no
        changes are made.
        '''
        edit_d = {}
        id_set = set()
        del_set = set()
        rc = True
        err_buf.start_tmp_lineno()
        cp = CliParser()
        for cli_text in lines2cli(s):
            err_buf.incr_lineno()
            cli_list = cp.parse2(cli_text)
            if cli_list:
                id = self._get_id(cli_list)
                if id in id_set:
                    common_err("duplicate element %s" % id)
                    rc = False
                id_set.add(id)
                edit_d[id] = cli_list
            elif cli_list is False:
                rc = False
        err_buf.stop_tmp_lineno()
        # we can't proceed if there was a syntax error, but we
        # can ask the user to fix problems
        if not no_remove:
            rc &= self.is_edit_valid(id_set)
            del_set = self.obj_ids - id_set
        if not rc:
            return rc
        mk_set = id_set - self.obj_ids
        upd_set = id_set & self.obj_ids

        rc = cib_factory.set_update(edit_d, mk_set, upd_set, del_set,
                                    upd_type="cli", method=method)
        if not rc:
            self._initialize()
        return rc


cib_verify = "crm_verify -V -p"


class CibObjectSetRaw(CibObjectSet):
    '''
    Edit or display one or more CIB objects (XML).
    '''
    def __init__(self, *args):
        CibObjectSet.__init__(self, *args)

    def repr(self, format="ignored"):
        "Return a string containing xml of all objects."
        cib_elem = cib_factory.obj_set2cib(self.obj_set)
        s = etree.tostring(cib_elem, pretty_print=True)
        s = '<?xml version="1.0" ?>\n%s' % s
        return s

    def _get_id(self, node):
        if node.tag == "fencing-topology":
            return node.tag
        else:
            return node.get("id")

    def save(self, s, no_remove=False, method='replace'):
        try:
            cib_elem = etree.fromstring(s)
        except etree.ParseError, msg:
            cib_parse_err(msg, s)
            return False
        sanitize_cib(cib_elem)
        if not show_unrecognized_elems(cib_elem):
            return False
        rc = True
        id_set = set()
        del_set = set()
        edit_d = {}
        for node in get_top_cib_nodes(cib_elem, []):
            id = self._get_id(node)
            if not id:
                common_err("element %s has no id!" %
                           etree.tostring(node, pretty_print=True))
                rc = False
            if id in id_set:
                common_err("duplicate element %s" % id)
                rc = False
            id_set.add(id)
            edit_d[id] = node
        if not no_remove:
            rc &= self.is_edit_valid(id_set)
            del_set = self.obj_ids - id_set
        if not rc:
            return rc
        mk_set = id_set - self.obj_ids
        upd_set = id_set & self.obj_ids
        rc = cib_factory.set_update(edit_d, mk_set, upd_set, del_set, "xml", method)
        if not rc:
            self._initialize()
        return rc

    def verify(self):
        if not self.obj_set:
            return True
        cli_display.set_no_pretty()
        rc = pipe_string(cib_verify, self.repr(format=-1))
        cli_display.reset_no_pretty()
        if rc not in (0, 1):
            common_debug(self.repr())
        return rc in (0, 1)

    def ptest(self, nograph, scores, utilization, actions, verbosity):
        if not cib_factory.is_cib_sane():
            return False
        cib_elem = cib_factory.obj_set2cib(self.obj_set)
        status = cib_status.get_status()
        if status is None:
            common_err("no status section found")
            return False
        cib_elem.append(copy.deepcopy(status))
        graph_s = etree.tostring(cib_elem)
        return run_ptest(graph_s, nograph, scores, utilization, actions, verbosity)


#
# XML generate utilities
#
def set_id(node, oldnode, id_hint, id_required=True):
    '''
    Set the id attribute for the node.
    Procedure:
    - if the node already contains "id", keep it
    - if the old node contains "id", copy that
    - if neither is true, then create a new one using id_hint
      (exception: if not id_required, then no new id is generated)
    Finally, save the new id in id_store.
    '''
    old_id = None
    new_id = node.get("id")
    if oldnode is not None and oldnode.get("id"):
        old_id = oldnode.get("id")
    if not new_id:
        new_id = old_id
    if not new_id:
        if id_required:
            new_id = id_store.new(node, id_hint)
    else:
        id_store.save(new_id)
    if new_id:
        node.set("id", new_id)
        if oldnode is not None and old_id == new_id:
            set_id_used_attr(oldnode)


def mkxmlsimple(e, oldnode, id_hint):
    '''
    Create an xml node from the (name, dict) pair. The name is the
    name of the element. The dict contains a set of attributes.
    '''
    node = etree.Element(e[0])
    for n, v in e[1]:
        if n == "$children":  # this one's skipped
            continue
        if n == "operation":
            v = v.lower()
        if n.startswith('$'):
            n = n.lstrip('$')
        if not isinstance(v, basestring):
            if isinstance(v, bool):
                v = str(v).lower()
            else:
                raise ValueError("cannot make attribute value from '%s'" % (v))
        if v:  # skip empty strings
            node.set(n, v)
    id_ref = node.get("id-ref")
    if id_ref:
        id_ref_2 = cib_factory.resolve_id_ref(e[0], id_ref)
        node.set("id-ref", id_ref_2)
    else:
        set_id(node, lookup_node(node, oldnode), id_hint)
    return node


def mkxmlnvpairs(e, oldnode, id_hint):
    '''
    Create xml from the (name, dict) pair. The name is the name of
    the element. The dict contains a set of nvpairs. Stuff such
    as instance_attributes.
    NB: Other tags not containing nvpairs are fine if the dict is empty.
    '''
    xml_node_type = e[0] in vars.defaults_tags and "meta_attributes" or e[0]
    node = etree.Element(xml_node_type)
    # another exception:
    # cluster_property_set and defaults have nvpairs as direct children
    # in that case the id_hint is equal id
    # and this is important in case there are multiple sets
    if (e[0] == "cluster_property_set" or e[0] in vars.defaults_tags) and id_hint:
        node.set("id", id_hint)
    match_node = lookup_node(node, oldnode)
    #if match_node:
        #print "found nvpairs set:", match_node.tag, match_node.get("id")
    id_ref = find_value(e[1], "$id-ref")
    if id_ref:
        id_ref_2 = cib_factory.resolve_id_ref(e[0], id_ref)
        node.set("id-ref", id_ref_2)
        if e[0] != "operations":
            return node  # id_ref is the only attribute (if not operations)
        e[1].remove(["$id-ref", id_ref])
    v = find_value(e[1], "$id")
    if v:
        node.set("id", v)
        e[1].remove(["$id", v])
    elif e[0] in vars.nvset_cli_names:
        node.set("id", id_hint)
    else:
        if e[0] == "operations":  # operations don't need no id
            set_id(node, match_node, id_hint, id_required=False)
        else:
            set_id(node, match_node, id_hint)
    try:
        subpfx = vars.subpfx_list[e[0]]
    except KeyError:
        subpfx = ''
    subpfx = subpfx and "%s_%s" % (id_hint, subpfx) or id_hint
    nvpair_pfx = node.get("id") or subpfx
    for n, v in e[1]:
        nvpair = etree.SubElement(node, "nvpair")
        nvpair.set("name", n)
        if v is not None:
            nvpair.set("value", v)
        set_id(nvpair, lookup_node(nvpair, match_node), nvpair_pfx)
    return node


def mkxmlop(e, oldnode, id_hint):
    '''
    Create an operation xml from the (name, dict) pair.
    '''
    node = etree.Element(e[0])
    inst_attr = []
    for n, v in e[1]:
        if n in olist(schema.get('attr', 'op', 'a')):
            node.set(n, v)
        else:
            inst_attr.append([n, v])
    tmp = etree.Element("operations")
    # first find old operations
    oldops = lookup_node(tmp, oldnode)
    oldop = lookup_node(node, oldops)
    set_id(node, oldop, id_hint)
    if inst_attr:
        e = ["instance_attributes", inst_attr]
        nia = mkxmlnvpairs(e, oldop, node.get("id"))
        node.append(nia)
    return node


def mkxmldate(e, oldnode, id_hint):
    '''
    Create a date_expression xml from the (name, dict) pair.
    '''
    node = etree.Element(e[0])
    operation = find_value(e[1], "operation").lower()
    node.set("operation", operation)
    # first find old date element
    old_date = lookup_node(node, oldnode)
    set_id(node, old_date, id_hint)
    date_spec_attr = []
    for n, v in e[1]:
        if n in olist(rng_attr_values_l('date_expression', 'operation')) or \
                n == "operation":
            continue
        elif n in vars.in_range_attrs:
            node.set(n, v)
        else:
            date_spec_attr.append([n, v])
    if not date_spec_attr:
        return node
    tag = operation == "date_spec" and "date_spec" or "duration"
    spec_elem = etree.SubElement(node, tag)
    # first find old date element
    old_date_spec = lookup_node(spec_elem, old_date)
    set_id(spec_elem, old_date_spec, id_hint)
    for n, v in date_spec_attr:
        spec_elem.set(n, v)
    return node


def mkxmlrsc_set(e, oldnode, id_hint):
    '''
    Create a resource_set xml from the (name, dict) pair.
    '''
    node = etree.Element(e[0])
    # first find old date element
    old_rsc_set = lookup_node(node, oldnode)
    set_id(node, old_rsc_set, id_hint)
    for ref in e[1]:
        if ref[0] == "resource_ref":
            ref_node = etree.SubElement(node, ref[0])
            ref_node.set(ref[1][0], ref[1][1])
        elif ref[0] in ("sequential", "require-all", "action", "role"):
            node.set(ref[0], ref[1])
    return node


def mkxmlaclrole_ref(e):
    '''
    Create a role reference xml. Very simple, but different from
    everything else.
    '''
    node = etree.Element(e[0])
    node.set(e[1][0], e[1][1])
    return node


def mkxmlhead(e):
    '''
    Create a fencing_topology xml.
    '''
    node = etree.Element(e[0])
    return node

conv_list = {
    "params": "instance_attributes",
    "meta": "meta_attributes",
    "property": "cluster_property_set",
    "rsc_defaults": "rsc_defaults",
    "op_defaults": "op_defaults",
    "attributes": "instance_attributes",
    "utilization": "utilization",
    "operations": "operations",
    "op": "op",
    "tag": "tag",
}


def mkxmlnode(e, oldnode, id_hint):
    '''
    Create xml from the (name, dict) pair. The name is the name of
    the element. The dict contains either a set of nvpairs or a
    set of attributes. The id is either generated or copied if
    found in the provided xml. Stuff such as instance_attributes.
    '''
    if e[0] in conv_list:
        e[0] = conv_list[e[0]]
    if e[0] in ("instance_attributes", "meta_attributes",
                "operations", "rsc_defaults",
                "op_defaults", "cluster_property_set",
                "utilization"):
        return mkxmlnvpairs(e, oldnode, id_hint)
    elif e[0] == "op":
        return mkxmlop(e, oldnode, id_hint)
    elif e[0] == "date_expression":
        return mkxmldate(e, oldnode, id_hint)
    elif e[0] == "resource_set":
        return mkxmlrsc_set(e, oldnode, id_hint)
    elif e[0] == "role_ref":
        return mkxmlaclrole_ref(e)
    else:
        return mkxmlsimple(e, oldnode, id_hint)


def set_nvpair(set_node, name, value):
    n_id = set_node.get("id")
    for c in set_node.iterchildren():
        if c.get("name") == name:
            c.set("value", value)
            return
    np = etree.SubElement(set_node, "nvpair")
    np.set("name", name)
    np.set("value", value)
    new_id = id_store.new(np, n_id)
    np.set("id", new_id)


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
        if not xml_obj_type in cib_object_map:
            unsupported_err(xml_obj_type)
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

    def _dump_state(self):
        'Print object status'
        print self.state_fmt % (self.obj_id,
                                self.origin,
                                self.updated,
                                self.parent and self.parent.obj_id or "",
                                len(self.children))

    def _repr_cli_xml(self, format):
        if format < 0:
            cli_display.set_no_pretty()
        try:
            h = cli_display.keyword("xml")
            l = etree.tostring(self.node, pretty_print=True).split('\n')
            l = [x for x in l if x]  # drop empty lines
            return "%s %s" % (h, cli_format(l, break_lines=(format > 0), xml=True))
        finally:
            if format < 0:
                cli_display.reset_no_pretty()

    def _gv_rsc_id(self):
        if self.parent and self.parent.obj_type in vars.clonems_tags:
            return "%s:%s" % (self.parent.obj_type, self.obj_id)
        else:
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

    def _repr_cli_head(self, format):
        'implemented in subclasses'
        pass

    def repr_cli(self, format=1):
        '''
        CLI representation for the node.
        _repr_cli_head and _repr_cli_child in subclasess.
        '''
        if self.nocli:
            return self._repr_cli_xml(format)
        l = []
        if format < 0:
            cli_display.set_no_pretty()
        head_s = self._repr_cli_head(format)
        # everybody must have a head
        if not head_s:
            if format < 0:
                cli_display.reset_no_pretty()
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
            s = self._repr_cli_child(c, format)
            if s:
                l.append(s)
        s = self._cli_format_and_comment(l, comments, break_lines=(format > 0))
        if format < 0:
            cli_display.reset_no_pretty()
        return s

    def _attr_set_str(self, node):
        '''
        Add $id=<id> if the set id is referenced by another
        element.
        '''
        id = node.get("id")
        add_id = cib_factory.is_id_refd(node.tag, id)
        return "%s %s" % (cli_display.keyword(self.set_names[node.tag]),
                          cli_pairs(nvpairs2list(node, add_id=add_id)))

    def _repr_cli_child(self, c, format):
        if c.tag in self.set_names:
            return self._attr_set_str(c)

    def _get_oldnode(self):
        '''Used to retrieve sub id's'''
        return self.node

    def set_id(self, obj_id=None):
        if obj_id:
            self.obj_id = obj_id
        else:
            self.obj_id = self.node is not None and self.node.get("id") or None

    def set_nodeid(self):
        if self.node is not None and self.obj_id:
            self.node.set("id", self.obj_id)

    def _cli_list2node(self, cli_list, oldnode):
        'implemented in subclasses'
        pass

    def cli2node(self, cli, oldnode=None):
        '''
        Convert CLI representation to a DOM node.
        Defined in subclasses.
        '''
        cli_list = mk_cli_list(cli)
        if not cli_list:
            return None
        if oldnode is None:
            oldnode = self._get_oldnode()
        comments = get_comments(cli_list)
        node = self._cli_list2node(cli_list, oldnode)
        if comments and node is not None:
            stuff_comments(node, comments)
        return node

    def _cli_format_and_comment(self, l, comments, break_lines):
        '''
        Format and add comment (if any).
        '''
        s = cli_format(l, break_lines=break_lines)
        cs = '\n'.join(comments)
        return (comments and format >= 0) and '\n'.join([cs, s]) or s

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
            common_debug("move comm %s" % etree.tostring(comm_node))
            self.node.remove(comm_node)
            self.node.insert(firstelem, comm_node)
            firstelem += 1
        common_debug("obj %s node: %s" % (self.obj_id, etree.tostring(self.node)))

    def mknode(self, obj_id):
        if self.xml_obj_type in vars.defaults_tags:
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
        rscstat = RscState()
        if not rscstat.can_delete(self.obj_id):
            common_err("cannot rename a running resource (%s)" % self.obj_id)
            return False
        if not is_live_cib() and self.node.tag == "node":
            common_err("cannot rename nodes")
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
        cli_display.set_no_pretty()
        cli_text = self.repr_cli(format=0)
        cli_display.reset_no_pretty()
        if not cli_text:
            return False
        common_debug("clitext: %s" % cli_text)
        xml2 = self.cli2node(cli_text)
        if xml2 is None:
            return False
        return xml_equals(self.node, xml2, show=True)

    def _verify_op_attributes(self, op_node):
        '''
        Check if all operation attributes are supported by the
        schema.
        '''
        rc = True
        op_id = op_node.get("name")
        for name in op_node.keys():
            vals = rng_attr_values(op_node.tag, name)
            if not vals:
                continue
            v = op_node.get(name)
            if v not in vals:
                common_warn("%s: op '%s' attribute '%s' value '%s' not recognized" %
                            (self.obj_id, op_id, name, v))
                rc = False
        return rc

    def _check_ops_attributes(self):
        '''
        Check if operation attributes settings are valid.
        '''
        rc = True
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

    def matchcli(self, cli_list):
        head = cli_list[0]
        return self.obj_type == head[0] \
            and self.obj_id == find_value(head[1], "id")

    def match(self, xml_obj_type, obj_id):
        return self.xml_obj_type == xml_obj_type and self.obj_id == obj_id

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

    def find_child_in_node(self, child):
        for c in self.node.iterchildren():
            if c.tag == child.obj_type and \
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
    elif score in rng_attr_values('rsc_order', 'kind'):
        lbl = score
    elif not score:
        lbl = 'Adv'
    else:
        lbl = "attr:%s" % score
    gv_obj.new_edge_attr(e_id, 'label', lbl)


def mk_cli_list(cli):
    'Sometimes we get a string and sometimes a list.'
    if isinstance(cli, basestring):
        cp = CliParser()
        # what follows looks strange, but the last string actually matters
        # the previous ones may be comments and are collected by the parser
        for s in lines2cli(cli):
            cli_list = cp.parse2(s)
        return cli_list
    else:
        return cli


class CibNode(CibObject):
    '''
    Node and node's attributes.
    '''
    set_names = {
        "instance_attributes": "attributes",
        "utilization": "utilization",
    }

    def _repr_cli_head(self, format):
        uname = self.node.get("uname")
        s = cli_display.keyword(self.obj_type)
        if self.obj_id != uname:
            if utils.noquotes(self.obj_id):
                s = "%s %s:" % (s, self.obj_id)
            else:
                s = '%s $id="%s"' % (s, self.obj_id)
        s = '%s %s' % (s, cli_display.id(uname))
        type = self.node.get("type")
        if type and type != vars.node_default_type:
            s = '%s:%s' % (s, type)
        return s

    def _cli_list2node(self, cli_list, oldnode):
        head = copy.copy(cli_list[0])
        head[0] = backtrans[head[0]]
        obj_id = find_value(head[1], "$id")
        if not obj_id:
            obj_id = find_value(head[1], "uname")
        if not obj_id:
            return None
        type = find_value(head[1], "type")
        if not vars.node_type_opt and not type:
            type = vars.node_default_type
        if type:
            head[1].append(["type", type])
        headnode = mkxmlsimple(head,
                               get_topnode(cib_factory.get_cib(),
                                           self.parent_type),
                               'node')
        id_hint = headnode.get("uname")
        for e in cli_list[1:]:
            n = mkxmlnode(e, oldnode, id_hint)
            headnode.append(n)
        remove_id_used_attributes(get_topnode(cib_factory.get_cib(), self.parent_type))
        return headnode

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
        self.attr_d = odict()
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
        for name in self.node.keys():
            if name != "id":  # skip the id
                self.set_attr(name, self.node.get(name))
        for p in self.node.xpath("instance_attributes/nvpair"):
            n = p.get("name")
            v = p.get("value")
            self.set_attr(n, v)

    def mkxml(self):
        # create an xml node
        if self.node is not None:
            if self.node.getparent() is not None:
                self.node.getparent().remove(self.node)
            id_store.remove_xml(self.node)
        self.node = etree.Element(self.elem_type)
        inst_attr = []
        for n, v in self.attr_d.iteritems():
            if n in olist(schema.get('attr', 'op', 'a')):
                self.node.set(n, v)
            else:
                inst_attr.append([n, v])
        set_id(self.node, None, self.prim)
        if inst_attr:
            e = ["instance_attributes", inst_attr]
            nia = mkxmlnvpairs(e, None, self.node.get("id"))
            self.node.append(nia)
        return self.node


class CibPrimitive(CibObject):
    '''
    Primitives.
    '''

    set_names = {
        "instance_attributes": "params",
        "meta_attributes": "meta",
        "utilization": "utilization",
    }

    def _repr_cli_head(self, format):
        if self.obj_type == "primitive":
            template_ref = self.node.get("template")
        else:
            template_ref = None
        if template_ref:
            rsc_spec = "@%s" % cli_display.idref(template_ref)
        else:
            rsc_spec = mk_rsc_type(self.node)
        s = cli_display.keyword(self.obj_type)
        id = cli_display.id(self.obj_id)
        return "%s %s %s" % (s, id, rsc_spec)

    def _repr_cli_child(self, c, format):
        if c.tag in self.set_names:
            return self._attr_set_str(c)
        elif c.tag == "operations":
            return cli_operations(c, break_lines=(format > 0))

    def _cli_list2node(self, cli_list, oldnode):
        '''
        Convert a CLI description to DOM node.
        Try to preserve as many ids as possible in case there's
        an old XML version.
        '''
        head = copy.copy(cli_list[0])
        head[0] = backtrans[head[0]]
        headnode = mkxmlsimple(head, oldnode, 'rsc')
        id_hint = headnode.get("id")
        operations = None
        for e in cli_list[1:]:
            n = mkxmlnode(e, oldnode, id_hint)
            if keyword_cmp(e[0], "operations"):
                operations = n
            if not keyword_cmp(e[0], "op"):
                headnode.append(n)
            else:
                if operations is None:
                    operations = mkxmlnode(["operations", {}], oldnode, id_hint)
                    headnode.append(operations)
                operations.append(n)
        remove_id_used_attributes(oldnode)
        return headnode

    def _append_op(self, op_node):
        try:
            ops_node = self.node.findall("operations")[0]
        except IndexError:
            ops_node = etree.SubElement(self.node, "operations")
        ops_node.append(op_node)

    def add_operation(self, cli_list):
        # check if there is already an op with the same interval
        comments = get_comments(cli_list)
        head = copy.copy(cli_list[0])
        name = find_value(head[1], "name")
        interval = find_value(head[1], "interval")
        if find_operation(self.node, name, interval) is not None:
            common_err("%s already has a %s op with interval %s" %
                       (self.obj_id, name, interval))
            return None
        # create an xml node
        op_node = mkxmlnode(head, None, self.obj_id)
        self._append_op(op_node)
        if comments and self.node is not None:
            stuff_comments(self.node, comments)
        # the resource is updated
        self.updated = True
        self.propagate_updated()
        return self

    def del_operation(self, op_node):
        if op_node.getparent() is None:
            return
        ops_node = op_node.getparent()
        op_node.getparent().remove(op_node)
        id_store.remove_xml(op_node)
        if len(ops_node) == 0:
            rmnode(ops_node)
        self.updated = True
        self.propagate_updated()

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
        self.updated = True
        self.propagate_updated()
        return new_op_node

    def del_op_attr(self, op_node, attr_n):
        name = op_node.get("name")
        op_obj = Op(name, self.obj_id, op_node)
        op_obj.del_attr(attr_n)
        new_op_node = op_obj.mkxml()
        self._append_op(new_op_node)
        # the resource is updated
        self.updated = True
        self.propagate_updated()
        return new_op_node

    def check_sanity(self):
        '''
        Check operation timeouts and if all required parameters
        are defined.
        '''
        if self.node is None:  # eh?
            common_err("%s: no xml (strange)" % self.obj_id)
            return utils.get_check_rc()
        rc3 = sanity_check_meta(self.obj_id, self.node, vars.rsc_meta_attributes)
        if self.obj_type == "primitive":
            r_node = reduce_primitive(self.node)
            if r_node is None:
                common_err("%s: no such resource template" % self.node.get("template"))
                return utils.get_check_rc()
        else:
            r_node = self.node
        ra = get_ra(r_node)
        if ra.mk_ra_node() is None:  # no RA found?
            if cib_factory.is_asymm_cluster():
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
            if self.parent and self.parent.obj_type in vars.clonems_tags:
                self._set_gv_attrs(gv_obj, self.parent.obj_type)

            template_ref = self.node.get("template")
            if template_ref:
                e = [template_ref, self.obj_id]
                e_id = gv_obj.new_edge(e)
                self._set_edge_attrs(gv_obj, e_id, 'template:edge')

        elif self.obj_type == "rsc_template":
            n = reduce_primitive(self.node)
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
            if self.parent and self.parent.obj_type in vars.clonems_tags:
                self._set_gv_attrs(gv_obj, self.parent.obj_type)


class CibContainer(CibObject):
    '''
    Groups and clones and ms.
    '''
    set_names = {
        "instance_attributes": "params",
        "meta_attributes": "meta",
    }

    def _repr_cli_head(self, format):
        children = []
        for c in self.node.iterchildren():
            if (self.obj_type == "group" and is_primitive(c)) or \
                    is_child_rsc(c):
                children.append(cli_display.rscref(c.get("id")))
            elif self.obj_type in vars.clonems_tags and is_child_rsc(c):
                children.append(cli_display.rscref(c.get("id")))
        s = cli_display.keyword(self.obj_type)
        id = cli_display.id(self.obj_id)
        return "%s %s %s" % (s, id, ' '.join(children))

    def _cli_list2node(self, cli_list, oldnode):
        head = copy.copy(cli_list[0])
        head[0] = backtrans[head[0]]
        headnode = mkxmlsimple(head, oldnode, 'grp')
        id_hint = headnode.get("id")
        for e in cli_list[1:]:
            n = mkxmlnode(e, oldnode, id_hint)
            headnode.append(n)
        v = find_value(head[1], "$children")
        if v:
            for child_id in v:
                obj = cib_factory.find_object(child_id)
                if obj:
                    headnode.append(copy.deepcopy(obj.node))
                else:
                    no_object_err(child_id)
        remove_id_used_attributes(oldnode)
        return headnode

    def check_sanity(self):
        '''
        Check meta attributes.
        '''
        if self.node is None:  # eh?
            common_err("%s: no xml (strange)" % self.obj_id)
            return utils.get_check_rc()
        l = vars.rsc_meta_attributes
        if self.obj_type == "clone":
            l += vars.clone_meta_attributes
        elif self.obj_type == "ms":
            l += vars.clone_meta_attributes + vars.ms_meta_attributes
        elif self.obj_type == "group":
            l += vars.group_meta_attributes
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
        if self.parent and self.parent.obj_type in vars.clonems_tags:
            self._set_sg_attrs(sg_obj, self.parent.obj_type)
        for child_rsc in self.children:
            child_rsc.repr_gv(sg_obj, from_grp=True)


class CibLocation(CibObject):
    '''
    Location constraint.
    '''

    def _repr_cli_head(self, format):
        rsc = None
        if "rsc" in self.node.keys():
            rsc = self.node.get("rsc")
        elif "rsc-pattern" in self.node.keys():
            rsc = '/%s/' % (self.node.get("rsc-pattern"))
        if rsc is not None:
            rsc = cli_display.rscref(rsc)
        elif self.node.find("resource_set") is not None:
            rsc = '{ %s }' % (' '.join(rsc_set_constraint(self.node, self.obj_type)))
        else:
            common_err("%s: unknown rsc_location format" % self.obj_id)
            return None
        s = cli_display.keyword(self.obj_type)
        id = cli_display.id(self.obj_id)
        s = "%s %s %s" % (s, id, rsc)
        pref_node = self.node.get("node")
        score = cli_display.score(get_score(self.node))
        if pref_node is not None:
            ret = "%s %s: %s" % (s, score, pref_node)
            role = self.node.get("role")
            if role is not None:
                ret += " role=%s" % (role)
            return ret
        else:
            return s

    def _repr_cli_child(self, c, format):
        if c.tag == "rule":
            return "%s %s" % \
                (cli_display.keyword("rule"), cli_rule(c))

    def _cli_list2node(self, cli_list, oldnode):
        head = copy.copy(cli_list[0])
        head[0] = backtrans[head[0]]
        headnode = mkxmlsimple(head, oldnode, 'location')
        id_hint = headnode.get("id")
        oldrule = None
        rule = None
        for e in cli_list[1:]:
            if e[0] in ("expression", "date_expression"):
                n = mkxmlnode(e, oldrule, id_hint)
            else:
                n = mkxmlnode(e, oldnode, id_hint)
            if e[0] == "resource_set":
                headnode.append(n)
            elif keyword_cmp(e[0], "rule"):
                add_missing_attr(n)
                rule = n
                headnode.append(n)
                oldrule = lookup_node(rule, oldnode, location_only=True)
            elif rule is not None:
                rule.append(n)
            else:
                headnode.append(n)
        remove_id_used_attributes(oldnode)
        return headnode

    def check_sanity(self):
        '''
        Check if node references match existing nodes.
        '''
        if self.node is None:  # eh?
            common_err("%s: no xml (strange)" % self.obj_id)
            return utils.get_check_rc()
        rc = 0
        uname = self.node.get("node")
        if uname and uname.lower() not in [id.lower() for id in cib_factory.node_id_list()]:
            common_warn("%s: referenced node %s does not exist" % (self.obj_id, uname))
            rc = 1
        pattern = self.node.get("rsc-pattern")
        if pattern:
            try:
                re.compile(pattern)
            except IndexError, e:
                common_warn("%s: '%s' may not be a valid regular expression (%s)" %
                            (self.obj_id, pattern, e))
                rc = 1
            except re.error, e:
                common_warn("%s: '%s' may not be a valid regular expression (%s)" %
                            (self.obj_id, pattern, e))
                rc = 1
        for enode in self.node.xpath("rule/expression"):
            if enode.get("attribute") == "#uname":
                uname = enode.get("value")
                ids = [i.lower() for i in cib_factory.node_id_list()]
                if uname and uname.lower() not in ids:
                    common_warn("%s: referenced node %s does not exist" % (self.obj_id, uname))
                    rc = 1
        return rc

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
        else:
            return
        rsc_id = gv_first_rsc(self.node.get("rsc"))
        e = [pref_node, rsc_id]
        e_id = gv_obj.new_edge(e)
        self._set_edge_attrs(gv_obj, e_id)
        gv_edge_score_label(gv_obj, e_id, score_n)


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


def _opt_set_name(n):
    return "cluster%s" % n.get("id")


def rsc_set_gv_edges(node, gv_obj):
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

    def _repr_cli_head(self, format):
        s = cli_display.keyword(self.obj_type)
        id = cli_display.id(self.obj_id)
        score = cli_display.score(get_score(self.node) or get_kind(self.node))
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
        return "%s %s %s: %s" % (s, id, score, ' '.join(col))

    def _repr_cli_child(self, c, format):
        pass  # no children here

    def _cli_list2node(self, cli_list, oldnode):
        head = copy.copy(cli_list[0])
        head[0] = backtrans[head[0]]
        headnode = mkxmlsimple(head, oldnode, '')
        id_hint = headnode.get("id")
        for e in cli_list[1:]:
            # if more than one element, it's a resource set
            n = mkxmlnode(e, oldnode, id_hint)
            headnode.append(n)
        remove_id_used_attributes(oldnode)
        return headnode

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


class CibRscTicket(CibSimpleConstraint):
    '''
    rsc_ticket constraint.
    '''

    def _repr_cli_head(self, format):
        s = cli_display.keyword(self.obj_type)
        id = cli_display.id(self.obj_id)
        ticket = cli_display.ticket(self.node.get("ticket"))
        if self.node.find("resource_set") is not None:
            col = rsc_set_constraint(self.node, self.obj_type)
        else:
            col = simple_rsc_constraint(self.node, self.obj_type)
        if not col:
            return None
        a = self.node.get("loss-policy")
        if a:
            col.append("loss-policy=%s" % a)
        return "%s %s %s: %s" % (s, id, ticket, ' '.join(col))


class CibProperty(CibObject):
    '''
    Cluster properties.
    '''

    def _repr_cli_head(self, format):
        s = cli_display.keyword(self.obj_type)
        if utils.noquotes(self.obj_id):
            s = "%s %s:" % (s, self.obj_id)
        else:
            s = '%s $id="%s"' % (s, self.obj_id)
        return s

    def _repr_cli_child(self, c, format):
        name = c.get("name")
        if "value" in c.keys():
            value = c.get("value")
        else:
            value = None
        return nvpair_format(name, value)

    def _get_oldnode(self):
        '''Used to retrieve sub id's'''
        if self.obj_type == "property":
            return get_topnode(cib_factory.get_cib(), self.parent_type)
        else:
            return self.node.getparent()

    def _cli_list2node(self, cli_list, oldnode):
        head = copy.copy(cli_list[0])
        head[0] = backtrans[head[0]]
        obj_id = find_value(head[1], "$id")
        if not obj_id:
            obj_id = cib_object_map[self.xml_obj_type][3]
        headnode = mkxmlnode(head, oldnode, obj_id)
        remove_id_used_attributes(oldnode)
        return headnode

    def matchcli(self, cli_list):
        head = cli_list[0]
        if self.obj_type != head[0]:
            return False
        # if no id specified return True
        # (match the first of a kind)
        if not find_value(head[1], "$id"):
            return True
        return self.obj_id == find_value(head[1], "$id")

    def check_sanity(self):
        '''
        Match properties with PE metadata.
        '''
        if self.node is None:  # eh?
            common_err("%s: no xml (strange)" % self.obj_id)
            return utils.get_check_rc()
        l = []
        if self.obj_type == "property":
            l = get_properties_list()
            l += ("dc-version", "cluster-infrastructure", "last-lrm-refresh")
        elif self.obj_type == "op_defaults":
            l = schema.get('attr', 'op', 'a')
        elif self.obj_type == "rsc_defaults":
            l = vars.rsc_meta_attributes
        rc = sanity_check_nvpairs(self.obj_id, self.node, l)
        return rc


def is_stonith_rsc(xmlnode):
    '''
    True if resource is stonith or derived from stonith template.
    '''
    if xmlnode.get('template'):
        xmlnode = reduce_primitive(xmlnode)
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

    def match(self, xml_obj_type, obj_id):
        return self.xml_obj_type == xml_obj_type

    def matchcli(self, cli_list):
        head = cli_list[0]
        return self.obj_type == head[0]

    def can_be_renamed(self):
        ''' Cannot rename this one. '''
        return False

    def _repr_cli_head(self, format):
        s = cli_display.keyword(self.obj_type)
        d = odict()
        for c in self.node.iterchildren("fencing-level"):
            target = c.get("target")
            if target not in d:
                d[target] = {}
            d[target][c.get("index")] = c.get("devices")
        dd = odict()
        for target in d.keys():
            sorted_keys = sorted([int(i) for i in d[target].keys()])
            dd[target] = [d[target][str(x)] for x in sorted_keys]
        d2 = {}
        for target in dd.keys():
            devs_s = ' '.join(dd[target])
            d2[devs_s] = 1
        if len(d2) == 1 and len(d) == len(cib_factory.node_id_list()):
            return "%s %s" % (s, devs_s)
        return cli_format([s] + ["%s: %s" % (x, ' '.join(dd[x]))
                                 for x in dd.keys()],
                          break_lines=(format > 0))

    def _same_levels(self, pl):
        for lvl_pl in pl:
            cli_append_attr(lvl_pl[1], "index", "")
        for n in cib_factory.node_id_list():
            for lvl_pl in pl:
                cli_replace_attr(lvl_pl[1], "target", n)
                yield copy.deepcopy(lvl_pl)

    def _different_levels(self, pl):
        for lvl_pl in pl:
            cli_append_attr(lvl_pl[1], "index", "")
            yield lvl_pl

    def _cli_list2node(self, cli_list, oldnode):
        head = copy.copy(cli_list[0])
        head[0] = backtrans[head[0]]
        node = mkxmlhead(head)
        if find_value(head[1][0][1], "target") == "@@":
            lvl_generator = self._same_levels
        else:
            lvl_generator = self._different_levels
        target_i = {}
        for lvl_pl in lvl_generator(head[1]):
            target = find_value(lvl_pl[1], "target")
            if target not in target_i:
                target_i[target] = 1
            cli_replace_attr(lvl_pl[1], "index", str(target_i[target]))
            node.append(mkxmlsimple(lvl_pl, oldnode, 'fencing'))
            target_i[target] += 1
        remove_id_used_attributes(oldnode)
        return node

    def _repr_cli_child(self, c, format):
        pass  # no children here

    def check_sanity(self):
        '''
        Targets are nodes and resource are stonith resources.
        '''
        if self.node is None:  # eh?
            common_err("%s: no xml (strange)" % self.obj_id)
            return utils.get_check_rc()
        rc = 0
        nl = self.node.findall("fencing-level")
        for target in [x.get("target") for x in nl]:
            if target.lower() not in [id.lower() for id in cib_factory.node_id_list()]:
                common_warn("%s: target %s not a node" % (self.obj_id, target))
                rc = 1
        stonith_rsc_l = [x.obj_id for x in
                         cib_factory.get_elems_on_type("type:primitive")
                         if is_stonith_rsc(x.node)]
        for devices in [x.get("devices") for x in nl]:
            for dev in devices.split(","):
                if not cib_factory.find_object(dev):
                    common_warn("%s: resource %s does not exist" % (self.obj_id, dev))
                    rc = 1
                elif dev not in stonith_rsc_l:
                    common_warn("%s: %s not a stonith resource" % (self.obj_id, dev))
                    rc = 1
        return rc


class CibAcl(CibObject):
    '''
    User and role ACL.
    '''

    def _repr_cli_head(self, format):
        s = cli_display.keyword(self.obj_type)
        id = cli_display.id(self.obj_id)
        return "%s %s" % (s, id)

    def _repr_cli_child(self, c, format):
        if c.tag in vars.acl_rule_names:
            return cli_acl_rule(c, format)
        else:
            return cli_acl_roleref(c, format)

    def _cli_list2node(self, cli_list, oldnode):
        head = copy.copy(cli_list[0])
        head[0] = backtrans[head[0]]
        headnode = mkxmlsimple(head, oldnode, '')
        if len(cli_list) == 1:
            return headnode
        id_hint = headnode.get("id")
        for e in cli_list[1:]:
            n = mkxmlnode(e, oldnode, id_hint)
            headnode.append(n)
        remove_id_used_attributes(oldnode)
        return headnode


class CibTag(CibObject):

    def _repr_cli_head(self, fmt):
        s = cli_display.keyword('tag')
        id_ = cli_display.id(self.obj_id)
        return "%s %s:" % (s, id_)

    def _repr_cli_child(self, c, fmt):
        return c.get('id')

    def _cli_list2node(self, cli_list, oldnode):
        """
        cli_list: [[tag] <id> [<rsc>, <rsc>...]]
        out: <tag id="<id>"><obj_ref id="<rsc>">...</tag>
        """
        tag = etree.Element('tag', id=cli_list[1])
        for rsc in cli_list[2]:
            etree.SubElement(tag, 'obj_ref', id=rsc)
        return tag

#
################################################################


#
# cib factory
#
cib_piped = "cibadmin -p"


def get_default_timeout():
    t = cib_factory.get_op_default("timeout")
    if t:
        return t
    t = cib_factory.get_property("default-action-timeout")
    if t:
        return t
    try:
        return get_pe_meta().param_default("default-action-timeout")
    except:
        return 0

# xml -> cli translations (and classes)
cib_object_map = {
    # xml_tag: ( cli_name, element class, parent element tag )
    "node": ("node", CibNode, "nodes"),
    "primitive": ("primitive", CibPrimitive, "resources"),
    "group": ("group", CibContainer, "resources"),
    "clone": ("clone", CibContainer, "resources"),
    "master": ("ms", CibContainer, "resources"),
    "template": ("rsc_template", CibPrimitive, "resources"),
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
    "tag": ("tag", CibTag, "tags"),
}

# generate a translation cli -> tag
backtrans = odict((item[0], key) for key, item in cib_object_map.iteritems())


def can_migrate(node):
    for c in node.iterchildren("meta_attributes"):
        pl = nvpairs2list(c)
        if find_value(pl, "allow-migrate") == "true":
            return True
    return False


cib_upgrade = "cibadmin --upgrade --force"


class CibFactory(Singleton):
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
        self.supported_cib_re = "^pacemaker-1[.][0123]$"

    def is_cib_sane(self):
        # try to initialize
        if self.cib_elem is None:
            self.initialize()
        if self.cib_elem is None:
            empty_cib_err()
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
        if not obj in parent.children:
            common_err("object %s does not reference its child %s" %
                       (parent.obj_id, obj.obj_id))
            return False
        if parent.node != obj.node.getparent():
            if obj.node.getparent() is None:
                common_err("object %s node is not a child of its parent %s" %
                           (obj.obj_id, parent.obj_id))
            else:
                common_err("object %s node is not a child of its parent %s, but %s:%s" %
                           (obj.obj_id,
                            parent.obj_id,
                            obj.node.getparent().tag,
                            obj.node.getparent().get("id")))
            return False
        return True

    def check_structure(self):
        #print "Checking structure..."
        if not self.is_cib_sane():
            return False
        rc = True
        for obj in self.cib_objects:
            #print "Checking %s... (%s)" % (obj.obj_id, obj.nocli)
            if obj.parent:
                if not self._check_parent(obj, obj.parent):
                    rc = False
            for child in obj.children:
                if not child.parent:
                    common_err("child %s does not reference its parent %s" %
                               (child.obj_id, obj.obj_id))
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
            common_warn("bad parameter for regtest: %s" % param)

    def get_schema(self):
        return self.cib_attrs["validate-with"]

    def change_schema(self, schema_st):
        'Use another schema'
        if schema_st == self.get_schema():
            common_info("already using schema %s" % schema_st)
            return True
        if not re.match(self.supported_cib_re, schema_st):
            common_err("schema %s not supported by the shell" % schema_st)
            return False
        self.cib_elem.set("validate-with", schema_st)
        if not schema.test_schema(self.cib_elem):
            self.cib_elem.set("validate-with", self.get_schema())
            common_err("schema %s does not exist" % schema_st)
            return False
        schema.init_schema(self.cib_elem)
        rc = True
        for obj in self.cib_objects:
            if schema.get('sub', obj.node.tag, 'a') is None:
                common_err("%s not supported by the RNG schema" % obj.node.tag)
                rc = False
        if not rc:
            # revert, as some elements won't validate
            self.cib_elem.set("validate-with", self.get_schema())
            schema.init_schema(self.cib_elem)
            common_err("current configuration not valid with %s, cannot change schema" % schema_st)
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
        if validator and re.match(self.supported_cib_re, validator):
            return True
        cib_ver_unsupported_err(validator, req)
        return False

    def upgrade_cib_06to10(self, force=False):
        'Upgrade the CIB from 0.6 to 1.0.'
        if not self.is_cib_sane():
            return False
        validator = self.cib_elem.get("validate-with")
        if force or not validator or re.match("0[.]6", validator):
            return ext_cmd(cib_upgrade) == 0

    def _import_cib(self, cib_elem):
        'Parse the current CIB (from cibadmin -Q).'
        self.cib_elem = cib_elem
        if self.cib_elem is None:
            return False
        if not self.is_cib_supported():
            self.reset()
            return False
        self._get_cib_attributes(self.cib_elem)
        schema.init_schema(self.cib_elem)
        return True

    #
    # create a doc from the list of objects
    # (used by CibObjectSetRaw)
    #
    def bump_epoch(self):
        try:
            self.cib_attrs["epoch"] = str(int(self.cib_attrs["epoch"])+1)
        except:
            self.cib_attrs["epoch"] = "1"

    def _get_cib_attributes(self, cib):
        for attr in cib.keys():
            self.cib_attrs[attr] = cib.get(attr)

    def _set_cib_attributes(self, cib):
        for attr in self.cib_attrs:
            cib.set(attr, self.cib_attrs[attr])

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
        try:
            cib_attr = self.cib_attrs[a]
        except KeyError:
            cib_attr = None
        return c.get(a) == cib_attr

    def is_current_cib_equal(self, silent=False):
        cib_elem = read_cib(cibdump2elem)
        if cib_elem is None:
            return False
        rc = self._attr_match(cib_elem, 'epoch') and \
            self._attr_match(cib_elem, 'admin_epoch')
        if not silent and not rc:
            common_warn("CIB changed in the meantime: won't touch it!")
        return rc

    def _state_header(self):
        'Print object status header'
        print CibObject.state_fmt % \
            ("", "origin", "updated", "parent", "children")

    def showobjects(self):
        self._state_header()
        for obj in self.cib_objects:
            obj._dump_state()
        if self.remove_queue:
            print "Remove queue:"
            for obj in self.remove_queue:
                obj._dump_state()

    def commit(self, force=False):
        'Commit the configuration to the CIB.'
        if not self.is_cib_sane():
            return False
        if cibadmin_can_patch():
            rc = self._patch_cib(force)
        else:
            rc = self._replace_cib(force)
        if rc:
            # reload the cib!
            common_debug("CIB commit successful")
            if is_live_cib():
                self.last_commit_time = time.time()
            self.reset()
            self.initialize()
        return rc

    def _update_schema(self):
        '''
        Set the validate-with, if the schema changed.
        '''
        s = '<cib validate-with="%s"/>' % self.cib_attrs["validate-with"]
        rc = pipe_string("%s -U" % cib_piped, s)
        if rc != 0:
            update_err("cib", "-U", s, rc)
            return False
        self.new_schema = False
        return True

    def _replace_cib(self, force):
        try:
            conf_el = self.cib_elem.findall("configuration")[0]
        except IndexError:
            common_error("cannot find the configuration element")
            return False
        if self.new_schema and not self._update_schema():
            return False
        cibadmin_opts = force and "-R --force" or "-R"
        rc = pipe_string("%s %s" % (cib_piped, cibadmin_opts), etree.tostring(conf_el))
        if rc != 0:
            update_err("cib", cibadmin_opts, etree.tostring(conf_el), rc)
            return False
        return True

    def _patch_cib(self, force):
        # copy the epoch from the current cib to both the target
        # cib and the original one (otherwise cibadmin won't want
        # to apply the patch)
        current_cib = read_cib(cibdump2elem)
        if current_cib is None:
            return False
        self._get_cib_attributes(current_cib)
        self._set_cib_attributes(self.cib_orig)
        current_cib = None  # don't need that anymore
        # now increase the epoch by 1
        self.bump_epoch()
        self._set_cib_attributes(self.cib_elem)
        cib_s = etree.tostring(self.cib_orig, pretty_print=True)
        tmpf = str2tmp(cib_s, suffix=".xml")
        if not tmpf:
            return False
        tmpfiles.add(tmpf)
        cibadmin_opts = force and "-P --force" or "-P"
        # produce a diff:
        # dump_new_conf | crm_diff -o self.cib_orig -n -
        common_debug("Input: %s" % (etree.tostring(self.cib_elem)))
        rc, cib_diff = filter_string("crm_diff -o %s -n -" % tmpf,
                                     etree.tostring(self.cib_elem))
        if not cib_diff:
            common_err("crm_diff apparently failed to produce the diff (rc=%d)" % rc)
            return False
        common_debug("Diff: %s" % (cib_diff))
        rc = pipe_string("%s %s" % (cib_piped, cibadmin_opts),
                         cib_diff)
        if rc != 0:
            update_err("cib", cibadmin_opts, cib_diff, rc)
            return False
        return True

    #
    # initialize cib_objects from CIB
    #
    def _save_node(self, node, pnode=None):
        '''
        Need pnode (parent node) acrobacy because cluster
        properties and rsc/op_defaults hold stuff in a
        meta_attributes child.
        '''
        if pnode is None:
            pnode = node
        obj = cib_object_map[pnode.tag][1](pnode.tag)
        obj.origin = "cib"
        obj.node = node
        obj.set_id()
        self.cib_objects.append(obj)

    def _populate(self):
        "Walk the cib and collect cib objects."
        all_nodes = get_interesting_nodes(self.cib_elem, [])
        if not all_nodes:
            return
        for node in processing_sort(all_nodes):
            if is_defaults(node):
                for c in node.xpath("./meta_attributes"):
                    self._save_node(c, node)
            else:
                self._save_node(node)
        for obj in self.cib_objects:
            obj.move_comments()
            fix_comments(obj.node)
        for obj in self.cib_objects:
            if not obj.cli_use_validate():
                obj.nocli = True
                obj.nocli_warn = False
                common_warn("object %s cannot be represented in the CLI notation" % (obj.obj_id))
        for obj in self.cib_objects:
            self._update_links(obj)

    def initialize(self, cib=None):
        if self.cib_elem is not None:
            return True
        if cib is None:
            cib = read_cib(cibdump2elem)
        elif isinstance(cib, basestring):
            cib = cibtext2elem(cib)
        if not self._import_cib(cib):
            return False
        sanitize_cib(self.cib_elem)
        if cibadmin_can_patch():
            self.cib_orig = copy.deepcopy(self.cib_elem)
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
        id_store has to be backed up too.
        '''
        self._state.append([copy.deepcopy(x)
                            for x in (self.cib_elem,
                                      self.cib_attrs,
                                      self.cib_objects,
                                      self.remove_queue,
                                      self.id_refs)])
        id_store.push_state()

    def _pop_state(self):
        try:
            common_debug("performing rollback")
            self.cib_elem, \
                self.cib_attrs, self.cib_objects, \
                self.remove_queue, self.id_refs = self._state.pop()
        except KeyError:
            return False
        # need to get addresses of all new objects created by
        # deepcopy
        for obj in self.cib_objects:
            obj.node = self.find_node(obj.xml_obj_type, obj.obj_id)
            self._update_links(obj)
        id_store.pop_state()
        return self.check_structure()

    def _drop_state(self):
        try:
            self._state.pop()
        except KeyError:
            pass
        id_store.drop_state()

    def _clean_state(self):
        self._state = []
        id_store.clean_state()

    def reset(self):
        if self.cib_elem is None:
            return
        self.cib_elem = None
        self.cib_orig = None
        self._init_vars()
        self._clean_state()
        id_store.clear()

    def find_objects(self, obj_id):
        "Find objects for id (can be a wildcard-glob)."
        matchfn = lambda x: fnmatch.fnmatch(x, obj_id)
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
        objs = self.find_objects(obj_id)
        if len(objs) > 0:
            return objs[0]
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

    def prim_id_list(self):
        "List of primitives ids (for group completion)."
        return [x.obj_id for x in self.cib_objects if x.obj_type == "primitive"]

    def children_id_list(self):
        "List of child ids (for clone/master completion)."
        return [x.obj_id for x in self.cib_objects if x.obj_type in vars.children_tags]

    def rsc_id_list(self):
        "List of all resource ids."
        return [x.obj_id for x in self.cib_objects
                if x.obj_type in vars.resource_tags]

    def top_rsc_id_list(self):
        "List of top resource ids (for constraint completion)."
        return [x.obj_id for x in self.cib_objects
                if x.obj_type in vars.resource_tags and not x.parent]

    def node_id_list(self):
        "List of node ids."
        return [x.node.get("uname") for x in self.cib_objects
                if x.obj_type == "node"]

    def f_prim_free_id_list(self):
        "List of possible primitives ids (for group completion)."
        return [x.obj_id for x in self.cib_objects
                if x.obj_type == "primitive" and not x.parent]

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
                if x.obj_type in vars.children_tags and not x.parent]

    #
    # a few helper functions
    #
    def find_object_for_node(self, node):
        "Find an object which matches a dom node."
        for obj in self.cib_objects:
            if node.tag == "fencing-topology" and \
                    obj.xml_obj_type == "fencing-topology":
                return obj
            if node.get("id") == obj.obj_id:
                return obj
        return None

    def find_object_for_cli(self, cli_list):
        "Find an object which matches the cli list."
        for obj in self.cib_objects:
            if obj.matchcli(cli_list):
                return obj
        return None

    def find_node(self, tag, id, strict=True):
        "Find a node of this type with this id."
        try:
            if tag in vars.defaults_tags:
                expr = '//%s/meta_attributes[@id="%s"]' % (tag, id)
            elif tag == 'fencing-topology':
                expr = '//fencing-topology' % tag
            else:
                expr = '//%s[@id="%s"]' % (tag, id)
            return self.cib_elem.xpath(expr)[0]
        except IndexError:
            if strict:
                common_warn("strange, %s element %s not found" % (tag, id))
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
            obj = self.find_object(obj_id)
            if not obj:
                no_object_err(obj_id)
                rc = False
                continue
            if obj.obj_type != "primitive":
                common_warn("element %s is not a primitive" % obj_id)
                rc = False
                continue
            r_node = reduce_primitive(obj.node)
            if r_node is None:
                # cannot do anything without template defined
                common_warn("template for %s not defined" % obj_id)
                rc = False
                continue
            ra = get_ra(r_node)
            if not ra.mk_ra_node():  # no RA found?
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
                        elif is_ms(obj.node.getparent()) and op in implied_ms_actions:
                            implied_ms_actions.remove(op)
                        elif op not in other_actions:
                            continue
                        adv_timeout = ra.get_adv_timeout(op, c2)
                        if adv_timeout:
                            c2.set("timeout", adv_timeout)
                            obj_modified = True
            l = implied_actions
            if can_migrate(r_node):
                l += implied_migrate_actions
            if is_ms(obj.node.getparent()):
                l += implied_ms_actions
            for op in l:
                adv_timeout = ra.get_adv_timeout(op)
                if not adv_timeout:
                    continue
                head_pl = ["op", []]
                head_pl[1].append(["name", op])
                head_pl[1].append(["timeout", adv_timeout])
                head_pl[1].append(["interval", "0"])
                cli_list = []
                cli_list.append(head_pl)
                if not obj.add_operation(cli_list):
                    rc = False
                else:
                    obj_modified = True
            if obj_modified:
                obj.updated = True
                obj.propagate_updated()
        return rc

    def is_id_refd(self, attr_list_type, id):
        '''Is this ID referenced anywhere?'''
        try:
            return self.id_refs[id] == attr_list_type
        except KeyError:
            return False

    def resolve_id_ref(self, attr_list_type, id_ref):
        '''
        User is allowed to specify id_ref either as a an object
        id or as attributes id. Here we try to figure out which
        one, i.e. if the former is the case to find the right
        id to reference.
        '''
        obj = self.find_object(id_ref)
        self.id_refs[id_ref] = attr_list_type
        if obj:
            node_l = obj.node.xpath(".//%s" % attr_list_type)
            if node_l:
                if len(node_l) > 1:
                    common_warn("%s contains more than one %s, using first" %
                                (obj.obj_id, attr_list_type))
                id = node_l[0].get("id")
                if not id:
                    common_err("%s reference not found" % id_ref)
                    return id_ref  # hope that user will fix that
                return id
        # verify if id_ref exists
        node_l = self.cib_elem.xpath(".//%s" % attr_list_type)
        for node in node_l:
            if node.get("id") == id_ref:
                return id_ref
        common_err("%s reference not found" % id_ref)
        return id_ref  # hope that user will fix that

    def _get_attr_value(self, obj_type, attr):
        if not self.is_cib_sane():
            return None
        for obj in self.cib_objects:
            if obj.obj_type == obj_type and obj.node is not None:
                pl = nvpairs2list(obj.node)
                v = find_value(pl, attr)
                if v:
                    return v
        return None

    def get_property(self, property):
        '''
        Get the value of the given cluster property.
        '''
        return self._get_attr_value("property", property)

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
        if obj_id and id_store.id_in_use(obj_id):
            return None
        for xml_obj_type, v in cib_object_map.items():
            if v[0] == obj_type:
                obj = v[1](xml_obj_type)
                obj.mknode(obj_id)
                common_debug("create CIB element: %s" % str(obj))
                return obj
        return None

    def modified_elems(self):
        return [x for x in self.cib_objects
                if x.updated or x.origin == "user"]

    def get_elems_on_type(self, spec):
        if not spec.startswith("type:"):
            return []
        t = spec[5:]
        return [x for x in self.cib_objects if x.obj_type == t]

    def mkobj_set(self, *args):
        if not args:
            return True, copy.copy(self.cib_objects)
        if args[0] == "NOOBJ":
            return True, []
        rc = True
        obj_set = set([])
        for spec in args:
            if spec == "changed":
                obj_set |= set(self.modified_elems())
            elif spec.startswith("type:"):
                obj_set |= set(self.get_elems_on_type(spec))
            else:
                objs = self.find_objects(spec)
                for obj in objs:
                    obj_set.add(obj)
                if len(objs) == 0:
                    no_object_err(spec)
                    rc = False
        return rc, obj_set

    def get_all_obj_set(self):
        return set(self.cib_objects)

    def is_cib_empty(self):
        return not self.get_elems_on_type("type:primitive")

    def has_cib_changed(self):
        return self.modified_elems() or self.remove_queue

    def _verify_constraints(self, node):
        '''
        Check if all resources referenced in a constraint exist
        '''
        rc = True
        constraint_id = node.get("id")
        for obj_id in referenced_resources(node):
            if not self.find_object(obj_id):
                constraint_norefobj_err(constraint_id, obj_id)
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
                common_err("in group %s child %s listed more than once" %
                           (obj_id, child_id))
                rc = False
            c_dict[child_id] = 1
        for other in [x for x in self.cib_objects
                      if x != obj and is_container(x.node)]:
            shared_obj = set(obj.children) & set(other.children)
            if shared_obj:
                common_err("%s contained in both %s and %s" %
                           (','.join([x.obj_id for x in shared_obj]),
                            obj_id, other.obj_id))
                rc = False
        return rc

    def _verify_child(self, child_id, parent_tag, obj_id):
        'Check if child exists and obj_id is (or may become) its parent.'
        child = self.find_object(child_id)
        if not child:
            no_object_err(child_id)
            return False
        if parent_tag == "group" and child.obj_type != "primitive":
            common_err("a group may contain only primitives; %s is %s" %
                       (child_id, child.obj_type))
            return False
        if child.parent and child.parent.obj_id != obj_id:
            common_err("%s already in use at %s" % (child_id, child.parent.obj_id))
            return False
        if not child.obj_type in vars.children_tags:
            common_err("%s may contain a primitive or a group; %s is %s" %
                       (parent_tag, child_id, child.obj_type))
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
            common_err("element %s (%s) not recognized" % (node.tag, obj_id))
            return False
        if is_container(node):
            rc &= self._verify_rsc_children(obj)
        elif is_constraint(node):
            rc &= self._verify_constraints(node)
        return rc

    def create_object(self, *args):
        cp = CliParser()
        out = cp.parse2(list(args))
        return self.create_from_cli(out) is not None

    def set_property_cli(self, cli_list):
        comments = get_comments(cli_list)
        head_pl = cli_list[0]
        obj_type = head_pl[0].lower()
        pset_id = find_value(head_pl[1], "$id")
        if pset_id:
            head_pl[1].remove(["$id", pset_id])
        else:
            pset_id = cib_object_map[backtrans[obj_type]][3]
        obj = self.find_object(pset_id)
        if not obj:
            if not is_id_valid(pset_id):
                invalid_id_err(pset_id)
                return None
            obj = self.new_object(obj_type, pset_id)
            if not obj:
                return None
            get_topnode(self.cib_elem, obj.parent_type).append(obj.node)
            obj.origin = "user"
            self.cib_objects.append(obj)
        for n, v in head_pl[1]:
            set_nvpair(obj.node, n, v)
        if comments and obj.node is not None:
            stuff_comments(obj.node, comments)
        obj.updated = True
        return obj

    def add_op(self, cli_list):
        '''Add an op to a primitive.'''
        head = cli_list[0]
        # does the referenced primitive exist
        rsc_id = find_value(head[1], "rsc")
        rsc_obj = self.find_object(rsc_id)
        if not rsc_obj:
            no_object_err(rsc_id)
            return None
        if rsc_obj.obj_type != "primitive":
            common_err("%s is not a primitive" % rsc_id)
            return None
        head[1].remove(["rsc", rsc_id])
        return rsc_obj.add_operation(cli_list)

    def create_from_cli(self, cli):
        'Create a new cib object from the cli representation.'
        cli_list = mk_cli_list(cli)
        if not cli_list:
            return None
        head = cli_list[0]
        obj_type = head[0].lower()
        obj_id = find_value(head[1], "id")
        if obj_type != "node" and obj_id and not is_id_valid(obj_id):
            invalid_id_err(obj_id)
            return None
        if len(cli_list) >= 2 and cli_list[1][0] == "raw":
            raw_elem = etree.fromstring(cli_list[1][1])
            return self.create_from_node(raw_elem)
        if obj_type in olist(vars.nvset_cli_names):
            return self.set_property_cli(cli_list)
        if obj_type == "op":
            return self.add_op(cli_list)
        if obj_type == "node":
            obj = self.find_object(obj_id)
            # make an exception and allow updating nodes
            if obj:
                self.merge_from_cli(obj, cli_list)
                return obj
        obj = self.new_object(obj_type, obj_id)
        if not obj:
            return None
        node = obj.cli2node(cli_list)
        return self._add_element(obj, node)

    def update_from_cli(self, obj, cli_list, method):
        '''
        Replace element from the cli intermediate.
        If this is an update and the element is properties, then
        the new properties should be merged with the old.
        Otherwise, users may be surprised.
        '''
        if len(cli_list) >= 2 and cli_list[1][0] == "raw":
            id_store.remove_xml(obj.node)
            raw_elem = etree.fromstring(cli_list[1][1])
            id_store.store_xml(raw_elem)
            return self.update_element(obj, raw_elem)
        if method == 'update' and obj.obj_type in vars.nvset_cli_names:
            self.merge_from_cli(obj, cli_list)
            return True
        return self.update_element(obj, obj.cli2node(cli_list))

    def update_from_node(self, obj, node):
        'Update element from a doc node.'
        id_store.replace_xml(obj.node, node)
        return self.update_element(obj, node)

    def update_element(self, obj, newnode):
        'Update element from a doc node.'
        if newnode is None:
            return False
        if not self.is_cib_sane():
            id_store.replace_xml(newnode, obj.node)
            return False
        oldnode = obj.node
        if xml_equals(oldnode, newnode):
            if newnode.getparent() is not None:
                newnode.getparent().remove(newnode)
            return True  # the new and the old versions are equal
        obj.node = newnode
        common_debug("update CIB element: %s" % str(obj))
        if oldnode.getparent() is not None:
            oldnode.getparent().replace(oldnode, newnode)
        obj.nocli = False  # try again after update
        self._adjust_children(obj)
        if not obj.cli_use_validate():
            obj.nocli_warn = True
            obj.nocli = True
        obj.updated = True
        obj.propagate_updated()
        return True

    def merge_from_cli(self, obj, cli_list):
        node = obj.cli2node(cli_list)
        if node is None:
            return
        if obj.obj_type in vars.nvset_cli_names:
            rc = merge_attributes(obj.node, node, "nvpair")
        else:
            rc = merge_nodes(obj.node, node)
        if rc:
            obj.updated = True
            obj.propagate_updated()

    def _cli_set_update(self, edit_d, mk_set, upd_set, del_set, method):
        '''
        Create/update/remove elements.
        edit_d is a dict with id keys and cli_list values.
        mk_set is a set of ids to be created.
        upd_set is a set of ids to be updated (replaced).
        del_set is a set to be removed.
        method is either replace or update.
        '''
        test_l = []
        for cli in processing_sort_cli([edit_d[x] for x in mk_set]):
            obj = self.create_from_cli(cli)
            if not obj:
                common_debug("create_from_cli '%s' failed" % (cli))
                return False
            test_l.append(obj)
        for id in upd_set:
            obj = self.find_object(id)
            if not obj:
                common_debug("%s not found!" % (id))
                return False
            if not self.update_from_cli(obj, edit_d[id], method):
                common_debug("update_from_cli failed: %s, %s, %s" % (obj, edit_d[id], method))
                return False
            test_l.append(obj)
        if not self.delete(*list(del_set)):
            common_debug("delete %s failed" % (list(del_set)))
            return False
        rc = True
        for obj in test_l:
            if not self.test_element(obj):
                common_debug("test_element failed for %s" % (obj))
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
        test_l = []
        for el in processing_sort([edit_d[x] for x in mk_set]):
            obj = self.create_from_node(el)
            if not obj:
                return False
            test_l.append(obj)
        for id in upd_set:
            obj = self.find_object(id)
            if not obj:
                return False
            if not self.update_from_node(obj, edit_d[id]):
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
        else:
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
            return
        old_children = [x for x in obj.children if x.parent == obj]
        obj.children = [self.find_object(x) for x in new_children_ids]
        # relink orphans to top
        for child in set(old_children) - set(obj.children):
            common_debug("relink child %s to top" % str(child))
            self._relink_child_to_top(child)
        self._update_children(obj)

    def _relink_child_to_top(self, obj):
        'Relink a child to the top node.'
        get_topnode(self.cib_elem, obj.parent_type).append(obj.node)
        obj.parent = None

    def _update_children(self, obj):
        '''For composite objects: update all children nodes.
        '''
        # unlink all and find them in the new node
        for child in obj.children:
            oldnode = child.node
            child.node = obj.find_child_in_node(child)
            if child.children:  # and children of children
                self._update_children(child)
            rmnode(oldnode)
            if child.parent and child.parent != obj:
                child.parent.updated = True  # the other parent updated
            child.parent = obj

    def test_element(self, obj):
        if not obj.xml_obj_type in vars.defaults_tags:
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
        if obj.obj_type not in vars.container_tags:
            return
        for c in obj.node.iterchildren():
            if is_child_rsc(c):
                child = self.find_object_for_node(c)
                if not child:
                    missing_obj_err(c)
                    continue
                child.parent = obj
                obj.children.append(child)
                if c != child.node:
                    common_debug("removing child %s node" % str(child))
                    rmnode(child.node)
                    child.node = c

    def _add_element(self, obj, node):
        obj.node = node
        obj.set_id()
        pnode = get_topnode(self.cib_elem, obj.parent_type)
        common_debug("append child %s to %s" % (obj.obj_id, pnode.tag))
        pnode.append(node)
        self._adjust_children(obj)
        self._redirect_children_constraints(obj)
        if not obj.cli_use_validate():
            self.nocli_warn = True
            obj.nocli = True
        self._update_links(obj)
        obj.origin = "user"
        self.cib_objects.append(obj)
        return obj

    def create_from_node(self, node):
        'Create a new cib object from a document node.'
        if node is None:
            return None
        try:
            obj_type = cib_object_map[node.tag][0]
        except KeyError:
            return None
        if is_defaults(node):
            node = get_rscop_defaults_meta_node(node)
            if node is None:
                return None
        obj = self.new_object(obj_type, node.get("id"))
        if not obj:
            return None
        if not id_store.store_xml(node):
            return None
        return self._add_element(obj, node)

    def _remove_obj(self, obj):
        "Remove a cib object."
        common_debug("remove object %s" % str(obj))
        for child in obj.children:
            # just relink, don't remove children
            self._relink_child_to_top(child)
        if obj.parent:  # remove obj from its parent, if any
            obj.parent.children.remove(obj)
        id_store.remove_xml(obj.node)
        rmnode(obj.node)
        self._add_to_remove_queue(obj)
        self.cib_objects.remove(obj)
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
                    err_buf.info("hanging %s deleted" % str(c_obj))
            elif deleted:
                err_buf.info("constraint %s updated" % str(c_obj))

    def related_constraints(self, obj):
        if not is_resource(obj.node):
            return []
        c_list = []
        for obj2 in self.cib_objects:
            if not is_constraint(obj2.node):
                continue
            if rsc_constraint(obj.obj_id, obj2.node):
                c_list.append(obj2)
        return c_list

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
                common_err("resource %s is running, can't delete it" % prim.obj_id)
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
                no_object_err(obj_id)
                rc = False
                continue
            if not rscstat.can_delete(obj_id):
                common_err("resource %s is running, can't delete it" % obj_id)
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
                    common_info("hanging %s deleted" % str(prim))
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
        if not self.is_cib_sane():
            return False
        if id_store.id_in_use(new_id):
            return False
        obj = self.find_object(old_id)
        if not obj:
            no_object_err(old_id)
            return False
        if not obj.can_be_renamed():
            return False
        for c_obj in self.related_constraints(obj):
            rename_rscref(c_obj, old_id, new_id)
        rename_id(obj.node, old_id, new_id)
        obj.obj_id = new_id
        id_store.rename(old_id, new_id)
        obj.updated = True
        obj.propagate_updated()

    def erase(self):
        "Remove all cib objects."
        # remove only bottom objects and no constraints
        # the rest will automatically follow
        if not self.is_cib_sane():
            return False
        erase_ok = True
        l = []
        rscstat = RscState()
        for obj in [obj for obj in self.cib_objects
                    if not obj.children and not is_constraint(obj.node)
                    and obj.obj_type != "node"]:
            if not rscstat.can_delete(obj.obj_id):
                common_warn("resource %s is running, can't delete it" % obj.obj_id)
                erase_ok = False
            else:
                l.append(obj)
        if not erase_ok:
            common_err("CIB erase aborted (nothing was deleted)")
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
            common_err("strange, but these objects remained:")
            for obj in self.cib_objects:
                if obj.obj_type != "node":
                    print >> sys.stderr, str(obj)
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

err_buf = ErrorBuffer.getInstance()
cib_factory = CibFactory.getInstance()
cli_display = CliDisplay.getInstance()
cib_status = CibStatus.getInstance()
id_store = IdMgmt.getInstance()
schema = Schema.getInstance()

# vim:ts=4:sw=4:et:
