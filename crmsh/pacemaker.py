# Copyright (C) 2009 Yan Gao <ygao@novell.com>
# See COPYING for license information.

import os
import tempfile
import copy
from lxml import etree


class PacemakerError(Exception):
    '''PacemakerError exceptions'''


def get_validate_name(cib_elem):
    if cib_elem is not None:
        return cib_elem.get("validate-with")
    else:
        return None


def get_validate_type(cib_elem):
    return "rng"


def get_schema_filename(validate_name):
    if not validate_name.endswith('.rng'):
        return "%s.rng" % (validate_name)
    return validate_name


def read_schema_local(validate_name, file_path):
    try:
        with open(file_path) as f:
            return f.read()
    except IOError as msg:
        raise PacemakerError("Cannot read schema file '%s': %s" % (file_path, msg))


def delete_dir(dir_path):
    real_path = os.path.realpath(dir_path)
    if real_path.count(os.sep) == len(real_path):
        raise PacemakerError("Do not delete the root directory")

    for root, dirs, files in os.walk(dir_path, False):
        for name in files:
            try:
                os.unlink(os.path.join(root, name))
            except OSError:
                continue
        for name in dirs:
            try:
                os.rmdir(os.path.join(root, name))
            except OSError:
                continue

    os.rmdir(dir_path)


def subset_select(sub_set, optional):
    "Helper used to select attributes/elements based on subset and optional flag"
    if sub_set == 'r':  # required
        return not optional
    if sub_set == 'o':  # optional
        return optional
    return True


def CrmSchema(cib_elem, local_dir):
    return RngSchema(cib_elem, local_dir)


class Schema(object):
    validate_name = None

    def __init__(self, cib_elem, local_dir, is_local=True, get_schema_fn=None):
        self.is_local = is_local
        if get_schema_fn is not None:
            self.get_schema_fn = get_schema_fn
        else:
            self.get_schema_fn = read_schema_local

        self.local_dir = local_dir
        self.refresh(cib_elem)
        self.schema_str_docs = {}
        self.schema_filename = None

    def update_schema(self):
        'defined in subclasses'
        raise NotImplementedError

    def find_elem(self, elem_name):
        'defined in subclasses'
        raise NotImplementedError

    def refresh(self, cib_elem):
        saved_validate_name = self.validate_name
        self.validate_name = get_validate_name(cib_elem)
        self.schema_filename = get_schema_filename(self.validate_name)
        if self.validate_name != saved_validate_name:
            return self.update_schema()

    def validate_cib(self, new_cib_elem):
        detail_msg = ""

        if self.is_local:
            schema_f = os.path.join(self.local_dir, self.schema_filename)
        else:
            try:
                tmp_f = self.tmp_schema_f()
            except EnvironmentError as msg:
                raise PacemakerError("Cannot expand the Relax-NG schema: " + str(msg))
            if tmp_f is None:
                raise PacemakerError("Cannot expand the Relax-NG schema")
            else:
                schema_f = tmp_f

        try:
            cib_elem = etree.fromstring(etree.tostring(new_cib_elem))
        except etree.Error as msg:
            raise PacemakerError("Failed to parse the CIB XML: " + str(msg))

        try:
            schema = etree.RelaxNG(file=schema_f)

        except etree.Error as msg:
            raise PacemakerError("Failed to parse the Relax-NG schema: " + str(msg))
        try:
            etree.clear_error_log()
        except:
            pass

        is_valid = schema.validate(cib_elem)
        if not is_valid:
            for error_entry in schema.error_log:
                detail_msg += error_entry.level_name + ": " + error_entry.message + "\n"

        if not self.is_local:
            try:
                delete_dir(os.path.dirname(tmp_f))
            except:
                pass

        return (is_valid, detail_msg)

    def tmp_schema_f(self):
        tmp_dir = tempfile.mkdtemp()
        for schema_doc_name in self.schema_str_docs:
            schema_doc_filename = os.path.join(tmp_dir, schema_doc_name)
            fd = os.open(schema_doc_filename, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o644)

            schema_doc_str = self.schema_str_docs[schema_doc_name]

            os.write(fd, schema_doc_str)
            os.close(fd)

        if self.schema_filename in self.schema_str_docs:
            return os.path.join(tmp_dir, self.schema_filename)
        else:
            return None

    def get_sub_elems_by_obj(self, obj, sub_set='a'):
        '''defined in subclasses'''
        raise NotImplementedError

    def get_elem_attrs_by_obj(self, obj, sub_set='a'):
        '''defined in subclasses'''
        raise NotImplementedError

    # sub_set: 'a'(all), 'r'(required), 'o'(optional)
    def get_elem_attrs(self, elem_name, sub_set='a'):
        elem_obj = self.find_elem(elem_name)
        if elem_obj is None:
            return None
        return self.get_elem_attrs_by_obj(elem_obj, sub_set)

    # sub_set: 'a'(all), 'r'(required), 'o'(optional)
    def get_sub_elems(self, elem_name, sub_set='a'):
        elem_obj = self.find_elem(elem_name)
        if elem_obj is None:
            return None
        return self.get_sub_elems_by_obj(elem_obj, sub_set)

    def supported_rsc_types(self):
        return self.get_sub_elems("resources")


def get_local_tag(el):
    return el.tag.replace("{%s}" % el.nsmap[None], "")


class RngSchema(Schema):
    expr = '//*[local-name() = $name]'

    def __init__(self, cib_elem, local_dir, is_local=True, get_schema_fn=None):
        self.rng_docs = {}
        Schema.__init__(self, cib_elem, local_dir, is_local=is_local, get_schema_fn=get_schema_fn)

    def update_schema(self):
        self.rng_docs = {}
        self.schema_str_docs = {}
        self.update_rng_docs(self.validate_name, self.schema_filename)
        return True

    def update_rng_docs(self, validate_name, filename):
        self.rng_docs[filename] = self.find_start_rng_node(validate_name, filename)
        if self.rng_docs[filename] is None:
            return
        for extern_ref in self.rng_docs[filename][0].xpath(self.expr, name="externalRef"):
            href_value = extern_ref.get("href")
            if self.rng_docs.get(href_value) is None:
                self.update_rng_docs(validate_name, href_value)

    def find_start_rng_node(self, validate_name, filename):
        schema_info = validate_name + " " + filename
        crm_schema = self.get_schema_fn(validate_name,
                                        os.path.join(self.local_dir, filename))
        if not crm_schema:
            raise PacemakerError("Cannot get the Relax-NG schema: " + schema_info)

        self.schema_str_docs[filename] = crm_schema

        try:
            grammar = etree.fromstring(crm_schema.encode('utf-8'))
        except Exception as msg:
            raise PacemakerError("Failed to parse the Relax-NG schema: " + str(msg) + schema_info)

        for n in grammar.getchildren():
            if isinstance(n.tag, str) and "start" in n.tag:
                return (grammar, n)
        else:
            raise PacemakerError("Cannot find the start in the Relax-NG schema: " + schema_info)

    def find_in_grammar(self, grammar, node, name):
        for elem_node in grammar.xpath(self.expr, name=node):
            if elem_node.get("name") == name:
                return elem_node
        return None

    def find_elem(self, elem_name):
        elem_node = None
        for (grammar, start_node) in list(self.rng_docs.values()):
            elem_node = self.find_in_grammar(grammar, 'element', elem_name)
            if elem_node is not None:
                return (grammar, elem_node)
        return None

    def rng_xpath(self, xpath, namespaces=None):
        return [grammar.xpath(xpath, namespaces=namespaces)
                for grammar, _ in list(self.rng_docs.values())]

    def get_sub_rng_nodes(self, grammar, rng_node):
        sub_rng_nodes = []
        for child_node in rng_node.iterchildren():
            if not isinstance(child_node.tag, str):
                continue
            local_tag = get_local_tag(child_node)
            if local_tag == "ref":
                def_node = self.find_in_grammar(grammar, 'define', child_node.get('name'))
                if def_node is not None:
                    sub_rng_nodes.extend(self.get_sub_rng_nodes(grammar, def_node))
            elif local_tag == "externalRef":
                nodes = self.get_sub_rng_nodes(*self.rng_docs[child_node.get("href")])
                sub_rng_nodes.extend(nodes)
            elif local_tag in ["element", "attribute", "value", "data", "text"]:
                sub_rng_nodes.append([(grammar, child_node)])
            elif local_tag in ["interleave", "optional", "zeroOrMore",
                               "choice", "group", "oneOrMore"]:
                nodes = self.get_sub_rng_nodes(grammar, child_node)
                for node in nodes:
                    node.append(copy.deepcopy(child_node))
                sub_rng_nodes.extend(nodes)
        return sub_rng_nodes

    def sorted_sub_rng_nodes_by_name(self, obj_type):
        rng_node = self.find_elem(obj_type)
        if rng_node is None or rng_node[1] is None:
            return None
        return self.sorted_sub_rng_nodes_by_node(*rng_node)

    def sorted_sub_rng_nodes_by_node(self, grammar, rng_node):
        sub_rng_nodes = self.get_sub_rng_nodes(grammar, rng_node)
        sorted_nodes = {}
        for sub_rng_node in sub_rng_nodes:
            name = get_local_tag(sub_rng_node[0][1])
            if sorted_nodes.get(name) is None:
                sorted_nodes[name] = []
            sorted_nodes[name].append(sub_rng_node)
        return sorted_nodes

    def get_elem_attr_objs(self, obj_type):
        return self.sorted_sub_rng_nodes_by_name(obj_type).get("attribute", [])

    def get_sub_elem_objs(self, obj_type):
        return self.sorted_sub_rng_nodes_by_name(obj_type).get("element", [])

    def find_decl(self, rng_node, name, first=True):
        decl_node_index = 0
        for decl_node in rng_node[1:]:
            if get_local_tag(decl_node) == name:
                decl_node_index = rng_node.index(decl_node) - len(rng_node)
                if first:
                    break
        return decl_node_index

    def get_sorted_decl_nodes(self, decl_nodes_list, decl_type):
        sorted_nodes = []
        for rng_nodes in decl_nodes_list:
            rng_node = rng_nodes.get(decl_type)
            if rng_node is not None and rng_node not in sorted_nodes:
                sorted_nodes.append(rng_node)
        return sorted_nodes

    def get_obj_name(self, rng_node):
        return rng_node[0][1].get("name")

    def get_attr_type(self, attr_rng_node):
        sub_rng_nodes = self.sorted_sub_rng_nodes_by_node(*attr_rng_node[0])
        for sub_rng_node in sub_rng_nodes.get("data", []):
            return sub_rng_nodes["data"][0][0][1].get("type")

        return None

    def get_attr_values(self, attr_rng_node):
        attr_values = []
        sub_rng_nodes = self.sorted_sub_rng_nodes_by_node(*attr_rng_node[0])
        for sub_rng_node in sub_rng_nodes.get("value", []):
            attr_values.append(sub_rng_node[0][1].text)

        return attr_values

    def get_attr_default(self, attr_rng_node):
        return attr_rng_node[0][1].get("ann:defaultValue")

    def _get_by_obj(self, rng_obj, typ, sub_set):
        """
        Used to select attributes or elements based on
        sub_set selector and optionality.
        typ: 'attribute' or 'element'
        sub_set: 'a'(all), 'r'(required), 'o'(optional)
        """
        grammar, rng_node = rng_obj
        if rng_node is None:
            return None

        selected = []
        sub_rng_nodes = self.get_sub_rng_nodes(grammar, rng_node)
        for node in sub_rng_nodes:
            head = node[0][1]
            if get_local_tag(head) != typ:
                continue
            name = head.get("name")
            if selected.count(name):
                continue
            # the complicated case: 'choice'
            optional = any(self.find_decl(node, opt) != 0
                           for opt in ("optional", "zeroOrMore"))
            if subset_select(sub_set, optional):
                selected.append(name)
        return selected

    def get_elem_attrs_by_obj(self, rng_obj, sub_set='a'):
        "sub_set: 'a'(all), 'r'(required), 'o'(optional)"
        return self._get_by_obj(rng_obj, 'attribute', sub_set=sub_set)

    def get_sub_elems_by_obj(self, rng_obj, sub_set='a'):
        "sub_set: 'a'(all), 'r'(required), 'o'(optional)"
        return self._get_by_obj(rng_obj, 'element', sub_set=sub_set)
