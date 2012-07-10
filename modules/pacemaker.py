# Copyright (C) 2009 Yan Gao <ygao@novell.com>
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
import tempfile
import xml.dom.minidom

support_lxml = False
try :
	from lxml import etree
	support_lxml = True
except ImportError :
	pass

class PacemakerError(Exception):
	'''PacemakerError exceptions'''

known_schemas = {
	"": ("dtd", "crm.dtd"),
	"pacemaker-0.6": ("dtd", "crm.dtd"),
	"transitional-0.6": ("dtd", "crm-transitional.dtd"),
	"pacemaker-0.7": ("rng", "pacemaker-1.0.rng"),
	"pacemaker-1.0": ("rng", "pacemaker-1.0.rng"),
	"pacemaker-1.1": ("rng", "pacemaker-1.1.rng"),
	"pacemaker-1.2": ("rng", "pacemaker-1.2.rng"),
	}

def get_validate_name(cib_dom_node) :
	if cib_dom_node :
		return cib_dom_node.getAttribute("validate-with")
	else :
		return None

def get_validate_type(cib_dom_node) : 
	validate_name = get_validate_name(cib_dom_node)
	if validate_name == None or known_schemas.get(validate_name) == None :
		return None
	else :
		return known_schemas.get(validate_name)[0]

def get_schema_filename(validate_name) :
	if validate_name == None or known_schemas.get(validate_name) == None :
		return None
	else :
		return known_schemas.get(validate_name)[1]

def read_schema_local(validate_name, file_path) :
	try :
		f = open(file_path)
		schema = f.read()
	except IOError, msg :
		raise PacemakerError("Cannot read the schema file: " + str(msg))

	f.close()
	return schema

def delete_dir(dir_path) :
	real_path = os.path.realpath(dir_path)
	if real_path.count(os.sep) == len(real_path) :
		raise PacemakerError("Do not delete the root directory")

	for root, dirs, files in os.walk(dir_path, False) :
    		for name in files :
			try :
				os.unlink(os.path.join(root, name))
			except OSError, msg :
				continue
		for name in dirs :
			try :
				os.rmdir(os.path.join(root, name))
			except OSError, msg :
				continue

	os.rmdir(dir_path)

def CrmSchema(cib_dom_node, local_dir) :
	validate_type = get_validate_type(cib_dom_node)
	if validate_type == "dtd" :
		return DtdSchema(cib_dom_node, local_dir)
	else :
		return RngSchema(cib_dom_node, local_dir)

class Schema :
	validate_name = None

	def __init__(self, cib_dom_node, local_dir, is_local = True, get_schema_fn = None) :
		self.is_local = is_local
		if get_schema_fn != None :
			self.get_schema_fn = get_schema_fn
		else :
			self.get_schema_fn = read_schema_local

		self.local_dir = local_dir
		self.refresh(cib_dom_node)

	def refresh(self, cib_dom_node) :
		saved_validate_name = self.validate_name
		self.validate_name = get_validate_name(cib_dom_node)
		self.schema_filename = get_schema_filename(self.validate_name)
		self.validate_type = get_validate_type(cib_dom_node)
		if self.validate_name != saved_validate_name :
			return self.update_schema()

	def validate_cib(self, new_cib_dom_node) :
		detail_msg = ""
		if not support_lxml :
			return (None, detail_msg)

		if self.is_local :
			schema_doc = os.path.join(self.local_dir, self.schema_filename)
		else :
			try :
				tmp_doc = self.tmp_schema_doc()
			except EnvironmentError, msg :
				raise PacemakerError("Cannot expand the Relax-NG schema: " + str(msg))
			if tmp_doc == None :
				raise PacemakerError("Cannot expand the Relax-NG schema")
			else :
				schema_doc = tmp_doc
		
		try :
			cib_doc = etree.fromstring(new_cib_dom_node.toxml())
		except etree.Error, msg :
			raise PacemakerError("Failed to parse the CIB XML: " + str(msg))
			
		try :
			if self.validate_type == 'rng' :
				schema = etree.RelaxNG(file = schema_doc)
			else :
				schema = etree.DTD(file = schema_doc)
				
		except etree.Error, msg :
			raise PacemakerError("Failed to parse the Relax-NG schema: " + str(msg))
		#try :
		#	schema.assertValid(cib_doc)
		#except etree.DocumentInvalid, err_msg :
		#	print err_msg
		#	print schema.error_log
		try :
			etree.clear_error_log()
		except :
			try :
				etree.clearErrorLog()
			except :
				pass

		is_valid = schema.validate(cib_doc)
		if not is_valid :
			for error_entry in schema.error_log :
				detail_msg += error_entry.level_name + ": " + error_entry.message + "\n"

		if not self.is_local :
			try :
				delete_dir(os.path.dirname(tmp_doc))
			except :
				pass

		return (is_valid, detail_msg)

	def tmp_schema_doc(self) :
		tmp_dir = tempfile.mkdtemp()
		for schema_doc_name in self.schema_str_docs :
			schema_doc_filename = os.path.join(tmp_dir, schema_doc_name)
			fd = os.open(schema_doc_filename, os.O_RDWR|os.O_CREAT|os.O_TRUNC, 0644)

			schema_doc_str = self.schema_str_docs[schema_doc_name]

			os.write(fd, schema_doc_str)
			os.close(fd)

		if self.schema_filename in  self.schema_str_docs :
			return os.path.join(tmp_dir, self.schema_filename)
		else :
			return None

	# sub_set: 'a'(all), 'r'(required), 'o'(optional)
	def get_elem_attrs(self, elem_name, sub_set = 'a') :
		elem_obj = self.find_elem(elem_name)
		if elem_obj == None :
			return None
		return self.get_elem_attrs_by_obj(elem_obj, sub_set)

	# sub_set: 'a'(all), 'r'(required), 'o'(optional)
	def get_sub_elems(self, elem_name, sub_set = 'a') :
		elem_obj = self.find_elem(elem_name)
		if elem_obj == None :
			return None
		return self.get_sub_elems_by_obj(elem_obj, sub_set)

	def supported_rsc_types(self) :
		return self.get_sub_elems("resources")

class DtdSchema(Schema) :
	def update_schema(self) :
		from xml.parsers.xmlproc.xmldtd import load_dtd_string
		self.schema_str_docs = {}

		dtd =  self.get_schema_fn(self.validate_name, \
			os.path.join(self.local_dir, self.schema_filename))
		if dtd == None :
			raise PaceamkerError("Cannot get the DTD:" + self.validate_name)
		self.complete_dtd = load_dtd_string(dtd)
		self.schema_str_docs[self.schema_filename] = dtd

		return True

	def find_elem(self, elem_name) :
		return self.complete_dtd.get_elem(elem_name)

	def get_elem_attr_objs(self, obj_type) :
		dtd_attrs = []
		dtd_elem = self.find_elem(obj_type)
		for name in dtd_elem.get_attr_list() :
			attr = dtd_elem.get_attr(name)
			dtd_attrs.append(attr)
		return dtd_attrs

	def get_sub_elem_objs(self, obj_type) :
		dtd_elems = []
		dtd_elem = self.find_elem(obj_type)
		for (name, mod) in dtd_elem.get_content_model()[1] :
			elem = self.find_elem(name)
			dtd_elems.append(elem)
		return dtd_elems

	def get_obj_name(self, dtd_obj) :
		return dtd_obj.get_name()

	def get_attr_type(self, dtd_attr) :
		return dtd_attr.get_type()

	def get_attr_values(self, dtd_attr) :
		attr_type = dtd_attr.get_type()
		if type(attr_type) == list:
			return attr_type
		else :
			return []

	def get_attr_default(self, dtd_attr) :
		return dtd_attr.get_default()

	# sub_set: 'a'(all), 'r'(required), 'o'(optional)
	def get_elem_attrs_by_obj(self, dtd_elem, sub_set = 'a') :
		attrs = []
		for name in dtd_elem.get_attr_list() :
			attr = dtd_elem.get_attr(name)
			attr_decl = attr.get_decl()

			if attr_decl != "#REQUIRED" :
				is_optional = True
			else :
				is_optional = False

			if sub_set == 'r' :
				if not is_optional :
					attrs.append(name)
			elif sub_set == 'o' :
				if is_optional :
					attrs.append(name)
			else :
				attrs.append(name)
		return attrs

	# sub_set: 'a'(all), 'r'(required), 'o'(optional)
	def get_sub_elems_by_obj(self, dtd_elem, sub_set = 'a') :
		elems = []
		(sep, cont, mod) = dtd_elem.get_content_model()

		for (name, sub_mod) in cont :
			if elems.count(name) :
				continue

			if sep == '|' or mod == '*' :
				is_optional = True
			else :
				if sub_mod in ['*', '?'] :
					is_optional = True
				else :
					is_optional = False

			if sub_set == 'r' :
				if not is_optional :
					elems.append(name)
			elif sub_set == 'o' :
				if is_optional :
					elems.append(name)
			else :
				elems.append(name)
				
		return elems

class RngSchema(Schema) :
	def update_schema(self) :
		self.rng_docs = {}
		self.schema_str_docs = {}
		self.update_rng_docs(self.validate_name, self.schema_filename)

		return True

	def update_rng_docs(self, validate_name = "", file= "") :
		self.rng_docs[file] = self.find_start_rng_node(validate_name, file)
		if self.rng_docs[file] == None :
			return
		for extern_ref in self.rng_docs[file][0].getElementsByTagName("externalRef") :
			href_value = extern_ref.getAttribute("href")
			if self.rng_docs.get(href_value) == None :
				self.update_rng_docs(validate_name, href_value)	

	def find_start_rng_node(self, validate_name = "", file = "") :
		schema_info = validate_name + " " + file
		crm_schema = self.get_schema_fn(validate_name, \
			os.path.join(self.local_dir, file))

		if not crm_schema :
			raise PacemakerError("Cannot get the Relax-NG schema: " + schema_info)

		self.schema_str_docs[file] = crm_schema

		try :
			rng_doc = xml.dom.minidom.parseString(crm_schema).documentElement
		except xml.parsers.expat.ExpatError, msg :
			raise PacemakerError("Failed to parse the Relax-NG schema: " + str(msg) + schema_info)

		start_nodes = rng_doc.getElementsByTagName("start")
		if len(start_nodes) > 0 :
			start_node = start_nodes[0] 
			return (rng_doc, start_node)
		else :
			raise PacemakerError("Cannot find the start in the Relax-NG schema: " + schema_info)

	def find_elem(self, elem_name) :
		elem_node = None
		for (rng_doc, start_node) in self.rng_docs.values() :
			for elem_node in rng_doc.getElementsByTagName("element") :
				if elem_node.getAttribute("name") == elem_name :
					return (rng_doc, elem_node)
		return None

	def get_sub_rng_nodes(self, rng_doc, rng_node) :
		sub_rng_nodes = []
		for child_node in rng_node.childNodes :
			if child_node.nodeType != xml.dom.Node.ELEMENT_NODE :
				continue
			if child_node.tagName == "ref" :
				for def_node in rng_doc.getElementsByTagName("define") :
					if def_node.getAttribute("name") == child_node.getAttribute("name") :
						break
				sub_rng_nodes.extend(self.get_sub_rng_nodes(rng_doc, def_node))
			elif child_node.tagName == "externalRef" :
				nodes = self.get_sub_rng_nodes(*self.rng_docs[child_node.getAttribute("href")])
				sub_rng_nodes.extend(nodes)
			elif child_node.tagName in ["element", "attribute", "value", "data", "text"] :
				sub_rng_nodes.append([(rng_doc, child_node)])
			elif child_node.tagName in ["interleave", "optional", "zeroOrMore", "choice", "group", "oneOrMore"] :
				nodes = self.get_sub_rng_nodes(rng_doc, child_node)
				for node in nodes :
					node.append(child_node)
				sub_rng_nodes.extend(nodes)
		return sub_rng_nodes

	def sorted_sub_rng_nodes_by_name(self, obj_type) :
		rng_node = self.find_elem(obj_type)	
		if rng_node == None or rng_node[1] == None :
			return None
		return self.sorted_sub_rng_nodes_by_node(*rng_node)

	def sorted_sub_rng_nodes_by_node(self, rng_doc, rng_node) :
		sub_rng_nodes = self.get_sub_rng_nodes(rng_doc, rng_node)
		sorted_nodes = {}
		for sub_rng_node in sub_rng_nodes :
			name = sub_rng_node[0][1].tagName
			if sorted_nodes.get(name) == None :
				sorted_nodes[name] = []
			sorted_nodes[name].append(sub_rng_node)
		return sorted_nodes

	def get_elem_attr_objs(self, obj_type) :
		return self.sorted_sub_rng_nodes_by_name(obj_type).get("attribute", [])

	def get_sub_elem_objs(self, obj_type) :
		return self.sorted_sub_rng_nodes_by_name(obj_type).get("element", [])

	def find_decl(self, rng_node, name, first = True) :
		decl_node_index = 0
		for decl_node in rng_node[1:] :
			if decl_node.tagName == name :
				decl_node_index = rng_node.index(decl_node) - len(rng_node)
				if first :
					break
		return decl_node_index

	def get_decl_rng_nodes(self, rng_node) :
		decl_rng_nodes = {}
		choice_index = manager.find_decl(rng_node, "choice", False)
		if choice_index != 0 :
			decl_rng_nodes["choice"] = rng_node[choice_index]

		first_choice_index = manager.find_decl(rng_node, "choice")
		if first_choice_index != choice_index :
			decl_rng_nodes["first_choice"] = rng_node[first_choice_index]

		group_index = manager.find_decl(rng_node, "group", False)
		if group_index != 0 :
			decl_rng_nodes["group"] = rng_node[group_index]

		first_group_index = manager.find_decl(rng_node, "group")
		if first_group_index != group_index :
			decl_rng_nodes["first_group"] = rng_node[first_group_index]

		return decl_rng_nodes

	def get_sorted_decl_nodes(self, decl_nodes_list, decl_type) :
		sorted_nodes = []
		for rng_nodes in decl_nodes_list :
			rng_node = rng_nodes.get(decl_type)
			if rng_node != None and rng_node not in sorted_nodes :
				sorted_nodes.append(rng_node)
		return sorted_nodes

	def get_obj_name(self, rng_node) :
		return rng_node[0][1].getAttribute("name")

	def get_attr_type(self, attr_rng_node) :
		sub_rng_nodes = self.sorted_sub_rng_nodes_by_node(*attr_rng_node[0])
		for sub_rng_node in sub_rng_nodes.get("data", []) :
			return sub_rng_nodes["data"][0][0][1].getAttribute("type")

		return None

	def get_attr_values(self, attr_rng_node) :
		attr_values = []
		sub_rng_nodes = self.sorted_sub_rng_nodes_by_node(*attr_rng_node[0])
		for sub_rng_node in sub_rng_nodes.get("value", []) :
			attr_values.append(sub_rng_node[0][1].childNodes[0].data)

		return attr_values

	def get_attr_default(self, attr_rng_node) :
		return attr_rng_node[0][1].getAttribute("ann:defaultValue")

	# sub_set: 'a'(all), 'r'(required), 'o'(optional)
	def get_elem_attrs_by_obj(self, rng_obj, sub_set = 'a') :
		(rng_doc, rng_node) = rng_obj
		if rng_node == None :
			return None

		attrs = []
		sub_rng_nodes = self.get_sub_rng_nodes(rng_doc, rng_node)
		for sub_rng_node in sub_rng_nodes :
			if sub_rng_node[0][1].tagName == "attribute" :
				name = sub_rng_node[0][1].getAttribute("name")
				if attrs.count(name) :
					continue

				if self.find_decl(sub_rng_node, "optional") != 0 \
                                        	or self.find_decl(sub_rng_node, "zeroOrMore") != 0 :
					is_optional = True
				else :
					is_optional = False

				# the complicated case: 'choice'
	                        #if self.find_decl(sub_rng_node, "choice") != 0 :

				if sub_set == 'r' :
					if not is_optional :
						attrs.append(name)
				elif sub_set == 'o' :
					if is_optional :
						attrs.append(name)
				else :
					attrs.append(name)
		return attrs

	# sub_set: 'a'(all), 'r'(required), 'o'(optional)
	def get_sub_elems_by_obj(self, rng_obj, sub_set = 'a') :
		(rng_doc, rng_node) = rng_obj
		if rng_node == None :
			return None

		elems = []
		sub_rng_nodes = self.get_sub_rng_nodes(rng_doc, rng_node)
		for sub_rng_node in sub_rng_nodes :
			if sub_rng_node[0][1].tagName == "element" :
				name = sub_rng_node[0][1].getAttribute("name")
				if elems.count(name) :
					continue

				if self.find_decl(sub_rng_node, "optional") != 0 \
                                        	or self.find_decl(sub_rng_node, "zeroOrMore") != 0 :
					is_optional = True
				else :
					is_optional = False

				# the complicated case: 'choice'
	                        #if self.find_decl(sub_rng_node, "choice") != 0 :

				if sub_set == 'r' :
					if not is_optional :
						elems.append(name)
				elif sub_set == 'o' :
					if is_optional :
						elems.append(name)
				else :
					elems.append(name)

		return elems

