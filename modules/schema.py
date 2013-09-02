# Copyright (C) 2012 Dejan Muhamedagic <dmuhamedagic@suse.de>
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

from singletonmixin import Singleton
import vars
from pacemaker import CrmSchema


def get_attrs(schema, name):
    return {
        'a': schema.get_elem_attrs(name, 'a'),
        'r': schema.get_elem_attrs(name, 'r'),
        'o': schema.get_elem_attrs(name, 'o'),
    }


def get_subs(schema, name):
    return {
        'a': schema.get_sub_elems(name, 'a'),
        'r': schema.get_sub_elems(name, 'r'),
        'o': schema.get_sub_elems(name, 'o'),
    }


def get_attr_details_d(schema, name):
    # some attributes' names don't repeat, can do a hash
    # (op)
    d = {}
    for attr_obj in schema.get_elem_attr_objs(name):
        attr_name = schema.get_obj_name(attr_obj)
        d[attr_name] = {
            't': schema.get_attr_type(attr_obj),     # type
            'v': schema.get_attr_values(attr_obj),   # values
            'd': schema.get_attr_default(attr_obj),  # default
        }
    return d


def get_attr_details_l(schema, name):
    # some attributes' names repeat, need a list
    # (date_expression)
    l = []
    for attr_obj in schema.get_elem_attr_objs(name):
        l.append({
            'n': schema.get_obj_name(attr_obj),      # name
            't': schema.get_attr_type(attr_obj),     # type
            'v': schema.get_attr_values(attr_obj),   # values
            'd': schema.get_attr_default(attr_obj),  # default
        })
    return l


def rng_attr_values_l(el_name, attr_name):
    l = g_schema.get('attr_det_l', el_name)
    l2 = []
    for el in l:
        if el['n'] == attr_name:
            l2 += el['v']
    return l2


def rng_attr_values(el_name, attr_name):
    try:
        return g_schema.get('attr_det', el_name)[attr_name]['v']
    except:
        return []


class Schema(Singleton):
    "Cache pacemaker schema stuff"
    cache_funcs = {
        'attr': get_attrs,
        'sub': get_subs,
        'attr_det': get_attr_details_d,
        'attr_det_l': get_attr_details_l,
    }

    def __init__(self):
        self.crm_schema = None

    def reset(self):
        self.store = {}

    def init_schema(self, cib):
        self.crm_schema = CrmSchema(cib, vars.crm_schema_dir)
        self.reset()

    def test_schema(self, cib):
        crm_schema = CrmSchema(cib, vars.crm_schema_dir)
        return crm_schema.validate_name

    def get(self, t, name, set=None):
        if not self.crm_schema:
            return []
        if t not in self.store:
            self.store[t] = {}
        if name not in self.store[t]:
            self.store[t][name] = self.cache_funcs[t](self.crm_schema, name)
        if set:
            return self.store[t][name][set]
        else:
            return self.store[t][name]

g_schema = Schema.getInstance()

# vim:ts=4:sw=4:et:
