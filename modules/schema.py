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

import config
import re
from pacemaker import CrmSchema


def is_supported(name):
    """
    Check if the given name is a supported schema name
    A short form is also accepted where the prefix
    pacemaker- is implied.
    """
    shortform = re.compile(r'^(\d+\.\d+)|next$')
    slist = config.core.supported_schemas
    for s in slist:
        if s == name:
            return True
        elif shortform.match(s) and 'pacemaker-' + s == name:
            return True
        elif shortform.match(name) and 'pacemaker-' + name == s:
            return True
    return False


def get_attrs(schema, name):
    return {
        'a': schema.get_elem_attrs(name, 'a'),  # all
        'r': schema.get_elem_attrs(name, 'r'),  # required
        'o': schema.get_elem_attrs(name, 'o'),  # optional
    }


def get_subs(schema, name):
    return {
        'a': schema.get_sub_elems(name, 'a'),  # all
        'r': schema.get_sub_elems(name, 'r'),  # required
        'o': schema.get_sub_elems(name, 'o'),  # optional
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


_cache_funcs = {
    'attr': get_attrs,
    'sub': get_subs,
    'attr_det': get_attr_details_d,
    'attr_det_l': get_attr_details_l,
}


_crm_schema = None
_store = {}


def reset():
    global _store
    _store = {}


def _load_schema(cib):
    return CrmSchema(cib, config.path.crm_dtd_dir)


def init_schema(cib):
    global _crm_schema
    _crm_schema = _load_schema(cib)
    reset()


def test_schema(cib):
    crm_schema = _load_schema(cib)
    return crm_schema.validate_name


def validate_name():
    if _crm_schema is None:
        return 'pacemaker-2.0'
    return _crm_schema.validate_name


def get(t, name, set=None):
    if _crm_schema is None:
        return []
    if t not in _store:
        _store[t] = {}
    if name not in _store[t]:
        _store[t][name] = _cache_funcs[t](_crm_schema, name)
    if set:
        return _store[t][name][set]
    else:
        return _store[t][name]


def rng_attr_values(el_name, attr_name):
    ""
    try:
        return get('attr_det', el_name)[attr_name]['v']
    except:
        return []


def rng_attr_values_l(el_name, attr_name):
    ""
    l = get('attr_det_l', el_name)
    l2 = []
    for el in l:
        if el['n'] == attr_name:
            l2 += el['v']
    return l2


# vim:ts=4:sw=4:et:
