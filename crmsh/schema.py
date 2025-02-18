# Copyright (C) 2012 Dejan Muhamedagic <dmuhamedagic@suse.de>
# See COPYING for license information.

import re
from . import config
from .pacemaker import CrmSchema, PacemakerError
from . import log


logger = log.setup_logger(__name__)
PCMK_MIN_SCHEMA_VERSION = 1.0


def is_supported(name):
    """
    Check if the given name is a supported schema name
    A short form is also accepted where the prefix
    pacemaker- is implied.

    Revision: The pacemaker schema version now
    changes too often for a strict check to make sense.
    Lets just check look for schemas we know we don't
    support.
    """
    name = re.match(r'pacemaker-(\d+\.\d+)$', name)
    if name:
        return float(name.group(1)) >= PCMK_MIN_SCHEMA_VERSION
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
    try:
        _crm_schema = _load_schema(cib)
    except PacemakerError as msg:
        logger.error(msg)
    reset()


def test_schema(cib):
    try:
        crm_schema = _load_schema(cib)
    except PacemakerError as msg:
        logger.error(msg)
        return None
    return crm_schema.validate_name


def validate_name():
    if _crm_schema is None:
        return 'pacemaker-2.0'
    return _crm_schema.validate_name


def get(t, name, subset=None):
    if _crm_schema is None:
        return []
    if t not in _store:
        _store[t] = {}
    if name not in _store[t]:
        _store[t][name] = _cache_funcs[t](_crm_schema, name)
    if subset:
        return _store[t][name][subset]
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


def rng_xpath(xpath, namespaces=None):
    if _crm_schema is None:
        return []
    return _crm_schema.rng_xpath(xpath, namespaces=namespaces)
# vim:ts=4:sw=4:et:
