# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# See COPYING for license information.
#
# Make sure that ids are unique.

import re
import copy
from . import constants
from . import xmlutil
from . import log


logger = log.setup_logger(__name__)
logger_utils = log.LoggerUtils(logger)
_id_store = {}
_state = []
ok = True  # error var


def push_state():
    _state.append(copy.deepcopy(_id_store))


def pop_state():
    try:
        global _id_store
        _id_store = _state.pop()
        return True
    except IndexError:
        return False


def drop_state():
    try:
        _state.pop()
    except KeyError:
        pass


def clean_state():
    global _state
    _state = []


def new(node, pfx):
    '''
    Create a unique id for the xml node.
    '''
    if re.search(r'^\d+$', pfx) and node.tag != "node":
        pfx = "num-{}".format(pfx)
    name = node.get("name")
    if node.tag == "nvpair":
        node_id = "%s-%s" % (pfx, name)
    elif node.tag == "op":
        interval = node.get("interval")
        if interval:
            node_id = "%s-%s-%s" % (pfx, name, interval)
        else:
            node_id = "%s-%s" % (pfx, name)
    else:
        subpfx = constants.subpfx_list.get(node.tag, '')
        if subpfx:
            node_id = "%s-%s" % (pfx, subpfx)
        else:
            node_id = pfx
    if is_used(node_id):
        node_id = _gen_free_id(node_id)
    # The ID type in XML allows only `^[_a-zA-Z][\w\-.]*$`
    # `crm_attribute` command replaces `#` with `.` in this case
    node_id = node_id.replace('#', '.')
    save(node_id)
    return node_id


def _gen_free_id(node_id):
    "generate a unique id"
    # shouldn't really get here
    for cnt in range(99):
        try_id = "%s-%d" % (node_id, cnt)
        if not is_used(try_id):
            node_id = try_id
            break
    return node_id


def check_node(node, lvl):
    global ok
    node_id = node.get("id")
    if not node_id:
        return
    if id_in_use(node_id):
        logger.error("id_store: id %s is in use", node_id)
        ok = False
        return


def _store_node(node, lvl):
    save(node.get("id"))


def _drop_node(node, lvl):
    remove(node.get("id"))


def check_xml(node):
    global ok
    ok = True
    xmlutil.xmltraverse_thin(node, check_node)
    return ok


def store_xml(node, thin=True):
    if not check_xml(node):
        return False
    if thin:
        xmlutil.xmltraverse_thin(node, _store_node)
    else:
        xmlutil.xmltraverse(node, _store_node)
    return True


def remove_xml(node):
    xmlutil.xmltraverse_thin(node, _drop_node)


def replace_xml(oldnode, newnode):
    remove_xml(oldnode)
    if not store_xml(newnode):
        store_xml(oldnode)
        return False
    return True


def is_used(node_id):
    return node_id in _id_store


def id_in_use(obj_id):
    if is_used(obj_id):
        logger_utils.id_used_err(obj_id)
        return True
    return False


def save(node_id):
    if not node_id:
        return
    _id_store[node_id] = 1


def rename(old_id, new_id):
    if not old_id or not new_id:
        return
    if not is_used(old_id):
        return
    if is_used(new_id):
        return
    remove(old_id)
    save(new_id)


def remove(node_id):
    if not node_id:
        return
    try:
        del _id_store[node_id]
    except KeyError:
        pass


def clear():
    global _id_store
    global _state
    _id_store = {}
    _state = []


def set_id(node, oldnode, id_hint, id_required=True):
    '''
    Set the id attribute for the node.
    - if the node already contains "id", keep it
    - if the old node contains "id", copy that
    - if the node contains "uname", copy that
    - else if required, create a new one using id_hint
    - save the new id in idmgmt.
    '''
    old_id = oldnode.get("id") if oldnode is not None else None
    new_id = node.get("id") or old_id or node.get("uname")
    if new_id:
        save(new_id)
    elif id_required:
        new_id = new(node, id_hint)
    if new_id:
        node.set("id", new_id)
        if oldnode is not None and old_id == new_id:
            xmlutil.set_id_used_attr(oldnode)


# vim:ts=4:sw=4:et:
