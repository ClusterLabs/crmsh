# Copyright (C) 2014 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

from lxml import etree
from . import constants


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
