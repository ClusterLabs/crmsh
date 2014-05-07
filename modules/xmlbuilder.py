# Copyright (C) 2014 Kristoffer Gronlund <kgronlund@suse.com>
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

from lxml import etree
import constants


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


def set_date_expression(expr, tag, values):
    """
    Fill in date_expression tag for date_spec/in_range operations
    expr: <date_expression/>
    values: [(name, value)...]
    """
    if set(k for k, _ in values) == set(constants.in_range_attrs):
        for k, v in values:
            expr.set(k, v)
        return expr
    subtag = child(expr, tag)
    for k, v in values:
        if k in constants.in_range_attrs:
            expr.set(k, v)
        else:
            subtag.set(k, v)
    return expr


def attributes(typename, rules, values, xmlid=None):
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
    for rule in rules:
        e.append(rule)
    for name, value in values:
        e.append(nvpair(name, value))
    return e
