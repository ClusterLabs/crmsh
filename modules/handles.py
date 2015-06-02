# Copyright (C) 2015 Kristoffer Gronlund <kgronlund@suse.com>
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

import re


class value(object):
    """
    An object that is indexable in mustasches,
    but also evaluates to a value itself.
    """
    def __init__(self, obj, value):
        self.value = value
        self.obj = obj
        self.get = obj.get

    def __call__(self):
        return self.value

    def __repr__(self):
        return repr((self.value, self.obj))

    def __str__(self):
        return str((self.value, self.obj))


def _join(d1, d2):
    d = d1.copy()
    d.update(d2)
    return d


def _resolve(path, values, strict):
    p = values
    while path and p is not None:
        p, path = p.get(path[0]), path[1:]
    if strict and path:
        raise ValueError("Not set: %s" % (':'.join(path)))
    return p() if callable(p) else p


def parse(template, values, strict=False):
    """
    Takes as input a template string and a dict
    of values, and replaces the following:
    {{object:key}} = look up key in object and insert value
    {{object}} = insert value if not None or False.
    {{#object}} ... {{/object}} = if object is a dict or value, process text. if object
    is a list, process text for each item in the list
    (can't nest these for items with the same name)
    {{^object}} ... {{/object}} = if object is falsy, process text.
    If a path evaluates to a callable, the callable will be invoked to get the value.
    """
    head_re = re.compile(r'\{\{(\#|\^)?([A-Za-z0-9\#\$:_-]+)\}\}')
    ret = ""
    while template:
        head = head_re.search(template)
        if head is None:
            ret += template
            break
        istart, iend, prefix, key = head.start(0), head.end(0), head.group(1), head.group(2)
        if istart > 0:
            ret += template[:istart]
        path, block, invert = key.split(':'), prefix == '#', prefix == '^'
        if not path:
            raise ValueError("empty {{}} block found")
        obj = _resolve(path, values, strict)
        if block or invert:
            tailtag = '{{/%s}}' % (key)
            tailidx = iend + template[head.end(0):].find(tailtag)
            if tailidx < iend:
                raise ValueError("Unclosed conditional: %s" % head.group(0))
            iend = tailidx + len(tailtag)
            body = template[head.end(0):tailidx]
            if body.startswith('\n') and (not ret or ret.endswith('\n')):
                ret = ret[:-1]
            if block:
                if obj in (None, False):
                    pass
                elif isinstance(obj, tuple) or isinstance(obj, list):
                    for it in obj:
                        ret += parse(body, _join(values, {key: it}))
                else:
                    ret += parse(body, _join(values, {key: obj}))
            elif not obj:
                ret += parse(body, _join(values, {key: ""}))
            if ret.endswith('\n') and template[iend:].startswith('\n'):
                iend += 1
        elif obj is not None:
            ret += str(obj)
        template = template[iend:]
    return ret
