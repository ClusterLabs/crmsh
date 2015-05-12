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


RESULT = ":result:"


def _resolve(path, values):
    p = values
    while path:
        p = p.get(path[0])
        if p is None:
            return None
        path = path[1:]
    return p


def parse(template, values):
    """
    Takes as input a template string and a dict
    of values, and replaces the following:
    {{object:key}} = look up key in object and insert value
    {{object}} = if object is found in the dict and is a dict itself,
    insert the value of the special key ":result:", if object is in the dict and is
    a value, insert the value
    {{#object}} ... {{/object}} = if object is a dict or value, process text. if object
    is a list, process text for each item in the list
    (can't nest these for items with the same name)
    {{^object}} ... {{/object}} = if object is falsy, process text.
    """
    head_re = re.compile(r'\{\{(\#|\^)?([A-Za-z0-9:_-]+)\}\}')
    ret = ""
    while template:
        head = head_re.search(template)
        if head is None:
            ret += template
            break
        istart, iend, prefix, key = head.start(0), head.end(0), head.group(1), head.group(2)
        if istart > 0:
            ret += template[:istart]
        path = key.split(':')
        if not path:
            raise ValueError("empty {{}} tag found")
        obj = _resolve(path, values)
        is_block = prefix == '#'
        is_invert = prefix == '^'
        if is_block or is_invert:
            tailtag = '{{/%s}}' % (key)
            tailidx = iend + template[head.end(0):].find(tailtag)
            if tailidx < iend:
                raise ValueError("Unclosed conditional: %s" % head.group(0))
            iend = tailidx + len(tailtag)
            body = template[head.end(0):tailidx]
            if body.startswith('\n') and (not ret or ret.endswith('\n')):
                ret = ret[:-1]
            if is_block:
                if obj is not None:
                    if isinstance(obj, tuple) or isinstance(obj, list):
                        for it in obj:
                            values2 = values.copy()
                            values2.update({key: it})
                            ret += parse(body, values2)
                    else:
                        values2 = values.copy()
                        values2.update({key: obj})
                        ret += parse(body, values2)
            elif not obj:
                values2 = values.copy()
                values2.update({key: ""})
                ret += parse(body, values2)
            if ret.endswith('\n') and template[iend:].startswith('\n'):
                iend += 1
        elif isinstance(obj, dict):
            result = obj.get(RESULT)
            if result is None:
                raise ValueError("%s references non-value object" % (head.group(0)))
            ret += str(result)
        elif obj is not None:
            ret += str(obj)
        template = template[iend:]
    return ret
