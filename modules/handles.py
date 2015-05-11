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


_RESULT_KEY = ":result:"


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
    """
    REHEAD = re.compile(r'\{\{(\#?[A-Za-z0-9:_-]+)\}\}')
    ret = ""
    while template:
        head = REHEAD.search(template)
        if head is None:
            ret += template
            break
        idx = head.start(0)
        if idx > 0:
            ret += template[:idx]
        key = head.group(1)
        is_block = key.startswith('#')
        if is_block:
            key = key[1:]
        path = key.split(':')
        if not path:
            raise ValueError("empty {{}} tag found")
        obj = _resolve(path, values)
        if is_block:
            tailtag = '{{/%s}}' % (key)
            tailidx_offset = template[head.end(0):].find(tailtag)
            if tailidx_offset < 0:
                raise ValueError("Unclosed conditional: %s" % head.group(0))
            tailidx = head.end(0) + tailidx_offset
            body = template[head.end(0):tailidx]
            if obj is None:
                pass
            elif isinstance(obj, tuple) or isinstance(obj, list):
                for it in obj:
                    values2 = values.copy()
                    values2.update({key: it})
                    ret += parse(body, values2)
            else:
                values2 = values.copy()
                values2.update({key: obj})
                ret += parse(body, values2)
            template = template[tailidx + len(tailtag):]
        elif isinstance(obj, dict):
            result = obj.get(_RESULT_KEY)
            if result is not None:
                ret += str(result)
            else:
                raise ValueError("%s references non-value object" % (head.group(0)))
        elif obj is not None:
            ret += str(obj)
            template = template[head.end(0):]
        else:
            template = template[head.end(0):]
    return ret
