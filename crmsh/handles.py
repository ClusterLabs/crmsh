# Copyright (C) 2015 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import re


headmatcher = re.compile(r'\{\{(\#|\^)?([A-Za-z0-9\#\$:_-]+)\}\}')


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
        return "handles.value(%s, %s)" % (repr(self.obj), repr(self.value))

    def __str__(self):
        return "handles.value(%s, %s)" % (repr(self.obj), repr(self.value))


def _join(d1, d2):
    d = d1.copy()
    d.update(d2)
    return d


def _resolve(path, context, strict):
    for values in context:
        r = path
        p = values
        while r and p is not None:
            p, r = p.get(r[0]), r[1:]
        if strict and r:
            continue
        if callable(p):
            p = p()
        if p is not None:
            return p
    if strict:
        raise ValueError("Not set: %s" % (':'.join(path)))
    return None


def _push(path, value, context):
    root = {}
    leaf = root
    for x in path[:-1]:
        leaf = {}
        root[x] = leaf
    leaf[path[-1]] = value
    ret = [root] + context
    return ret


def _textify(obj):
    if obj is None:
        return ''
    elif obj is True:
        return 'true'
    elif obj is False:
        return 'false'
    return str(obj)


def _parse(template, context, strict):
    ret = ""
    while template:
        head = headmatcher.search(template)
        if head is None:
            ret += template
            break
        istart, iend, prefix, key = head.start(0), head.end(0), head.group(1), head.group(2)
        if istart > 0:
            ret += template[:istart]
        path, block, invert = key.split(':'), prefix == '#', prefix == '^'
        if not path:
            raise ValueError("empty {{}} block found")
        obj = _resolve(path, context, strict)
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
                elif isinstance(obj, (tuple, list)):
                    for it in obj:
                        ret += _parse(body, _push(path, it, context), strict)
                else:
                    ret += _parse(body, context, strict)
            elif not obj:
                ret += _parse(body, _push(path, "", context), strict)
            if ret.endswith('\n') and template[iend:].startswith('\n'):
                iend += 1
        elif obj is not None:
            ret += _textify(obj)
        template = template[iend:]
    return ret


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
    return _parse(template, [values], strict)
