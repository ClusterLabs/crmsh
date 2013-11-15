# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
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

from ordereddict import odict
import re
import vars


class ListFmt(object):
    """
    List builder tool: takes a format string
    of [ ... ] to build a list, text for literal labels,
    and % patterns to insert arguments.
    """
    _IDENT_RE = re.compile(r'[a-zA-Z0-9_$-]+')

    def __init__(self, fmt, args):
        self.stack = []
        self.n = 0
        self.args = args
        self.fmt = fmt

    def arg(self):
        self.n += 1
        self.fwd()
        return self.args[self.n - 1]

    def add(self, item):
        if self.stack:
            self.stack[-1].append(item)
        return self.stack

    def fwd(self, n=1):
        self.fmt = self.fmt[n:]

    def ident(self):
        m = self._IDENT_RE.match(self.fmt)
        if not m:
            self.fwd()
        else:
            tok = m.group(0)
            self.fwd(len(tok))
            if self.fmt[0] == '%':
                a = self.arg()
                if a is None:
                    tok = None
                else:
                    tok += a
            self.add(tok)

    def apply(self):
        ret = None
        while self.fmt:
            if self.fmt[0] == '[':
                self.fwd()
                self.stack.append([])
            elif self.fmt[0] == ']':
                lst = self.stack.pop()
                if None not in lst:
                    if not self.add(lst):
                        ret = lst
                self.fwd()
            elif self.fmt[0] == '%':
                self.add(self.arg())
            else:
                self.ident()
        return ret


def listfmt(fmt, *args):
    return ListFmt(fmt, args).apply()


class Expr(object):
    def __init__(self):
        self.comments = []
        self.description = None

    def _to_list(self):
        """
        Convert object to nested list form.
        """
        raise NotImplemented

    def to_list(self):
        """
        Convert object to nested list form.
        Adds comments to output.
        """
        l = self._to_list()
        if self.comments:
            l.append(['comments', self.comments])
        return l


class Resource(Expr):
    def __init__(self):
        Expr.__init__(self)
        self.id = None
        self.params = odict()
        self.meta = odict()

    def _op_to_list(self, ret):
        for typ, val in self.operations:
            if typ == '$id' or typ == '$id-ref':
                ret.append(['operations', [[typ, val]]])
            else:
                ret.append(['op', [['name', typ]] + val])

    def _to_list_impl(self, typ):
        head = None
        prim = typ in ('primitive', 'rsc_template')
        if prim and self.template:
            head = listfmt(
                '[% [[id %] [template %] [description %]]]',
                typ, self.id, self.template, self.description)
        elif prim:
            head = listfmt(
                '[% [[id %] [class %] [provider %] [type %] [description %]]]',
                typ, self.id, self.ra_class, self.ra_provider, self.ra_type, self.description)
        else:
            head = listfmt('[% [[id %] [$children %]]]', typ, self.id, self.children)
        ret = [head]
        if self.params:
            ret.append(['params', self.params.items()])
        if self.meta:
            ret.append(['meta', self.meta.items()])
        if prim and self.utilization:
            ret.append(['utilization', self.utilization.items()])
        if prim and self.operations:
            self._op_to_list(ret)
        return ret


class Primitive(Resource):
    def __init__(self):
        Resource.__init__(self)
        self.template = None
        self.ra_class = None
        self.ra_provider = None
        self.ra_type = None
        self.utilization = odict()
        self.operations = []

    def _to_list(self):
        return self._to_list_impl('primitive')


class RscTemplate(Resource):
    def __init__(self):
        Resource.__init__(self)
        self.ra_class = None
        self.ra_provider = None
        self.ra_type = None
        self.utilization = odict()
        self.operations = []

    def _to_list(self):
        return self._to_list_impl('rsc_template')


class Group(Resource):
    def __init__(self):
        Resource.__init__(self)
        self.children = []

    def _to_list(self):
        return self._to_list_impl('group')


class Clone(Resource):
    def __init__(self):
        Resource.__init__(self)
        self.children = None

    def _to_list(self):
        return self._to_list_impl('clone')


class Master(Resource):
    def __init__(self):
        Resource.__init__(self)
        self.children = None

    def _to_list(self):
        return self._to_list_impl('ms')


class Constraint(Expr):
    def __init__(self):
        Expr.__init__(self)
        self.id = None


class Location(Constraint):
    def __init__(self):
        Constraint.__init__(self)
        self.resource = None
        self.score = None
        self.node = None
        self.role = None
        self.rules = []
        self.simple = False

    def _to_list(self):
        ret = None
        if self.score and self.node:
            ret = listfmt('[[location [[id %] [rsc %] % [node %] [role %]]]]',
                          self.id, self.resource, self.score, self.node, self.role)
        else:
            ret = listfmt('[[location [[id %] [rsc %]]]]',
                          self.id, self.resource) + self.rules
        return ret


class Colocation(Constraint):
    def __init__(self):
        Constraint.__init__(self)
        self.score = None
        self.resources = []
        self.node_attribute = None
        self.simple = False

    def _to_list(self):
        ret = listfmt(
            '[[colocation [[id %] % [node-attribute %]]]]',
            self.id, self.score, self.node_attribute)
        if self.simple:
            for attr in reversed(self.resources):
                ret[0][1].insert(2, attr)
        else:
            ret += self.resources
        return ret


class Order(Constraint):
    def __init__(self):
        Constraint.__init__(self)
        self.kind = None
        self.score = None
        self.resources = []
        self.symmetrical = None
        self.simple = False

    def _to_list(self):
        if self.kind:
            ret = listfmt(
                '[[order [[id %] [kind %] [symmetrical %]]]]',
                self.id, self.kind, self.symmetrical)
        else:
            ret = listfmt(
                '[[order [[id %] % [symmetrical %]]]]',
                self.id, self.score, self.symmetrical)
        if self.simple:
            for attr in reversed(self.resources):
                ret[0][1].insert(2, attr)
        else:
            ret += self.resources
        return ret


class RscTicket(Constraint):
    def __init__(self):
        Constraint.__init__(self)
        self.ticket = None
        self.resources = []
        self.loss_policy = None
        self.simple = False

    def _to_list(self):
        ret = listfmt(
            '[[rsc_ticket [[id %] [ticket %] [loss-policy %]]]]',
            self.id, self.ticket, self.loss_policy)
        if self.simple:
            for attr in reversed(self.resources):
                ret[0][1].insert(2, attr)
        else:
            ret += self.resources
        return ret


class Monitor(Expr):
    def __init__(self):
        Expr.__init__(self)
        self.resource = None
        self.role = None
        self.role_class = None
        self.interval = None
        self.timeout = None

    def _to_list(self):
        return listfmt(
            '[[op [[rsc %] [% %] [interval %] [timeout %] [name monitor]]]]',
            self.resource, self.role_class, self.role, self.interval, self.timeout)


class Node(Expr):
    def __init__(self):
        Expr.__init__(self)
        self.id = None
        self.uname = None
        self.type = None
        self.attributes = odict()
        self.utilization = odict()

    def _to_list(self):
        t = self.type
        if t and t.lower() == vars.node_default_type:
            t = None
        attrs = self.attributes.items() or None
        utils = self.utilization.items() or None
        return listfmt(
            '[[node [[uname %] [type %] [id %] [description %]]] ' +
            '[attributes %] [utilization %]]',
            self.uname, t, self.id or self.uname, self.description, attrs, utils)


class Property(Expr):
    def __init__(self):
        Expr.__init__(self)
        self.type = None
        self.values = []

    def _to_list(self):
        return [[self.type, [[n, v] for n, v in self.values]]]


class FencingTopology(Expr):
    def __init__(self):
        Expr.__init__(self)
        self.levels = []

    def add_level(self, target, devices):
        self.levels.append(['fencing-level', [['target', target], ['devices', devices]]])

    def _to_list(self):
        return [['fencing_topology', self.levels]]


class ACLRight(object):
    def __init__(self):
        self.right = None  # read, write, deny
        self.specs = []

    def __repr__(self):
        return repr(self._to_list())

    def _to_list(self):
        return [self.right, self.specs]


class Role(Expr):
    def __init__(self):
        Expr.__init__(self)
        self.role_id = None
        self.rules = []

    def _to_list(self):
        ret = listfmt('[[role [[id %]]]]', self.role_id)
        ret.extend(r._to_list() for r in self.rules)
        return ret


class User(Expr):
    def __init__(self):
        Expr.__init__(self)
        self.uid = None
        self.roles = []
        self.rules = []

    def _to_list(self):
        ret = listfmt('[[user [[id %]]]]', self.uid)
        for role in self.roles:
            ret.append(['role_ref', ['id', role]])
        ret.extend(r._to_list() for r in self.rules)
        return ret


class RawXML(Expr):
    def __init__(self):
        Expr.__init__(self)
        self.id = None
        self.type = None
        self.raw = None

    def _to_list(self):
        return listfmt('[[% [[id %]]] [raw %]]', self.type, self.id, self.raw)
