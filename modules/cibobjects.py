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


class Expr(object):
    def __init__(self):
        self.comments = []
        self.description = None

    def to_list(self):
        """
        Convert object to nested list form.
        """
        raise NotImplemented


class Resource(Expr):
    def __init__(self):
        Expr.__init__(self)
        self.id = None
        self.params = odict()
        self.meta = odict()


class Primitive(Resource):
    def __init__(self):
        Resource.__init__(self)
        self.template = None
        self.ra_class = None
        self.ra_provider = None
        self.ra_type = None
        self.utilization = odict()
        self.operations = []


class RscTemplate(Resource):
    def __init__(self):
        Resource.__init__(self)
        self.ra_class = None
        self.ra_provider = None
        self.ra_type = None
        self.utilization = odict()
        self.operations = []


class Group(Resource):
    def __init__(self):
        Resource.__init__(self)
        self.children = []


class Clone(Resource):
    def __init__(self):
        Resource.__init__(self)
        self.resource = None


class Master(Resource):
    def __init__(self):
        Resource.__init__(self)
        self.resource = None


class Constraint(Expr):
    def __init__(self):
        Expr.__init__(self)
        self.id = None


class Location(Constraint):
    class Rule(object):
        def __init__(self):
            self.id = None
            self.role = None
            self.score = None

    def __init__(self):
        Constraint.__init__(self)
        self.resource = None
        self.score = None
        self.node = None
        self.rules = []


class Colocation(Constraint):
    def __init__(self):
        Constraint.__init__(self)
        self.score = None
        self.resources = []
        self.node_attribute = None


class Order(Constraint):
    def __init__(self):
        Constraint.__init__(self)
        self.score = None
        self.resources = []
        self.symmetrical = None


class RscTicket(Constraint):
    def __init__(self):
        Constraint.__init__(self)
        self.kind = None
        self.score = None
        self.resources = []
        self.loss_policy = None


class Monitor(Expr):
    def __init__(self):
        Expr.__init__(self)
        self.resource = None
        self.role = None
        self.interval = None
        self.timeout = None


class Node(Expr):
    def __init__(self):
        Expr.__init__(self)
        self.id = None
        self.uname = None
        self.type = None
        self.attributes = odict()
        self.utilization = odict()


class Property(Expr):
    def __init__(self):
        Expr.__init__(self)
        self.id = None
        self.values = []


class RscDefaults(Expr):
    def __init__(self):
        Expr.__init__(self)
        self.id = None
        self.values = []


class OpDefaults(Expr):
    def __init__(self):
        Expr.__init__(self)
        self.id = None
        self.values = []


class FencingTopology(Expr):
    class Level(object):
        def __init__(self, target, devices):
            self.target = target
            self.devices = devices

    def __init__(self):
        Expr.__init__(self)
        self.levels = []

    def add_level(self, target, devices):
        self.levels.append(self.Level(target, devices))


class ACLRule(object):
    def __init__(self):
        self.right = None  # read, write, deny
        self.specs = []
        self.attribute = None

    def __repr__(self):
        return "acl:rule(%s, %s, attr=%s)" % (
            self.right, ", ".join(str(s) for s in self.specs), self.attribute)


class Role(Expr):
    def __init__(self):
        Expr.__init__(self)
        self.role_id = None
        self.rules = []


class User(Expr):
    def __init__(self):
        Expr.__init__(self)
        self.uid = None
        self.roles = []
        self.rules = []


class RawXML(Expr):
    def __init__(self):
        Expr.__init__(self)
        self.id = None
        self.type = None
        self.raw = None

    def to_xml(self):
        """
        Returns an XML string.
        """
        return self.raw
