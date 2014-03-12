# Copyright (C) 2014 Kristoffer Gronlund <kgronlund@suse.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

import sys
import utils
import command
import completers as compl
import options
import xmlutil
from cibconfig import CibFactory

cib_factory = CibFactory.getInstance()


class Assist(command.UI):
    '''
    The assist UI collects what could be called
    configuration macros. Things like merging
    multiple resources into a template, or building
    a colocated set with a relation to a dummy
    resource.
    '''
    name = "assist"

    def __init__(self):
        command.UI.__init__(self)
        # for interactive use, we want to populate the CIB
        # immediately so that tab completion works
        if options.interactive:
            cib_factory.initialize()

    #def do_distill(self, context):
    #    '''
    #    Detect and merge resources if the
    #    resulting template makes for a smaller
    #    configuration.
    #    '''
    #    # TODO
    #    return True

    @command.skill_level('administrator')
    @command.completers_repeating(compl.call(cib_factory.prim_id_list))
    @command.name('weak-bond')
    @command.alias('weak_bond')
    def do_weak_bond(self, context, *nodes):
        '''
        Create a 'weak' colocation:
        Colocating a non-sequential resource set with
        a dummy resource which is not monitored creates,
        in effect, a colocation which does not imply any
        internal relationship between resources.
        '''
        if not cib_factory.is_cib_sane():
            return False

        if len(nodes) < 2:
            context.fatal_error("Need at least two arguments")

        for node in nodes:
            obj = cib_factory.find_object(node)
            if not obj:
                context.fatal_error("Object not found: %s" % (node))
            if not xmlutil.is_primitive(obj.node):
                context.fatal_error("Object not primitive: %s" % (node))

        constraint_name = self.make_unique_name('place-constraint-')
        dummy_name = self.make_unique_name('place-dummy-')
        print "Create weak bond / independent colocation"
        print "The following elements will be created:"
        print "   * Colocation constraint, ID: %s" % (constraint_name)
        print "   * Dummy resource, ID: %s" % (dummy_name)
        if not utils.can_ask() or utils.ask("Create resources?"):
            cib_factory.create_object('primitive', dummy_name, 'ocf:heartbeat:Dummy')
            colo = ['colocation', constraint_name, 'inf:', '(']
            colo.extend(nodes)
            colo.append(')')
            colo.append(dummy_name)
            cib_factory.create_object(*colo)

    def make_unique_name(self, prefix):
        n = 0
        while n < 1000:
            n += 1
            name = "%s%s" % (prefix, n)
            for _id in cib_factory.id_list():
                if name == _id.lower():
                    continue
            return name
        raise ValueError("Failed to generate unique resource ID with prefix '%s'" % (prefix))
