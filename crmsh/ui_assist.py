# Copyright (C) 2014 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

from . import utils
from . import command
from . import completers as compl
from . import xmlutil
from . import cibconfig


def rmattrs(e, *attrs):
    "remove the given attributes from an XML element"
    for attr in attrs:
        if attr in e.attrib:
            del e.attrib[attr]


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
        self.cib_factory = cibconfig.cib_factory_instance()

    def requires(self):
        self.cib_factory.initialize(no_side_effects=True)
        return True

    @command.skill_level('administrator')
    @command.completers_repeating(compl.call(cibconfig.cib_factory_instance().prim_id_list))
    def do_template(self, context, *primitives):
        '''
        Create a shared template for the given primitives
        '''
        if len(primitives) < 1:
            context.fatal_error("Expected at least one primitive argument")
        objs = [self.cib_factory.find_resource(p) for p in primitives]
        for prim, obj in zip(primitives, objs):
            if obj is None:
                context.fatal_error("Primitive %s not found" % (prim))
        if objs and all(obj.obj_type == 'primitive' for obj in objs):
            return self._template_primitives(context, objs)
        context.fatal_error("Cannot create a template for the given resources")

    def _template_primitives(self, context, primitives):
        """
        Try to template the given primitives:
        Templating means creating a rsc_template and moving
        shared attributes and other commonalities into that template
        (this second step is currently not available)
        """
        shared_template = None
        if all('template' in obj.node.attrib for obj in primitives):
            return True
        if len(set(xmlutil.mk_rsc_type(obj.node) for obj in primitives)) != 1:
            context.fatal_error("Cannot template the given primitives")

        node = primitives[0].node
        template_name = self.make_unique_name('template-%s-' % (node.get('type').lower()))
        shared_template = self.cib_factory.create_object('rsc_template', template_name,
                                                    xmlutil.mk_rsc_type(node))
        if not shared_template:
            context.fatal_error("Error creating template")
        for obj in primitives:
            obj.node.set('template', template_name)
            rmattrs(obj.node, 'class', 'provider', 'type')
            obj.set_updated()

        if not self._pull_attributes(context, shared_template, primitives):
            context.fatal_error("Error when copying attributes into template")

        context.info("Template created: %s" % (template_name))
        return True

    def _pull_attributes(self, context, template, primitives):
        '''
        TODO: take any attributes shared by all primitives and
        move them into the shared template
        '''
        return True

    @command.skill_level('administrator')
    @command.completers_repeating(compl.call(cibconfig.cib_factory_instance().prim_id_list))
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
        if len(nodes) < 2:
            context.fatal_error("Need at least two arguments")

        for node in nodes:
            obj = self.cib_factory.find_resource(node)
            if not obj:
                context.fatal_error("Object not found: %s" % (node))
            if not xmlutil.is_primitive(obj.node):
                context.fatal_error("Object not primitive: %s" % (node))

        constraint_name = self.make_unique_name('place-constraint-')
        dummy_name = self.make_unique_name('place-dummy-')
        print("Create weak bond / independent colocation")
        print("The following elements will be created:")
        print("   * Colocation constraint, ID: %s" % (constraint_name))
        print("   * Dummy resource, ID: %s" % (dummy_name))
        if not utils.can_ask() or utils.ask("Create resources?"):
            self.cib_factory.create_object('primitive', dummy_name, 'ocf:heartbeat:Dummy')
            colo = ['colocation', constraint_name, 'inf:', '(']
            colo.extend(nodes)
            colo.append(')')
            colo.append(dummy_name)
            self.cib_factory.create_object(*colo)

    def make_unique_name(self, prefix):
        n = 0
        while n < 1000:
            n += 1
            name = "%s%s" % (prefix, n)
            for _id in self.cib_factory.id_list():
                if name == _id.lower():
                    continue
            return name
        raise ValueError("Failed to generate unique resource ID with prefix '%s'" % (prefix))
