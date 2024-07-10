# Copyright (C) 2014 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

from . import command
from . import completers as compl
from . import config
from .cibconfig import cib_factory
from . import utils
from . import xmlutil

_compl_actions = compl.choice(['start', 'stop', 'monitor', 'meta-data', 'validate-all',
                               'promote', 'demote', 'notify', 'reload', 'migrate_from',
                               'migrate_to', 'recover'])


class Maintenance(command.UI):
    '''
    Commands that should only be run while in
    maintenance mode.
    '''
    name = "maintenance"

    rsc_maintenance = "crm_resource -r '%s' --meta -p maintenance -v '%s'"

    def __init__(self):
        command.UI.__init__(self)

    def requires(self):
        cib_factory.initialize(no_side_effects=True)
        return True

    def _onoff(self, resource, onoff):
        if resource is not None:
            return utils.ext_cmd(self.rsc_maintenance % (resource, onoff)) == 0
        else:
            cib_factory.create_object('property', 'maintenance-mode=%s' % (onoff))
            return cib_factory.commit()

    @command.skill_level('administrator')
    @command.completers_repeating(compl.call(cib_factory.rsc_id_list))
    def do_on(self, context, resource=None):
        '''
        Enable maintenance mode (for the optional resource or for everything)
        '''
        return self._onoff(resource, 'true')

    @command.skill_level('administrator')
    @command.completers_repeating(compl.call(cib_factory.rsc_id_list))
    def do_off(self, context, resource=None):
        '''
        Disable maintenance mode (for the optional resource or for everything)
        '''
        return self._onoff(resource, 'false')

    def _in_maintenance_mode(self, obj):
        if cib_factory.get_property("maintenance-mode") == "true":
            return True
        v = obj.meta_attributes("maintenance")
        return v and all(x == 'true' for x in v)

    def _runs_on_this_node(self, resource):
        nodes = utils.running_on(resource)
        return set(nodes) == set([utils.this_node()])

    @command.skill_level('administrator')
    @command.completers(compl.call(cib_factory.rsc_id_list), _compl_actions, compl.choice(["ssh"]))
    def do_action(self, context, resource, action, ssh=None):
        '''
        Issue action out-of-band to the given resource, making
        sure that the resource is in maintenance mode first
        '''
        obj = cib_factory.find_object(resource)
        if not obj:
            context.fatal_error("Resource not found: %s" % (resource))
        if not xmlutil.is_resource(obj.node):
            context.fatal_error("Not a resource: %s" % (resource))
        if not config.core.force and not self._in_maintenance_mode(obj):
            context.fatal_error("Not in maintenance mode.")

        if ssh is None:
            if action not in ('start', 'monitor'):
                if not self._runs_on_this_node(resource):
                    context.fatal_error("Resource %s must be running on this node (%s)" %
                                        (resource, utils.this_node()))

            from . import rsctest
            return rsctest.call_resource(obj.node, action, [utils.this_node()], local_only=True)
        elif ssh == "ssh":
            from . import rsctest
            if action in ('start', 'promote', 'demote', 'recover', 'meta-data'):
                return rsctest.call_resource(obj.node, action,
                                             [utils.this_node()], local_only=True)
            else:
                all_nodes = cib_factory.node_id_list()
                return rsctest.call_resource(obj.node, action, all_nodes, local_only=False)
        else:
            context.fatal_error("Unknown argument: %s" % (ssh))
