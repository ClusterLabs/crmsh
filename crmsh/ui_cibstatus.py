# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

from . import command
from . import completers as compl
from . import utils
from . import ui_utils
from . import constants
from .cibstatus import cib_status


_status_node_list = compl.call(cib_status.status_node_list)


class CibStatusUI(command.UI):
    '''
    The CIB status section management user interface class
    '''
    name = "cibstatus"

    @command.skill_level('expert')
    def do_load(self, context, org):
        "usage: load {<file>|shadow:<cib>|live}"
        return cib_status.load(org)

    @command.skill_level('expert')
    def do_save(self, context, dest=None):
        "usage: save [<file>|shadow:<cib>]"
        return cib_status.save(dest)

    @command.skill_level('administrator')
    def do_origin(self, context):
        "usage: origin"
        state = cib_status.modified and " (modified)" or ""
        print("%s%s" % (cib_status.origin, state))

    @command.skill_level('administrator')
    @command.completers(compl.choice(['changed']))
    def do_show(self, context, changed=""):
        "usage: show [changed]"
        if changed:
            if changed != "changed":
                context.fatal_error("Expected 'changed', got '%s'" % (changed))
            return cib_status.list_changes()
        return cib_status.show()

    @command.skill_level('administrator')
    @command.completers(compl.booleans)
    def do_quorum(self, context, opt):
        "usage: quorum <bool>"
        if not utils.verify_boolean(opt):
            context.fatal_error("%s: bad boolean option" % opt)
        return cib_status.set_quorum(utils.is_boolean_true(opt))

    @command.skill_level('expert')
    @command.completers(_status_node_list, compl.choice(constants.node_states))
    def do_node(self, context, node, state):
        "usage: node <node> {online|offline|unclean}"
        return cib_status.edit_node(node, state)

    @command.skill_level('expert')
    @command.completers(compl.null, compl.choice(list(cib_status.ticket_ops.keys())))
    def do_ticket(self, context, ticket, subcmd):
        "usage: ticket <ticket> {grant|revoke|activate|standby}"
        return cib_status.edit_ticket(ticket, subcmd)

    @command.skill_level('expert')
    @command.completers(compl.choice(constants.ra_operations),
                        compl.call(cib_status.status_rsc_list),
                        compl.choice(list(constants.lrm_exit_codes.keys())),
                        compl.choice(list(constants.lrm_status_codes.keys())),
                        compl.choice(constants.node_states))
    def do_op(self, context, op, rsc, rc, op_status=None, node=''):
        "usage: op <operation> <resource> <exit_code> [<op_status>] [<node>]"
        if rc in constants.lrm_exit_codes:
            num_rc = constants.lrm_exit_codes[rc]
        else:
            num_rc = rc
        if not num_rc.isdigit():
            context.fatal_error("Invalid exit code '%s'" % num_rc)
        num_op_status = op_status
        if op_status:
            if op_status in constants.lrm_status_codes:
                num_op_status = constants.lrm_status_codes[op_status]
            if not num_op_status.isdigit():
                context.fatal_error("Invalid operation status '%s'" % num_op_status)
        return cib_status.edit_op(op, rsc, num_rc, num_op_status, node)

    @command.skill_level('administrator')
    @command.completers(compl.choice(['nograph']))
    def do_run(self, context, *args):
        "usage: run [nograph] [v...] [scores] [utilization]"
        return ui_utils.ptestlike(cib_status.run, '', context.get_command_name(), args)

    @command.skill_level('administrator')
    @command.completers(compl.choice(['nograph']))
    def do_simulate(self, context, *args):
        "usage: simulate [nograph] [v...] [scores] [utilization]"
        return ui_utils.ptestlike(cib_status.simulate, '', context.get_command_name(), args)
