# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
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

import command
import utils
import ui_utils
from cibstatus import CibStatus


class CibStatusUI(command.UI):
    '''
    The CIB status section management user interface class
    '''
    name = "cibstatus"

    def __init__(self):
        command.UI.__init__(self)
        self.cib_status = CibStatus.getInstance()

    @command.skill_level('expert')
    def do_load(self, context, org):
        "usage: load {<file>|shadow:<cib>|live}"
        return self.cib_status.load(org)

    @command.skill_level('expert')
    def do_save(self, context, dest=None):
        "usage: save [<file>|shadow:<cib>]"
        return self.cib_status.save(dest)

    @command.skill_level('administrator')
    def do_origin(self, context):
        "usage: origin"
        state = self.cib_status.modified and " (modified)" or ""
        print "%s%s" % (self.cib_status.origin, state)

    @command.skill_level('administrator')
    def do_show(self, context, changed=""):
        "usage: show [changed]"
        if changed:
            if changed != "changed":
                context.fatal_error("Expected 'changed', got '%s'" % (changed))
            return self.cib_status.list_changes()
        return self.cib_status.show()

    @command.skill_level('administrator')
    def do_quorum(self, context, opt):
        "usage: quorum <bool>"
        if not utils.verify_boolean(opt):
            context.fatal_error("%s: bad boolean option" % opt)
        return self.cib_status.set_quorum(utils.is_boolean_true(opt))

    @command.skill_level('expert')
    def do_node(self, cmd, node, state):
        "usage: node <node> {online|offline|unclean}"
        return self.cib_status.edit_node(node, state)

    @command.skill_level('expert')
    def do_ticket(self, cmd, ticket, subcmd):
        "usage: ticket <ticket> {grant|revoke|activate|standby}"
        return self.cib_status.edit_ticket(ticket, subcmd)

    @command.skill_level('expert')
    def do_op(self, context, op, rsc, rc, op_status=None, node=''):
        "usage: op <operation> <resource> <exit_code> [<op_status>] [<node>]"
        if rc in vars.lrm_exit_codes:
            num_rc = vars.lrm_exit_codes[rc]
        else:
            num_rc = rc
        if not num_rc.isdigit():
            context.fatal_error("Invalid exit code '%s'" % num_rc)
        num_op_status = op_status
        if op_status:
            if op_status in vars.lrm_status_codes:
                num_op_status = vars.lrm_status_codes[op_status]
            if not num_op_status.isdigit():
                context.fatal_error("Invalid operation status '%s'" % num_op_status)
        return self.cib_status.edit_op(op, rsc, num_rc, num_op_status, node)

    @command.skill_level('administrator')
    def do_run(self, context, *args):
        "usage: run [nograph] [v...] [scores] [utilization]"
        return ui_utils.ptestlike(self.cib_status.run, '', context.get_command_name(), args)

    @command.skill_level('administrator')
    def do_simulate(self, context, *args):
        "usage: simulate [nograph] [v...] [scores] [utilization]"
        return ui_utils.ptestlike(self.cib_status.simulate, '', context.get_command_name(), args)
