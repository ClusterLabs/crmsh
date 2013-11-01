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

import time
import command
import completers as compl
import utils
from msg import bad_usage, common_warn, no_prog_err

_ticket_commands = {
    'grant': "crm_ticket -t '%s' -g",
    'revoke': "crm_ticket -t '%s' -r",
    'delete': "crm_ticket -t '%s' -D granted",
    'standby': "crm_ticket -t '%s' -s",
    'activate': "crm_ticket -t '%s' -a",
    'show': "crm_ticket -t '%s' -G granted",
    'time': "crm_ticket -t '%s' -G last-granted",
}


class Site(command.UI):
    '''
    The site class
    '''
    name = "site"

    def requires(self):
        if not utils.is_program('crm_ticket'):
            no_prog_err('crm_ticket')
            return False
        return True

    @command.skill_level('administrator')
    @command.completers(compl.choice(_ticket_commands.keys()))
    def do_ticket(self, context, subcmd, ticket):
        "usage: ticket {grant|revoke|standby|activate|show|time|delete} <ticket>"
        cmd = context.get_command_name()
        try:
            attr_cmd = _ticket_commands[subcmd]
        except KeyError:
            bad_usage(cmd, '%s %s' % (subcmd, ticket))
            return False
        if not utils.is_name_sane(ticket):
            return False
        if subcmd not in ("show", "time"):
            return utils.ext_cmd(attr_cmd % ticket) == 0
        rc, l = utils.stdout2list(attr_cmd % ticket)
        try:
            val = l[0]
        except IndexError:
            common_warn("apparently nothing to show for ticket %s" % ticket)
            return False
        if subcmd == "show":
            if val == "false":
                print "ticket %s is revoked" % ticket
            elif val == "true":
                print "ticket %s is granted" % ticket
            else:
                common_warn("unexpected value for ticket %s: %s" % (ticket, val))
                return False
        else:  # time
            if not utils.is_int(val):
                common_warn("unexpected value for ticket %s: %s" % (ticket, val))
                return False
            if val == "-1":
                print "%s: no such ticket" % ticket
                return False
            print "ticket %s last time granted on %s" % (ticket, time.ctime(int(val)))
