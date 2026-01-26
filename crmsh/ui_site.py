# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import time
from . import command
from . import completers as compl
from . import utils
from . import log
from . import options


logger = log.setup_logger(__name__)
logger_utils = log.LoggerUtils(logger)
_ticket_commands = {
    'grant': "%s -t '%s' -g",
    'revoke': "%s -t '%s' -r",
    'delete': "%s -t '%s' -D granted",
    'standby': "%s -t '%s' -s",
    'activate': "%s -t '%s' -a",
    'show': "%s -t '%s' -G granted",
    'time': "%s -t '%s' -G last-granted",
}


def _show(context, ticket, val):
    "Display status of ticket"
    if val == "false":
        print("ticket %s is revoked" % ticket)
    elif val == "true":
        print("ticket %s is granted" % ticket)
    else:
        context.fatal_error("unexpected value for ticket %s: %s" % (ticket, val))


def _time(context, ticket, val):
    "Display grant time for ticket"
    if not utils.is_int(val):
        context.fatal_error("unexpected value for ticket %s: %s" % (ticket, val))
    if val == "-1":
        context.fatal_error("%s: no such ticket" % ticket)
    print("ticket %s last time granted on %s" % (ticket, time.ctime(int(val))))


class Site(command.UI):
    '''
    The site class
    '''
    name = "site"

    def requires(self):
        if not utils.is_program('crm_ticket'):
            logger_utils.no_prog_err('crm_ticket')
            return False
        return True

    @command.skill_level('administrator')
    @command.completers(compl.choice(list(_ticket_commands.keys())))
    def do_ticket(self, context, subcmd, ticket):
        "usage: ticket {grant|revoke|standby|activate|show|time|delete} <ticket>"

        base_cmd = "crm_ticket"
        if options.force:
            base_cmd += " --force"

        attr_cmd = _ticket_commands.get(subcmd)
        if not attr_cmd:
            context.fatal_error('Expected one of %s' % '|'.join(list(_ticket_commands.keys())))
        if not utils.is_name_sane(ticket):
            return False
        if subcmd not in ("show", "time"):
            return utils.ext_cmd(attr_cmd % (base_cmd, ticket)) == 0
        rc, l = utils.stdout2list(attr_cmd % (base_cmd, ticket))
        try:
            val = l[0]
        except IndexError:
            context.fatal_error("apparently nothing to show for ticket %s" % ticket)
        if subcmd == "show":
            _show(context, ticket, val)
        else:  # time
            _time(context, ticket, val)
