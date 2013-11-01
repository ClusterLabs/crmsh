# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
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

import utils

crm_mon_prog = "crm_mon"


def has_crm_mon():
    p = crm_mon_prog
    if not utils.is_program(p):
        raise IOError("%s not available, check your installation" % crm_mon_prog)


def crm_mon(opts=''):
    """
    Run 'crm_mon -1'
    opts: Additional options to pass to crm_mon
    returns: rc, stdout
    """
    has_crm_mon()
    status_cmd = "%s -1 %s" % (crm_mon_prog, opts)
    return utils.get_stdout(utils.add_sudo(status_cmd))


def cmd_status(args):
    '''
    Calls crm_mon -1, passing optional extra arguments.
    Displays the output, paging if necessary.
    Raises ValueError if an illegal argument is passed.
    Raises IOError if crm_mon fails.
    '''
    crm_mon_opts = {
        "bynode": "-n",
        "inactive": "-r",
        "ops": "-o",
        "timing": "-t",
        "failcounts": "-f",
    }

    has_crm_mon()

    def check(arg, val):
        if not val:
            raise ValueError("Unknown argument to status: " + str(arg))
        return val
    extra_options = ' '.join(check(arg, crm_mon_opts.get(arg)) for arg in args)

    rc, s = crm_mon(extra_options)
    if rc != 0:
        raise IOError("crm_mon exited with code %d. Output: '%s'" % (rc, s))

    utils.page_string(s)
