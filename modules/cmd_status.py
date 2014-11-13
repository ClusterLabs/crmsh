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

_crm_mon = None


def crm_mon(opts=''):
    """
    Run 'crm_mon -1'
    opts: Additional options to pass to crm_mon
    returns: rc, stdout
    """
    global _crm_mon
    if _crm_mon is None:
        if not utils.is_program("crm_mon"):
            raise IOError("crm_mon not available, check your installation")
        _, out = utils.get_stdout("crm_mon --help")
        if "--pending" in out:
            _crm_mon = "crm_mon -1 -j"
        else:
            _crm_mon = "crm_mon -1"

    status_cmd = "%s %s" % (_crm_mon, opts)
    return utils.get_stdout(utils.add_sudo(status_cmd))


def cmd_status(args):
    '''
    Calls crm_mon -1, passing optional extra arguments.
    Displays the output, paging if necessary.
    Raises IOError if crm_mon fails.
    '''
    opts = {
        "bynode": "-n",
        "inactive": "-r",
        "ops": "-o",
        "timing": "-t",
        "failcounts": "-f",
        "verbose": "-V",
        "quiet": "-Q",
        "html": "--as-html",
        "xml": "--as-xml",
        "simple": "-s",
        "tickets": "-c",
        "noheaders": "-D",
        "detail": "-R",
        "brief": "-b",
    }
    extra = ' '.join(opts.get(arg, arg) for arg in args)
    rc, s = crm_mon(extra)
    if rc != 0:
        raise IOError("crm_mon (rc=%d): %s" % (rc, s))

    utils.page_string(s)
    return True
