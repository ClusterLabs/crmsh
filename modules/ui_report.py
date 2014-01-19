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

import os
import command
import utils
from msg import no_prog_err
import config


class Report(command.UI):
    '''
    Implements the report interface in crmsh.
    '''
    name = "report"

    extcmd = os.path.join(config.path.sharedir, 'hb_report')

    def requires(self):
        if not utils.is_program(self.extcmd):
            no_prog_err(self.extcmd)
            return False
        return True

    def do_create(self, context, *args):
        '''
        Create a new report.

        create -f "YYYY-MM-DD H:M:S" [-t "YYYY-MM-DD H:M:S"] [options ...] [dest]
        '''
        cmd = [self.extcmd] + list(args)
        return utils.ext_cmd(cmd, shell=False) == 0
