# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import os
import subprocess
from signal import signal, SIGPIPE, SIG_DFL

from . import utils
from . import config
from . import options


def report_tool():
    toolopts = [os.path.join(config.path.sharedir, 'hb_report', 'hb_report'),
                'hb_report',
                'crm_report']
    for tool in toolopts:
        if utils.is_program(tool):
            return tool
    return None


def create_report(context, args):
    extcmd = report_tool()
    if not extcmd:
        context.fatal_error("No reporting tool found")
    extraopts = str(config.core.report_tool_options).strip().split()
    cmd = [extcmd] + extraopts + list(args)
    if options.regression_tests:
        print(".EXT", cmd)
    return subprocess.call(cmd, shell=False, preexec_fn=lambda: signal(SIGPIPE, SIG_DFL))
