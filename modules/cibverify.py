# Copyright (C) 2014 Kristoffer Gronlund <kgronlund@suse.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#

import re
from . import utils
from .msg import err_buf


cib_verify = "crm_verify --verbose -p"
VALIDATE_RE = re.compile(r"^Entity: line (\d)+: element (\w+): " +
                         r"Relax-NG validity error : (.+)$")


def _prettify(line, indent=0):
    m = VALIDATE_RE.match(line)
    if m:
        return "%s%s (%s): %s" % (indent*' ', m.group(2), m.group(1), m.group(3))
    return line


def verify(cib):
    rc, _, stderr = utils.get_stdout_stderr(cib_verify, cib)
    for i, line in enumerate(line for line in stderr.split('\n') if line):
        if i == 0:
            err_buf.error(_prettify(line, 0))
        else:
            err_buf.writemsg(_prettify(line, 7))
    return rc
