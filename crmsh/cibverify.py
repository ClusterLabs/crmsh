# Copyright (C) 2014 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import re
from . import utils
from .msg import err_buf


cib_verify = "crm_verify -VV -p"
VALIDATE_RE = re.compile(r"^Entity: line (\d)+: element (\w+): " +
                         r"Relax-NG validity error : (.+)$")


def _prettify(line, indent=0):
    m = VALIDATE_RE.match(line)
    if m:
        return "%s%s (%s): %s" % (indent*' ', m.group(2), m.group(1), m.group(3))
    return line


def verify(cib):
    rc, _, stderr = utils.get_stdout_stderr(cib_verify, cib.encode('utf-8'))
    for i, line in enumerate(line for line in stderr.split('\n') if line):
        if i == 0:
            if "warning:" in line:
                err_buf.warning(_prettify(line, 0))
            else:
                err_buf.error(_prettify(line, 0))
        else:
            err_buf.writemsg(_prettify(line, 7))
    return rc
