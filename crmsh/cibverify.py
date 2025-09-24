# Copyright (C) 2014 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import re
from .sh import ShellUtils
from . import log


logger = log.setup_logger(__name__)
cib_verify = "crm_verify -VV -p"
VALIDATE_RE = re.compile(r"^Entity: line (\d)+: element (\w+): " +
                         r"Relax-NG validity error : (.+)$")
RC_MISCONFIGURATION = 78 # from pacemaker include/crm/common/results.h


def _prettify(line, indent=0):
    m = VALIDATE_RE.match(line)
    if m:
        return "%s%s (%s): %s" % (indent*' ', m.group(2), m.group(1), m.group(3))
    return line


def verify(cib):
    found_error = False
    rc, _, stderr = ShellUtils().get_stdout_stderr(cib_verify, cib.encode('utf-8'))
    for i, line in enumerate(line for line in stderr.split('\n') if line):
        indent = 0 if i == 0 else 7
        print(_prettify(line, indent))
        if re.search(r"\berror\b", line, re.IGNORECASE):
            found_error = True
    if rc == RC_MISCONFIGURATION and not found_error:
        rc = 1
    return rc
