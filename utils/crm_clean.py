#!/usr/bin/env python
from __future__ import print_function
from __future__ import unicode_literals
import os
import sys
import shutil
errors = []
mydir = os.path.dirname(os.path.abspath(sys.modules[__name__].__file__))
def bad(path):
    return ((not os.path.isabs(path)) or os.path.dirname(path) == '/' or
            path.startswith('/var') or path.startswith('/usr') or
            (not path.startswith(mydir)))
for f in sys.argv[1:]:
    if bad(f):
        errors.append("cannot remove %s from %s" % (f, mydir))
        continue
    try:
        if os.path.isfile(f):
            os.remove(f)
        elif os.path.isdir(f):
            if os.path.isfile(os.path.join(f, 'crm_script.debug')):
                print(open(os.path.join(f, 'crm_script.debug')).read())

            # to check whether this clean request came from health
            # if it does, delete all except health-report
            del_flag = 0
            for x in os.listdir(f):
                if x.startswith("health-report"):
                    del_flag = 1

            if del_flag == 1:
                for x in os.listdir(f):
                    if x.startswith("health-report"):
                        continue
                    if os.path.isfile(x):
                        os.remove(x)
                    elif os.path.isdir(x):
                        shutil.rmtree(x)
            else:
                shutil.rmtree(f)
    except OSError as e:
        errors.append(e)
if errors:
    print('\n'.join(errors), file=sys.stderr)
    sys.exit(1)
