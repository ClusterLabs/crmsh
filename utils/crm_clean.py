#!/usr/bin/env python
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
                print open(os.path.join(f, 'crm_script.debug')).read()
            shutil.rmtree(f)
    except OSError, e:
        errors.append(e)
if errors:
    print >>sys.stderr, '\n'.join(errors)
    sys.exit(1)
