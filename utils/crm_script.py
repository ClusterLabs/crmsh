import sys
import subprocess as proc
try:
    import json
except ImportError:
    import simplejson as json
def call(cmd, shell=False):
    p = proc.Popen(cmd, shell=shell, stdin=None, stdout=proc.PIPE, stderr=proc.PIPE)
    out, err = p.communicate()
    return p.returncode, out.strip(), err.strip()
def get_input():
    return json.load(open('./script.input'))
def exit_fail(msg):
    print >>sys.stderr, msg
    sys.exit(1)
def exit_ok(data):
    print json.dumps(data)
    sys.exit(0)
def is_true(s):
    return s.lower() in ('yes', 'true', '1', 'on')
def service(name, action):
    return call('service', name, action)
def package(name, state):
    rc, out, err = call(['./package_manager.py', '-n', name, '-s', state])
    if rc != 0:
        raise IOError(err)
    return json.loads(out)
def check_package(name, state):
    rc, out, err = call(['./package_manager.py', '--dry-run', '-n', name, '-s', state])
    if rc != 0:
        raise IOError(err)
    return json.loads(out)
def rpmcheck(names):
    rc, out, err = call(['./rpmcheck.py'] + names)
    if rc != 0:
        raise IOError(err)
    return json.loads(out)
