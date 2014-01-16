import os
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
def host():
    return os.uname()[1]
_input = None
def get_input():
    global _input
    if _input is None:
        _input =  json.load(open('./script.input'))
    return _input
def parameters():
    return get_input()[0]
def param(name):
    return parameters().get(name)
def output(step_idx):
    if step_idx < len(get_input()):
        return get_input()[step_idx]
    return {}
def exit_fail(msg):
    print >>sys.stderr, msg
    sys.exit(1)
def exit_ok(data):
    print json.dumps(data)
    sys.exit(0)
def is_true(s):
    if s in (True, False):
        return s
    return s.lower() in ('yes', 'true', '1', 'on')
def service(name, action):
    return call(['systemctl', action, name + '.service'])
def package(name, state):
    rc, out, err = call(['./crm_pkg.py', '-n', name, '-s', state])
    if rc != 0:
        raise IOError(err)
    return json.loads(out)
def check_package(name, state):
    rc, out, err = call(['./crm_pkg.py', '--dry-run', '-n', name, '-s', state])
    if rc != 0:
        raise IOError(err)
    return json.loads(out)
def rpmcheck(names):
    rc, out, err = call(['./crm_rpmcheck.py'] + names)
    if rc != 0:
        raise IOError(err)
    return json.loads(out)
