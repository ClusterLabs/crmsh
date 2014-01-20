import os
import sys
import getpass
import select
import subprocess as proc
try:
    import json
except ImportError:
    import simplejson as json

_input = None

# read stdin, if there's anything to read
_stdin_data = {}
while sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
    line = sys.stdin.readline()
    if line:
        d = line.split(':', 1)
        if len(d) == 2:
            _stdin_data[d[0].strip()] = d[1].strip()
    else:
        break


def host():
    return os.uname()[1]


def get_input():
    global _input
    if _input is None:
        _input = json.load(open('./script.input'))
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


def call(cmd, shell=False):
    p = proc.Popen(cmd, shell=shell, stdin=None, stdout=proc.PIPE, stderr=proc.PIPE)
    out, err = p.communicate()
    return p.returncode, out.strip(), err.strip()


def sudo_call(cmd, shell=False):
    if getpass.getuser() == 'root' or not is_true(param('sudo')) or not _stdin_data.get('sudo'):
        return call(cmd, shell=shell)
    os.unsetenv('SSH_ASKPASS')
    call(['sudo', '-k'], shell=False)
    sudo_prompt = 'crm_script_sudo_prompt'
    cmd = ['sudo', '-H', '-S', '-p', sudo_prompt] + cmd
    p = proc.Popen(cmd, shell=shell, stdin=proc.PIPE, stdout=proc.PIPE, stderr=proc.PIPE)
    sudo_pass = _stdin_data.get('sudo', 'linux')
    out, err = p.communicate(input=sudo_pass)
    return p.returncode, out.strip(), err.strip()


def service(name, action):
    if action.startswith('is-'):
        return call(['/usr/bin/systemctl', action, name + '.service'])
    return sudo_call(['/usr/bin/systemctl', action, name + '.service'])


def package(name, state):
    rc, out, err = sudo_call(['./crm_pkg.py', '-n', name, '-s', state])
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
