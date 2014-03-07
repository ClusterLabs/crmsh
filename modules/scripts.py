# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
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

import sys
import time
import random
import os
import shutil
import getpass
import subprocess
import yaml
import config
import options
from msg import err_buf
import userdir

try:
    from psshlib import api as pssh
    has_pssh = True
except ImportError:
    has_pssh = False

import utils

try:
    import json
except ImportError:
    import simplejson as json


def script_dirs():
    ret = []
    for d in options.scriptdir.split(';'):
        if d and os.path.isdir(d):
            ret.append(d)
    ret.append(os.path.join(userdir.CONFIG_HOME, 'scripts'))
    ret.append(os.path.join(config.path.sharedir, 'scripts'))
    return ret


def _check_control_persist():
    '''
    Checks if ControlPersist is available. If so,
    we'll use it to make things faster.
    '''
    cmd = 'ssh -o ControlPersist'.split()
    if options.regression_tests:
        print ".EXT", cmd
    cmd = subprocess.Popen(cmd,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
    (out, err) = cmd.communicate()
    return "Bad configuration option" not in err


def _generate_workdir_name():
    '''
    Generate a temporary folder name to use while
    running the script
    '''
    # TODO: make use of /tmp configurable
    basefile = 'crm-tmp-%s-%s' % (time.time(), random.randint(0, 2**48))
    basetmp = os.path.join(utils.get_tempdir(), basefile)
    return basetmp


def resolve_script(name):
    for d in script_dirs():
        script_main = os.path.join(d, name, 'main.yml')
        if os.path.isfile(script_main):
            return script_main
    return None


def list_scripts():
    '''
    List the available cluster installation scripts.
    '''
    l = []

    def path_combine(p0, p1):
        if p0:
            return os.path.join(p0, p1)
        return p1

    def recurse(root, prefix):
        try:
            curdir = path_combine(root, prefix)
            for f in os.listdir(curdir):
                if os.path.isdir(os.path.join(curdir, f)):
                    if os.path.isfile(os.path.join(curdir, f, 'main.yml')):
                        l.append(path_combine(prefix, f))
                    else:
                        recurse(root, path_combine(prefix, f))
        except OSError:
            pass
    for d in script_dirs():
        recurse(d, '')
    return sorted(l)


def load_script(script):
    main = resolve_script(script)
    if main and os.path.isfile(main):
        return yaml.load(open(main))[0]
    return None


def _step_action(step):
    name = step.get('name')
    if 'type' in step:
        return name, step.get('type'), step.get('call')
    else:
        for typ in ['collect', 'validate', 'apply', 'apply_local', 'report']:
            if typ in step:
                return name, typ, step[typ].strip()
    return name, None, None


def arg0(cmd):
    return cmd.split()[0]


def _verify_step(scriptdir, scriptname, step):
    step_name, step_type, step_call = _step_action(step)
    if not step_name:
        raise ValueError("Error in %s: Step missing name" % (scriptname))
    if not step_type:
        raise ValueError("Error in %s: Step '%s' has no action defined" %
                         (scriptname, step_name))
    if not step_call:
        raise ValueError("Error in %s: Step '%s' has no call defined" %
                         (scriptname, step_name))
    if not os.path.isfile(os.path.join(scriptdir, arg0(step_call))):
        raise ValueError("Error in %s: Step '%s' file not found: %s" %
                         (scriptname, step_name, step_call))


def verify(name):
    script = resolve_script(name)
    if not script:
        raise ValueError("%s not found" % (name))
    script_dir = os.path.dirname(script)
    main = load_script(name)
    for key in ['name', 'description', 'parameters', 'steps']:
        if key not in main:
            raise ValueError("Error in %s: Missing %s" % (name, key))
    for step in main.get('steps', []):
        _verify_step(script_dir, name, step)
    return main


def common_params():
    "Parameters common to all cluster scripts"
    return [('nodes', None, 'List of nodes to execute the script for'),
            ('dry_run', 'no', 'If set, only execute collecting and validating steps'),
            ('step', None, 'If set, only execute the named step'),
            ('statefile', None, 'When single-stepping, the state is saved in the given file'),
            ('user', config.core.user or None, 'Run script as the given user'),
            ('sudo', 'no',
             'If set, crm will prompt for a sudo password and use sudo when appropriate'),
            ('port', None, 'Port to connect on'),
            ('timeout', '600', 'Execution timeout in seconds')]


def common_param_default(name):
    for param, default, _ in common_params():
        if param == name:
            return default
    return None


def describe(name):
    '''
    Prints information about the given script.
    '''
    script = load_script(name)
    from help import HelpEntry

    def rewrap(txt):
        import textwrap
        paras = []
        for para in txt.split('\n'):
            paras.append('\n'.join(textwrap.wrap(para)))
        return '\n\n'.join(paras)
    desc = rewrap(script.get('description', 'No description available'))

    params = script.get('parameters', [])
    desc += "Parameters (* = Required):\n"
    for name, value, description in common_params():
        if value is not None:
            defval = ' (default: %s)' % (value)
        else:
            defval = ''
        desc += "  %-24s %s%s\n" % (name, description, defval)
    for p in params:
        rq = ''
        if p.get('required'):
            rq = '*'
        defval = p.get('default', None)
        if defval is not None:
            defval = ' (default: %s)' % (defval)
        else:
            defval = ''
        desc += "  %-24s %s%s\n" % (p['name'] + rq, p.get('description', ''), defval)

    desc += "\nSteps:\n"
    for step in script.get('steps', []):
        name = step.get('name')
        if name:
            desc += "  * %s\n" % (name)

    e = HelpEntry(script.get('name', name), desc)
    e.paginate()


def param_completion_list(name):
    "Returns completions for the given script"
    try:
        script = load_script(name)
        ps = [p['name'] + '=' for p in script.get('parameters', [])]
        ps += [p[0] + '=' for p in common_params()]
        return ps
    except Exception:
        return [p[0] + '=' for p in common_params()]


def _make_options(params):
    "Setup pssh options."
    opts = pssh.Options()
    opts.timeout = int(params['timeout'])
    opts.recursive = True
    opts.ssh_options += [
        'KbdInteractiveAuthentication=no',
        'PreferredAuthentications=gssapi-with-mic,gssapi-keyex,hostbased,publickey',
        'PasswordAuthentication=no',
        'StrictHostKeyChecking=no',
        'ControlPersist=no']
    if config.core.debug:
        opts.ssh_extra += ['-vvv']
    return opts


def _open_script(name):
    filename = resolve_script(name)
    main = verify(name)
    if main is None or filename is None:
        raise ValueError('Loading script failed: ' + name)
    script_dir = os.path.dirname(filename)
    return main, filename, script_dir


def _filter_dict(d, name, fn, *args):
    'filter the given element in the dict through the function fn'
    d[name] = fn(d[name], *args)


def _filter_nodes(nodes, user, port):
    'filter function for the nodes element'
    if nodes:
        nodes = nodes.replace(',', ' ').split()
    else:
        nodes = utils.list_cluster_nodes()
    if not nodes:
        raise ValueError("No hosts")
    nodes = [(node, port or None, user or None) for node in nodes]
    return nodes


def _parse_parameters(name, args, main):
    '''
    Parse run parameters into a dict.
    '''
    args = utils.nvpairs2dict(args)
    params = {}
    for key, default, _ in common_params():
        params[key] = default
    for key, val in args.iteritems():
        params[key] = val
    for param in main['parameters']:
        name = param['name']
        if name not in params:
            if 'default' not in param:
                raise ValueError("Missing required parameter %s" % (name))
            params[name] = param['default']

    user = params['user']
    port = params['port']
    _filter_dict(params, 'nodes', _filter_nodes, user, port)
    _filter_dict(params, 'dry_run', utils.is_boolean_true)
    _filter_dict(params, 'sudo', utils.is_boolean_true)
    _filter_dict(params, 'statefile', lambda x: (x and os.path.abspath(x)) or x)
    if config.core.debug:
        params['debug'] = True
    return params


def _extract_localnode(hosts):
    """
    Remove loal node from hosts list, so
    we can treat it separately
    """
    this_node = utils.this_node()
    hosts2 = []
    local_node = None
    for h, p, u in hosts:
        if h != this_node:
            hosts2.append((h, p, u))
        else:
            local_node = (h, p, u)
    return local_node, hosts2


def _set_controlpersist(opts):
    #_has_controlpersist = _check_control_persist()
    #if _has_controlpersist:
    #    opts.ssh_options += ["ControlMaster=auto",
    #                         "ControlPersist=30s",
    #                         "ControlPath=/tmp/crm-ssh-%r@%h:%p"]
    # unfortunately, due to bad interaction between pssh and ssh,
    # ControlPersist is broken
    # See: http://code.google.com/p/parallel-ssh/issues/detail?id=67
    # Fixed in openssh 6.3
    pass


def _create_script_workdir(scriptdir, workdir):
    "Create workdir and copy contents of scriptdir into it"
    cmd = ["mkdir", "-p", os.path.dirname(workdir)]
    if options.regression_tests:
        print ".EXT", cmd
    if subprocess.call(cmd, shell=False) != 0:
        raise ValueError("Failed to create temporary working directory")
    try:
        shutil.copytree(scriptdir, workdir)
    except (IOError, OSError), e:
        raise ValueError(e)


def _copy_utils(dst):
    '''
    Copy run utils to the destination directory
    '''
    try:
        import glob
        for f in glob.glob(os.path.join(config.path.sharedir, 'utils/*.py')):
            shutil.copy(os.path.join(config.path.sharedir, f), dst)
    except (IOError, OSError), e:
        raise ValueError(e)


def _create_remote_workdirs(hosts, path, opts):
    "Create workdirs on remote hosts"
    ok = True
    for host, result in pssh.call(hosts,
                                  "mkdir -p %s" % (os.path.dirname(path)),
                                  opts).iteritems():
        if isinstance(result, pssh.Error):
            err_buf.error("[%s]: %s" % (host, result))
            ok = False
    if not ok:
        raise ValueError("Failed to create working folders, aborting.")


def _copy_to_remote_dirs(hosts, path, opts):
    "Copy a local folder to same location on remote hosts"
    ok = True
    for host, result in pssh.copy(hosts,
                                  path,
                                  path, opts).iteritems():
        if isinstance(result, pssh.Error):
            err_buf.error("[%s]: %s" % (host, result))
            ok = False
    if not ok:
        raise ValueError("Failed when copying script data, aborting.")


def _copy_to_all(workdir, hosts, local_node, src, dst, opts):
    """
    Copy src to dst both locally and remotely
    """
    ok = True
    ret = pssh.copy(hosts, src, dst, opts)
    for host, result in ret.iteritems():
        if isinstance(result, pssh.Error):
            err_buf.error("[%s]: %s" % (host, result))
            ok = False
        else:
            rc, out, err = result
            if rc != 0:
                err_buf.error("[%s]: %s" % (host, err))
                ok = False
    if local_node and not src.startswith(workdir):
        try:
            if os.path.abspath(src) != os.path.abspath(dst):
                if os.path.isfile(src):
                    shutil.copy(src, dst)
                else:
                    shutil.copytree(src, dst)
        except (IOError, OSError, shutil.Error), e:
            err_buf.error("[%s]: %s" % (utils.this_node(), e))
            ok = False
    return ok


class RunStep(object):
    def __init__(self, main, params, local_node, hosts, opts, workdir):
        self.main = main
        self.data = [params]
        self.local_node = local_node
        self.hosts = hosts
        self.opts = opts
        self.dry_run = params.get('dry_run', False)
        self.sudo = params.get('sudo', False)
        self.workdir = workdir
        self.statefile = os.path.join(self.workdir, 'script.input')
        self.dstfile = os.path.join(self.workdir, 'script.input')
        self.in_progress = False
        self.sudo_pass = None

    def _build_cmdline(self, sname, stype, scall):
        cmdline = 'cd "%s"; ./%s' % (self.workdir, scall)
        if config.core.debug:
            import pprint
            print "** %s [%s] - %s" % (sname, stype, scall)
            print cmdline
            pprint.pprint(self.data)
        return cmdline

    def single_step(self, step_name, statefile):
        self.statefile = statefile
        for step in self.main['steps']:
            name, action, call = _step_action(step)
            if name == step_name:
                # if this is not the first step, load step data
                if step != self.main['steps'][0]:
                    if os.path.isfile(statefile):
                        self.data = json.load(open(statefile))
                    else:
                        raise ValueError("No state for step: %s" % (step_name))
                result = self.run_step(name, action, call)
                json.dump(self.data, open(self.statefile, 'w'))
                return result
        err_buf.error("%s: Step not found" % (step_name))
        return False

    def _update_state(self):
        json.dump(self.data, open(self.statefile, 'w'))
        return _copy_to_all(self.workdir,
                            self.hosts,
                            self.local_node,
                            self.statefile,
                            self.dstfile,
                            self.opts)

    def start(self, txt):
        if not options.batch:
            sys.stdout.write(txt)
            sys.stdout.flush()
            self.in_progress = True

    def flush(self):
        if self.in_progress:
            self.in_progress = False
            sys.stdout.write('\r')
            sys.stdout.flush()

    def ok(self, fmt, *args):
        self.flush()
        err_buf.ok(fmt % args)

    def out(self, fmt, *args):
        self.flush()
        print fmt % args

    def error(self, fmt, *args):
        self.flush()
        err_buf.error(fmt % args)

    def debug(self, msg):
        err_buf.debug(msg)

    def run_step(self, name, action, call):
        """
        Execute a single step
        """

        self.start('%s...' % (name))
        try:
            cmdline = self._build_cmdline(name, action, call)
            if not self._update_state():
                raise ValueError("Failed when updating input, aborting.")
            output = None
            ok = False
            if action in ('collect', 'apply'):
                result = self._process_remote(cmdline)
                if result is not None:
                    self.data.append(result)
                    ok = True
            elif action == 'validate':
                result = self._process_local(cmdline)
                if result is not None:
                    if result:
                        result = json.loads(result)
                    else:
                        result = {}
                    self.data.append(result)
                    if isinstance(result, dict):
                        for k, v in result.iteritems():
                            self.data[0][k] = v
                    ok = True
            elif action == 'apply_local':
                result = self._process_local(cmdline)
                if result is not None:
                    if result:
                        result = json.loads(result)
                    else:
                        result = {}
                    self.data.append(result)
                    ok = True
            elif action == 'report':
                result = self._process_local(cmdline)
                if result is not None:
                    output = result
                    ok = True
            if ok:
                self.ok(name)
            if output:
                self.out(output)
            return ok
        finally:
            self.flush()

    def all_steps(self):
        # TODO: run asynchronously on remote nodes
        # run on remote nodes
        # run on local nodes
        # TODO: wait for remote results
        for step in self.main['steps']:
            name, action, call = _step_action(step)
            if action in ('apply', 'apply_local'):
                if self.dry_run:
                    break
                self._check_sudo_pass()
            if not self.run_step(name, action, call):
                return False
        return True

    def _check_sudo_pass(self):
        if self.sudo and not self.sudo_pass:
            prompt = "sudo password: "
            self.sudo_pass = getpass.getpass(prompt=prompt)

    def _process_remote(self, cmdline):
        """
        Handle a step that executes on all nodes
        """
        ok = True
        step_result = {}

        if self.sudo_pass:
            self.opts.input_stream = u'sudo: %s\n' % (self.sudo_pass)
        else:
            self.opts.input_stream = None

        for host, result in pssh.call(self.hosts,
                                      cmdline,
                                      self.opts).iteritems():
            if isinstance(result, pssh.Error):
                self.error("[%s]: %s", host, result)
                ok = False
            else:
                rc, out, err = result
                if rc != 0:
                    self.error("[%s]: %s%s", host, out, err)
                    ok = False
                else:
                    step_result[host] = json.loads(out)
        if self.local_node:
            ret = self._process_local(cmdline)
            if ret is None:
                ok = False
            else:
                step_result[self.local_node[0]] = json.loads(ret)
        if ok:
            self.debug("%s" % repr(step_result))
            return step_result
        return None

    def _process_local(self, cmdline):
        """
        Handle a step that executes locally
        """
        if self.sudo_pass:
            input_s = u'sudo: %s\n' % (self.sudo_pass)
        else:
            input_s = None
        rc, out, err = utils.get_stdout_stderr(cmdline, input_s=input_s, shell=True)
        if rc != 0:
            self.error("[%s]: Error (%d): %s", self.local_node[0], rc, err)
            return None
        self.debug("%s" % repr(out))
        return out


def _run_cleanup(hosts, workdir, opts):
    "Clean up after the cluster script"
    if hosts and workdir:
        for host, result in pssh.call(hosts,
                                      "%s %s" % (os.path.join(workdir, 'crm_clean.py'),
                                                 workdir),
                                      opts).iteritems():
            if isinstance(result, pssh.Error):
                err_buf.warning("[%s]: Failed to clean up %s: %s" % (host, workdir, result))
            else:
                rc, out, err = result
                print out
    if workdir and os.path.isdir(workdir):
        shutil.rmtree(workdir)


def _print_debug(hosts, workdir, opts):
    "Print debug output (if any)"
    dbglog = os.path.join(workdir, 'crm_script.debug')
    for host, result in pssh.call(hosts,
                                  "[ -f '%s' ] && cat '%s'" % (dbglog, dbglog),
                                  opts).iteritems():
        if isinstance(result, pssh.Error):
            err_buf.error("[%s]: %s" % (host, result))
        else:
            rc, out, err = result
            print out
            print err


def run(name, args):
    '''
    Run the given script on the given set of hosts
    name: a cluster script is a folder <name> containing a main.yml file
    args: list of nvpairs
    '''
    if not has_pssh:
        raise ValueError("PSSH library is not installed or is not up to date.")
    workdir = _generate_workdir_name()
    main, filename, script_dir = _open_script(name)
    params = _parse_parameters(name, args, main)
    if params['askpass'] and not utils.is_program('sshpass'):
        raise ValueError("The program 'sshpass' is required to use SSH password login.")
    hosts = params['nodes']
    err_buf.info(main['name'])
    err_buf.info("Nodes: " + ', '.join([x[0] for x in hosts]))
    local_node, hosts = _extract_localnode(hosts)
    opts = _make_options(params)
    _set_controlpersist(opts)

    try:
        _create_script_workdir(script_dir, workdir)
        _copy_utils(workdir)
        _create_remote_workdirs(hosts, workdir, opts)
        _copy_to_remote_dirs(hosts, workdir, opts)
        # make sure all path references are relative to the script directory
        os.chdir(workdir)

        stepper = RunStep(main, params, local_node, hosts, opts, workdir)
        step = params['step']
        statefile = params['statefile']
        if step or statefile:
            if not step or not statefile:
                raise ValueError("Must set both step and statefile")
            return stepper.single_step(step, statefile)
        else:
            return stepper.all_steps()

    except (OSError, IOError), e:
        import traceback
        traceback.print_exc()
        raise ValueError("Internal error while running %s: %s" % (name, e))
    finally:
        if not config.core.debug:
            _run_cleanup(hosts, workdir, opts)
        else:
            _print_debug(hosts, workdir, opts)
