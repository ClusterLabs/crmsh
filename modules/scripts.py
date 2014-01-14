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

import config
import yaml
import time
import random
import os
import subprocess
import shutil
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


_SCRIPTS_DIR = [os.path.join(userdir.CONFIG_HOME, 'scripts'),
                os.path.join(config.path.sharedir, 'scripts')]


def _check_control_persist():
    '''
    Checks if ControlPersist is available. If so,
    we'll use it to make things faster.
    '''
    cmd = subprocess.Popen('ssh -o ControlPersist'.split(),
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
    (out, err) = cmd.communicate()
    return "Bad configuration option" not in err


def _remote_tmp_basename():
    '''
    Generate a temporary folder name to use remotely
    '''
    # TODO: make use of /tmp configurable
    basefile = 'crm-tmp-%s-%s' % (time.time(), random.randint(0, 2**48))
    basetmp = os.path.join(utils.get_tempdir(), basefile)
    return basetmp


def resolve_script(name):
    for d in _SCRIPTS_DIR:
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
    for d in _SCRIPTS_DIR:
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
                return name, typ, step['typ'].strip()
    return name, None, None


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
    if not os.path.isfile(os.path.join(scriptdir, step_call)):
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
    if params:
        desc += "Parameters (* = Required):\n"
        for p in params:
            rq = ''
            if p.get('required'):
                rq = '*'
            desc += "  %-24s %s\n" % (p['name'] + rq, p.get('description', ''))

    e = HelpEntry(script.get('name', name), desc)
    e.paginate()


def run(host_aliases, name, args, dry_run=False):
    '''
    Run the given script on the given set of hosts
    '''
    if not has_pssh:
        raise ValueError("PSSH library is not installed or is not up to date.")

    remote_tmp = _remote_tmp_basename()
    try:
        filename = resolve_script(name)
        main = verify(name)
        if main is None:
            raise ValueError('Loading script failed: ' + name)

        script_dir = os.path.dirname(filename)

        # process parameters
        params = {}
        for key, val in utils.nvpairs2dict(args).iteritems():
            params[key] = val
        for param in main['parameters']:
            name = param['name']
            if name not in params:
                if 'default' in param:
                    params[name] = param['default']
                else:
                    raise ValueError("Missing required parameter %s" % (name))

        # use cluster nodes if none are given
        if host_aliases is None:
            host_aliases = utils.list_cluster_nodes()
        if not host_aliases:
            raise ValueError("No hosts")

        err_buf.info(main['name'])
        err_buf.info("Nodes: " + ', '.join(host_aliases))

        local_node = utils.this_node()
        if local_node in host_aliases:
            host_aliases = list(host_aliases)
            host_aliases.remove(local_node)
        else:
            local_node = None

        # TODO: allow more options here, like user, port...
        opts = pssh.Options()
        opts.timeout = 60
        opts.recursive = True
        #_has_controlpersist = _check_control_persist()
        #if _has_controlpersist:
        #    opts.ssh_options += ["ControlMaster=auto",
        #                         "ControlPersist=30s",
        #                         "ControlPath=/tmp/crm-ssh-%r@%h:%p"]
        # unfortunately, due to bad interaction between pssh and ssh,
        # ControlPersist is broken
        # See: http://code.google.com/p/parallel-ssh/issues/detail?id=67
        # Fixed in openssh 6.3
        opts.ssh_options += ['ControlPersist=no']

        # create temporary working folder locally,
        # and prepare files to send to other nodes
        if subprocess.call(["mkdir", "-p", os.path.dirname(remote_tmp)], shell=False) != 0:
            raise ValueError("Failed to create temporary working directory")
        try:
            shutil.copytree(script_dir, remote_tmp)
        except (IOError, OSError), e:
            raise ValueError(e)
        try:
            import glob
            for f in glob.glob(os.path.join(config.path.sharedir, 'utils/*.py')):
                shutil.copy(os.path.join(config.path.sharedir, f), remote_tmp)
        except (IOError, OSError), e:
            raise ValueError(e)

        # Create temporary working folders remotely
        ok = True
        for host, result in pssh.call(host_aliases,
                                      "mkdir -p %s" % (os.path.dirname(remote_tmp)),
                                      opts).iteritems():
            if isinstance(result, pssh.Error):
                err_buf.error("[%s]: %s" % (host, result))
                ok = False
            else:
                err_buf.ok("[%s]: Create working folder" % (host))
        if not ok:
            raise ValueError("Failed to create working folders, aborting.")

        # and copy script data to remote nodes
        for host, result in pssh.copy(host_aliases,
                                      remote_tmp,
                                      remote_tmp, opts).iteritems():
            if isinstance(result, pssh.Error):
                err_buf.error("[%s]: %s" % (host, result))
                ok = False
            else:
                err_buf.ok("[%s]: Copy script data" % (host))
        if not ok:
            raise ValueError("Failed when copying script data, aborting.")

        # Ok, now we work from the temporary folder
        script_dir = remote_tmp
        # make sure all path references are relative to the script directory
        os.chdir(script_dir)

        # data passed to steps
        # built up as steps are processed
        # hostname is replaced for each node
        data = [params]

        for step in main['steps']:
            step_name, step_type, step_call = _step_action(step)

            # TODO: run asynchronously on remote nodes
            # run on remote nodes
            # run on local nodes
            # TODO: wait for remote results

            cmdline = 'cd "%s"; ./%s' % (remote_tmp, step_call)

            # update script.input
            input_file = os.path.join(remote_tmp, 'script.input')
            json.dump(data, open(input_file, 'w'))
            if not _copy_to_all(remote_tmp, host_aliases,
                                local_node, input_file, input_file, opts):
                raise ValueError("Failed when updating input, aborting.")

            if step_type == 'collect':
                step_result = {}
                for host, result in pssh.call(host_aliases,
                                              cmdline,
                                              opts).iteritems():
                    if isinstance(result, pssh.Error):
                        err_buf.error("[%s]: %s" % (host, result))
                        ok = False
                    else:
                        rc, out, err = result
                        if rc != 0:
                            err_buf.error("[%s]: %s" % (host, err))
                            ok = False
                        else:
                            step_result[host] = json.loads(out)
                if local_node:
                    rc, out, err = utils.get_stdout_stderr(cmdline)
                    if rc != 0:
                        err_buf.error("[%s]: %s" % (local_node, err))
                        ok = False
                    else:
                        step_result[local_node] = json.loads(out)
                if ok:
                    data.append(step_result)
                    err_buf.ok(step_name)
            elif step_type == 'apply':
                if dry_run:
                    break
                step_result = {}
                for host, result in pssh.call(host_aliases,
                                              cmdline,
                                              opts).iteritems():
                    if isinstance(result, pssh.Error):
                        err_buf.error("[%s]: %s" % (host, result))
                        ok = False
                    else:
                        rc, out, err = result
                        if rc != 0:
                            err_buf.error("[%s]: %s" % (host, err))
                            ok = False
                        else:
                            step_result[host] = json.loads(out)
                if local_node:
                    rc, out, err = utils.get_stdout_stderr(cmdline)
                    if rc != 0:
                        err_buf.error("[%s]: %s" % (host, err))
                        ok = False
                    else:
                        step_result[local_node] = json.loads(out)
                if ok:
                    data.append(step_result)
                    err_buf.ok(step_name)
            elif step_type == 'validate':
                # execute script locally
                # update params with returned updated values
                rc, out = utils.get_stdout(cmdline)
                if rc != 0:
                    ok = False
                elif out:
                    outp = json.loads(out)
                    for k, v in outp:
                        data[0][k] = v
                if ok:
                    err_buf.ok(step_name)
            elif step_type == 'apply_local':
                if dry_run:
                    break
                rc, out = utils.get_stdout(cmdline)
                if rc != 0:
                    ok = False
                elif out:
                    outp = json.loads(out)
                    data.append(outp)
                if ok:
                    err_buf.ok(step_name)
            elif step_type == 'report':
                rc, out = utils.get_stdout(cmdline)
                if rc != 0:
                    ok = False
                else:
                    print out
            if not ok:
                raise ValueError("%s [FAIL]: Aborting." % (step_name))
    except (OSError, IOError), e:
        import traceback
        traceback.print_exc()
        raise ValueError("Internal error: %s" % (e))
    finally:
        # TODO: safe cleanup on remote nodes
        for host, result in pssh.call(host_aliases,
                                      "%s %s" % (os.path.join(remote_tmp, 'crm_clean.py'),
                                                 remote_tmp),
                                      opts).iteritems():
            if isinstance(result, pssh.Error):
                err_buf.warning("[%s]: Failed to clean up %s" % (host, remote_tmp))
                ok = False
        if os.path.isdir(remote_tmp):
            shutil.rmtree(remote_tmp)


def _copy_to_all(remote_tmp, host_aliases, local_node, src, dst, opts):
    ok = True
    ret = pssh.copy(host_aliases, src, dst, opts)
    for host, result in ret.iteritems():
        if isinstance(result, pssh.Error):
            err_buf.error("[%s]: %s" % (host, result))
            ok = False
        else:
            rc, out, err = result
            if rc != 0:
                err_buf.error("[%s]: %s" % (host, err))
                ok = False
    if local_node and not src.startswith(remote_tmp):
        try:
            if os.path.isfile(src):
                shutil.copy(src, dst)
            else:
                shutil.copytree(src, dst)
        except (IOError, OSError), e:
            err_buf.error("[%s]: %s" % (utils.this_node(), e))
            ok = False
    return ok
