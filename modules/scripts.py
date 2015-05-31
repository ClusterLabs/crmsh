# Copyright (C) 2015 Kristoffer Gronlund <kgronlund@suse.com>
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
#
# A rewrite of cluster scripts with more functionality built in
# (including a mustashe-like templating language), and a JSON API
# for Hawk to use.

import os
import sys
import subprocess
import getpass
import time
import shutil
import random
from glob import glob
from lxml import etree

try:
    import json
except ImportError:
    import simplejson as json


try:
    import parallax
except ImportError:
    pass


from . import config
from . import handles
from . import options
from . import userdir
from . import utils
from .msg import err_buf, common_debug


_script_cache = None
_script_version = 2.2


class Actions(object):
    """
    Each method in this class handles a particular step action.
    """
    def collect(self, step):
        step.set_nodes()
        step.run_command()
        step.record_json()

    def validate(self, step):
        step.set_local()
        step.run_command()
        step.validate_json()

    def apply(self, step):
        step.set_nodes()
        step.run_command()
        step.record_json()

    def apply_local(self, step):
        step.set_local()
        step.run_command()
        step.record_json()

    def report(self, step):
        step.set_local()
        step.run_command()
        step.out()

    def call(self, step):
        step.set_nodes()
        step.execute_shell()

    def cib(self, step):
        # generate cib
        # runner.execute_local("crm configure load update ./step_cib")
        txt = step.parse_text()
        fn = utils.str2tmp(txt)
        step.set_local()
        step.execute(['crm', 'configure', 'load', 'update', fn])

    def install(self, step):
        step.set_nodes()
        step.copy_and_run('''#!/usr/bin/env python
import crm_script
import crm_init

crm_init.install_packages(%s)
crm_script.exit_ok(True)
        ''' % (step.data['packages']))

    def service(self, step):
        services = "\n".join([('crm_script.service(%s, %s)' % (s['name'], s['action']))
                              for s in step.data['services']])
        step.set_nodes()
        step.copy_and_run('''#!/usr/bin/env python
import crm_script
import crm_init

%s
crm_script.exit_ok(True)
''' % (services))

_actions = dict([(n, getattr(Actions, n)) for n in dir(Actions) if not n.startswith('_')])


def _find_action(step):
    """return name of action for step"""
    for a in _actions.keys():
        if a in step:
            return a
    return None


def _make_options(params):
    "Setup parallax options."
    opts = parallax.Options()
    opts.inline = True
    opts.timeout = int(params['timeout'])
    opts.recursive = True
    opts.ssh_options += [
        'KbdInteractiveAuthentication=no',
        'PreferredAuthentications=gssapi-with-mic,gssapi-keyex,hostbased,publickey',
        'PasswordAuthentication=no',
        'StrictHostKeyChecking=no',
        'ControlPersist=no']
    if options.regression_tests:
        opts.ssh_extra += ['-vvv']
    return opts


def _parse_yaml(scriptname, scriptfile):
    data = None
    try:
        import yaml
        with open(scriptfile) as f:
            data = yaml.load(f)[0]
    except ImportError as e:
        raise ValueError("Failed to load yaml module: %s" % (e))
    except Exception as e:
        raise ValueError("Failed to parse script main: %s" % (e))

    if data:
        ver = data.get('version')
        if ver is None or str(ver) != str(_script_version):
            data = _upgrade_yaml(data)

    if 'parameters' in data:
        data['steps'] = [{'parameters': data['parameters']}]
        del data['parameters']
    else:
        data['steps'] = []

    if 'name' not in data:
        data['name'] = scriptname

    return data


def _upgrade_yaml(data):
    """
    Upgrade a parsed yaml document from
    an older version.
    """

    if 'version' in data and data['version'] > _script_version:
        raise ValueError("Unknown version (expected < %s, got %s)" % (_script_version, data['version']))

    data['version'] = _script_version
    data['category'] = 'Script'
    if 'name' in data:
        data['shortdesc'] = data['name']
        del data['name']
    if 'description' in data:
        data['longdesc'] = data['description']
        del data['description']

    data['actions'] = data['steps']
    paramstep = {'parameters': data['parameters']}
    data['steps'] = [paramstep]
    del data['parameters']

    for p in paramstep['parameters']:
        if 'description' in p:
            p['shortdesc'] = p['description']
            del p['description']
        if 'required' not in p:
            p['required'] = 'default' not in p

    for action in data['actions']:
        if 'name' in action:
            action['shortdesc'] = action['name']
            del action['name']

    return data


def _append_cib_action(actions, text):
    """
    append the given cib action to the list
    of actions. If the previous action is a
    cib action with no special conditions,
    merge the two.
    """
    if len(actions) and actions[-1].keys() == ['cib']:
        actions[-1]['cib'] = "\n".join([actions[-1]['cib'], text])
    else:
        actions.append({'cib': text})


def _parse_hawk_template(workflow, name, type, step, actions):
    """
    TODO: convert hawk <if>, <insert> tags into handles
    """
    path = os.path.join(os.path.dirname(workflow), '../templates')
    for t in glob(os.path.join(path, '*.xml')):
        xml = etree.parse(t).getroot()
        if xml.get('name') == type:
            common_debug("Found matching template: %s" % (t))
            break
    else:
        raise ValueError("Template not found: %s" % (name))

    step['shortdesc'] = ''.join(xml.xpath('./shortdesc/text()'))
    step['longdesc'] = ''.join(xml.xpath('./longdesc/text()'))

    _append_cib_action(actions, _hawk_to_handles(name, xml.xpath('./crm_script')[0]))

    for item in xml.xpath('./parameters/parameter'):
        obj = {}
        obj['name'] = item.get('name')
        obj['required'] = item.get('required', False)
        content = next(item.iter('content'))
        obj['type'] = content.get('type', 'string')
        obj['default'] = content.get('default', None)
        obj['shortdesc'] = ''.join(item.xpath('./shortdesc/text()'))
        obj['longdesc'] = ''.join(item.xpath('./longdesc/text()'))
        obj['error'] = ''
        obj['when'] = ''
        step['parameters'].append(obj)


def _hawk_to_handles(context, tag):
    """
    input: a context name to prefix variable references with (may be empty)
    and a crm_script tag
    output: text with {{handles}}
    """
    def mkhandle(pfx, scope, text):
        if scope:
            return '{{%s%s:%s}}' % (pfx, scope, text)
        else:
            return '{{%s%s}}' % (pfx, text)

    s = ""
    s += tag.text
    for c in tag:
        if c.tag == 'if':
            cond = c.get('set')
            if cond:
                s += mkhandle('#', context, cond)
                s += _hawk_to_handles(context, c)
                s += mkhandle('/', context, cond)
        elif c.tag == 'insert':
            param = c.get('param')
            src = c.get('from_template') or context
            s += mkhandle('', src, param)
        s += c.tail
    return s


def _parse_hawk_workflow(scriptname, scriptfile):
    """
    TODO: convert hawk <if>, <insert> tags into handles
    """
    xml = etree.parse(scriptfile).getroot()
    if xml.tag != "workflow":
        raise ValueError("Not a hawk workflow: %s" % (scriptfile))
    data = {
        'version': 2.2,
        'name': xml.get('name'),
        'shortdesc': ''.join(xml.xpath('./shortdesc/text()')),
        'longdesc': ''.join(xml.xpath('./longdesc/text()')),
        'category': 'Wizard',
        'include': [],
        'parameters': [],
        'actions': [],
    }

    # the parameters together form a step with an optional stepdesc
    # then each template becomes an additional step with an optional stepdesc
    paramstep = {
        'stepdesc': ''.join(xml.xpath('./parameters/stepdesc/text()')),
        'parameters': []
    }
    data['parameters'].append(paramstep)
    for item in xml.xpath('./parameters/parameter'):
        obj = {}
        obj['name'] = item.get('name')
        obj['required'] = item.get('required', False)
        content = next(item.iter('content'))
        obj['type'] = content.get('type', 'string')
        obj['default'] = content.get('default', None)
        obj['shortdesc'] = ''.join(item.xpath('./shortdesc/text()'))
        obj['longdesc'] = ''.join(item.xpath('./longdesc/text()'))
        obj['error'] = ''
        obj['when'] = ''
        paramstep['parameters'].append(obj)

    data['actions'] = []

    for item in xml.xpath('./templates/template'):
        templatestep = {
            'stepdesc': ''.join(item.xpath('./stepdesc/text()')),
            'name': item.get('name'),
            'required': item.get('required'),
            'parameters': []
        }
        data['parameters'].append(templatestep)

        _parse_hawk_template(scriptfile, item.get('name'), item.get('type', item.get('name')),
                             templatestep, data['actions'])

    _append_cib_action(data['actions'], _hawk_to_handles('', xml.xpath('./crm_script')[0]))

    if config.core.debug:
        import pprint
        print("Parsed hawk workflow:")
        pprint.pprint(data)
    return data


def _build_script_cache():
    global _script_cache
    if _script_cache is not None:
        return
    _script_cache = {}
    for d in _script_dirs():
        if d:
            for s in glob(os.path.join(d, '*/main.yml')):
                name = os.path.dirname(s).split('/')[-1]
                if name not in _script_cache:
                    _script_cache[name] = os.path.join(d, s)
            for s in glob(os.path.join(d, 'workflows/*.xml')):
                name = os.path.splitext(os.path.basename(s))[0]
                if name not in _script_cache:
                    _script_cache[name] = os.path.join(d, s)


def list_scripts():
    '''
    List the available cluster installation scripts.
    Yields the names of the main script files.
    '''
    _build_script_cache()
    return sorted(_script_cache.keys())


def _postprocess_script(data):
    """
    Post-process the parsed script into an executable
    form. This means parsing all included agents and
    scripts, merging parameters, steps and actions.
    """
    ver = data.get('version')
    if ver is None or str(ver) != str(_script_version):
        raise ValueError("Unsupported script version (expected %s, got %s)" % (_script_version, repr(ver)))

    if 'shortdesc' not in data:
        data['shortdesc'] = ''

    if 'longdesc' not in data:
        data['longdesc'] = ''

    if 'category' not in data:
        data['category'] = 'Custom'

    if 'actions' not in data:
        data['actions'] = []

    # includes add parameter steps and actions
    # an agent include works like a hawk template:
    # it adds a parameter step and a cib action
    # a script include however adds any number of
    # parameter steps and actions
    for inc in data.get('include', []):
        pass

    for step in data['steps']:
        if 'stepdesc' not in step:
            step['stepdesc'] = ''
            if 'shortdesc' in step:
                step['stepdesc'] = step['shortdesc']
        for p in step['parameters']:
            if 'name' not in p:
                raise ValueError("Parameter has no name: %s" % (p.keys()))
            if 'shortdesc' not in p:
                p['shortdesc'] = ''

    for item in data.get('actions', []):
        action = _find_action(item)
        if action is None:
            raise ValueError("Unknown action: %s" % (item.keys()))
        item['_name'] = action
        item['_text'] = item[action]
        del item[action]

    return data


def load_script(script):
    _build_script_cache()
    if script not in _script_cache:
        raise ValueError("Script not found: %s" % (script))
    s = _script_cache[script]
    if isinstance(s, basestring):
        if s.endswith('.yml'):
            parsed = _parse_yaml(script, s)
        elif s.endswith('.xml'):
            parsed = _parse_hawk_workflow(script, s)
        if parsed is None:
            raise ValueError("Failed to parse script: %s (%s)" % (script, s))

        obj = _postprocess_script(parsed)
        _script_cache[script] = obj
        return obj
    return s


def _script_dirs():
    "list of directories that may contain cluster scripts"
    ret = [d for d in options.scriptdir.split(';') if d and os.path.isdir(d)]
    return ret + [os.path.join(userdir.CONFIG_HOME, 'scripts'),
                  os.path.join(config.path.sharedir, 'scripts')]


def _check_control_persist():
    '''
    Checks if ControlPersist is available. If so,
    we'll use it to make things faster.
    '''
    cmd = 'ssh -o ControlPersist'.split()
    if options.regression_tests:
        print(".EXT", cmd)
    cmd = subprocess.Popen(cmd,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
    (out, err) = cmd.communicate()
    return "Bad configuration option" not in err


def _parallax_call(hosts, cmd, opts):
    "parallax.call with debug logging"
    if config.core.debug or options.regression_tests:
        err_buf.debug("parallax.call(%s, %s)" % (repr(hosts), cmd))
    return parallax.call(hosts, cmd, opts)


def _resolve_script(name):
    for p in list_scripts():
        if p.endswith('.yml'):
            if os.path.dirname(p).endswith('/' + name):
                return p
        elif p.endswith('.xml'):
            if os.path.splitext(os.path.basename(p))[0] == name:
                return p
    return None


def _parallax_copy(hosts, src, dst, opts):
    "parallax.copy with debug logging"
    if config.core.debug or options.regression_tests:
        err_buf.debug("parallax.copy(%s, %s, %s)" % (repr(hosts), src, dst))
    return parallax.copy(hosts, src, dst, opts)


def _generate_workdir_name():
    '''
    Generate a temporary folder name to use while
    running the script
    '''
    # TODO: make use of /tmp configurable
    basefile = 'crm-tmp-%s-%s' % (time.time(), random.randint(0, 2**48))
    basetmp = os.path.join(utils.get_tempdir(), basefile)
    return basetmp


def _print_output(host, rc, out, err):
    "Print the output from a process that ran on host"
    if out:
        err_buf.ok("[%s]: %s" % (host, out))
    if err:
        err_buf.error("[%s]: %s" % (host, err))


def _print_debug(local_node, hosts, workdir, opts):
    "Print debug output (if any)"
    dbglog = os.path.join(workdir, 'crm_script.debug')
    for host, result in _parallax_call(hosts,
                                       "[ -f '%s' ] && cat '%s'" % (dbglog, dbglog),
                                       opts).iteritems():
        if isinstance(result, parallax.Error):
            err_buf.error("[%s]: %s" % (host, result))
        else:
            _print_output(host, *result)
    if os.path.isfile(dbglog):
        f = open(dbglog).read()
        err_buf.ok("[%s]: %s" % (local_node, f))


def _cleanup_local(workdir):
    "clean up the local tmp dir"
    if workdir and os.path.isdir(workdir):
        cleanscript = os.path.join(workdir, 'crm_clean.py')
        if os.path.isfile(cleanscript):
            if subprocess.call([cleanscript, workdir], shell=False) != 0:
                shutil.rmtree(workdir)
        else:
            shutil.rmtree(workdir)


def _run_cleanup(local_node, hosts, workdir, opts):
    "Clean up after the cluster script"
    if hosts and workdir:
        cleanscript = os.path.join(workdir, 'crm_clean.py')
        for host, result in _parallax_call(hosts,
                                           "%s %s" % (cleanscript,
                                                      workdir),
                                           opts).iteritems():
            if isinstance(result, parallax.Error):
                err_buf.debug("[%s]: Failed to clean up %s" % (host, workdir))
                err_buf.error("[%s]: Clean: %s" % (host, result))
            else:
                _print_output(host, *result)
    _cleanup_local(workdir)


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
    err_buf.debug("Local node: %s, Remote hosts: %s" % (
        local_node,
        ', '.join(h[0] for h in hosts2)))
    return local_node, hosts2


def _common_params():
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


def _common_param_default(name):
    for param, default, _ in _common_params():
        if param == name:
            return default
    return None


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
    for key, default, _ in _common_params():
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


def _set_controlpersist(opts):
    #_has_controlpersist = _check_control_persist()
    #if _has_controlpersist:
    #    opts.ssh_options += ["ControlMaster=auto",
    #                         "ControlPersist=30s",
    #                         "ControlPath=/tmp/crm-ssh-%r@%h:%p"]
    # unfortunately, due to bad interaction between parallax and ssh,
    # ControlPersist is broken
    # See: http://code.google.com/p/parallel-ssh/issues/detail?id=67
    # Fixed in openssh 6.3
    pass


def arg0(cmd):
    return cmd.split()[0]


def _flatten_parameters(steps):
    pret = []
    for step in steps:
        stepname = step.get('name', '')
        for param in step.get('parameters', []):
            if stepname:
                pret.append('%s:%s' % (stepname, param['name']))
            else:
                pret.append(param['name'])
    return pret


def param_completion_list(name):
    """
    Returns completions for the given script
    """
    try:
        script = load_script(name)
        params = _flatten_parameters(script.get('steps', []))
        ps = [p['name'] + '=' for p in params]
        return ps
    except Exception:
        return []


def _step_action(step):
    name = step.get('name')
    if 'type' in step:
        return name, step.get('type'), step.get('call')
    else:
        for typ in ['collect', 'validate', 'apply', 'apply_local', 'report']:
            if typ in step:
                return name, typ, step[typ].strip()
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
    if not os.path.isfile(os.path.join(scriptdir, arg0(step_call))):
        raise ValueError("Error in %s: Step '%s' file not found: %s" %
                         (scriptname, step_name, step_call))


def _verify(name):
    script = _resolve_script(name)
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


def _open_script(name):
    filename = _resolve_script(name)
    main = _verify(name)
    if main is None or filename is None:
        raise ValueError('Loading script failed: ' + name)
    script_dir = os.path.dirname(filename)
    return main, filename, script_dir


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
    for host, result in _parallax_call(hosts,
                                       "mkdir -p %s" % (os.path.dirname(path)),
                                       opts).iteritems():
        if isinstance(result, parallax.Error):
            err_buf.error("[%s]: Start: %s" % (host, result))
            ok = False
    if not ok:
        msg = "Failed to connect to one or more of these hosts via SSH: %s" % (
            ', '.join(h[0] for h in hosts))
        raise ValueError(msg)


def _copy_to_remote_dirs(hosts, path, opts):
    "Copy a local folder to same location on remote hosts"
    ok = True
    for host, result in _parallax_copy(hosts,
                                       path,
                                       path, opts).iteritems():
        if isinstance(result, parallax.Error):
            err_buf.error("[%s]: %s" % (host, result))
            ok = False
    if not ok:
        raise ValueError("Failed when copying script data, aborting.")


def _copy_to_all(workdir, hosts, local_node, src, dst, opts):
    """
    Copy src to dst both locally and remotely
    """
    ok = True
    ret = _parallax_copy(hosts, src, dst, opts)
    for host, result in ret.iteritems():
        if isinstance(result, parallax.Error):
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
            err_buf.error("[%s]: %s" % (local_node, e))
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
        if args:
            print fmt % args
        else:
            print fmt

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

        for host, result in _parallax_call(self.hosts,
                                           cmdline,
                                           self.opts).iteritems():
            if isinstance(result, parallax.Error):
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


def run(name, args):
    '''
    Run the given script on the given set of hosts
    name: a cluster script is a folder <name> containing a main.yml or main.xml file
    args: list of nvpairs
    '''
    workdir = _generate_workdir_name()
    main, filename, script_dir = _open_script(name)
    params = _parse_parameters(name, args, main)
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
            _run_cleanup(local_node, hosts, workdir, opts)
        else:
            _print_debug(local_node, hosts, workdir, opts)


def verify(script, values):
    """
    Verify the given parameter values, reporting
    errors where such are detected.

    Return a list of actions to perform.

    TODO FIXME
    """
    return script['actions']
