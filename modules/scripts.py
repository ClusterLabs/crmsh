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
import re
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
    has_parallax = True
except ImportError:
    has_parallax = False


from . import config
from . import handles
from . import options
from . import userdir
from . import utils
from .msg import err_buf, common_debug


_script_cache = None
_script_version = 2.2

_action_shortdescs = {
    'cib': 'Configure CIB',
    'install': 'Install packages',
    'call': 'Run command on nodes',
    'copy': 'Install file on nodes',
    'crm': 'Run crm command',
    'collect': 'Collect data from nodes',
    'verify': 'Verify collected data',
    'apply': 'Apply changes to nodes',
    'apply_local': 'Apply changes to cluster'
}


class Actions(object):
    """
    Each method in this class handles a particular action.
    """
    @staticmethod
    def _parse(script, action, params, values):
        """
        This special method parses the action action into a
        form that the particular action can handle. It's here
        to bring it closer to the actual actions. I want to
        do this conversion as early in the parse as possible,
        so the verify output can be as useful as possible.

        action: action data (dict)
        params: flat list of parameter values
        values: processed list of parameter values (for handles.parse)

        returns: True to process, False to exclude

        TODO:
        validate the action given actual parameters:
        we want to pass most values through handles,
        for example for the copy action, we should be
        able to use configurable parameters as arguments
        here using {{this syntax}}.
        In fact, all the handles-parsing should happen here,
        so we can verify that it parses OK before the
        actions start running.
        """
        name = action['name']
        action['value'] = action[name]
        del action[name]
        action['text'] = ''
        if name == 'install':
            if isinstance(action['value'], basestring):
                val = handles.parse(action['value'], values, strict=True).strip()
                action['value'] = val
            action['text'] = ' '.join(action['value'])
        # service takes a list of objects with a single key;
        # mapping service: state
        # the text field will be converted to lines where
        # each line is <service> -> <state>
        elif name == 'service':
            if isinstance(action['value'], basestring):
                val = handles.parse(action['value'], values, strict=True).strip()
                action['value'] = [dict([v.split(':', 1)]) for v in val.split()]

            def arrow(v):
                return ' -> '.join(x.items()[0])
            action['text'] = '\n'.join([arrow(x) for x in action['value']])
        elif name == 'cib' or name == 'crm':
            action['text'] = handles.parse(action['value'], values, strict=True).strip()
            action['value'] = _remove_empty_lines(action['text'])
        elif name == 'call':
            action['value'] = handles.parse(action['value'], values, strict=True).strip()
        elif name == 'copy':
            action['value'] = handles.parse(action['value'], values, strict=True).strip()
            action['to'] = handles.parse(action['to'], values, strict=True).strip()
            action['text'] = "%s -> %s" % (action['value'], action['to'])

        if 'shortdesc' not in action:
            action['shortdesc'] = _action_shortdescs.get(name, '')
        else:
            action['shortdesc'] = handles.parse(action['shortdesc'], values, strict=True)
        if 'longdesc' not in action:
            action['longdesc'] = ''
        else:
            action['longdesc'] = handles.parse(action['longdesc'], values, strict=True)

        when = handles.parse(action.get('when', ''), values, strict=True)
        when = when.strip() if when else when
        if when:
            if params.get(when):
                return True
            return False
        return True

    @staticmethod
    def _needs_sudo(action):
        if action['name'] == 'call' and action.get('sudo'):
            return True
        return action['name'] in ('apply', 'apply_local', 'install', 'service')

    def collect(self, run, action):
        "input: shell command"
        run.run_command(action.get('nodes'), action['value'])
        run.record_json()

    def validate(self, run, action):
        "input: shell command"
        run.run_command(action.get('nodes'), action['value'])
        run.validate_json()

    def apply(self, run, action):
        "input: shell command"
        run.run_command(action.get('nodes', 'all'), action['value'])
        run.record_json()

    def apply_local(self, run, action):
        "input: shell command"
        run.run_command(action.get('nodes'), action['value'])
        run.record_json()

    def report(self, run, action):
        "input: shell command"
        run.run_command(action.get('nodes'), action['value'])
        run.report_result()

    def call(self, run, action):
        """
        input: shell command / script
        TODO: actually allow script here
        """
        run.call(action.get('nodes'), action['value'])

    def copy(self, run, action):
        """
        copy: <from>
        to: <path>
        template: true|false
        """
        fil = action['value']
        if not os.path.isfile(fil):
            raise ValueError("File not found: %s" % (fil))

    def crm(self, run, action):
        """
        input: crm command sequence
        """
        fn = run.str2tmp(action['value'])
        run.call(None, 'crm -f %s' % (fn))

    def cib(self, run, action):
        "input: cli configuration script"
        # generate cib
        # runner.execute_local("crm configure load update ./action_cib")
        fn = run.str2tmp(action['value'])
        run.call(None, 'crm configure load update %s' % (fn))

    def install(self, run, action):
        """
        input: list of packages
        or: map of <os>: <packages>
        """
        run.execute_shell(action.get('nodes'), '''#!/usr/bin/env python
import crm_script
import crm_init

crm_init.install_packages(%s)
crm_script.exit_ok(True)
        ''' % (action['value']))

    def service(self, run, action):
        services = "\n".join([('crm_script.service(%s, %s)' % (s['name'], s['action']))
                              for s in action['value']])
        run.execute_shell(action.get('nodes'), '''#!/usr/bin/env python
import crm_script
import crm_init

%s
crm_script.exit_ok(True)
''' % (services))

    def include(self, run, action):
        """
        Treated differently: at parse time,
        the include actions should disappear
        and be replaced with actions generated
        from the include. Either from an included
        script, or a cib generated from an agent
        include.
        """

_actions = dict([(n, getattr(Actions, n)) for n in dir(Actions) if not n.startswith('_')])


def _find_action(action):
    """return name of action for action"""
    for a in _actions.keys():
        if a in action:
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

    data['dir'] = os.path.dirname(scriptfile)

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


_hawk_template_cache = {}


def _parse_hawk_template(workflow, name, type, step, actions):
    """
    TODO: convert hawk <if>, <insert> tags into handles
    """
    path = os.path.join(os.path.dirname(workflow), '../templates')
    if path in _hawk_template_cache:
        xml = _hawk_template_cache[path]
    else:
        for t in glob(os.path.join(path, '*.xml')):
            xml = etree.parse(t).getroot()
            if xml.get('name') == type:
                common_debug("Found matching template: %s" % (t))
                _hawk_template_cache[path] = xml
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


def _mkhandle(pfx, scope, text):
    if scope:
        return '{{%s%s:%s}}' % (pfx, scope, text)
    else:
        return '{{%s%s}}' % (pfx, text)


def _hawk_to_handles(context, tag):
    """
    input: a context name to prefix variable references with (may be empty)
    and a crm_script tag
    output: text with {{handles}}
    """
    s = ""
    s += tag.text
    for c in tag:
        if c.tag == 'if':
            cond = c.get('set')
            if cond:
                s += _mkhandle('#', context, cond)
                s += _hawk_to_handles(context, c)
                s += _mkhandle('/', context, cond)
        elif c.tag == 'insert':
            param = c.get('param')
            src = c.get('from_template') or context
            s += _mkhandle('', src, param)
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
        'dir': None,
        'steps': [],
        'actions': [],
    }

    # the parameters together form a step with an optional stepdesc
    # then each template becomes an additional step with an optional stepdesc
    paramstep = {
        'stepdesc': ''.join(xml.xpath('./parameters/stepdesc/text()')),
        'parameters': []
    }
    data['steps'].append(paramstep)
    for item in xml.xpath('./parameters/parameter'):
        obj = {}
        obj['name'] = item.get('name')
        obj['required'] = item.get('required', False)
        obj['unique'] = item.get('unique', False)
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
        data['steps'].append(templatestep)

        _parse_hawk_template(scriptfile, item.get('name'), item.get('type', item.get('name')),
                             templatestep, data['actions'])
        for override in item.xpath('/override'):
            name = override.get("name")
            for param in templatestep['parameters']:
                if param['name'] == name:
                    param['default'] = override.get("value")
                    param['required'] = False
                    break

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
            # workflows have to be fully parsed to find the name
            for s in glob(os.path.join(d, 'workflows/*.xml')):
                name = os.path.splitext(os.path.basename(s))[0]
                _load_script_file(name, s)


def list_scripts():
    '''
    List the available cluster installation scripts.
    Yields the names of the main script files.
    '''
    _build_script_cache()
    return sorted(_script_cache.keys())


def _meta_text(meta, tag):
    for c in meta.iterchildren(tag):
        return c.text
    return ''


def _listfindpend(needle, haystack, keyfn, orfn):
    for x in haystack:
        if keyfn(x) == needle:
            return x
    x = orfn()
    haystack.append(x)
    return x


def _make_cib_for_agent(name, agent, data, ops):
    template = ['primitive', "{{%s:id}}" % (name), agent]
    params = []
    ops = [op.strip() for op in ops.split('\n') if op.strip()]
    for param in data['parameters']:
        paramname = param['name']
        if paramname == 'id':
            # FIXME: What if the resource actually has a parameter named id?
            continue
        path = ':'.join((name, paramname)) if name else paramname
        params.append('{{#%s}}%s="{{%s}}"{{/%s}}' % (path, paramname, path, path))
    ret = ' '.join(template + params + ops)
    return ret


def _merge_objects(o1, o2):
    for key, value in o2.iteritems():
        o1[key] = value


def _process_include(script, include):
    """
    includes add parameter steps and actions
    an agent include works like a hawk template:
    it adds a parameter step
    a script include however adds any number of
    parameter steps and actions

    OK. here's what to do: Don't rescope the steps
    and actions. Instead, keep the actions attached
    to script step 0, as above. And for each step, add
    a scope which states its scope. Then, when evaluating
    handles, build custom environments for those scopes to
    pass into handles.parse.

    This is just for scripts, no need to do this for agents.
    Of course, how about scripts that include other scripts?
    _scope has to be a list which gets expanded...
    """
    if 'agent' in include:
        import ra
        agent = include['agent']
        info = ra.get_ra(agent)
        meta = info.meta()
        if meta is None:
            raise ValueError("Unknown resource type: %s" % (agent))
        name = include.get('name', meta.get('name'))
        if not name:
            cls, provider, type = ra.disambiguate_ra_type(agent)
            name = type
        step = _listfindpend(name, script['steps'], lambda x: x.get('name'), lambda: {
            'name': name,
            'longdesc': '',
            'shortdesc': '',
            'stepdesc': '',
            'parameters': [],
        })
        step['longdesc'] = include.get('longdesc') or _meta_text(meta, 'longdesc')
        step['shortdesc'] = include.get('shortdesc') or _meta_text(meta, 'shortdesc')
        step['stepdesc'] = include.get('stepdesc') or step['shortdesc']
        step['required'] = include.get('required', True)
        step['parameters'].append({
            'name': 'id',
            'shortdesc': 'Identifier for the cluster resource',
            'longdesc': '',
            'required': True,
            'unique': True,
            'type': 'resource-id',
        })
        for param in meta.xpath('./parameters/parameter'):
            pname = param.get('name')
            pobj = _listfindpend(pname, step['parameters'], lambda x: x.get('name'), lambda: {'name': pname})
            pobj['required'] = _make_boolean(param.get('required', False))
            pobj['unique'] = _make_boolean(param.get('unique', False))
            pobj['longdesc'] = _meta_text(param, 'longdesc')
            pobj['shortdesc'] = _meta_text(param, 'shortdesc')
            ctype = param.xpath('./content/@type')
            cexample = param.xpath('./content/@default')
            if ctype:
                pobj['type'] = ctype[0]
            if cexample:
                pobj['example'] = cexample[0]

        for param in include.get('parameters', []):
            pname = param['name']
            pobj = _listfindpend(pname, step['parameters'], lambda x: x.get('name'), lambda: {'name': pname})
            for key, value in param.iteritems():
                pobj[key] = value

        step['value'] = _make_cib_for_agent(name, agent, step, include.get('ops', ''))

        for action in script['actions']:
            if 'include' in action and action['include'] == name:
                del action['include']
                action['cib'] = step['value']

    elif 'script' in include:
        name = include['script']
        subscript = load_script(name)
        include['sub-script'] = subscript

        # TODO: Add subscript steps to this script
        # (nested: so TODO: handle nested steps everywhere)
    else:
        raise ValueError("Unknown include type in (%s): %s" % (script['name'], ', '.join(include.keys())))


def _postprocess_script(script):
    """
    Post-process the parsed script into an executable
    form. This means parsing all included agents and
    scripts, merging parameters, steps and actions.
    """
    ver = script.get('version')
    if ver is None or str(ver) != str(_script_version):
        raise ValueError("Unsupported script version (expected %s, got %s)" % (_script_version, repr(ver)))

    if 'shortdesc' not in script:
        script['shortdesc'] = ''

    if 'longdesc' not in script:
        script['longdesc'] = ''

    if 'category' not in script:
        script['category'] = 'Custom'

    if 'actions' not in script:
        script['actions'] = []

    for inc in script.get('include', []):
        _process_include(script, inc)

    script['steps'] = [step for step in script['steps'] if step['parameters']]

    for step in script['steps']:
        step['required'] = _make_boolean(step.get('required', True))
        if 'stepdesc' not in step:
            step['stepdesc'] = ''
            if 'shortdesc' in step:
                step['stepdesc'] = step['shortdesc']
        for p in step['parameters']:
            if 'name' not in p:
                raise ValueError("Parameter has no name: %s" % (p.keys()))
            if 'shortdesc' not in p:
                p['shortdesc'] = ''
            if 'value' in p and 'default' not in p:
                p['default'] = p['value']
                del p['value']
            if 'required' not in p and 'default' in p:
                p['required'] = False
            elif 'required' not in p:
                p['required'] = True
            else:
                p['required'] = _make_boolean(p['required'])
            if 'unique' in p:
                p['unique'] = _make_boolean(p['unique'])
            if 'default' in p and p['default'] is None:
                del p['default']
            if 'when' not in p:
                p['when'] = ''
            if 'error' not in p:
                p['error'] = ''
            if 'type' not in p or p['type'] == '':
                if p['name'] == 'id':
                    p['type'] = 'resource-id'
                else:
                    p['type'] = 'string'

    return script


def _join_script_lines(txt):
    s = ""
    current_line = ""
    for line in [line for line in txt.split('\n')]:
        if not line.strip():
            pass
        elif re.match('^\s+\S', line):
            current_line += line
        else:
            if current_line.strip():
                s += current_line + "\n"
            current_line = line
    if current_line:
        s += current_line + "\n"
    return s


def _load_script_file(script, filename):
    if filename.endswith('.yml'):
        parsed = _parse_yaml(script, filename)
    elif filename.endswith('.xml'):
        parsed = _parse_hawk_workflow(script, filename)
    if parsed is None:
        raise ValueError("Failed to parse script: %s (%s)" % (script, filename))
    obj = _postprocess_script(parsed)
    if 'name' in obj:
        script = obj['name']
    if script not in _script_cache or isinstance(_script_cache[script], basestring):
        _script_cache[script] = obj
    return obj


def load_script(script):
    _build_script_cache()
    if script not in _script_cache:
        common_debug("cache: %s" % (_script_cache.keys()))
        raise ValueError("Script not found: %s" % (script))
    s = _script_cache[script]
    if isinstance(s, basestring):
        return _load_script_file(script, s)
    return s


def _script_dirs():
    "list of directories that may contain cluster scripts"
    ret = [d for d in options.scriptdir.split(';') if d and os.path.isdir(d)]
    return ret + [os.path.join(userdir.CONFIG_HOME, 'scripts'),
                  os.path.join(config.path.sharedir, 'scripts'),
                  os.path.join(userdir.CONFIG_HOME, 'wizard'),
                  os.path.join(config.path.sharedir, 'wizard'),
                  config.path.hawk_wizards]


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


def _tempname(prefix):
    return '%s-%s%s' % (prefix,
                        hex(int(time.time()))[2:],
                        hex(random.randint(0, 2**48))[2:])


def _generate_workdir_name():
    '''
    Generate a temporary folder name to use while
    running the script
    '''
    # TODO: make use of /tmp configurable
    basefile = _tempname('crm-tmp')
    basetmp = os.path.join(utils.get_tempdir(), basefile)
    if os.path.isdir(basetmp):
        raise ValueError("Invalid temporary workdir %s" % (basetmp))
    return basetmp


def _print_debug(printer, local_node, hosts, workdir, opts):
    "Print debug output (if any)"
    dbglog = os.path.join(workdir, 'crm_script.debug')
    for host, result in _parallax_call(hosts,
                                       "[ -f '%s' ] && cat '%s'" % (dbglog, dbglog),
                                       opts).iteritems():
        if isinstance(result, parallax.Error):
            printer.error(host, result)
        else:
            printer.output(host, *result)
    if os.path.isfile(dbglog):
        f = open(dbglog).read()
        printer.output(local_node, 0, f, '')


def _cleanup_local(workdir):
    "clean up the local tmp dir"
    if workdir and os.path.isdir(workdir):
        cleanscript = os.path.join(workdir, 'crm_clean.py')
        if os.path.isfile(cleanscript):
            if subprocess.call([cleanscript, workdir], shell=False) != 0:
                shutil.rmtree(workdir)
        else:
            shutil.rmtree(workdir)


def _run_cleanup(printer, has_remote_actions, local_node, hosts, workdir, opts):
    "Clean up after the cluster script"
    if has_remote_actions and hosts and workdir:
        cleanscript = os.path.join(workdir, 'crm_clean.py')
        for host, result in _parallax_call(hosts,
                                           "%s %s" % (cleanscript,
                                                      workdir),
                                           opts).iteritems():
            if isinstance(result, parallax.Error):
                printer.debug("[%s]: Failed to clean up %s" % (host, workdir))
                printer.error(host, "Clean: %s" % (result))
            else:
                printer.output(host, *result)
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
            ('dry_run', 'no', 'If set, simulate execution only'),
            ('action', None, 'If set, only execute a single action (index, as returned by verify)'),
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


def _scoped_param(step_name, name):
    if step_name:
        return ':'.join((step_name, name))
    return name


def _parse_parameters(script, args):
    '''
    Process parameter list from command line
    into an actual list of parameters (add
    optional parameters with defaults, etc.)

    Parameters are given as step:name, or simply name
    for common parameters or step-zero-parameters.
    '''
    errors = []
    params = {}
    for key, default, _ in _common_params():
        params[key] = default
    for key, val in args.iteritems():
        params[key] = val
    for step in script['steps']:
        step_name = step.get('name')
        step_required = step['required']
        for param in step['parameters']:
            name = param['name']
            scoped = _scoped_param(step_name, name)
            if scoped not in params:
                if 'required' in param:
                    if param['required'] is True:
                        if step_required:
                            errors.append(scoped)
                    elif 'default' in param:
                        params[scoped] = param['default']
                elif 'default' in param:
                    params[scoped] = param['default']
                elif step_required:
                    errors.append(scoped)
    if errors:
        raise ValueError("Missing required parameter(s): %s" % (', '.join(errors)))

    user = params['user']
    port = params['port']
    _filter_dict(params, 'nodes', _filter_nodes, user, port)
    _filter_dict(params, 'dry_run', utils.is_boolean_true)
    _filter_dict(params, 'sudo', utils.is_boolean_true)
    _filter_dict(params, 'statefile', lambda x: (x and os.path.abspath(x)) or x)
    if config.core.debug:
        params['debug'] = True
    return params


def _handles_values(steps, params):
    """
    TODO FIXME

    Given a particular script and
    values for the parameters of
    the script, produce the values
    argument to pass to handles.parse.

    For sub-scripts and agent includes,
    this involves resolving the "value"
    of a particular include. The include
    will be a step in steps, and needs
    some meta-data to tell us what it
    generates.

    If a non-required step lacks values,
    it should be added to the output as a
    false value.
    """
    # postfill holds values that may themselves
    # be unexpanded templates, and in need of
    # expansion
    postfill = []
    ret = {}
    for step in steps:
        name = step.get('name', '')
        if name:
            obj = {}
            vobj = handles.value(obj, '# %s' % (name))
            ret[name] = vobj
            postfill.append((vobj, step.get('value', vobj.value)))
        else:
            obj = ret
        for param in step['parameters']:
            pname = param['name']
            scoped = _scoped_param(name, pname)
            if scoped in params:
                obj[pname] = params[scoped]
            else:
                obj[pname] = None
    for vobj, value in postfill:
        vobj.value = handles.parse(value, ret)
    return ret


def _has_remote_actions(actions):
    """
    True if any actions execute on remote nodes
    """
    for action in actions:
        if action['name'] in ('collect', 'apply', 'install', 'service'):
            return True
        if action.get('nodes') == 'all':
            return True
    return False


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


def _create_script_workdir(scriptdir, workdir):
    "Create workdir and copy contents of scriptdir into it"
    cmd = ["mkdir", "-p", workdir]
    if options.regression_tests:
        print ".EXT", cmd
    if subprocess.call(cmd, shell=False) != 0:
        raise ValueError("Failed to create temporary working directory")
    if scriptdir is not None:
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
                                       "mkdir -p %s" % (path),
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


class RunActions(object):
    def __init__(self, printer, script, params, actions, local_node, hosts, opts, workdir):
        self.printer = printer
        self.script = script
        self.data = [params]
        self.actions = actions
        self.local_node = local_node
        self.hosts = hosts
        self.opts = opts
        self.dry_run = params.get('dry_run', False)
        self.sudo = params.get('sudo', False)
        self.workdir = workdir
        self.statefile = os.path.join(self.workdir, 'script.input')
        self.dstfile = os.path.join(self.workdir, 'script.input')
        self.sudo_pass = None
        self.result = None
        self.output = None
        self.rc = False

    def single_action(self, action_index, statefile):
        self.statefile = statefile
        try:
            action_index = int(action_index) - 1
        except ValueError:
            raise ValueError("action parameter must be an index")
        if action_index < 1 or action_index >= len(self.actions):
            raise ValueError("action index out of range")

        action = self.actions[action_index]
        common_debug("Execute: %s" % (action))
        # if this is not the first action, load action data
        if action_index != 1:
            if not os.path.isfile(statefile):
                raise ValueError("No state for action: %s" % (action_index))
            self.data = json.load(open(statefile))
        if Actions._needs_sudo(action):
            self._check_sudo_pass()
        result = self._run_action(action)
        json.dump(self.data, open(self.statefile, 'w'))
        return result

    def all_actions(self):
        # TODO: run asynchronously on remote nodes
        # run on remote nodes
        # run on local nodes
        # TODO: wait for remote results
        # TODO: combine consecutive actions
        # where possible (CIB applications etc.)
        for action in self.actions:
            if Actions._needs_sudo(action):
                self._check_sudo_pass()
            if not self._run_action(action):
                return False
        return True

    def _update_state(self):
        json.dump(self.data, open(self.statefile, 'w'))
        return _copy_to_all(self.workdir,
                            self.hosts,
                            self.local_node,
                            self.statefile,
                            self.dstfile,
                            self.opts)

    def run_command(self, nodes, command):
        "called by Actions"
        cmdline = 'cd "%s"; ./%s' % (self.workdir, command)
        self.printer.debug_command(nodes, command)
        if not self._update_state():
            raise ValueError("Failed when updating input, aborting.")
        if nodes == 'all':
            self.result = self._process_remote(cmdline)
        else:
            self.result = self._process_local(cmdline)

    def record_json(self):
        "called by Actions"
        if self.result is not None:
            if self.result:
                self.result = json.loads(self.result)
            else:
                self.result = {}
            self.data.append(self.result)
            self.rc = True
        else:
            self.rc = False

    def validate_json(self):
        "called by Actions"
        if self.result is not None:
            if self.result:
                self.result = json.loads(self.result)
            else:
                self.result = {}
            self.data.append(self.result)
            if isinstance(self.result, dict):
                for k, v in self.result.iteritems():
                    self.data[0][k] = v
            self.rc = True
        else:
            self.rc = False

    def report_result(self):
        "called by Actions"
        if self.result is not None:
            self.output = self.result
            self.rc = True
        else:
            self.rc = False

    def _run_action(self, action):
        """
        Execute a single action
        """
        method = _actions[action['name']]
        self.printer.start(action)
        try:
            self.output = None
            self.result = None
            self.rc = False
            if self.dry_run:
                self.rc = True
            else:
                method(Actions(), self, action)
            self.printer.finish(action, self.rc, self.output)
            return self.rc
        finally:
            self.printer.flush()
        return False

    def _check_sudo_pass(self):
        if self.sudo and not self.sudo_pass:
            prompt = "sudo password: "
            self.sudo_pass = getpass.getpass(prompt=prompt)

    def call(self, nodes, cmdline):
        if nodes == 'all':
            self.result = self._process_remote(cmdline)
        else:
            self.result = self._process_local(cmdline)

    def execute_shell(self, nodes, cmdscript):
        """
        execute the shell script...
        """
        tmpf = run.str2tmp(cmdscript)
        if nodes == 'all':
            ok = _copy_to_remote_dirs(self.hosts,
                                      tmpf,
                                      self.opts)
            if not ok:
                self.result = False
            else:
                cmdline = "sh %s" % (tmpf)
                self.result = self._process_remote(cmdline)
        else:
            cmdline = "sh %s" % (tmpf)
            self.result = self._process_local(cmdline)

    def str2tmp(self, s):
        """
        Create a temporary file in the temp workdir
        Returns path to file
        """
        fn = os.path.join(self.workdir, _tempname('str2tmp'))
        try:
            with open(fn, "w") as f:
                f.write(s)
                if not s.endswith('\n'):
                    f.write("\n")
        except IOError, msg:
            err_buf.error(msg)
            return
        return fn

        return utils.str2tmp(s)

    def _process_remote(self, cmdline):
        """
        Handle an action that executes on all nodes
        """
        ok = True
        action_result = {}

        if self.sudo_pass:
            self.opts.input_stream = u'sudo: %s\n' % (self.sudo_pass)
        else:
            self.opts.input_stream = None

        for host, result in _parallax_call(self.hosts,
                                           cmdline,
                                           self.opts).iteritems():
            if isinstance(result, parallax.Error):
                self.printer.error(host, result)
                ok = False
            else:
                rc, out, err = result
                if rc != 0:
                    self.printer.error(host, "%s%s" % (out, err))
                    ok = False
                else:
                    action_result[host] = json.loads(out)
        if self.local_node:
            ret = self._process_local(cmdline)
            if ret is None:
                ok = False
            else:
                action_result[self.local_node[0]] = json.loads(ret)
        if ok:
            self.printer.debug("%s" % repr(action_result))
            return action_result
        return None

    def _process_local(self, cmdline):
        """
        Handle an action that executes locally
        """
        if self.sudo_pass:
            input_s = u'sudo: %s\n' % (self.sudo_pass)
        else:
            input_s = None
        rc, out, err = utils.get_stdout_stderr(cmdline, input_s=input_s, shell=True)
        if rc != 0:
            self.printer.error(self.local_node[0], "Error (%d): %s" % (rc, err))
            return None
        self.printer.debug("%s" % repr(out))
        return out


def run(script, args, printer):
    '''
    Run the given script on the given set of hosts
    name: a cluster script is a folder <name> containing a main.yml or main.xml file
    args: list of nvpairs
    printer: Object that receives and formats output
    '''
    workdir = _generate_workdir_name()
    params = _parse_parameters(script, args)
    name = script['name']
    script_dir = script['dir']
    hosts = params['nodes']
    printer.print_header(script, params, hosts)
    local_node, hosts = _extract_localnode(hosts)
    opts = _make_options(params)
    _set_controlpersist(opts)

    # pull out the actions to perform based on the actual
    # parameter values (so discard actions conditional on
    # conditions that are false)
    actions = _process_actions(script, params)
    has_remote_actions = _has_remote_actions(actions)

    try:
        _create_script_workdir(script_dir, workdir)
        _copy_utils(workdir)
        if has_remote_actions:
            _create_remote_workdirs(hosts, workdir, opts)
            _copy_to_remote_dirs(hosts, workdir, opts)
        # make sure all path references are relative to the script directory
        os.chdir(workdir)

        runner = RunActions(printer, script, params, actions, local_node, hosts, opts, workdir)
        action = params['action']
        statefile = params['statefile']
        if action or statefile:
            if not action or not statefile:
                raise ValueError("Must set both action and statefile")
            return runner.single_action(action, statefile)
        else:
            return runner.all_actions()

    except (OSError, IOError), e:
        import traceback
        traceback.print_exc()
        raise ValueError("Internal error while running %s: %s" % (name, e))
    finally:
        if not config.core.debug:
            _run_cleanup(printer, has_remote_actions, local_node, hosts, workdir, opts)
        else:
            _print_debug(printer, local_node, hosts, workdir, opts)


def _remove_empty_lines(txt):
    return '\n'.join(line for line in txt.split('\n') if line.strip())


def _process_actions(script, params):
    """
    Given parameter values, we can process
    all the handles data and generate all the
    actions to perform, validate and check conditions.
    """
    subactions = {}
    for inc in script.get('include', []):
        obj = inc.get('sub-script')
        if obj:
            try:
                subparams = params.get(inc['script'], {})
                subactions[inc['script']] = _process_actions(obj, subparams)
            except ValueError as err:
                raise ValueError("Error in included script %s: %s" % (inc['script'], err))

    values = _handles_values(script['steps'], params)
    from copy import deepcopy
    actions = deepcopy(script['actions'])
    ret = []
    for action in actions:
        name = _find_action(action)
        if name is None:
            raise ValueError("Unknown action: %s" % (action.keys()))
        action['name'] = name
        if name == 'include':
            ret.extend(subactions[action['include']])
        elif Actions._parse(script, action, params, values):
            ret.append(action)
    return ret


def verify(script, args):
    """
    Verify the given parameter values, reporting
    errors where such are detected.

    Return a list of actions to perform.
    """
    return _process_actions(script, _parse_parameters(script, args))


def _make_boolean(v):
    if isinstance(v, basestring):
        return utils.get_boolean(v)
    return v not in (False, None)
