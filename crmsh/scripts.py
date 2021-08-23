# Copyright (C) 2015 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import os
import re
import subprocess
import getpass
import time
import shutil
import socket
import random
from copy import deepcopy
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
from . import log


logger = log.setup_logger(__name__)


_script_cache = None
_script_version = 2.2
_strict_handles = False

_action_shortdescs = {
    'cib': 'Configure cluster resources',
    'install': 'Install packages',
    'service': 'Manage system services',
    'call': 'Run command on nodes',
    'copy': 'Install file on nodes',
    'crm': 'Run crm command',
    'collect': 'Collect data from nodes',
    'verify': 'Verify collected data',
    'apply': 'Apply changes to nodes',
    'apply_local': 'Apply changes to cluster'
}


class Text(object):
    """
    Idea: Replace all fields that may contain
    references to data with Text objects, that
    lazily resolve when asked to.
    Context needed is the script in which this
    Text resolves. What we do is that we install
    the parameter values in the script, so we can
    get it from here.

    This can also then be responsible for the
    various kinds of output cleanup/formatting
    (desc, cib, etc)
    """
    DESC = 1
    CIB = 2
    SHORTDESC = 3

    @staticmethod
    def shortdesc(script, text):
        return Text(script, text, kind=Text.SHORTDESC)

    @staticmethod
    def desc(script, text):
        return Text(script, text, kind=Text.DESC)

    @staticmethod
    def cib(script, text):
        return Text(script, text, kind=Text.CIB)

    @staticmethod
    def isa(obj):
        return isinstance(obj, str) or isinstance(obj, Text)

    def __init__(self, script, text, kind=None):
        self.script = script
        if isinstance(text, Text):
            self.text = text.text
        else:
            self.text = text
        self._kind = kind

    def _parse(self):
        val = self.text
        if val in (True, False):
            return "true" if val else "false"
        if not isinstance(val, str):
            return str(val)
        return handles.parse(val, self.script.get('__values__', {})).strip()

    def __repr__(self):
        return repr(self.text)

    def __str__(self):
        if self._kind == self.DESC:
            return format_desc(self._parse())
        elif self._kind == self.SHORTDESC:
            return self._parse()
        elif self._kind == self.CIB:
            return format_cib(self._parse())
        return self._parse()

    def __eq__(self, obj):
        return str(self) == str(obj)


class WhenExpr(object):
    def __init__(self, script, prog):
        self.script = script
        self.prog = prog

    def __repr__(self):
        return repr(self.prog)

    def __str__(self):
        lenv = self.script.get('__values__', {})
        inp = handles.parse(self.prog, lenv).strip()
        try:
            from .minieval import minieval, InvalidExpression
            return str(minieval(inp, lenv)).lower()
        except InvalidExpression as err:
            raise ValueError(str(err))


def _strip(desc):
    if desc is None:
        return None
    return desc.strip()


def format_desc(desc):
    import textwrap
    return '\n\n'.join([textwrap.fill(para) for para in desc.split('\n\n') if para.strip()])


def format_cib(text):
    text = re.sub(r'[ ]+', ' ', text)
    text = re.sub(r'\n[ \t\f\v]+', '\n\t', text)
    i = 0
    while True:
        i = text.find('\n\t\n')
        if i < 0:
            break
        text = text[:i] + text[i+2:]
    return text


def space_cib(text):
    """
    After merging CIB commands, space separate lines out
    """
    return re.sub(r'\n([^\t])', r'\n\n\1', re.sub(r'[\n\r]+', r'\n', text))


class Actions(object):
    """
    Each method in this class handles a particular action.
    """
    @staticmethod
    def parse(script, action):
        """
        action: action data (dict)
        params: flat list of parameter values
        values: processed list of parameter values (for handles.parse)

        Converts {'cib': "primitive..."} into {"name": "cib", "value": "primitive..."}
        Each action has two values: "value" may be a non-textual object
        depending on the type of action. "text" is visual context to display
        to a user (so a cleaned up CIB, or the list of packages to install)
        """
        name = action['name']
        action['value'] = action[name]
        del action[name]
        action['text'] = ''
        value = action['value']
        if name == 'install':
            if Text.isa(value):
                action['value'] = str(value).split()
            action['text'] = ' '.join(action['value'])
        # service takes a list of objects with a single key;
        # mapping service: state
        # the text field will be converted to lines where
        # each line is <service> -> <state>
        elif name == 'service':
            if Text.isa(value):
                value = [dict([v.split(':', 1)]) for v in str(value).split()]
                action['value'] = value

            def arrow(v):
                return ' -> '.join(list(v.items())[0])
            action['text'] = '\n'.join([arrow(x) for x in value])
        elif name == 'cib' or name == 'crm':
            action['text'] = str(Text.cib(script, value))
            action['value'] = _remove_empty_lines(action['text'])
        elif name == 'call':
            action['value'] = Text(script, value)
        elif name == 'copy':
            action['value'] = Text(script, value)
            action['template'] = _make_boolean(action.get('template', False))
            action['to'] = Text(script, action.get('to', action['value']))
            action['text'] = "%s -> %s" % (action['value'], action['to'])

        if 'shortdesc' not in action:
            action['shortdesc'] = _action_shortdescs.get(name, '')
        else:
            action['shortdesc'] = Text.shortdesc(script, action['shortdesc'])
        if 'longdesc' not in action:
            action['longdesc'] = ''
        else:
            action['longdesc'] = Text.desc(script, action['longdesc'])

        hre = handles.headmatcher
        ident_re = re.compile(r'([a-z_-][a-z0-9_-]*)$', re.IGNORECASE)

        if 'when' in action:
            when = action['when']
            if ident_re.match(when):
                action['when'] = Text(script, '{{%s}}' % (when))
            elif when:
                action['when'] = WhenExpr(script, when)
            else:
                del action['when']
        for k, v in action.items():
            if isinstance(v, str) and hre.search(v):
                v = Text(script, v)
            if Text.isa(v):
                action[k] = str(v).strip()

    @staticmethod
    def mergeable(action):
        return action['name'] in ('cib', 'crm', 'install', 'service')

    @staticmethod
    def merge(into, new):
        """
        Merge neighbour actions.
        Note: When this is called, all text values
        should already be "reduced", that is, any
        variable references already resolved.
        """
        if into.get('nodes') != new.get('nodes'):
            return False
        if into['name'] in ('cib', 'crm'):
            into['value'] = '\n'.join([str(into['value']), str(new['value'])])
            into['text'] = space_cib('\n'.join([str(into['text']), str(new['text'])]))
        elif into['name'] == 'service':
            into['value'].extend(new['value'])
            into['text'] = '\n'.join([str(into['text']), str(new['text'])])
        elif into['name'] == 'install':
            into['value'].extend(new['value'])
            into['text'] = ' '.join([str(into['text']), str(new['text'])])
        if new['shortdesc']:
            newd = str(new['shortdesc'])
            if newd != str(into['shortdesc']):
                into['shortdesc'] = _strip(newd)
        if new['longdesc']:
            newd = str(new['longdesc'])
            if newd != str(into['longdesc']):
                into['longdesc'] = newd
        return True

    @staticmethod
    def needs_sudo(action):
        if action['name'] == 'call':
            return action.get('sudo') or action.get('nodes') != 'local'
        return action['name'] in ('apply', 'apply_local', 'install', 'service')

    def __init__(self, run, action):
        self._run = run
        self._action = action
        self._value = action['value']
        if not isinstance(self._value, list):
            self._value = str(self._value)
        self._text = str(action['text'])
        self._nodes = str(action.get('nodes', ''))

    def collect(self):
        "input: shell command"
        self._run.run_command(self._nodes or 'all', self._value, True)
        self._run.record_json()

    def validate(self):
        "input: shell command"
        self._run.run_command(None, self._value, True)
        self._run.validate_json()

    def apply(self):
        "input: shell command"
        self._run.run_command(self._nodes or 'all', self._value, True)
        self._run.record_json()

    def apply_local(self):
        "input: shell command"
        self._run.run_command(None, self._value, True)
        self._run.record_json()

    def report(self):
        "input: shell command"
        self._run.run_command(None, self._value, False)
        self._run.report_result()

    def call(self):
        """
        input: shell command / script

        TODO: actually allow script here
        """
        self._run.call(self._nodes, self._value)

    def copy(self):
        """
        copy: <from>
        to: <path>
        template: true|false

        TODO: FIXME: Verify that it works...
        TODO: FIXME: Error handling
        """
        if not os.path.exists(self._value):
            raise ValueError("File not found: %s" % (self._value))
        if self._action['template']:
            fn = self._run.str2tmp(str(Text.cib(self._run.script, open(self._value).read())))
            self._value = fn
        self._run.copy_file(self._nodes, self._value, str(self._action['to']))

    def _crm_do(self, act):
        fn = self._run.str2tmp(_join_script_lines(self._value))
        if config.core.debug:
            args = '-d --wait --no'
        else:
            args = '--wait --no'
        if self._action.get('force'):
            args = args + ' --force'
        self._run.call(None, 'crm %s %s %s' % (args, act, fn))

    def crm(self):
        """
        input: crm command sequence
        """
        return self._crm_do('-f')

    def cib(self):
        "input: cli configuration script"
        return self._crm_do('configure load update')

    def install(self):
        """
        input: list of packages
        or: map of <os>: <packages>
        """
        self._run.execute_shell(self._nodes or 'all', '''#!/usr/bin/env python3
import crm_script
import crm_init

crm_init.install_packages(%s)
crm_script.exit_ok(True)
        ''' % (self._value))

    def service(self):
        values = []
        for s in self._value:
            for v in s.items():
                values.append(v)
        services = "\n".join([('crm_script.service%s' % repr(v)) for v in values])
        self._run.execute_shell(self._nodes or 'all', '''#!/usr/bin/env python3
import crm_script
import crm_init

%s
crm_script.exit_ok(True)
''' % (services))

    def include(self):
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
    for a in list(_actions.keys()):
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
            data = yaml.load(f, Loader=yaml.SafeLoader)
            if isinstance(data, list):
                data = data[0]
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
    elif 'steps' not in data:
        data['steps'] = []
    data['name'] = scriptname
    data['dir'] = os.path.dirname(scriptfile)
    return data


def _rename(obj, key, to):
    if key in obj:
        obj[to] = obj[key]
        del obj[key]


def _upgrade_yaml(data):
    """
    Upgrade a parsed yaml document from
    an older version.
    """
    if 'version' in data and data['version'] > _script_version:
        raise ValueError("Unknown version (expected < %s, got %s)" % (_script_version, data['version']))

    data['version'] = _script_version
    data['category'] = data.get('category', 'Legacy')
    _rename(data, 'name', 'shortdesc')
    _rename(data, 'description', 'longdesc')

    data['actions'] = data.get('steps', [])
    paramstep = {'parameters': data.get('parameters', [])}
    data['steps'] = [paramstep]
    if 'parameters' in data:
        del data['parameters']

    for p in paramstep['parameters']:
        _rename(p, 'description', 'shortdesc')
        _rename(p, 'default', 'value')
        if 'required' not in p:
            p['required'] = 'value' not in p

    for action in data['actions']:
        _rename(action, 'name', 'shortdesc')

    return data


_hawk_template_cache = {}


def _parse_hawk_template(workflow, name, kind, step, actions):
    """
    Convert a hawk template into steps + a cib action
    """
    path = os.path.join(os.path.dirname(workflow), '../templates', kind + '.xml')
    if path in _hawk_template_cache:
        xml = _hawk_template_cache[path]
    elif os.path.isfile(path):
        xml = etree.parse(path).getroot()
        logger.debug("Found matching template: %s", path)
        _hawk_template_cache[path] = xml
    else:
        raise ValueError("Template does not exist: %s" % (path))

    step['shortdesc'] = _strip(''.join(xml.xpath('./shortdesc/text()')))
    step['longdesc'] = ''.join(xml.xpath('./longdesc/text()'))

    actions.append({'cib': _hawk_to_handles(name, xml.xpath('./crm_script')[0])})

    for item in xml.xpath('./parameters/parameter'):
        obj = {}
        obj['name'] = item.get('name')
        obj['required'] = item.get('required', False)
        content = next(item.iter('content'))
        obj['type'] = content.get('type', 'string')
        val = content.get('default', content.get('value', None))
        if val:
            obj['value'] = val
        obj['shortdesc'] = _strip(''.join(item.xpath('./shortdesc/text()')))
        obj['longdesc'] = ''.join(item.xpath('./longdesc/text()'))
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
    Reads a hawk workflow into a script.

    TODO: Parse hawk workflows that invoke legacy cluster scripts?
    """
    xml = etree.parse(scriptfile).getroot()
    if xml.tag != "workflow":
        raise ValueError("Not a hawk workflow: %s" % (scriptfile))
    data = {
        'version': 2.2,
        'name': scriptname,
        'shortdesc': _strip(''.join(xml.xpath('./shortdesc/text()'))),
        'longdesc': ''.join(xml.xpath('./longdesc/text()')),
        'category': ''.join(xml.xpath('./@category')) or 'Wizard',
        'dir': None,
        'steps': [],
        'actions': [],
    }

    # the parameters together form a step with an optional shortdesc
    # then each template becomes an additional step with an optional shortdesc
    paramstep = {
        'shortdesc': _strip(''.join(xml.xpath('./parameters/stepdesc/text()'))),
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
        val = content.get('default', content.get('value', None))
        if val is not None:
            obj['value'] = val
        obj['shortdesc'] = _strip(''.join(item.xpath('./shortdesc/text()')))
        obj['longdesc'] = ''.join(item.xpath('./longdesc/text()'))
        paramstep['parameters'].append(obj)

    data['actions'] = []

    for item in xml.xpath('./templates/template'):
        templatestep = {
            'shortdesc': _strip(''.join(item.xpath('./stepdesc/text()'))),
            'name': item.get('name'),
            # Optional steps in the legacy wizards was broken (!?)
            'required': True,  # item.get('required'),
            'parameters': []
        }
        data['steps'].append(templatestep)

        _parse_hawk_template(scriptfile, item.get('name'), item.get('type', item.get('name')),
                             templatestep, data['actions'])
        for override in item.xpath('./override'):
            name = override.get("name")
            for param in templatestep['parameters']:
                if param['name'] == name:
                    param['value'] = override.get("value")
                    param['required'] = False
                    break

    data['actions'].append({'cib': _hawk_to_handles('', xml.xpath('./crm_script')[0])})

    if config.core.debug:
        import pprint
        print("Parsed hawk workflow:")
        pprint.pprint(data)
    return data


def build_script_cache():
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
            for s in glob(os.path.join(d, '*.yml')):
                name = os.path.splitext(os.path.basename(s))[0]
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
    build_script_cache()
    return sorted(_script_cache.keys())


def _meta_text(meta, tag):
    for c in meta.iterchildren(tag):
        return c.text
    return ''


def _listfind(needle, haystack, keyfn):
    for x in haystack:
        if keyfn(x) == needle:
            return x
    return None


def _listfindpend(needle, haystack, keyfn, orfn):
    for x in haystack:
        if keyfn(x) == needle:
            return x
    x = orfn()
    haystack.append(x)
    return x


def _make_cib_for_agent(name, agent, data, ops):
    aid = "{{%s:id}}" % (name) if name else "{{id}}"
    template = ['primitive %s %s' % (aid, agent)]
    params = []
    ops = [op.strip() for op in ops.split('\n') if op.strip()]
    for param in data['parameters']:
        paramname = param['name']
        if paramname == 'id':
            # FIXME: What if the resource actually has a parameter named id?
            continue
        path = ':'.join((name, paramname)) if name else paramname
        params.append('{{#%s}}%s="{{%s}}"{{/%s}}' % (path, paramname, path, path))
    ret = '\n\t'.join(template + params + ops)
    return ret


def _merge_objects(o1, o2):
    for key, value in o2.items():
        o1[key] = value


def _lookup_step(name, steps, stepname):
    for step in steps:
        if step.get('name', '') == stepname:
            return step
    if not stepname and len(steps) == 1:
        return steps[0]
    if not stepname:
        raise ValueError("Parameter '%s' not found" % (name))
    raise ValueError("Referenced step '%s' not found in '%s'" % (stepname, name))


def _process_agent_include(script, include):
    from . import ra
    agent = include['agent']
    info = ra.get_ra(agent)
    meta = info.meta()
    if meta is None:
        raise ValueError("No meta-data for agent: %s" % (agent))
    name = include.get('name', meta.get('name'))
    if not name:
        cls, provider, name = ra.disambiguate_ra_type(agent)
    if 'name' not in include:
        include['name'] = name
    step = _listfindpend(name, script['steps'], lambda x: x.get('name'), lambda: {
        'name': name,
        'longdesc': '',
        'shortdesc': '',
        'parameters': [],
    })
    step['longdesc'] = include.get('longdesc') or _meta_text(meta, 'longdesc')
    step['shortdesc'] = _strip(include.get('shortdesc') or _meta_text(meta, 'shortdesc'))
    step['required'] = include.get('required', True)
    step['parameters'].append({
        'name': 'id',
        'shortdesc': 'Identifier for the cluster resource',
        'longdesc': '',
        'required': True,
        'unique': True,
        'type': 'resource',
    })

    def newparamobj(param):
        pname = param.get('name')
        return _listfindpend(pname, step['parameters'], lambda x: x.get('name'), lambda: {'name': pname})

    for param in meta.xpath('./parameters/parameter'):
        pobj = newparamobj(param)
        pobj['required'] = _make_boolean(param.get('required', False))
        pobj['unique'] = _make_boolean(param.get('unique', False))
        pobj['longdesc'] = _meta_text(param, 'longdesc')
        pobj['shortdesc'] = _strip(_meta_text(param, 'shortdesc'))
        # set 'advanced' flag on all non-required agent parameters by default
        # a UI should hide these parameters unless "show advanced" is set
        pobj['advanced'] = not pobj['required']
        ctype = param.xpath('./content/@type')
        cexample = param.xpath('./content/@default')
        if ctype:
            pobj['type'] = ctype[0]
        if cexample:
            pobj['example'] = cexample[0]

    for param in include.get('parameters', []):
        pobj = newparamobj(param)
        # Make any overriden parameters non-advanced
        # unless explicitly set to advanced
        pobj['advanced'] = False
        for key, value in param.items():
            if key in ('shortdesc', 'longdesc'):
                pobj[key] = value
            elif key == 'value':
                pobj[key] = Text(script, value)
            else:
                pobj[key] = value
            if 'value' in pobj:
                pobj['required'] = False

    # If the script doesn't have any base parameters
    # and the name of this step is the same as the
    # script name itself, then make this the base step
    hoist = False
    hoist_from = None
    if step['name'] == script['name']:
        zerostep = _listfind('', script['steps'], lambda x: x.get('name', ''))
        if not zerostep:
            hoist = True
        elif zerostep.get('parameters'):
            zp = zerostep['parameters']
            for pname in [p['name'] for p in step['parameters']]:
                if _listfind(pname, zp, lambda x: x['name']):
                    break
            else:
                hoist, hoist_from = True, zerostep

    # use step['name'] here in case we did the zerostep hoist
    step['value'] = Text.cib(script, _make_cib_for_agent('' if hoist else step['name'],
                                                         agent, step, include.get('ops', '')))

    if hoist:
        step['name'] = ''
        if hoist_from:
            step['parameters'] = hoist_from['parameters'] + step['parameters']
            script['steps'] = [s for s in script['steps'] if s != hoist_from]

    if not step['name']:
        del step['name']

    # this works despite possible hoist above,
    # since name is still the actual name
    for action in script['actions']:
        if 'include' in action and action['include'] == name:
            del action['include']
            action['cib'] = step['value']


def _process_script_include(script, include):
    script_name = include['script']
    if 'name' not in include:
        include['name'] = script_name
    subscript = load_script(script_name)
    name = include['name']

    scriptstep = {
        'name': name,
        'shortdesc': subscript['shortdesc'],
        'longdesc': subscript['longdesc'],
        'required': _make_boolean(include.get('required', True)),
        'steps': deepcopy(subscript['steps']),
        'sub-script': subscript,
    }

    def _merge_step_params(step, params):
        for param in params:
            _merge_step_param(step, param)

    def _merge_step_param(step, param):
        for p in step.get('parameters', []):
            if p['name'] == param['name']:
                for key, value in param.items():
                    if key in ('shortdesc', 'longdesc'):
                        p[key] = value
                    elif key == 'value' and Text.isa(value):
                        p[key] = Text(script, value)
                    else:
                        p[key] = value
                if 'value' in p:
                    p['required'] = False
                break
        else:
            raise ValueError("Referenced parameter '%s' not found in '%s'" % (param['name'], name))

    for incparam in include.get('parameters', []):
        if 'step' in incparam and 'name' not in incparam:
            _merge_step_params(_lookup_step(name, scriptstep.get('steps', []), incparam['step']),
                               incparam['parameters'])
        else:
            _merge_step_param(_lookup_step(name, scriptstep.get('steps', []), ''),
                              incparam)

    script['steps'].append(scriptstep)


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
        return _process_agent_include(script, include)

    elif 'script' in include:
        return _process_script_include(script, include)
    else:
        raise ValueError("Unknown include type: %s" % (', '.join(list(include.keys()))))


def _postprocess_script_step(script, step):
    if 'name' in step and not step['name']:
        del step['name']
    step['required'] = _make_boolean(step.get('required', True))
    step['shortdesc'] = _strip(step.get('shortdesc', ''))
    step['longdesc'] = step.get('longdesc', '')
    for p in step.get('parameters', []):
        if 'name' not in p:
            raise ValueError("Parameter has no name: %s" % (list(p.keys())))
        p['shortdesc'] = _strip(p.get('shortdesc', ''))
        p['longdesc'] = p.get('longdesc', '')
        if 'default' in p and 'value' not in p:
            p['value'] = p['default']
            del p['default']
        if 'value' in p:
            if p['value'] is None:
                del p['value']
            elif isinstance(p['value'], str):
                p['value'] = Text(script, p['value'])
        if 'required' not in p:
            p['required'] = False
        else:
            p['required'] = _make_boolean(p['required'])
        if 'advanced' in p:
            p['advanced'] = _make_boolean(p['advanced'])
        else:
            p['advanced'] = False
        if 'unique' in p:
            p['unique'] = _make_boolean(p['unique'])
        else:
            p['unique'] = False
        if 'type' not in p or p['type'] == '':
            if p['name'] == 'id':
                p['type'] = 'resource'
            else:
                p['type'] = 'string'
    for s in step.get('steps', []):
        _postprocess_script_step(script, s)


def _postprocess_script_steps(script):
    def empty(step):
        if 'parameters' in step and len(step['parameters']) > 0:
            return False
        if 'steps' in step and len(step['steps']) > 0:
            return False
        return True

    script['steps'] = [step for step in script['steps'] if not empty(step)]

    for step in script['steps']:
        _postprocess_script_step(script, step)


def _postprocess_script(script):
    """
    Post-process the parsed script into an executable
    form. This means parsing all included agents and
    scripts, merging parameters, steps and actions.
    """
    ver = script.get('version')
    if ver is None or str(ver) != str(_script_version):
        raise ValueError("Unsupported script version (expected %s, got %s)" % (_script_version, repr(ver)))

    if 'category' not in script:
        script['category'] = 'Custom'

    if 'actions' not in script:
        script['actions'] = []

        # if we include subscripts but have no defined actions, assume that's a
        # mistake and generate include actions for all includes
        for inc in [{"include": inc['name']} for inc in script.get('include', [])]:
            script['actions'].append(inc)

    _postprocess_script_steps(script)

    # Includes may add steps, or modify parameters,
    # but assume that any included data is already
    # postprocessed. To run this before the
    # step processing would risk replacing Text() objects
    # with references to other scripts with references
    # to this script.
    for inc in script.get('include', []):
        _process_include(script, inc)

    for action in script['actions']:
        if 'include' in action:
            includes = [inc['name'] for inc in script.get('include', [])]
            if action['include'] not in includes:
                raise ValueError("Script references '%s', but only includes: %s" %
                                 (action['include'], ', '.join(includes)))

    if 'include' in script:
        del script['include']

    def _setdesc(name):
        desc = script.get(name)
        if desc is None:
            desc = ''
        if not desc:
            if script['steps'] and script['steps'][0][name]:
                desc = script['steps'][0][name]
                script['steps'][0][name] = ''
        script[name] = desc
    _setdesc('shortdesc')
    _setdesc('longdesc')

    return script


def _join_script_lines(txt):
    s = ""
    current_line = ""
    for line in [line for line in txt.split('\n')]:
        if not line.strip():
            pass
        elif re.match(r'^\s+\S', line):
            current_line += line
        else:
            if current_line.strip():
                s += current_line + "\n"
            current_line = line
    if current_line:
        s += current_line + "\n"
    return s


def load_script_file(script, filename):
    if filename.endswith('.yml'):
        parsed = _parse_yaml(script, filename)
    elif filename.endswith('.xml'):
        parsed = _parse_hawk_workflow(script, filename)
    if parsed is None:
        raise ValueError("Failed to parse script: %s (%s)" % (script, filename))
    obj = _postprocess_script(parsed)
    if 'name' in obj:
        script = obj['name']
    if script not in _script_cache or isinstance(_script_cache[script], str):
        _script_cache[script] = obj
    return obj


def load_script_string(script, yml):
    build_script_cache()
    import io
    import yaml
    data = yaml.load(io.StringIO(yml), Loader=yaml.SafeLoader)
    if isinstance(data, list):
        data = data[0]
    if 'parameters' in data:
        data['steps'] = [{'parameters': data['parameters']}]
        del data['parameters']
    elif 'steps' not in data:
        data['steps'] = []
    data['name'] = script
    data['dir'] = None

    obj = _postprocess_script(data)
    if 'name' in obj:
        script = obj['name']
    _script_cache[script] = obj
    return obj


def load_script(script):
    build_script_cache()
    if script not in _script_cache:
        logger.debug("cache: %s", list(_script_cache.keys()))
        raise ValueError("Script not found: %s" % (script))
    s = _script_cache[script]
    if isinstance(s, str):
        try:
            return load_script_file(script, s)
        except KeyError as err:
            raise ValueError("Error when loading script %s: Expected key %s not found" % (script, err))
        except Exception as err:
            raise ValueError("Error when loading script %s: %s" % (script, err))
    return s


def _script_dirs():
    "list of directories that may contain cluster scripts"
    ret = [d for d in options.scriptdir.split(';') if d and os.path.isdir(d)]
    return ret + [os.path.join(userdir.CONFIG_HOME, 'scripts'),
                  os.path.join(config.path.sharedir, 'scripts'),
                  config.path.hawk_wizards]


def _check_control_persist():
    '''
    Checks if ControlPersist is available. If so,
    we'll use it to make things faster.
    '''
    cmd = 'ssh -o ControlPersist'.split()
    if options.regression_tests:
        print((".EXT", cmd))
    cmd = subprocess.Popen(cmd,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
    (out, err) = cmd.communicate()
    return "Bad configuration option" not in err


def _parallax_call(printer, hosts, cmd, opts):
    "parallax.call with debug logging"
    printer.debug("parallax.call(%s, %s)" % (repr(hosts), cmd))
    return parallax.call(hosts, cmd, opts)


def _resolve_script(name):
    for p in list_scripts():
        if p.endswith('main.yml') and os.path.dirname(p).endswith('/' + name):
            return p
        elif p.endswith('.yml') and os.path.splitext(os.path.basename(p))[0] == name:
            return p
        elif p.endswith('.xml') and os.path.splitext(os.path.basename(p))[0] == name:
            return p
    return None


def _parallax_copy(printer, hosts, src, dst, opts):
    "parallax.copy with debug logging"
    printer.debug("parallax.copy(%s, %s, %s)" % (repr(hosts), src, dst))
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
    if hosts:
        for host, result in _parallax_call(printer, hosts,
                                           "if [ -f '%s' ]; then cat '%s'; fi" % (dbglog, dbglog),
                                           opts).items():
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
        for host, result in _parallax_call(printer, hosts,
                                           "%s %s" % (cleanscript,
                                                      workdir),
                                           opts).items():
            if isinstance(result, parallax.Error):
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
    logger.debug("Local node: %s, Remote hosts: %s", local_node, ', '.join(h[0] for h in hosts2))
    return local_node, hosts2


# TODO: remove common params?
# Pass them in a separate list of options?
# Right now these names are basically reserved..
def common_params():
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
    for param, default, _ in common_params():
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


def _scoped_param(context, name):
    if context:
        return ':'.join(context) + ':' + name
    return name


def _find_by_name(params, name):
    try:
        return next(x for x in params if x.get('name') == name)
    except StopIteration:
        return None


_IDENT_RE = re.compile(r'^([a-z0-9_#$-][^\s=]*)$', re.IGNORECASE)


def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True


def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True

# Types:
# OCF types
#
# string
# integer
# boolean
#
# Propose to add
# resource ==> a valid resource identifier
# ip_address ==> a valid ipv4 or ipv6 address
# ip_network ==> a valid ipv4 or ipv6 network (or address without /XX)
# port ==> integer between 0 and 65535
# email ==> a valid email address

# node ==> name of a node in the cluster
# select <value>, <value>, <value>, ... ==> any of the values in the list.
# range <n> <m> ==> integer in range
# rx <rx> ==> anything matching the regular expression.


def _valid_integer(value):
    try:
        return True, int(value, base=0)
    except ValueError:
        return False, value


def _valid_ip(value):
    return is_valid_ipv4_address(value) or is_valid_ipv6_address(value)


def _verify_type(param, value, errors):
    if value is None:
        value = ''
    vtype = param.get('type')
    if not vtype:
        return value
    elif vtype == 'integer':
        ok, _ = _valid_integer(value)
        if not ok:
            errors.append("%s=%s is not an integer" % (param.get('name'), value))
    elif vtype == 'string':
        return value
    elif vtype == 'boolean':
        return "true" if _make_boolean(value) else "false"
    elif vtype == 'resource':
        try:
            if not _IDENT_RE.match(value):
                errors.append("%s=%s invalid resource identifier" % (param.get('name'), value))
        except TypeError as e:
            errors.append("%s=%s %s" % (param.get('name'), value, str(e)))
    elif vtype == 'enum':
        if 'values' not in param:
            errors.append("%s=%s enum without list of values" % (param.get('name'), value))
        else:
            opts = param['values']
            if isinstance(opts, str):
                opts = opts.replace(',', ' ').split(' ')
            for v in opts:
                if value.lower() == v.lower():
                    return v
            errors.append("%s=%s does not match '%s'" % (param.get('name'), value, "|".join(opts)))
    elif vtype == 'ip_address':
        if not _valid_ip(value):
            errors.append("%s=%s is not an IP address" % (param.get('name'), value))
    elif vtype == 'ip_network':
        sp = value.rsplit('/', 1)
        if len(sp) == 1 and not (is_valid_ipv4_address(value) or is_valid_ipv6_address(value)):
            errors.append("%s=%s is not a valid IP network" % (param.get('name'), value))
        elif len(sp) == 2 and (not _valid_ip(sp[0]) or not _valid_integer(sp[1])):
            errors.append("%s=%s is not a valid IP network" % (param.get('name'), value))
        else:
            errors.append("%s=%s is not a valid IP network" % (param.get('name'), value))
    elif vtype == 'port':
        ok, ival = _valid_integer(value)
        if not ok:
            errors.append("%s=%s is not a valid port" % (param.get('name'), value))
        if ival < 0 or ival > 65535:
            errors.append("%s=%s is out of port range" % (param.get('name'), value))
    elif vtype == 'email':
        if not re.match(r'[^@]+@[^@]+', value):
            errors.append("%s=%s is not a valid email address" % (param.get('name'), value))
    else:
        errors.append("%s=%s is unknown type %s" % (param.get('name'), value, vtype))
    return value


_NO_RESOLVE = object()


def _resolve_direct(step, pname, pvalue, path, errors):
    step_parameters = step.get('parameters', [])
    step_steps = step.get('steps', [])
    param = _find_by_name(step_parameters, pname)
    if param is not None:
        # resolved to a parameter... now verify the value type?
        return _verify_type(param, pvalue, errors)
    substep = _find_by_name(step_steps, pname)
    if substep is not None:
        # resolved to a step... recurse
        return _resolve_params(substep, pvalue, path + [pname], errors)
    return _NO_RESOLVE


def _resolve_unnamed_step(step, pname, pvalue, path, errors):
    step_steps = step.get('steps', [])
    substep = _find_by_name(step_steps, '')
    if substep is not None:
        return _resolve_direct(substep, pname, pvalue, path, errors)
    return _NO_RESOLVE


def _resolve_single_step(step, pname, pvalue, path, errors):
    step_steps = step.get('steps', [])
    if len(step_steps) >= 1:
        first_step = step_steps[0]
        return _resolve_direct(first_step, pname, pvalue, path + [first_step.get('name')], errors)
    return _NO_RESOLVE


def _resolve_params(step, params, path, errors):
    """
    any parameter that doesn't resolve is an error
    """
    ret = {}

    for pname, pvalue in params.items():
        result = _resolve_direct(step, pname, pvalue, path, errors)
        if result is not _NO_RESOLVE:
            ret[pname] = result
            continue

        result = _resolve_unnamed_step(step, pname, pvalue, path, errors)
        if result is not _NO_RESOLVE:
            ret[pname] = result
            continue

        result = _resolve_single_step(step, pname, pvalue, path, errors)
        if result is not _NO_RESOLVE:
            stepname = step['steps'][0].get('name', '')
            if stepname not in ret:
                ret[stepname] = {}
            ret[stepname][pname] = result
            ret[pname] = result
            continue

        errors.append("Unknown parameter %s" % (':'.join(path + [pname])))

    return ret


def _check_parameters(script, params):
    '''
    1. Fill in values where none are supplied and there's a value
    in the step data
    2. Check missing values
    3. For each input parameter: look it up and adjust the path
    '''
    errors = []
    # params = deepcopy(params)
    # recursively resolve parameters: report
    # error if a parameter can't be resolved
    # TODO: move "common params" out of the params dict completely
    # pass as flags to command line

    def _split_commons(params):
        ret, cdict = {}, dict([(c, d) for c, d, _ in common_params()])
        for key, value in params.items():
            if key in cdict:
                cdict[key] = value
            else:
                ret[key] = deepcopy(value)
        return ret, cdict

    params, commons = _split_commons(params)
    params = _resolve_params(script, params, [], errors)

    if errors:
        raise ValueError('\n'.join(errors))

    for key, value in commons.items():
        params[key] = value

    def _fill_values(path, into, source, srcreq):
        """
        Copy values into into while checking for missing required parameters.
        If into has content, all required parameters ARE required, even if the
        whole step is not required (since we're supplying it). This is checked
        by checking if the step is not required, but there are some parameters
        set by the user anyway.
        """
        if 'required' in source:
            srcreq = (source['required'] and srcreq) or (into and srcreq)

        for param in source.get('parameters', []):
            if param['name'] not in into:
                if 'value' in param:
                    into[param['name']] = param['value']
                elif srcreq and param['required']:
                    errors.append(_scoped_param(path, param['name']))

        for step in source.get('steps', []):
            required = step.get('required', True)
            if not required and step['name'] not in into:
                continue
            if not required and step['name'] in into and into[step['name']]:
                required = True
            if 'name' not in step:
                _fill_values(path, into, step, required and srcreq)
            else:
                if step['name'] not in into:
                    into[step['name']] = {}
                _fill_values(path + [step['name']], into[step['name']], step, required and srcreq)

    _fill_values([], params, script, True)

    if errors:
        raise ValueError("Missing required parameter(s): %s" % (', '.join(errors)))

    # if config.core.debug:
    #    from pprint import pprint
    #    print("Checked script parameters:")
    #    pprint(params)
    return params


def _handles_values(ret, script, params, subactions):
    """
    Generate a values structure that the handles
    templates understands.
    """
    def _process(to, context, params):
        """
        to: level writing to
        context: source step
        params: values for step
        """
        for key, value in params.items():
            if not isinstance(value, dict):
                to[key] = value

        for step in context.get('steps', []):
            name = step.get('name', '')
            if name:
                if step['required'] or name in params:
                    obj = {}
                    vobj = handles.value(obj, '')
                    to[name] = vobj
                    subaction = None
                    if step.get('sub-script'):
                        subaction = subactions.get(step['sub-script']['name'])
                    if subaction and subaction[-1]['name'] == 'cib':
                        vobj.value = Text.cib(script, subaction[-1]['value'])
                    else:
                        vobj.value = Text.cib(script, step.get('value', vobj.value))

                    _process(obj, step, params.get(name, {}))
            else:
                _process(to, step, params)

    _process(ret, script, params)


def _has_remote_actions(actions):
    """
    True if any actions execute on remote nodes
    """
    for action in actions:
        if action['name'] in ('collect', 'apply', 'install', 'service', 'copy'):
            return True
        if action.get('nodes') == 'all':
            return True
    return False


def _set_controlpersist(opts):
    # _has_controlpersist = _check_control_persist()
    # if _has_controlpersist:
    #    opts.ssh_options += ["ControlMaster=auto",
    #                         "ControlPersist=30s",
    #                         "ControlPath=/tmp/crm-ssh-%r@%h:%p"]
    # unfortunately, due to bad interaction between parallax and ssh,
    # ControlPersist is broken
    # See: http://code.google.com/p/parallel-ssh/issues/detail?id=67
    # Supposedly fixed in openssh 6.3, but isn't: This may be an
    # issue in parallel-ssh, not openssh
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


def _create_script_workdir(script, workdir):
    "Create workdir and copy contents of scriptdir into it"
    scriptdir = script['dir']
    try:
        if scriptdir is not None:
            if os.path.basename(scriptdir) == script['name']:
                cmd = ["mkdir", "-p", os.path.dirname(workdir)]
            else:
                cmd = ["mkdir", "-p", workdir]
            if options.regression_tests:
                print(".EXT", cmd)
            if subprocess.call(cmd, shell=False) != 0:
                raise ValueError("Failed to create temporary working directory")
            # only copytree if script is a dir
            if os.path.basename(scriptdir) == script['name']:
                shutil.copytree(scriptdir, workdir)
        else:
            cmd = ["mkdir", "-p", workdir]
            if options.regression_tests:
                print(".EXT", cmd)
            if subprocess.call(cmd, shell=False) != 0:
                raise ValueError("Failed to create temporary working directory")
    except (IOError, OSError) as e:
        raise ValueError(e)


def _copy_utils(dst):
    '''
    Copy run utils to the destination directory
    '''
    try:
        import glob
        for f in glob.glob(os.path.join(config.path.sharedir, 'utils/*.py')):
            shutil.copy(f, dst)
    except (IOError, OSError) as e:
        raise ValueError(e)


def _create_remote_workdirs(printer, hosts, path, opts):
    "Create workdirs on remote hosts"
    ok = True
    for host, result in _parallax_call(printer, hosts,
                                       "mkdir -p %s" % (os.path.dirname(path)),
                                       opts).items():
        if isinstance(result, parallax.Error):
            printer.error(host, "Start: %s" % (result))
            ok = False
    if not ok:
        msg = "Failed to connect to one or more of these hosts via SSH: %s" % (
            ', '.join(h[0] for h in hosts))
        raise ValueError(msg)


def _copy_to_remote_dirs(printer, hosts, path, opts):
    "Copy a local folder to same location on remote hosts"
    ok = True
    for host, result in _parallax_copy(printer, hosts,
                                       path,
                                       path, opts).items():
        if isinstance(result, parallax.Error):
            printer.debug("_copy_to_remote_dirs failed: %s, %s, %s" % (hosts, path, opts))
            printer.error(host, result)
            ok = False
    if not ok:
        raise ValueError("Failed when copying script data, aborting.")
    return ok


def _copy_local(printer, workdir, local_node, src, dst):
    ok = True
    if local_node and not src.startswith(workdir):
        try:
            if os.path.abspath(src) != os.path.abspath(dst):
                if os.path.isfile(src):
                    shutil.copy(src, dst)
                else:
                    shutil.copytree(src, dst)
        except (IOError, OSError, shutil.Error) as e:
            printer.error(local_node, e)
            ok = False
    return ok


def _copy_to_all(printer, workdir, hosts, local_node, src, dst, opts):
    """
    Copy src to dst both locally and remotely
    """
    ok = True
    ret = _parallax_copy(printer, hosts, src, dst, opts)
    for host, result in ret.items():
        if isinstance(result, parallax.Error):
            printer.error(host, result)
            ok = False
        else:
            rc, out, err = result
            if rc != 0:
                printer.error(host, err)
                ok = False
    return ok and _copy_local(printer, workdir, local_node, src, dst)


def _clean_parameters(params):
    ret = []
    for param in params:
        rp = {}
        for elem in ('name', 'required', 'unique', 'advanced', 'type', 'example'):
            if elem in param:
                rp[elem] = param[elem]
        if 'shortdesc' in param:
            rp['shortdesc'] = _strip(param['shortdesc'])
        if 'longdesc' in param:
            rp['longdesc'] = format_desc(param['longdesc'])
        if 'value' in param:
            val = param['value']
            if isinstance(val, Text):
                val = val.text
            rp['value'] = val
        ret.append(rp)
    return ret


def clean_steps(steps):
    ret = []
    for step in steps:
        rstep = {}
        if 'name' in step:
            rstep['name'] = step['name']
        if 'shortdesc' in step:
            rstep['shortdesc'] = _strip(step['shortdesc'])
        if 'longdesc' in step:
            rstep['longdesc'] = format_desc(step['longdesc'])
        if 'required' in step:
            rstep['required'] = step['required']
        if 'parameters' in step:
            rstep['parameters'] = _clean_parameters(step['parameters'])
        if 'steps' in step:
            rstep['steps'] = clean_steps(step['steps'])
        ret.append(rstep)
    return ret


def clean_run_params(params):
    for key, value in params.items():
        if isinstance(value, dict):
            clean_run_params(value)
        elif Text.isa(value):
            params[key] = str(value)
    return params


def _chmodx(path):
    "chmod +x <path>"
    mode = os.stat(path).st_mode
    mode |= (mode & 0o444) >> 2
    os.chmod(path, mode)


class RunActions(object):
    def __init__(self, printer, script, params, actions, local_node, hosts, opts, workdir):
        self.printer = printer
        self.script = script
        self.data = [clean_run_params(params)]
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

    def prepare(self, has_remote_actions):
        if not self.dry_run:
            _create_script_workdir(self.script, self.workdir)
            json.dump(self.data, open(self.statefile, 'w'))
            _copy_utils(self.workdir)
            if has_remote_actions:
                _create_remote_workdirs(self.printer, self.hosts, self.workdir, self.opts)
                _copy_to_remote_dirs(self.printer, self.hosts, self.workdir, self.opts)
            # make sure all path references are relative to the script directory
            os.chdir(self.workdir)

    def single_action(self, action_index, statefile):
        self.statefile = statefile
        try:
            action_index = int(action_index) - 1
        except ValueError:
            raise ValueError("action parameter must be an index")
        if action_index < 0 or action_index >= len(self.actions):
            raise ValueError("action index out of range")

        action = self.actions[action_index]
        logger.debug("Execute: %s", action)
        # if this is not the first action, load action data
        if action_index != 1:
            if not os.path.isfile(statefile):
                raise ValueError("No state for action: %s" % (action_index))
            self.data = json.load(open(statefile))
        if Actions.needs_sudo(action):
            self._check_sudo_pass()
        result = self._run_action(action)
        json.dump(self.data, open(self.statefile, 'w'))
        return result

    def all_actions(self):
        # TODO: run asynchronously on remote nodes
        # run on remote nodes
        # run on local nodes
        # TODO: wait for remote results
        for action in self.actions:
            if Actions.needs_sudo(action):
                self._check_sudo_pass()
            if not self._run_action(action):
                return False
        return True

    def _update_state(self):
        if self.dry_run:
            return True
        json.dump(self.data, open(self.statefile, 'w'))
        return _copy_to_all(self.printer,
                            self.workdir,
                            self.hosts,
                            self.local_node,
                            self.statefile,
                            self.dstfile,
                            self.opts)

    def run_command(self, nodes, command, is_json_output):
        "called by Actions"
        cmdline = 'cd "%s"; ./%s' % (self.workdir, command)
        if not self._update_state():
            raise ValueError("Failed when updating input, aborting.")
        self.call(nodes, cmdline, is_json_output)

    def copy_file(self, nodes, src, dst):
        if not self._is_local(nodes):
            ok = _copy_to_all(self.printer,
                              self.workdir,
                              self.hosts,
                              self.local_node,
                              src,
                              dst,
                              self.opts)
        else:
            ok = _copy_local(self.printer,
                             self.workdir,
                             self.local_node,
                             src,
                             dst)
        self.result = '' if ok else None
        self.rc = ok

    def record_json(self):
        "called by Actions"
        if self.result is not None:
            if not self.result:
                self.result = {}
            self.data.append(self.result)
            self.rc = True
        else:
            self.rc = False

    def validate_json(self):
        "called by Actions"
        if self.dry_run:
            self.rc = True
            return

        if self.result is not None:
            if not self.result:
                self.result = ''
            self.data.append(self.result)
            if isinstance(self.result, dict):
                for k, v in self.result.items():
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
            method(Actions(self, action))
            self.printer.finish(action, self.rc, self.output)
            return self.rc
        finally:
            self.printer.flush()
        return False

    def _check_sudo_pass(self):
        if self.sudo and not self.sudo_pass and userdir.getuser() != 'root':
            prompt = "sudo password: "
            self.sudo_pass = getpass.getpass(prompt=prompt)

    def _is_local(self, nodes):
        islocal = False
        if nodes == 'all':
            pass
        elif nodes == 'local':
            islocal = True
        elif nodes is not None and nodes != []:
            islocal = nodes == [self.local_node_name()]
        else:
            islocal = True
        self.printer.debug("is_local (%s): %s" % (nodes, islocal))
        return islocal

    def call(self, nodes, cmdline, is_json_output=False):
        if cmdline.startswith("#!"):
            self.execute_shell(nodes or 'all', cmdline)
        else:
            if not self._is_local(nodes):
                self.result = self._process_remote(cmdline, is_json_output)
            else:
                self.result = self._process_local(cmdline, is_json_output)
            self.rc = self.result not in (False, None)

    def execute_shell(self, nodes, cmdscript):
        """
        execute the shell script...
        """
        cmdscript = str(cmdscript).rstrip() + '\n'
        if self.dry_run:
            self.printer.print_command(nodes, cmdscript)
            self.result = ''
            self.rc = True
            return
        elif config.core.debug:
            self.printer.print_command(nodes, cmdscript)

        tmpf = self.str2tmp(cmdscript)
        _chmodx(tmpf)
        if not self._is_local(nodes):
            ok = _copy_to_remote_dirs(self.printer,
                                      self.hosts,
                                      tmpf,
                                      self.opts)
            if not ok:
                self.result = False
            else:
                cmdline = 'cd "%s"; %s' % (self.workdir, tmpf)
                self.result = self._process_remote(cmdline, False)
        else:
            cmdline = 'cd "%s"; %s' % (self.workdir, tmpf)
            self.result = self._process_local(cmdline, False)
        self.rc = self.result not in (None, False)

    def str2tmp(self, s):
        """
        Create a temporary file in the temp workdir
        Returns path to file
        """
        fn = os.path.join(self.workdir, _tempname('str2tmp'))
        if self.dry_run:
            self.printer.print_command(self.local_node_name(), 'temporary file <<END\n%s\nEND\n' % (s))
            return fn
        elif config.core.debug:
            self.printer.print_command(self.local_node_name(), 'temporary file <<END\n%s\nEND\n' % (s))
        try:
            with open(fn, "w") as f:
                f.write(s)
                if not s.endswith('\n'):
                    f.write("\n")
        except IOError as msg:
            self.printer.error(self.local_node_name(), "Write failed: %s" % (msg))
            return
        return fn

    def _process_remote(self, cmdline, is_json_output):
        """
        Handle an action that executes on all nodes
        """
        ok = True
        action_result = {}

        if self.sudo_pass:
            self.opts.input_stream = u'sudo: %s\n' % (self.sudo_pass)
        else:
            self.opts.input_stream = None

        if self.dry_run:
            self.printer.print_command(self.hosts, cmdline)
            return {}
        elif config.core.debug:
            self.printer.print_command(self.hosts, cmdline)

        for host, result in _parallax_call(self.printer,
                                           self.hosts,
                                           cmdline,
                                           self.opts).items():
            if isinstance(result, parallax.Error):
                self.printer.error(host, "Remote error: %s" % (result))
                ok = False
            else:
                rc, out, err = result
                out = utils.to_ascii(out)
                if rc != 0:
                    self.printer.error(host, "Remote error (rc=%s) %s%s" % (rc, out, err))
                    ok = False
                elif is_json_output:
                    action_result[host] = json.loads(out)
                else:
                    action_result[host] = out
        if self.local_node:
            ret = self._process_local(cmdline, False)
            if ret is None:
                ok = False
            elif is_json_output:
                action_result[self.local_node_name()] = json.loads(ret)
            else:
                action_result[self.local_node_name()] = ret
        if ok:
            self.printer.debug("Result: %s" % repr(action_result))
            return action_result
        return None

    def _process_local(self, cmdline, is_json_output):
        """
        Handle an action that executes locally
        """
        if self.sudo_pass:
            input_s = u'sudo: %s\n' % (self.sudo_pass)
        else:
            input_s = None
        if self.dry_run:
            self.printer.print_command(self.local_node_name(), cmdline)
            return {}
        elif config.core.debug:
            self.printer.print_command(self.local_node_name(), cmdline)
        rc, out, err = utils.get_stdout_stderr(cmdline, input_s=input_s, shell=True)
        if rc != 0:
            self.printer.error(self.local_node_name(), "Error (%d): %s" % (rc, err))
            return None
        self.printer.debug("Result(local): %s" % repr(out))
        if is_json_output:
            if out != '':
                out = json.loads(out)
        return out

    def local_node_name(self):
        if self.local_node:
            return self.local_node[0]
        return "localhost"


def run(script, params, printer):
    '''
    Run the given script on the given set of hosts
    name: a cluster script is a folder <name> containing a main.yml or main.xml file
    params: a tree of parameters
    printer: Object that receives and formats output
    '''
    workdir = _generate_workdir_name()
    # pull out the actions to perform based on the actual
    # parameter values (so discard actions conditional on
    # conditions that are false)
    params = _check_parameters(script, params)
    user = params['user']
    port = params['port']
    _filter_dict(params, 'nodes', _filter_nodes, user, port)
    _filter_dict(params, 'dry_run', _make_boolean)
    _filter_dict(params, 'sudo', _make_boolean)
    _filter_dict(params, 'statefile', lambda x: (x and os.path.abspath(x)) or x)
    if config.core.debug:
        params['debug'] = True
    actions = _process_actions(script, params)
    name = script['name']
    hosts = params['nodes']
    printer.print_header(script, params, hosts)
    local_node, hosts = _extract_localnode(hosts)
    opts = _make_options(params)
    _set_controlpersist(opts)

    dry_run = params.get('dry_run', False)

    has_remote_actions = _has_remote_actions(actions)

    try:
        runner = RunActions(printer, script, params, actions, local_node, hosts, opts, workdir)
        runner.prepare(has_remote_actions)
        action = params['action']
        statefile = params['statefile']
        if action or statefile:
            if not action or not statefile:
                raise ValueError("Must set both action and statefile")
            return runner.single_action(action, statefile)
        else:
            return runner.all_actions()

    except (OSError, IOError) as e:
        import traceback
        traceback.print_exc()
        raise ValueError("Internal error while running %s: %s" % (name, e))
    finally:
        if not dry_run:
            if not config.core.debug:
                _run_cleanup(printer, has_remote_actions, local_node, hosts, workdir, opts)
            elif has_remote_actions:
                _print_debug(printer, local_node, hosts, workdir, opts)
            else:
                _print_debug(printer, local_node, None, workdir, opts)


def _remove_empty_lines(txt):
    return '\n'.join(line for line in txt.split('\n') if line.strip())


def _process_actions(script, params):
    """
    Given parameter values, we can process
    all the handles data and generate all the
    actions to perform, validate and check conditions.
    """

    subactions = {}
    values = {}
    script['__values__'] = values

    for step in script['steps']:
        _handles_values(values, script, params, subactions)
        if not step.get('required', True) and not params.get(step['name']):
            continue
        obj = step.get('sub-script')
        if obj:
            try:
                subparams = params.get(step['name'], {})
                subactions[step['name']] = _process_actions(obj, subparams)
            except ValueError as err:
                raise ValueError("Error in included script %s: %s" % (step['name'], err))

    _handles_values(values, script, params, subactions)
    actions = deepcopy(script['actions'])

    ret = []
    for action in actions:
        name = _find_action(action)
        if name is None:
            raise ValueError("Unknown action: %s" % (list(action.keys())))
        action['name'] = name
        toadd = []
        if name == 'include':
            if action['include'] in subactions:
                toadd.extend(subactions[action['include']])
        else:
            Actions.parse(script, action)
            if 'when' in action:
                when = str(action['when']).strip()
                if when not in (False, None, '', 'false'):
                    toadd.append(action)
            else:
                toadd.append(action)
        if ret:
            for add in toadd:
                if Actions.mergeable(add) and ret[-1]['name'] == add['name']:
                    if not Actions.merge(ret[-1], add):
                        ret.append(add)
                else:
                    ret.append(add)
        else:
            ret.extend(toadd)
    return ret


def verify(script, params, external_check=True):
    """
    Verify the given parameter values, reporting
    errors where such are detected.

    Return a list of actions to perform.
    """
    params = _check_parameters(script, params)
    actions = _process_actions(script, params)

    if external_check and all(action['name'] == 'cib' for action in actions) and utils.is_program('crm'):
        errors = set([])
        cmd = ["cib new"]
        for action in actions:
            cmd.append(_join_script_lines(action['value']))
        cmd.extend(["verify", "commit", "\n"])
        try:
            logger.debug("Try executing %s", "\n".join(cmd))
            rc, out = utils.filter_string(['crm', '-f', '-', 'configure'], "\n".join(cmd).encode('utf-8'), stderr_on='stdout', shell=False)
            errm = re.compile(r"^ERROR: \d+: (.*)$")
            outp = []
            for l in (out or "").splitlines():
                m = errm.match(l)
                if m:
                    errors.add(m.group(1))
                else:
                    outp.append(l)
            if rc != 0 and len(errors) == 0:
                errors.add("Failed to verify (rc=%s): %s" % (rc, "\n".join(outp)))
        except OSError as e:
            errors.add(str(e))
        if len(errors):
            raise ValueError("\n".join(errors))

    return actions


def _make_boolean(v):
    if isinstance(v, str):
        return utils.get_boolean(v)
    return v not in (0, False, None)
