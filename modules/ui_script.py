# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#


import sys

try:
    import json
except ImportError:
    import simplejson as json

from . import config
from . import command
from . import scripts
from . import utils
from . import options
from . import completers as compl
from .msg import err_buf


class _ConsolePrinter(object):
    def __init__(self):
        self.in_progress = False

    def print_header(self, script, params, hosts):
        if script['shortdesc']:
            err_buf.info(script['shortdesc'])
        err_buf.info("Nodes: " + ', '.join([x[0] for x in hosts]))

    def error(self, host, message):
        err_buf.error("[%s]: %s" % (host, message))

    def output(self, host, rc, out, err):
        if out:
            err_buf.ok("[%s]: %s" % (host, out))
        if err or rc != 0:
            err_buf.error("[%s]: (rc=%d) %s" % (host, rc, err))

    def start(self, action):
        if not options.batch:
            txt = '%s...' % (action['shortdesc'] or action['name'])
            sys.stdout.write(txt)
            sys.stdout.flush()
            self.in_progress = True

    def finish(self, action, rc, output):
        self.flush()
        if rc:
            err_buf.ok(action['shortdesc'] or action['name'])
        if output:
            print(output)

    def flush(self):
        if self.in_progress:
            self.in_progress = False
            sys.stdout.write('\r')
            sys.stdout.flush()

    def debug(self, msg):
        if config.core.debug:
            err_buf.debug(msg)

    def debug_command(self, nodes, command):
        if config.core.debug:
            import pprint
            print "** [%s] - %s" % (nodes, command)
            pprint.pprint(self.data)


class _JsonPrinter(object):
    def __init__(self):
        self.results = []

    def print_header(self, script, params, hosts):
        pass

    def error(self, host, message):
        self.results.append({'host': host, 'error': message})

    def output(self, host, rc, out, err):
        ret = {'host': host, 'rc': rc, 'output': out}
        if err:
            ret['error'] = err
        self.results.append(ret)

    def start(self, action):
        pass

    def finish(self, action, rc, output):
        ret = {'rc': rc, 'shortdesc': action['shortdesc']}
        if rc != 0:
            ret['error'] = output
        else:
            ret['output'] = output
        print(json.dumps(ret))

    def flush(self):
        pass

    def debug(self, msg):
        if config.core.debug:
            err_buf.debug(msg)

    def debug_command(self, nodes, command):
        if config.core.debug:
            import pprint
            print "** [%s] - %s" % (nodes, command)
            pprint.pprint(self.data)


def describe_param(p, name):
    opt = ' (required) ' if p['required'] else ''
    opt += ' (unique) ' if p['unique'] else ''
    if 'value' in p:
        opt += (' (default: %s)' % (p['value'])) if p['value'] else ''
    s = "  %s%s\n" % (name, opt)
    s += "      %s\n" % (p['shortdesc'])
    return s


def _scoped_name(context, name):
    if context:
        return ':'.join(context) + ':' + name
    return name


def describe_step(icontext, context, s):
    ret = "%s. %s\n" % ('.'.join(icontext), s['stepdesc'].strip() or 'Parameters')
    if s.get('longdesc'):
        ret += s['longdesc']
    else:
        ret += '\n'
    if s.get('name'):
        context = context + [s['name']]
    for p in s.get('parameters', []):
        ret += describe_param(p, _scoped_name(context, p['name']))
    for i, step in enumerate(s.get('steps', [])):
        describe_step(icontext + [i], context, step)
    return ret


def _nvpairs2parameters(args):
    """
    input: list with name=value nvpairs, where each name is a :-path
    output: dict tree of name:value, where value can be a nested dict tree
    """
    def _set(d, path, val):
        if len(path) == 1:
            d[path[0]] = val
        else:
            if path[0] not in d:
                d[path[0]] = {}
            _set(d[path[0]], path[1:], val)

    ret = {}
    for key, val in utils.nvpairs2dict(args).iteritems():
        _set(ret, key.split(':'), val)
    return ret


class Script(command.UI):
    '''
    Cluster scripts can perform cluster-wide configuration,
    validation and management. See the `list` command for
    an overview of available scripts.

    The script UI is a thin veneer over the scripts
    backend module.
    '''
    name = "script"

    def do_list(self, context):
        '''
        List available scripts.
        '''
        for name in scripts.list_scripts():
            script = scripts.load_script(name)
            if script is not None:
                print("%-16s %s" % (script['name'], script['shortdesc'].strip()))

    @command.completers_repeating(compl.call(scripts.list_scripts))
    @command.alias('info')
    def do_describe(self, context, name):
        '''
        Describe the given script.
        '''
        script = scripts.load_script(name)
        if script is None:
            return False

        vals = {
            'name': script['name'],
            'category': script['category'],
            'shortdesc': script['shortdesc'].strip(),
            'longdesc': script['longdesc'].strip(),
            'steps': "\n".join((describe_step([i + 1], s) for i, s in enumerate(script['steps'])))}
        print("""%(name)s (%(category)s)
%(shortdesc)s

%(longdesc)s

%(steps)s
""" % vals)

    @command.completers(compl.call(scripts.list_scripts))
    def do_verify(self, context, name, *args):
        '''
        Verify the script parameters
        '''
        script = scripts.load_script(name)
        if script is None:
            return False
        ret = scripts.verify(script, _nvpairs2parameters(args))
        if ret is None:
            return False
        if not ret:
            print("OK (no actions)")
        for i, action in enumerate(ret):
            shortdesc = action.get('shortdesc', '')
            text = action.get('text') or action.get('longdesc', '')
            print("%s. %s\n" % (i + 1, shortdesc))
            if text:
                for line in text.split('\n'):
                    print("\t%s" % (line))
                print('')

    @command.completers(compl.call(scripts.list_scripts))
    def do_run(self, context, name, *args):
        '''
        Run the given script.
        '''
        if not scripts.has_parallax:
            raise ValueError("The parallax python package is missing")
        script = scripts.load_script(name)
        if script is not None:
            return scripts.run(script, _nvpairs2parameters(args), _ConsolePrinter)
        return False

    @command.name('_print')
    @command.skill_level('administrator')
    @command.completers(compl.call(scripts.list_scripts))
    def do_print(self, context, name):
        '''
        Debug print the given script.
        '''
        script = scripts.load_script(name)
        if script is not None:
            import pprint
            pprint.pprint(script)
        return False

    def do_json(self, context, command):
        """
        JSON API for the scripts, for use in web frontends.
        Line-based output: enter a JSON command,
        get lines of output back. In the description below, the output is
        described as an array, but really it is returned line-by-line with
        a terminator value: "end"

        API:

        ["list"]
        => [{name, shortdesc, category}]
        ["describe", <name>]
        => [{name, shortdesc, longdesc, category, <<steps>>}]
        <<steps>> := [{stepname, shortdesc, longdesc, required, <<params>>}]
        <<params>> := [{name, shortdesc, longdesc, required, unique, type, value, example}]
        ["verify", <name>, <values>]
        => [{shortdesc, longdesc, nodes}]
        ["run", <name>, <values>]
        => [{shortdesc, rc, output|error}]
        """
        cmd = json.loads(command)
        if cmd[0] == "list":
            for name in scripts.list_scripts():
                script = scripts.load_script(name)
                if script is not None:
                    print(json.dumps({'name': script['name'],
                                      'category': script['category'],
                                      'shortdesc': script['shortdesc'],
                                      'longdesc': script['longdesc']}))
        elif cmd[0] == "describe":
            name = cmd[1]
            script = scripts.load_script(name)
            if script is None:
                return False
            print(json.dumps({'name': script['name'],
                              'category': script['category'],
                              'shortdesc': script['shortdesc'],
                              'longdesc': script['longdesc'],
                              'steps': script['steps']}))
        elif cmd[0] == "verify":
            name = cmd[1]
            params = cmd[2]
            script = scripts.load_script(name)
            if script is None:
                return False
            ret = scripts.verify(script, params)
            if ret is None:
                return False
            for action in ret:
                print(json.dumps({'shortdesc': action.get('shortdesc', ''),
                                  'longdesc': action.get('text') or action.get('longdesc', ''),
                                  'nodes': action.get('nodes', '')}))
        elif cmd[0] == "run":
            name = cmd[1]
            params = cmd[2]
            if not scripts.has_parallax:
                raise ValueError("The parallax python package is missing")
            script = scripts.load_script(name)
            if script is None:
                return False
            scripts.run(script, params, _JsonPrinter())
        else:
            raise ValueError("Unknown command: %s" % (cmd[0]))
        print('"end"')
