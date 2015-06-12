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


class ConsolePrinter(object):
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
        else:
            err_buf.error("%s (rc=%s)" % (action['shortdesc'] or action['name'], rc))
        if output:
            print(output)

    def flush(self):
        if self.in_progress:
            self.in_progress = False
            if not config.core.debug:
                sys.stdout.write('\r')
            else:
                sys.stdout.write('\n')
            sys.stdout.flush()

    def debug(self, msg):
        if config.core.debug or options.regression_tests:
            self.flush()
            err_buf.debug(msg)

    def print_command(self, nodes, command):
        self.flush()
        sys.stdout.write("** %s - %s\n" % (nodes, command))


class JsonPrinter(object):
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

    def print_command(self, nodes, command):
        pass


def describe_param(p, name, all):
    if not all and p.get('advanced'):
        return ""
    opt = ' (required) ' if p['required'] else ''
    opt += ' (unique) ' if p['unique'] else ''
    if 'value' in p:
        opt += (' (default: %s)' % (repr(p['value']))) if p['value'] else ''
    s = "  %s%s\n" % (name, opt)
    s += "      %s\n" % (p['shortdesc'])
    return s


def _scoped_name(context, name):
    if context:
        return ':'.join(context) + ':' + name
    return name


def describe_step(icontext, context, s, all):
    ret = "%s. %s" % ('.'.join([str(i + 1) for i in icontext]), scripts.format_desc(s['shortdesc']) or 'Parameters')
    if not s['required']:
        ret += ' (optional)'
    ret += '\n\n'
    if s.get('name'):
        context = context + [s['name']]
    for p in s.get('parameters', []):
        ret += describe_param(p, _scoped_name(context, p['name']), all)
    for i, step in enumerate(s.get('steps', [])):
        ret += describe_step(icontext + [i], context, step, all)
    ret += '\n'
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

    @command.completers_repeating(compl.choice(['all', 'names']))
    def do_list(self, context, *args):
        '''
        List available scripts.
        hides scripts with category Script or '' by default,
        unless "all" is passed as argument
        '''
        for arg in args:
            if arg.lower() not in ("all", "names"):
                context.error("Unexpected argument '%s': expected  [all|names]" % (all))
        all = any([x for x in args if x.lower() == 'all'])
        names = any([x for x in args if x.lower() == 'names'])
        if not names:
            categories = {}
            for name in scripts.list_scripts():
                try:
                    script = scripts.load_script(name)
                    if script is None:
                        continue
                    cat = script['category'].lower()
                    if not all and cat == 'script':
                        continue
                    if cat not in categories:
                        categories[cat] = []
                    categories[cat].append("%-16s %s" % (script['name'], script['shortdesc']))
                except ValueError as err:
                    err_buf.error(str(err))
                    continue
            for c, lst in sorted(categories.iteritems(), key=lambda x: x[0]):
                if c:
                    print("%s:\n" % (c.capitalize()))
                for s in sorted(lst):
                    print(s)
                print('')
        elif all:
            for name in scripts.list_scripts():
                print(name)
        else:
            for name in scripts.list_scripts():
                try:
                    script = scripts.load_script(name)
                    if script is None or script['category'] == 'script':
                        continue
                except ValueError as err:
                    err_buf.error(str(err))
                    continue
                print(name)

    @command.completers_repeating(compl.call(scripts.list_scripts))
    @command.alias('info')
    def do_describe(self, context, name, all=None):
        '''
        Describe the given script.
        '''
        script = scripts.load_script(name)
        if script is None:
            return False

        all = all == 'all'

        vals = {
            'name': script['name'],
            'category': str(script['category']).capitalize(),
            'shortdesc': str(script['shortdesc']),
            'longdesc': scripts.format_desc(script['longdesc']),
            'steps': "\n".join((describe_step([i], [], s, all) for i, s in enumerate(script['steps'])))}
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
            text = str(action.get('text', ''))
            longdesc = str(action.get('longdesc', ''))
            print("%s. %s\n" % (i + 1, shortdesc))
            if longdesc:
                for line in str(longdesc).split('\n'):
                    print("\t%s" % (line))
                print('')
            if text:
                for line in str(text).split('\n'):
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
            return scripts.run(script, _nvpairs2parameters(args), ConsolePrinter())
        return False

    @command.name('_print')
    @command.skill_level('administrator')
    @command.completers(compl.call(scripts.list_scripts))
    def do_print(self, context, name):
        '''
        Debug print the given script.
        '''
        script = scripts.load_script(name)
        if script is None:
            return False
        import pprint
        pprint.pprint(script)

    @command.name('_actions')
    @command.skill_level('administrator')
    @command.completers(compl.call(scripts.list_scripts))
    def do_actions(self, context, name, *args):
        '''
        Debug print the actions for the given script.
        '''
        script = scripts.load_script(name)
        if script is None:
            return False
        ret = scripts.verify(script, _nvpairs2parameters(args))
        if ret is None:
            return False
        import pprint
        pprint.pprint(ret)

    @command.name('_convert')
    def do_convert(self, context, fromdir, tgtdir):
        """
        Convert hawk wizards to cluster scripts
        Needs more work to be really useful.
        fromdir: hawk wizard directory
        tgtdir: where the cluster script will be written
        """
        import yaml
        import os
        import glob
        if not os.path.isdir(fromdir):
            context.error("Expected <fromdir> <todir>")
        scripts._build_script_cache()
        if not os.path.isdir(tgtdir):
            context.error("Expected <fromdir> <todir>")
        for f in glob.glob(os.path.join(fromdir, 'workflows/*.xml')):
            name = os.path.splitext(os.path.basename(f))[0]
            script = scripts._load_script_file(name, f)
            if script is not None:
                try:
                    os.mkdir(os.path.join(tgtdir, name))
                except:
                    pass
                tgtfile = os.path.join(tgtdir, name, "main.yml")
                with open(tgtfile, 'w') as tf:
                    try:
                        print("%s -> %s" % (f, tgtfile))
                        yaml.dump(script, tf, default_flow_style=False)
                    except Exception as err:
                        print(err)

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
                try:
                    script = scripts.load_script(name)
                    if script is not None:
                        print(json.dumps({'name': script['name'],
                                          'category': script['category'].lower(),
                                          'shortdesc': script['shortdesc'],
                                          'longdesc': scripts.format_desc(script['longdesc'])}))
                except ValueError as err:
                    err_buf.debug(str(err))
                    continue
        elif cmd[0] == "describe":
            name = cmd[1]
            script = scripts.load_script(name)
            if script is None:
                return False
            print(json.dumps({'name': script['name'],
                              'category': script['category'].lower(),
                              'shortdesc': script['shortdesc'],
                              'longdesc': scripts.format_desc(script['longdesc']),
                              'steps': scripts.clean_steps(script['steps'])}))
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
                                  'longdesc': str(action.get('longdesc', '')),
                                  'text': str(action.get('text', '')),
                                  'nodes': action.get('nodes', '')}))
        elif cmd[0] == "run":
            name = cmd[1]
            params = cmd[2]
            if not scripts.has_parallax:
                raise ValueError("The parallax python package is missing")
            script = scripts.load_script(name)
            if script is None:
                return False
            scripts.run(script, params, JsonPrinter())
        else:
            raise ValueError("Unknown command: %s" % (cmd[0]))
        print('"end"')
