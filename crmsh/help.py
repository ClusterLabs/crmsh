# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

'''
The commands exposed by this module all
get their data from the doc/crm.8.adoc text
file. In that file, there are help for
 - topics
 - levels
 - commands in levels

The help file is lazily loaded when the first
request for help is made.

All help is in the following form in the manual:
[[cmdhelp_<level>_<cmd>,<short help text>]]
=== ...
Long help text.
...
[[cmdhelp_<level>_<cmd>,<short help text>]]

Help for the level itself is like this:

[[cmdhelp_<level>,<short help text>]]
'''
import dataclasses
import functools
import io
import os
import re
import typing

from .sh import ShellUtils
from .utils import fuzzy_get
from .utils import page_string
from . import config
from . import clidisplay
from . import log
from . import ra


logger = log.setup_logger(__name__)


class HelpFilter(object):
    _B0 = re.compile(r'^\.{4,}')
    _B1 = re.compile(r'^\*{4,}')
    _QUOTED = re.compile(r'`([^`]+)`')
    _MONO = re.compile(r'\+([^+]+)\+')
    _TOPIC = re.compile(r'(.*)::$')
    _TOPIC2 = re.compile(r'^\.\w+')

    def __init__(self):
        self.in_block = False

    def _filter(self, line):
        block_edge = self._B0.match(line) or self._B1.match(line)
        if block_edge and not self.in_block:
            self.in_block = True
            return ''
        elif block_edge and self.in_block:
            self.in_block = False
            return ''
        elif not self.in_block:
            if self._TOPIC2.match(line):
                return clidisplay.help_topic(line[1:])
            line = self._QUOTED.sub(clidisplay.help_keyword(r'\1'), line)
            line = self._MONO.sub(clidisplay.help_block(r'\1'), line)
            line = self._TOPIC.sub(clidisplay.help_topic(r'\1'), line)
            return line
        else:
            return clidisplay.help_block(line)

    def __call__(self, text):
        return '\n'.join([self._filter(line) for line in text.splitlines()]) + '\n'


class HelpEntry(object):
    def __init__(self, short_help, long_help='', alias_for=None, generated=False):
        if short_help:
            self.short = short_help[0].upper() + short_help[1:]
        else:
            self.short = 'Help'
        self._long_help = long_help
        self.alias_for = alias_for
        self.generated = generated

    @property
    def long_help(self):
        return self._long_help

    @long_help.setter
    def long_help(self, value):
        self._long_help = value

    def is_alias(self):
        return self.alias_for is not None

    def paginate(self):
        '''
        Display help, paginated.
        Replace asciidoc syntax with colorized output where possible.
        '''
        helpfilter = HelpFilter()

        short_help = clidisplay.help_header(self.short)
        long_help = self.long_help
        if long_help:
            long_help = helpfilter(long_help)
            if not long_help.startswith('\n'):
                long_help = '\n' + long_help

        prefix = ''
        if self.is_alias():
            prefix = helpfilter("(Redirected from `%s` to `%s`)\n" % self.alias_for)

        page_string(short_help + '\n' + prefix + long_help)

    def __str__(self):
        if self.long_help:
            return self.short + '\n' + self.long_help
        return self.short

    def __repr__(self):
        return str(self)


class LazyHelpEntryFromCli(HelpEntry):
    """lazy load from cli --help"""
    def __init__(
            self,
            short_help: str,
            cmd_args: typing.Sequence[str],
            alias_for=None, generated=False,
    ):
        super().__init__(short_help, '', alias_for, generated)
        self._cmd_args = cmd_args

    @functools.cached_property
    def long_help(self):
        args = ['crm']
        args.extend(self._cmd_args)
        args.append('--help-without-redirect')
        rc, stdout, _ = ShellUtils.get_stdout_stderr(args, shell=False, mix_stderr=True)
        return stdout

    def paginate(self):
        page_string('{}\n\n{}'.format(self.short, self.long_help))


@dataclasses.dataclass
class SubcommandTreeNode:
    """Tree node representing subcommmand hierarchy and holding HelpEntries"""
    name: str
    help: HelpEntry
    children: dict[str, typing.Self]

    def make_sublevel_recursively(self, sublevels: typing.Sequence[str]) -> typing.Self:
        current_level = self
        for sublevel in sublevels:
            x = current_level.children.get(sublevel, None)
            if x is None:
                x = SubcommandTreeNode(sublevel, HelpEntry(''), dict())
                current_level.children[sublevel] = x
            current_level = x
        return current_level


HELP_FILE = os.path.join(config.path.sharedir, 'crm.8.adoc')

_DEFAULT = HelpEntry('No help available', long_help='', alias_for=None, generated=True)
_REFERENCE_RE = re.compile(r'<<[^,]+,(.+)>>')

# loaded on demand
# _LOADED is set to True when an attempt
# has been made (so it won't be tried again)
_LOADED = False
_TOPICS = {}
_COMMAND_TREE = SubcommandTreeNode(
    'crm',
    HelpEntry(''),
    dict()
)

_TOPICS["Overview"] = HelpEntry("Available help topics and commands", generated=True)
_TOPICS["Topics"] = HelpEntry("Available help topics", generated=True)


def _titleline(title, desc, suffix='', width=16):
    return '%-0*s %s\n' % (width, ('`%s`' % (title)) + suffix, desc)


_hidden_commands = ('up', 'cd', 'help', 'quit', 'ls')


def get_max_width(dict_):
    max_width = 16
    for key in list(dict_.keys()):
        if max_width < len(key):
            max_width = len(key)
    if max_width >= 16:
        max_width += 2
    return max_width


def _render_command_tree(out: io.StringIO, node: SubcommandTreeNode, indent: int):
    max_width = get_max_width(node.children)
    for name, node in sorted(node.children.items(), key=lambda x: (bool(x[1].children), x[0])):
        if name == node.name:   # is not an alias
            for _ in range(indent):
                out.write('\t')
            if node.children:
                out.write(_titleline(name, node.help.short, suffix='/', width=max_width))
                _render_command_tree(out, node, indent + 1)
                out.write('\n')
            else:
                out.write(_titleline(name, node.help.short, width=max_width))


def help_overview():
    '''
    Returns an overview of all available
    topics and commands.
    '''
    _load_help()
    s = io.StringIO()
    s.write("Available topics:\n\n")
    max_width = get_max_width(_TOPICS)
    for title, topic in _TOPICS.items():
        s.write('\t' + _titleline(title, topic.short, width=max_width))
    s.write("\nAvailable commands:\n\n")
    _render_command_tree(s, _COMMAND_TREE, 1)
    return HelpEntry('Help overview for crmsh\n', s.getvalue(), generated=True)


def help_topics():
    '''
    Returns an overview of all available
    topics.
    '''
    _load_help()
    s = ''
    max_width = get_max_width(_TOPICS)
    for title, topic in _TOPICS.items():
        s += '\t' + _titleline(title, topic.short, width=max_width)
    return HelpEntry('Available topics\n', s, generated=True)


def list_help_topics():
    _load_help()
    return list(_TOPICS.keys())


def help_topic(topic):
    '''
    Returns a help entry for a given topic.
    '''
    _load_help()
    return _TOPICS.get(topic, _DEFAULT)


def _get_level_help(root: SubcommandTreeNode, levels: typing.Sequence[str]):
    node = root
    for level in levels:
        if node is not None:
            node = fuzzy_get(node.children, level)
        else:
            return None
    return node.help


def help_level(levels: typing.Sequence[str]):
    '''
    Returns a help entry for a given level.
    '''
    _load_help()
    help = _get_level_help(_COMMAND_TREE, levels)
    if help is None:
        return _DEFAULT
    else:
        return help


def help_command(levels: typing.Sequence[str]):
    '''
    Returns a help entry for a given command
    '''
    _load_help()
    help = _get_level_help(_COMMAND_TREE, levels)
    if help is None:
            raise ValueError("Undocumented topic '{}'".format(' '.join(levels)))
    else:
        return help


def _is_help_topic(arg):
    return arg and arg[0].isupper()


def _is_command(levels: typing.Sequence[str]):
    node = _COMMAND_TREE
    for level in levels:
        if node is not None:
            node = fuzzy_get(node.children, level)
    return node is not None and not node.children


def _is_level(levels: typing.Sequence[str]):
    node = _COMMAND_TREE
    for level in levels:
        if node is not None:
            node = fuzzy_get(node.children, level)
    return node is not None and node.children


def _is_property(levels: typing.Sequence[str]):
    return len(levels) == 3 and levels[0] == 'configure' and levels[1] == 'property'


def help_contextual(levels: typing.Sequence[str]):
    """
    Returns contextual help
    """
    _load_help()
    if len(levels) == 0:
        return help_overview()
    elif len(levels) == 1 and _is_help_topic(levels[0]):
        return help_topic(levels[0])
    elif _is_command(levels) or _is_level(levels):
        return help_command(levels[0:])
    elif _is_property(levels):
        agent = ra.get_properties_meta()
        if agent:
            all_properties = agent.params()
            property_name = levels[-1]
            if property_name in all_properties:
                print(agent.meta_parameter(property_name))
            else:
                raise ValueError(f"Unknown property '{property_name}'")
        return None
    else:
        topic = levels[0].lower()
        t = fuzzy_get(_TOPICS, topic)
        if t:
            return t
    raise ValueError('No help found for "crm {}". Run "crm help overview" to list all help entries.'.format(
        ' '.join(levels),
    ))


def add_help(levels: typing.Sequence[str], entry):
    '''
    Takes a help entry as argument and inserts it into the
    help system.

    Used to define some help texts statically, for example
    for 'up' and 'help' itself.
    '''
    node = _COMMAND_TREE.make_sublevel_recursively(levels[:-1])
    node.children[levels[-1]] = SubcommandTreeNode(levels[-1], entry, dict())


def _load_help():
    '''
    Lazily load and parse crm.8.adoc.
    '''
    global _LOADED
    if _LOADED:
        return
    _LOADED = True

    def parse_header(line):
        'returns a new entry'
        entry = {'type': '', 'name': '', 'short': '', 'long': '', "from_cli": False}
        line = line[2:-3]  # strip [[ and ]]\n
        info, short_help = line.split(',', 1)
        # TODO see https://github.com/ClusterLabs/crmsh/pull/644
        # This solution has shortcome to delete the content of adoc,
        # which lose the static man page archive
        if "From Code" in short_help:
            short_help, _ = short_help.split(',')
            entry['from_cli'] = True
        entry['short'] = short_help.strip()
        info = info.split('.')
        if info[0] == 'topics':
            entry['type'] = 'topic'
            entry['name'] = info[-1]
        elif info[0] == 'cmdhelp':
            if len(info) == 2:
                entry['type'] = 'level'
                entry['name'] = info[1]
            elif len(info) >= 3:
                entry['type'] = 'command'
                entry['subcommand'] = info[1:]

        return entry

    def process(entry):
        'writes the entry into topics/levels/commands'
        short_help = entry['short']
        long_help = entry['long']
        if long_help.startswith('=='):
            long_help = long_help.split('\n', 1)[1]
        name = entry['name']
        if entry['type'] == 'topic':
            _TOPICS[name] = HelpEntry(short_help, long_help.rstrip())
        elif entry['type'] == 'level':
            _COMMAND_TREE.children[name] = SubcommandTreeNode(name, HelpEntry(short_help, long_help.rstrip()), dict())
        elif entry['type'] == 'command':
            subcommand = entry['subcommand']
            if entry['from_cli']:
                help_entry = LazyHelpEntryFromCli(short_help, subcommand)
            else:
                help_entry = HelpEntry(short_help, long_help.rstrip())
            level = _COMMAND_TREE.make_sublevel_recursively(subcommand[:-1])
            level.children[subcommand[-1]] = SubcommandTreeNode(subcommand[-1], help_entry, dict())

    def filter_line(line):
        '''clean up an input line
         - <<...>> references -> short description
        '''
        return _REFERENCE_RE.sub(r'\1', line)

    def append_subcommand_list_to_long_description(node: SubcommandTreeNode):
        if isinstance(node.help, LazyHelpEntryFromCli) or not node.children:
            return
        buf = io.StringIO()
        buf.write(node.help.long_help)
        buf.write('\n\nCommands:\n')
        max_width = get_max_width(node.children)
        for name, child in sorted(node.children.items(), key=lambda x: (bool(x[1].children), x[0])):
            if name in _hidden_commands or name.startswith('_'):
                continue
            buf.write('\t')
            buf.write(_titleline(name, child.help.short, width=max_width))
            append_subcommand_list_to_long_description(child)
        node.help.long_help = buf.getvalue()

    def fixup_help_aliases(help_node: SubcommandTreeNode, childinfo):
        "add help for aliases"
        for name, childinfo in childinfo.children.items():
            if name in help_node.children:
                fixup_help_aliases(help_node.children[name], childinfo)
                for alias in childinfo.aliases:
                    help_node.children[alias] = help_node.children[name]
        return

    def fixup_topics():
        "fix entries for topics and overview"
        _TOPICS["Overview"] = help_overview()
        _TOPICS["Topics"] = help_topics()

    try:
        name = os.getenv("CRM_HELP_FILE") or HELP_FILE
        with open(name, 'r') as helpfile:
            entry = None
            for line in helpfile:
                if line.startswith('[['):
                    if entry is not None:
                        process(entry)
                    entry = parse_header(line)
                elif entry is not None and line.startswith('===') and entry['long']:
                    process(entry)
                    entry = None
                elif entry is not None:
                    entry['long'] += filter_line(line)
            if entry is not None:
                process(entry)
        append_subcommand_list_to_long_description(_COMMAND_TREE)
        #fixup_root_commands()
        from . import ui_root
        for name, childinfo in ui_root.Root.children().items():
            # the 1st level uses children(), but deeper levels uses children
            # this requires us to write the 1st level of the recursion separately
            if name in _COMMAND_TREE.children:
                fixup_help_aliases(_COMMAND_TREE.children[name], childinfo)
                for alias in childinfo.aliases:
                    ui_root.Root.children()[alias] = ui_root.Root.children()[name]
        fixup_topics()
    except IOError as msg:
        logger.error("Help text not found! %s", msg)

# vim:ts=4:sw=4:et:
