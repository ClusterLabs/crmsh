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

import os
import re
from .sh import ShellUtils
from .utils import page_string
from . import config
from . import clidisplay
from . import log


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
        self.long = long_help
        self.alias_for = alias_for
        self.generated = generated
        self.from_cli = False
        self.level = False
        self.name = False

    def is_alias(self):
        return self.alias_for is not None

    def paginate(self):
        '''
        Display help, paginated.
        Replace asciidoc syntax with colorized output where possible.
        '''
        helpfilter = HelpFilter()

        short_help = clidisplay.help_header(self.short)
        if self.from_cli and self.level and self.name:
            level = '' if self.level == 'root' else self.level
            _, output, _ = ShellUtils().get_stdout_stderr(f"crm {level} {self.name} --help-without-redirect")
            page_string(short_help + '\n\n'+ output)
            return

        long_help = self.long
        if long_help:
            long_help = helpfilter(long_help)
            if not long_help.startswith('\n'):
                long_help = '\n' + long_help

        prefix = ''
        if self.is_alias():
            prefix = helpfilter("(Redirected from `%s` to `%s`)\n" % self.alias_for)

        page_string(short_help + '\n' + prefix + long_help)

    def set_long_help(self, long_help):
        self.long = long_help

    def set_long_lazy_load_source(self, level, name, from_cli):
        self.level = level
        self.name = name
        self.from_cli = from_cli

    def __str__(self):
        if self.long:
            return self.short + '\n' + self.long
        return self.short

    def __repr__(self):
        return str(self)


HELP_FILE = os.path.join(config.path.sharedir, 'crm.8.adoc')

_DEFAULT = HelpEntry('No help available', long_help='', alias_for=None, generated=True)
_REFERENCE_RE = re.compile(r'<<[^,]+,(.+)>>')

# loaded on demand
# _LOADED is set to True when an attempt
# has been made (so it won't be tried again)
_LOADED = False
_TOPICS = {}
_LEVELS = {}
_COMMANDS = {}

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


def help_overview():
    '''
    Returns an overview of all available
    topics and commands.
    '''
    _load_help()
    s = "Available topics:\n\n"
    max_width = get_max_width(_TOPICS)
    for title, topic in _TOPICS.items():
        s += '\t' + _titleline(title, topic.short, width=max_width)
    s += "\n"
    s += "Available commands:\n\n"

    max_width = get_max_width(_COMMANDS.get('root', {}))
    for title, command in _COMMANDS.get('root', {}).items():
        if not command.is_alias():
            s += '\t' + _titleline(title, command.short, width=max_width)
    s += "\n"

    max_width_1 = get_max_width(_LEVELS)
    for title, level in sorted(iter(_LEVELS.items()), key=lambda x: x[0]):
        if title != 'root' and title in _COMMANDS:
            s += '\t' + _titleline(title, level.short, suffix='/', width=max_width_1)
            max_width_2 = get_max_width(_COMMANDS[title])
            for cmdname, cmd in sorted(iter(_COMMANDS[title].items()), key=lambda x: x[0]):
                if cmdname in _hidden_commands or cmdname.startswith('_'):
                    continue
                if not cmd.is_alias():
                    s += '\t\t' + _titleline(cmdname, cmd.short, width=max_width_2)
            s += "\n"
    return HelpEntry('Help overview for crmsh\n', s, generated=True)


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


def help_level(level):
    '''
    Returns a help entry for a given level.
    '''
    _load_help()
    from .command import fuzzy_get
    return fuzzy_get(_LEVELS, level) or _DEFAULT


def help_command(level, command):
    '''
    Returns a help entry for a given command
    '''
    _load_help()
    from .command import fuzzy_get
    lvlhelp = fuzzy_get(_COMMANDS, level)
    if not lvlhelp:
        raise ValueError("Undocumented topic '%s'" % (level))
    cmdhelp = fuzzy_get(lvlhelp, command)
    if not cmdhelp:
        raise ValueError("Undocumented topic '%s' in '%s'" % (command, level))
    return cmdhelp


def _is_help_topic(arg):
    return arg and arg[0].isupper()


def _is_command(level, command):
    from .command import fuzzy_get
    return level in _COMMANDS and fuzzy_get(_COMMANDS[level], command)


def _is_level(level):
    from .command import fuzzy_get
    return fuzzy_get(_LEVELS, level)


def help_contextual(context, subject, subtopic):
    """
    Returns contextual help
    """
    _load_help()
    if subject is None:
        if context == 'root':
            return help_overview()
        return help_level(context)
    if _is_help_topic(subject):
        return help_topic(subject)
    if subtopic is not None:
        return help_command(subject, subtopic)
    if _is_command(context, subject):
        return help_command(context, subject)
    if _is_level(subject):
        return help_level(subject)
    from .command import fuzzy_get
    t = fuzzy_get(_TOPICS, subject.lower())
    if t:
        return t
    raise ValueError("No help found for '%s'! 'overview' lists all help entries" % (subject))


def add_help(entry, topic=None, level=None, command=None):
    '''
    Takes a help entry as argument and inserts it into the
    help system.

    Used to define some help texts statically, for example
    for 'up' and 'help' itself.
    '''
    if topic:
        if topic not in _TOPICS or _TOPICS[topic] is _DEFAULT:
            _TOPICS[topic] = entry
    elif level and command:
        if level not in _LEVELS:
            _LEVELS[level] = HelpEntry("No description available", generated=True)
        if level not in _COMMANDS:
            _COMMANDS[level] = {}
        lvl = _COMMANDS[level]
        if command not in lvl or lvl[command] is _DEFAULT:
            lvl[command] = entry
    elif level:
        if level not in _LEVELS or _LEVELS[level] is _DEFAULT:
            _LEVELS[level] = entry


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
        info = info.split('_')
        if info[0] == 'topics':
            entry['type'] = 'topic'
            entry['name'] = info[-1]
        elif info[0] == 'cmdhelp':
            if len(info) == 2:
                entry['type'] = 'level'
                entry['name'] = info[1]
            elif len(info) >= 3:
                entry['type'] = 'command'
                entry['level'] = info[1]
                entry['name'] = '_'.join(info[2:])

        return entry

    def process(entry):
        'writes the entry into topics/levels/commands'
        short_help = entry['short']
        long_help = entry['long']
        if long_help.startswith('=='):
            long_help = long_help.split('\n', 1)[1]
        helpobj = HelpEntry(short_help, long_help.rstrip())
        name = entry['name']
        if entry['type'] == 'topic':
            _TOPICS[name] = helpobj
        elif entry['type'] == 'level':
            _LEVELS[name] = helpobj
        elif entry['type'] == 'command':
            lvl = entry['level']
            if lvl not in _COMMANDS:
                _COMMANDS[lvl] = {}
            helpobj.set_long_lazy_load_source(entry['level'], entry['name'], entry['from_cli'])
            _COMMANDS[lvl][name] = helpobj

    def filter_line(line):
        '''clean up an input line
         - <<...>> references -> short description
        '''
        return _REFERENCE_RE.sub(r'\1', line)

    def append_cmdinfos():
        "append command information to level descriptions"
        for lvlname, level in _LEVELS.items():
            if lvlname in _COMMANDS:
                level.long += "\n\nCommands:\n"
                max_width = get_max_width(_COMMANDS[lvlname])
                for cmdname, cmd in sorted(iter(_COMMANDS[lvlname].items()), key=lambda x: x[0]):
                    if cmdname in _hidden_commands or cmdname.startswith('_'):
                        continue
                    level.long += "\t" + _titleline(cmdname, cmd.short, width=max_width)
                level.long += "\n"
                for cmdname, cmd in sorted(iter(_COMMANDS[lvlname].items()), key=lambda x: x[0]):
                    if cmdname in _hidden_commands:
                        level.long += "\t" + _titleline(cmdname, cmd.short, width=max_width)

    def fixup_root_commands():
        "root commands appear as levels"

        strip_topics = []
        for tname, topic in _LEVELS.items():
            if not _COMMANDS.get(tname):
                strip_topics.append(tname)
        for t in strip_topics:
            del _LEVELS[t]

    def fixup_help_aliases():
        "add help for aliases"

        def add_help_for_alias(lvlname, command, alias):
            if lvlname not in _COMMANDS:
                return
            if command not in _COMMANDS[lvlname]:
                return
            if alias in _COMMANDS[lvlname]:
                return
            info = _COMMANDS[lvlname][command]
            _COMMANDS[lvlname][alias] = HelpEntry(info.short, info.long, (alias, command))

        def add_aliases_for_level(lvl):
            for name, info in lvl.children().items():
                for alias in info.aliases:
                    add_help_for_alias(lvl.name, info.name, alias)
                if info.level:
                    add_aliases_for_level(info.level)
        from .ui_root import Root
        add_aliases_for_level(Root)

    def fixup_topics():
        "fix entries for topics and overview"
        _TOPICS["Overview"] = help_overview()
        _TOPICS["Topics"] = help_topics()

    try:
        name = os.getenv("CRM_HELP_FILE") or HELP_FILE
        helpfile = open(name, 'r')
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
        helpfile.close()
        append_cmdinfos()
        fixup_root_commands()
        fixup_help_aliases()
        fixup_topics()
    except IOError as msg:
        logger.error("Help text not found! %s", msg)

# vim:ts=4:sw=4:et:
