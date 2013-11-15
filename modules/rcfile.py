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
'''
Holds user-configurable options.
The goal is to make all assumptions configurable (base directory etc).
The installer can install a default RC file in /etc/crm/crm.conf which sets the assumptions
for that system.

Options are loaded when the module is loaded.
To access an option, use

import config
if config.core.debug:
  ...
'''

import ConfigParser

_GLOBAL = '/etc/crm/settings'
_PERUSER = '~/.config/crm/settings'
_parser = None


class _ConfigValue(object):
    def __init__(self, value):
        self._value = value

    def load(self, value):
        "Set value without triggering a config file save"
        self._value = value


class _Section(object):
    pass


class core(_Section):
    editor = _ConfigValue("$EDITOR")
    pager = _ConfigValue("$PAGER")
    user = _ConfigValue("")
    skill_level = _ConfigValue("expert")
    sort_elements = _ConfigValue("yes")
    check_frequency = _ConfigValue("always")
    check_mode = _ConfigValue("strict")
    wait = _ConfigValue("no")
    add_quotes = _ConfigValue("yes")
    manage_children = _ConfigValue("ask")
    force = _ConfigValue("no")
    debug = _ConfigValue("no")
    ptest = _ConfigValue("")
    dotty = _ConfigValue("")
    dot = _ConfigValue("")


class path(_Section):
    prefix = _ConfigValue("/usr")
    datadir = _ConfigValue("%(prefix)s/share")
    sharedir = _ConfigValue("%(datadir)s/crmsh")
    cache = _ConfigValue("/var/cache/crm")
    crm_config = _ConfigValue("/var/lib/pacemaker/cib")
    crm_daemon_dir = _ConfigValue("%(prefix)s/lib64/pacemaker")
    crm_daemon_user = _ConfigValue("hacluster")
    ocf_root = _ConfigValue("%(prefix)s/lib/ocf")
    crm_dtd_dir = _ConfigValue("%(datadir)s/pacemaker")
    pe_state_dir = _ConfigValue("/var/lib/pacemaker/pengine")
    heartbeat_dir = _ConfigValue("/var/lib/heartbeat")
    hb_delnode = _ConfigValue("%(datadir)s/heartbeat/hb_delnode")
    nagios_plugins = _ConfigValue("%(prefix)s/lib/nagios/plugins")


class color(_Section):
    style = _ConfigValue("color")
    error = _ConfigValue("red bold")
    ok = _ConfigValue("green bold")
    warn = _ConfigValue("yellow bold")
    info = _ConfigValue("cyan")
    help_keyword = _ConfigValue("blue bold underline")
    help_header = _ConfigValue("normal bold")
    help_topic = _ConfigValue("yellow bold")
    help_block = _ConfigValue("cyan")
    keyword = _ConfigValue("yellow")
    identifier = _ConfigValue("normal")
    attr_name = _ConfigValue("cyan")
    attr_value = _ConfigValue("red")
    resource_reference = _ConfigValue("green")
    id_reference = _ConfigValue("green")
    score = _ConfigValue("magenta")
    ticket = _ConfigValue("magenta")


def load():
    global _parser
    if _parser:
        return _parser
    _parser = ConfigParser.SafeConfigParser()

    # Read config files
    for loc in (_GLOBAL, _PERUSER):
        _parser.readfp(open(loc), loc)

    # Update configuration objects with values from config files
    for section in (core, path, color):
        section_name = section.__class__.__name__
        if _parser.has_section(section_name):
            for key, value in _parser.items(section_name):
                cv = getattr(section, key)
                if cv and isinstance(cv, _ConfigValue):
                    cv.load(value)

    return _parser


def save():
    if _parser:
        f = open(_PERUSER, 'w')
        if f:
            _parser.write(f)
            f.close()

# automatically load as soon as a config value is accessed
load()
