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


class _Section(object):
    def _load(self, name):
        # read values from parser
        # read from envvar if startswith('$')
        pass


class core(_Section):
    editor = "$EDITOR"
    pager = "$PAGER"
    user = ""
    skill_level = "expert"
    sort_elements = "yes"
    check_frequency = "always"
    check_mode = "strict"
    wait = "no"
    add_quotes = "yes"
    manage_children = "ask"
    force = "no"
    debug = "no"
    ptest = ""
    dotty = ""
    dot = ""


class path(_Section):
    prefix = "/usr"
    datadir = "%(prefix)s/share"
    sharedir = "%(datadir)s/crmsh"
    cache = "/var/cache/crm"
    crm_config = "/var/lib/pacemaker/cib"
    crm_daemon_dir = "%(prefix)s/lib64/pacemaker"
    crm_daemon_user = "hacluster"
    ocf_root = "%(prefix)s/lib/ocf"
    crm_dtd_dir = "%(datadir)s/pacemaker"
    pe_state_dir = "/var/lib/pacemaker/pengine"
    heartbeat_dir = "/var/lib/heartbeat"
    hb_delnode = "%(datadir)s/heartbeat/hb_delnode"
    nagios_plugins = "%(prefix)s/lib/nagios/plugins"


class color(_Section):
    style = "color"
    error = "red bold"
    ok = "green bold"
    warn = "yellow bold"
    info = "cyan"
    help_keyword = "blue bold underline"
    help_header = "normal bold"
    help_topic = "yellow bold"
    help_block = "cyan"
    keyword = "yellow"
    identifier = "normal"
    attr_name = "cyan"
    attr_value = "red"
    resource_reference = "green"
    id_reference = "green"
    score = "magenta"
    ticket = "magenta"


def load():
    global _parser
    if _parser:
        return _parser
    _parser = ConfigParser.SafeConfigParser()
    for loc in (_GLOBAL, _PERUSER):
        _parser.readfp(open(loc), loc)

    for section in ('core', 'path', 'color'):
        pass
    return _parser


def save():
    if _parser:
        f = open(_PERUSER, 'w')
        if f:
            _parser.write(f)
            f.close()

# automatically load as soon as a config value is accessed
load()
