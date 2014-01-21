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
'''

import os
import cStringIO
import ConfigParser

_SYSTEMWIDE = '/etc/crmsh/settings'
_PERUSER = '~/.config/crmsh/settings'
_DEFAULT = '''
[core]
editor = $EDITOR
pager = $PAGER
user =
skill_level = expert
sort_elements = yes
check_frequency = always
check_mode = strict
wait = no
add_quotes = yes
manage_children = ask
force = no
debug = no
ptest =
dotty =
dot =

[path]
sharedir = /usr/share/crmsh
cache = /var/cache/crm
crm_config = /var/lib/pacemaker/cib
crm_daemon_dir = /usr/lib64/pacemaker
crm_daemon_user = hacluster
ocf_root = /usr/lib/ocf
crm_dtd_dir = /usr/share/pacemaker
pe_state_dir = /var/lib/pacemaker/pengine
heartbeat_dir = /var/lib/heartbeat
hb_delnode = /usr/share/heartbeat/hb_delnode
nagios_plugins = /usr/lib/nagios/plugins

[color]
style = color
error = red bold
ok = green bold
warn = yellow bold
info = cyan
help_keyword = blue bold underline
help_header = normal bold
help_topic = yellow bold
help_block = cyan
keyword = yellow
identifier = normal
attr_name = cyan
attr_value = red
resource_reference = green
id_reference = green
score = magenta
ticket = magenta
'''
_parser = None


def _stringify(val):
    if val is True:
        return 'true'
    elif val is False:
        return 'false'
    elif isinstance(val, basestring):
        return val
    else:
        return str(val)


class _Configuration(object):
    def __init__(self):
        self._defaults = None
        self._systemwide = None
        self._user = None

    def load(self):
        self._defaults = ConfigParser.SafeConfigParser(allow_no_value=True)
        self._defaults.readfp(cStringIO.StringIO(_DEFAULT))

        if os.path.isfile(_SYSTEMWIDE):
            self._systemwide = ConfigParser.SafeConfigParser(allow_no_value=True)
        if os.path.isfile(_PERUSER):
            self._user = ConfigParser.SafeConfigParser(allow_no_value=True)

    def get_impl(self, section, name):
        if self._user and self._user.has_option(section, name):
            return self._user.get(section, name) or ''
        if self._systemwide and self._systemwide.has_option(section, name):
            return self._systemwide.get(section, name) or ''
        return self._defaults.get(section, name) or ''

    def get(self, section, name):
        val = self.get_impl(section, name)
        if val.startswith('$'):
            return os.getenv(val[1:])
        elif val.startswith('\\$'):
            return val[1:]
        else:
            return val

    def set(self, section, name, value):
        if section not in ('core', 'path', 'color'):
            print "ERROR: config: Invalid section " + str(section)
            return
        if self._user is None:
            self._user = ConfigParser.SafeConfigParser(allow_no_value=True)
        if not self._user.has_section(section):
            self._user.add_section(section)
        self._user.set(section, name, _stringify(value))

    def save(self):
        if self._user:
            os.makedirs(os.path.dirname(_PERUSER))
            fp = open(_PERUSER, 'w')
            self._user.write(fp)
            fp.close()


_configuration = _Configuration()


class _Section(object):
    def __init__(self, section):
        object.__setattr__(self, 'section', section)

    def __getattr__(self, name):
        return _configuration.get(self.section, name)

    def __setattr__(self, name, value):
        _configuration.set(self.section, name, value)


def load():
    _configuration.load()


def save():
    '''
    Only save options that are not default
    '''
    _configuration.save()


def has_user_config():
    return os.path.isfile(_PERUSER)


load()
core = _Section('core')
path = _Section('path')
color = _Section('color')
