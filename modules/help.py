# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
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

import os
import re
from cache import WCache
from utils import odict, page_string
from vars import Vars
from msg import common_info, common_err, common_debug, common_warn
import config

# this table needs to match cmd_table of TopLevel in ui.py
init_help_tab = {
    "options": ("user preferences", """
Several user preferences are available. Note that it is possible
to save the preferences to a startup file.
"""),
    "cib": ("manage shadow CIBs", """
A shadow CIB is a regular cluster configuration which is kept in
a file. The CRM and the CRM tools may manage a shadow CIB in the
same way as the live CIB (i.e. the current cluster configuration).
A shadow CIB may be applied to the cluster in one step.
"""),
    "resource": ("resources management", """
Everything related to resources management is available at this
level. Most commands are implemented using the crm_resource(8)
program.
"""),
    "node": ("nodes management", """
A few node related tasks such as node standby are implemented
here.
"""),
    "ra": ("resource agents information center", """
This level contains commands which show various information about
the installed resource agents. It is available both at the top
level and at the `configure` level.
"""),
    "configure": ("CRM cluster configuration", """
The configuration level.

Note that you can change the working CIB at the cib level. It is
advisable to configure shadow CIBs and then commit them to the
cluster.
"""),
    "history": ("CRM cluster history", """
The history level.

Examine Pacemaker's history: node and resource events, logs.
"""),
    "site": ("Geo-cluster support", """
The site level.

Geo-cluster related management.
"""),
}


def load_init_help_tab(help_tab, levels):
    help_tab["."] = ("", """
This is crm shell, a Pacemaker command line interface.
""")
    for lvl in levels:
        try:
            help_tab[lvl] = init_help_tab[lvl]
        except:
            pass
    help_tab["status"] = ("show cluster status", """
Show cluster status. The status is displayed by crm_mon. Supply
additional arguments for more information or different format.
See crm_mon(8) for more details.

Usage:
...............
        status [<option> ...]

        option :: bynode | inactive | ops | timing | failcounts
...............
""")


#
# help or make users feel less lonely
#
def add_shorthelp(topic, shorthelp, short_tab):
    '''
    Join topics ("%s,%s") if they share the same short
    description.
    '''
    for i in range(len(short_tab)):
        if short_tab[i][1] == shorthelp:
            short_tab[i][0] = "%s,%s" % (short_tab[i][0], topic)
            return
    short_tab.append([topic, shorthelp])


def topic_help(help_tab, topic):
    if topic not in help_tab:
        print "Sorry, could not find any help for %s" % topic
        return False
    if type(help_tab[topic][0]) == type(()):
        shorthelp = help_tab[topic][0][0]
        longhelp = help_tab[topic][0][1]
    else:
        shorthelp = help_tab[topic][0]
        longhelp = help_tab[topic][1]
    if longhelp:
        page_string(longhelp)
    else:
        print shorthelp
    return True


def add_static_help(help_tab):
    '''Add help items used everywhere'''
    help_tab["help"] = ("show help (help topics for list of topics)", """
The help subsystem consists of the command reference and a list
of topics. The former is what you need in order to get the
details regarding a specific command. The latter should help with
concepts and examples.
""")
    help_tab["end"] = ("go back one level", "")
    help_tab["quit"] = ("exit the program", "")


def is_level(s):
    return len(s.split("_")) == 2


def help_short(s):
    r = re.search("_[^,]+,(.*)\]\]", s)
    return r and r.group(1) or ''


class HelpSystem(object):
    '''
    The help system. All help is in the following form in the
    manual:
    [[cmdhelp_<level>_<cmd>,<short help text>]]
    === ...
    Long help text.
    ...
    [[cmdhelp_<level>_<cmd>,<short help text>]]

    Help for the level itself is like this:

    [[cmdhelp_<level>,<short help text>]]
    '''
    help_text_file = os.path.join(config.DATADIR, config.PACKAGE, "crm.8.txt")
    topics_tok = "topics"

    def __init__(self):
        self.key_pos = {}
        self.leveld = {}
        self.no_help_file = False  # don't print repeatedly messages
        self.bad_index = False  # don't print repeatedly warnings for bad index

    def get_short_help(self, help_tab):
        short_tab = []
        for topic in help_tab:
            if topic == '.':
                continue
            # with odict, for whatever reason, python parses differently:
            # help_tab["..."] = ("...","...") and
            # help_tab["..."] = ("...","""
            # ...""")
            # a parser bug?
            if type(help_tab[topic][0]) == type(()):
                shorthelp = help_tab[topic][0][0]
            else:
                shorthelp = help_tab[topic][0]
            add_shorthelp(topic, shorthelp, short_tab)
        return short_tab

    def overview(self, help_tab):
        s = help_tab['.'][1]
        # cheating here a bit, but ...
        if "crm shell topics" not in help_tab['.'][1]:
            s = "%s\nAvailable commands:\n" % s
        short_tab = self.get_short_help(help_tab)
        l = [s]
        for t, d in short_tab:
# TODO: figure out how to make appending '/' work _only_ in case
# t is really a level, becase some commands share name with
# levels (e.g. history resource, history node)
#            if self.is_level(t):
#                t = "%s/" % t
            l.append("\t%-16s %s" % (t, d))
        page_string("\n".join(l))

    def cmd_help(self, help_tab, topic=''):
        "help!"
        # help_tab is an odict (ordered dictionary):
        # help_tab[topic] = (short_help, long_help)
        # topic '.' is a special entry for the top level
        if not help_tab:
            common_info("sorry, help not available")
            return False
        if not topic or topic == "topics":
            self.overview(help_tab)
        else:
            return topic_help(help_tab, topic)
        return True

    def open_file(self, name, mode):
        try:
            f = open(name, mode)
            return f
        except IOError, msg:
            common_err("%s open: %s" % (name, msg))
            common_err("extensive help system is not available")
            self.no_help_file = True
            return None

    def drop_index(self):
        common_info("removing index")
        os.unlink(vars.index_file)
        self.key_pos = {}
        self.leveld = {}
        self.leveld[self.topics_tok] = []
        self.bad_index = True

    def mk_index(self):
        '''
        Prepare an index file, sorted by topic, with seek positions
        Do we need a hash on content?
        '''
        if self.no_help_file:
            return False
        crm_help_v = os.getenv("CRM_HELP_FILE")
        if crm_help_v:
            self.help_text_file = crm_help_v
        help_f = self.open_file(self.help_text_file, "r")
        if not help_f:
            return False
        idx_f = self.open_file(vars.index_file, "w")
        if not idx_f:
            return False
        common_debug("building help index")
        key_pos = odict()
        while 1:
            pos = help_f.tell()
            s = help_f.readline()
            if not s:
                break
            if s.startswith("[["):
                r = re.search(r'..([^,]+),', s)
                if r:
                    key_pos[r.group(1)] = pos
        help_f.close()
        for key in key_pos:
            print >>idx_f, '%s %d' % (key, key_pos[key])
        idx_f.close()
        return True

    def is_index_old(self):
        try:
            t_idx = os.path.getmtime(vars.index_file)
        except:
            return True
        try:
            t_help = os.path.getmtime(self.help_text_file)
        except:
            return True
        return t_help > t_idx

    def load_index(self):
        if self.is_index_old():
            self.mk_index()
        self.key_pos = {}
        self.leveld = {}
        self.leveld[self.topics_tok] = []
        idx_f = self.open_file(vars.index_file, "r")
        if not idx_f:
            return False
        cur_lvl = ''
        for s in idx_f:
            a = s.split()
            if len(a) != 2:
                if not self.bad_index:
                    common_err("index file corrupt")
                    idx_f.close()
                    self.drop_index()
                    return self.load_index()  # this runs only once
                return False
            key = a[0]
            fpos = long(a[1])
            if key.startswith("cmdhelp_"):
                if is_level(key):
                    if key != cur_lvl:
                        cur_lvl = key
                        self.leveld[cur_lvl] = []
                else:
                    self.leveld[cur_lvl].append(key)
            elif key.startswith("%s_" % self.topics_tok):
                self.leveld[self.topics_tok].append(key)
            self.key_pos[key] = fpos
        idx_f.close()
        return True

    def is_level(self, s):
        return (("cmdhelp_%s" % s) in self.leveld) or (s in init_help_tab)

    def __filter(self, s):
        if '<<' in s:
            return re.sub(r'<<[^,]+,(.+)>>', r'\1', s)
        else:
            return s

    def _load_help_one(self, key, skip=2):
        longhelp = ''
        self.help_f.seek(self.key_pos[key])
        shorthelp = help_short(self.help_f.readline())
        for i in range(skip-1):
            self.help_f.readline()
        l = []
        for s in self.help_f:
            if l and (s.startswith("[[") or s.startswith("=")):
                break
            l.append(self.__filter(s))
        if l and l[-1] == '\n':  # drop the last line of empty
            l.pop()
        if l:
            longhelp = ''.join(l)
        if not shorthelp or not longhelp:
            if not self.bad_index:
                common_warn("help topic %s not found" % key)
                self.drop_index()
        return shorthelp, longhelp

    def cmdhelp(self, s):
        if not self.key_pos and not self.load_index():
            return None, None
        if not s in self.key_pos:
            if not self.bad_index:
                common_warn("help topic %s not found" % s)
                self.drop_index()
            return None, None
        return self._load_help_one(s)

    def _load_topics(self, help_tab):
        '''
        Get the topic help text.
        '''
        lvl_s = self.topics_tok
        if not lvl_s in self.leveld:
            if not self.bad_index:
                common_warn("help table for topics not found")
                self.drop_index()
            return None
        help_tab["."] = ["", """
List of crm shell topics.
"""]
        try:
            for key in self.leveld[lvl_s]:
                cmd = key[len(lvl_s)+1:]
                help_tab[cmd] = self._load_help_one(key, skip=1)
        except:
            pass

    def _load_cmd_level(self, lvl, help_tab):
        '''
        Get the command help text.
        '''
        lvl_s = "cmdhelp_%s" % lvl
        if not lvl_s in self.leveld:
            if not self.bad_index:
                common_warn("help table for level %s not found" % lvl)
                self.drop_index()
            return
        common_debug("loading help table for level %s" % lvl)
        help_tab["."] = self._load_help_one(lvl_s)
        try:
            for key in self.leveld[lvl_s]:
                cmd = key[len(lvl_s)+1:]
                help_tab[cmd] = self._load_help_one(key)
        except:
            pass
        add_static_help(help_tab)

    def _load_level(self, lvl):
        '''
        For the given level, create a help table.
        '''
        if wcache.is_cached("lvl_help_tab_%s" % lvl):
            return wcache.retrieve("lvl_help_tab_%s" % lvl)
        if not self.key_pos and not self.load_index():
            return None
        self.help_f = self.open_file(self.help_text_file, "r")
        if not self.help_f:
            return None
        help_tab = odict()
        if lvl == self.topics_tok:
            self._load_topics(help_tab)
        else:
            self._load_cmd_level(lvl, help_tab)
        self.help_f.close()
        return help_tab

    def load_level(self, lvl):
        help_tab = self._load_level(lvl)
        if self.bad_index:  # try again
            help_tab = self._load_level(lvl)
        return wcache.store("lvl_help_tab_%s" % lvl, help_tab)

    def load_topics(self):
        return self.load_level(self.topics_tok)

wcache = WCache.getInstance()
vars = Vars.getInstance()

# vim:ts=4:sw=4:et:
