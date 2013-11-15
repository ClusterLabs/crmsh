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

import os
import utils

from msg import common_warn, common_info, common_debug

HOME_DIR = utils.gethomedir() or './'

HISTORY_FILE = os.path.join(HOME_DIR, ".crm_history")
RC_FILE = os.path.join(HOME_DIR, ".crm.rc")
CRMCONF_DIR = os.path.join(HOME_DIR, ".crmconf")

# see http://standards.freedesktop.org/basedir-spec
CONFIG_HOME = os.path.join(HOME_DIR, ".config")
CACHE_HOME = os.path.join(HOME_DIR, ".cache")
try:
    from xdg import BaseDirectory
    CONFIG_HOME = BaseDirectory.xdg_config_home
    CACHE_HOME = BaseDirectory.xdg_cache_home
except:
    pass

GRAPHVIZ_USER_FILE = os.path.join(CONFIG_HOME, "graphviz")


def mv_user_files():
    '''
    Called from main
    '''
    global HISTORY_FILE
    global RC_FILE
    global CRMCONF_DIR

    def _xdg_file(name, xdg_name, chk_fun, directory):
        if not name:
            return name
        if not os.path.isdir(directory):
            os.makedirs(directory, 0700)
        new = os.path.join(directory, xdg_name)
        if directory == CONFIG_HOME and chk_fun(new) and chk_fun(name):
            common_warn("both %s and %s exist, please cleanup" % (name, new))
            return name
        if chk_fun(name):
            if directory == CONFIG_HOME:
                common_info("moving %s to %s" % (name, new))
            else:
                common_debug("moving %s to %s" % (name, new))
            os.rename(name, new)
        return new

    HISTORY_FILE = _xdg_file(HISTORY_FILE, "history", os.path.isfile, CACHE_HOME)
    RC_FILE = _xdg_file(RC_FILE, "rc", os.path.isfile, CONFIG_HOME)
    CRMCONF_DIR = _xdg_file(CRMCONF_DIR, "crmconf", os.path.isdir, CONFIG_HOME)
