# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import os
from . import log


logger = log.setup_logger(__name__)


def getuser():
    "Returns the name of the current user"
    import getpass
    return getpass.getuser()


def gethomedir(user=''):
    return os.path.expanduser("~" + user)


# see http://standards.freedesktop.org/basedir-spec
CONFIG_HOME = os.path.join(os.path.expanduser("~/.config"), 'crm')
CACHE_HOME = os.path.join(os.path.expanduser("~/.cache"), 'crm')
try:
    from xdg import BaseDirectory
    CONFIG_HOME = os.path.join(BaseDirectory.xdg_config_home, 'crm')
    CACHE_HOME = os.path.join(BaseDirectory.xdg_cache_home, 'crm')
except:
    pass

# TODO: move to CONFIG_HOME
HISTORY_FILE = os.path.expanduser("~/.crm_history")
RC_FILE = os.path.expanduser("~/.crm.rc")
CRMCONF_DIR = os.path.expanduser("~/.crmconf")

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
        os.makedirs(directory, 0o700, exist_ok=True)
        # FileExistsError will be raised if `directory` exists and it is not a directory
        new = os.path.join(directory, xdg_name)
        if directory == CONFIG_HOME and chk_fun(new) and chk_fun(name):
            logger.warning("both %s and %s exist, please cleanup", name, new)
            return name
        if chk_fun(name):
            if directory == CONFIG_HOME:
                logger.info("moving %s to %s", name, new)
            else:
                logger.debug("moving %s to %s", name, new)
            os.rename(name, new)
        return new

    HISTORY_FILE = _xdg_file(HISTORY_FILE, "history", os.path.isfile, CACHE_HOME)
    RC_FILE = _xdg_file(RC_FILE, "rc", os.path.isfile, CONFIG_HOME)
    CRMCONF_DIR = _xdg_file(CRMCONF_DIR, "crmconf", os.path.isdir, CONFIG_HOME)
