# Copyright (C) 2015 Kristoffer Gronlund <kgronlund@suse.com>
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
#
# A rewrite of cluster scripts with more functionality built in
# (including a mustashe-like templating language), and a JSON API
# for Hawk to use.

import os
import subprocess
import time
import random
from . import config
from . import handles
from . import options
from . import userdir
from . import utils
from .msg import err_buf


try:
    import parallax
    has_parallax = True
except ImportError:
    has_parallax = False


class ClusterScript(object):
    """
    DESCRIBE: list parameters (grouped), options, information
    DRYRYN: given these parameter values, describe actions that would be taken
    APPLY: given these parameter values, apply actions

    """
    def __init__(self, env, desc):
        self.name = ""
        self.shortdesc = ""
        self.longdesc = ""
        self.category = ""
        self.parameters = ""
        self.agents = ""

    def describe_json(self):
        """
        generate a description of the script,
        which parameters it takes, etc
        """

    def dryrun(self, values):
        """
        generate a list of (nodes, action) tuples
        where nodes is a list of nodes to execute the step on,
        and action is the code to run on those nodes
        """

    def apply(self, values):
        """
        generate a list of (nodes, action) tuples
        where nodes is a list of nodes to execute the step on,
        and action is the code to run on those nodes
        """


def list_scripts():
    '''
    List the available cluster installation scripts.
    '''
    l = []

    def path_combine(p0, p1):
        if p0:
            return os.path.join(p0, p1)
        return p1

    def recurse(root, prefix):
        try:
            curdir = path_combine(root, prefix)
            for f in os.listdir(curdir):
                if os.path.isdir(os.path.join(curdir, f)):
                    if os.path.isfile(os.path.join(curdir, f, 'main.yml')):
                        l.append(path_combine(prefix, f))
                    else:
                        recurse(root, path_combine(prefix, f))
        except OSError:
            pass
    for d in _script_dirs():
        recurse(d, '')
    return sorted(l)


def load_script(script):
    main = _resolve_script(script)
    if main and os.path.isfile(main):
        try:
            import yaml
            return yaml.load(open(main))[0]
        except ImportError, e:
            raise ValueError("PyYAML error: %s" % (e))
    return None


def describe(name):
    '''
    Prints information about the given script.
    '''


def param_completion_list(name):
    "Returns completions for the given script"


def run(name, args):
    '''
    Run the given script on the given set of hosts
    name: a cluster script is a folder <name> containing a main.yml file
    args: list of nvpairs
    '''


def _script_dirs():
    "list of directories that may contain cluster scripts"
    ret = []
    for d in options.scriptdir.split(';'):
        if d and os.path.isdir(d):
            ret.append(d)
    ret.append(os.path.join(userdir.CONFIG_HOME, 'scripts'))
    ret.append(os.path.join(config.path.sharedir, 'scripts'))
    return ret


def _check_control_persist():
    '''
    Checks if ControlPersist is available. If so,
    we'll use it to make things faster.
    '''
    cmd = 'ssh -o ControlPersist'.split()
    if options.regression_tests:
        print ".EXT", cmd
    cmd = subprocess.Popen(cmd,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
    (out, err) = cmd.communicate()
    return "Bad configuration option" not in err


def _parallax_call(hosts, cmd, opts):
    "parallax.call with debug logging"
    if config.core.debug or options.regression_tests:
        err_buf.debug("parallax.call(%s, %s)" % (repr(hosts), cmd))
    return parallax.call(hosts, cmd, opts)


def _resolve_script(name):
    for d in _script_dirs():
        script_main = os.path.join(d, name, 'main.yml')
        if os.path.isfile(script_main):
            return script_main
    return None


def _parallax_copy(hosts, src, dst, opts):
    "parallax.copy with debug logging"
    if config.core.debug or options.regression_tests:
        err_buf.debug("parallax.copy(%s, %s, %s)" % (repr(hosts), src, dst))
    return parallax.copy(hosts, src, dst, opts)


def _generate_workdir_name():
    '''
    Generate a temporary folder name to use while
    running the script
    '''
    # TODO: make use of /tmp configurable
    basefile = 'crm-tmp-%s-%s' % (time.time(), random.randint(0, 2**48))
    basetmp = os.path.join(utils.get_tempdir(), basefile)
    return basetmp
