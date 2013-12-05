# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
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

import os
import config
import command
import utils
import yaml
from msg import err_buf
from userprefs import Options


_SCRIPTS_DIR = os.path.join(config.path.sharedir, 'scripts')


def _list_cluster_nodes():
    '''
    Returns a list of nodes in the cluster.
    '''
    def getname(line):
        while len(line) > 1:
            if line[0] == 'node:':
                return line[1]
            line = line[1:]
        return None

    try:
        rc, outp = utils.stdout2list(['crmadmin', '-N'], stderr_on=False, shell=False)
        if rc != 0:
            raise IOError("crmadmin failed (RC=%s): %s" % (rc, outp))
        return [x for x in [getname(line.split()) for line in outp] if x]
    except OSError, msg:
        raise ValueError("Error getting list of nodes from crmadmin: %s" % (msg))

class Cluster(command.UI):
    '''
    Whole cluster management.

    - Package installation
    - System configuration
    - Corosync configuration
    - Network troubleshooting
    - Perform other callouts/cluster-wide devops operations
    '''
    name = "cluster"

    def requires(self):
        stack = utils.cluster_stack()
        if len(stack) > 0 and stack != 'corosync':
            err_buf.warn("Unsupported cluster stack %s detected." % (stack))
            return False
        return True

    def __init__(self):
        command.UI.__init__(self)
        # ugly hack to allow overriding the node list
        # for the cluster commands that operate before
        # there is an actual cluster
        self._inventory_nodes = None
        self._inventory_target = None

    @command.skill_level('administrator')
    def do_create(self, context, *args):
        args = utils.nvpairs2dict(args)
        if 'nodes' not in args:
            args['nodes'] = utils.this_node()
        print "Creating a cluster on %s" % (args['nodes'])

        print "* Check Hostname..."
        print "* Check NTP..."
        print "* Check IP Address..."
        print "* Check connectivity..."
        print "* Configure Firewall..."
        print "* Check multicast connectivity..."
        print "* Configure SSH..."
        print "* Configure Corosync..."
        print "* Configure Pacemaker..."

        #print "* Configure csync2..."
        #print "* Configure OCFS2..."
        #print "* Configure SBD..."

        context.fatal_error("Not implemented.")

    @command.skill_level('administrator')
    def do_add(self, context, node):
        '''
        Add the given node to the cluster.
        Installs packages, sets up corosync and pacemaker, etc.
        Must be executed from a node in an existing cluster.
        '''
        # verify that localhost is in a cluster and that
        # the given node is not in the cluster
        if self._node_in_cluster(node):
            context.fatal_error("Node already in cluster: %s" % (node))
        # check health of cluster
        # probe new node
        # install stuff on new node
        # update corosync configuration to include new node
        context.fatal_error("Not implemented.")

    @command.skill_level('administrator')
    def do_remove(self, context, node):
        '''
        Remove the given node from the cluster.
        '''
        if not self._node_in_cluster(node):
            context.fatal_error("Node not in cluster: %s" % (node))

        context.fatal_error("Not implemented.")

    def _node_in_cluster(self, node):
        return node in _list_cluster_nodes()

    def do_status(self, context):
        '''
        Quick cluster health status. Corosync status, DRBD status...
        '''
        stack = utils.cluster_stack()
        if not stack:
            err_buf.error("Cluster stack not detected!")
        else:
            print "* Cluster stack: " + utils.cluster_stack()
        if utils.cluster_stack() == 'corosync':
            rc, outp = utils.get_stdout(['corosync-cfgtool', '-s'], shell=False)
            print outp
            rc, outp = utils.get_stdout(['corosync-quorumtool', '-s'], shell=False)
            print outp

    def do_health(self, context):
        '''
        Extensive health check.
        '''
        context.fatal_error("Not implemented.")

    def do_wait_for_startup(self, context, timeout='10'):
        "usage: wait_for_startup [<timeout>]"
        import time
        t0 = time.time()
        timeout = float(timeout)
        cmd = 'crm_mon -s -1 2&>1 >/dev/null'
        ret = utils.ext_cmd(cmd)
        while ret in (107, 64) and time.time() < t0 + timeout:
            time.sleep(1)
            ret = utils.ext_cmd(cmd)
        if ret != 0:
            context.fatal_error("Timed out waiting for cluster (rc = %s)" % (ret))

    def do_list(self, context):
        '''
        List the available cluster installation scripts.
        '''
        for script in self._list_scripts():
            setup_file, script_dir = self._resolve_script(context, script)
            if os.path.isfile(setup_file):
                setup = yaml.load(open(setup_file))[0]
                print "%-16s %s" % (script, setup.get('name', ''))

    def _list_scripts(self):
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
                        if os.path.isfile(os.path.join(curdir, f, 'setup.yml')):
                            l.append(path_combine(prefix, f))
                        else:
                            recurse(root, path_combine(prefix, f))
            except OSError:
                pass
        recurse(_SCRIPTS_DIR, '')
        return sorted(l)

    def _resolve_script(self, context, name):
        '''
        Check if the script with the given name exists.
        It needs to be a directory in the _SCRIPTS_DIR directory,
        with a file named setup.yml inside.

        If the directory is not found or the file does not exist,
        a fatal error is reported.

        Returns (setup_file_path, script_dir)
        '''
        script_dir = os.path.join(_SCRIPTS_DIR, name)
        setup_file = os.path.join(script_dir, 'setup.yml')
        if not os.path.isfile(setup_file):
            context.fatal_error("%s not found.", name)
        return setup_file, script_dir

    def do_describe(self, context, name):
        '''
        Describe the given cluster script
        '''
        setup_file, script_dir = self._resolve_script(context, name)
        setup = yaml.load(open(setup_file))[0]
        from help import HelpEntry

        def rewrap(txt):
            import textwrap
            paras = []
            for para in txt.split('\n'):
                paras.append('\n'.join(textwrap.wrap(para)))
            return '\n\n'.join(paras)
        desc = rewrap(setup.get('description', 'No description available'))

        params = setup.get('parameters', [])
        if params:
            desc += "Parameters (* = Required):\n"
            for p in params:
                rq = ''
                if p.get('required'):
                    rq = '*'
                desc += "  %-24s %s\n" % (p['name'] + rq, p.get('description', ''))

        e = HelpEntry(setup.get('name', name),
                      desc)
        e.paginate()

    @command.skill_level('administrator')
    def do_apply(self, context, name, *args):
        '''
        Apply the given cluster script.
        '''
        setup_file, script_dir = self._resolve_script(context, name)

        setup = yaml.load(open(setup_file))[0]

        args = utils.nvpairs2dict(args)

        if 'nodes' in args:
            if ',' in args['nodes']:
                self._inventory_nodes = [x.strip() for x in args['nodes'].split(',')]
            else:
                self._inventory_nodes = [args['nodes']]
        if 'target' in args:
            if ',' in args['target']:
                self._inventory_target = [x.strip() for x in args['target'].split(',')]
            else:
                self._inventory_target = [args['target']]
        check = utils.is_boolean_true(args.get('check', 'no'))

        for p in setup.get('parameters', []):
            name = p['name']
            if name not in args:
                if p.get('required', False):
                    context.fatal_error("Missing parameter: %s" % (p['name']))
                elif 'default' in p:
                    args[name] = p['default']

        if 'nodes' in args:
            del args['nodes']
        if 'target' in args:
            del args['target']
        if 'check' in args:
            del args['check']

        print args, check
        context.fatal_error("Not implemented.")

    def _inventory(self):
        '''
        Returns {'nodes':[], 'local':[], 'target':[]}
        '''
        hosts = self._inventory_nodes or _list_cluster_nodes()
        self._inventory_nodes = None
        target = self._inventory_target or []
        self._inventory_target = None
        this_node = utils.this_node()
        if not hosts:
            hosts = []
        return {'nodes': hosts, 'local': [this_node], 'target': target}

    @command.skill_level('expert')
    def do_run(self, context, cmd):
        '''
        Execute the given command on all nodes, report outcome
        '''
        inventory = self._inventory()
        if not inventory:
            context.fatal_error("No hosts defined")
        context.fatal_error("Not implemented.")

    @command.skill_level('administrator')
    def do_reload(self, context):
        '''
        Reload the corosync configuration
        '''
        return utils.ext_cmd('corosync-cfgtool -R') == 0

options = Options.getInstance()
