# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import os
from . import command, sh
from . import completers
from . import utils
from . import corosync
from . import parallax
from . import bootstrap
from . import log
from .service_manager import ServiceManager

logger = log.setup_logger(__name__)


def _push_completer(args):
    try:
        n = utils.list_cluster_nodes()
        n.remove(utils.this_node())
        if args[-1] in n:
            # continue complete
            return [args[-1]]
        for item in args:
            if item in n:
                n.remove(item)
        return n
    except:
        n = []


def _diff_nodes(args):
    try:
        if len(args) > 3:
            return []
        n = utils.list_cluster_nodes()
        if args[-1] in n:
            # continue complete
            return [args[-1]]
        for item in args:
            if item in n:
                # remove already complete item
                n.remove(item)
        return n
    except:
        return []


class Corosync(command.UI):
    '''
    Corosync is the underlying messaging layer for most HA clusters.
    This level provides commands for editing and managing the corosync
    configuration.
    '''
    name = "corosync"

    def requires(self):
        return corosync.check_tools()

    @command.completers(completers.choice(['ring', 'quorum', 'qdevice', 'qnetd']))
    def do_status(self, context, status_type="ring"):
        '''
        Quick cluster health status. Corosync status or QNetd status
        '''
        if not ServiceManager(sh.ClusterShellAdaptorForLocalShell(sh.LocalShell())).service_is_active("corosync.service"):
            logger.error("corosync.service is not running!")
            return False

        try:
            corosync.query_status(status_type)
        except ValueError as err:
            logger.error(str(err))
            return False

    @command.skill_level('administrator')
    def do_reload(self, context):
        '''
        Reload the corosync configuration
        '''
        return corosync.cfgtool('-R')[0] == 0

    @command.skill_level('administrator')
    @command.completers_repeating(_push_completer)
    def do_push(self, context, *nodes):
        '''
        Push corosync configuration to other cluster nodes.
        If no nodes are provided, configuration is pushed to
        all other cluster nodes.
        '''
        if not nodes:
            nodes = utils.list_cluster_nodes()
            nodes.remove(utils.this_node())
        return corosync.push_configuration(nodes)

    @command.skill_level('administrator')
    @command.completers(_push_completer)
    def do_pull(self, context, node):
        '''
        Pull corosync configuration from another node.
        '''
        return corosync.pull_configuration(node)

    @command.completers_repeating(_diff_nodes)
    def do_diff(self, context, *nodes):
        '''
        Compare corosync configuration between nodes.
        '''
        checksum = False
        if nodes and nodes[0] == '--checksum':
            checksum = True
            nodes = nodes[1:]
        if not nodes:
            nodes = utils.list_cluster_nodes()
        return corosync.diff_configuration(nodes, checksum=checksum)

    @command.skill_level('administrator')
    def do_edit(self, context):
        '''
        Edit the corosync configuration.
        '''
        cfg = corosync.conf()
        try:
            utils.edit_file_ext(cfg, template='')
        except IOError as e:
            context.fatal_error(str(e))

    def do_show(self, context):
        '''
        Display the corosync configuration.
        '''
        cfg = corosync.conf()
        if not os.path.isfile(cfg):
            context.fatal_error("No corosync configuration found on this node.")
        utils.page_string(open(cfg).read())

    def do_log(self, context):
        '''
        Display the corosync log file (if any).
        '''
        logfile = corosync.get_value('logging.logfile')
        if not logfile:
            context.fatal_error("No corosync log file configured")
        utils.page_file(logfile)

    @command.skill_level('administrator')
    @command.completers(completers.call(corosync.get_all_paths))
    def do_get(self, context, path):
        """Get a corosync configuration value"""
        for v in corosync.get_values(path):
            print(v)

    @command.skill_level('administrator')
    @command.completers(completers.call(corosync.get_all_paths))
    def do_set(self, context, path, value, index: int = 0):
        """Set a corosync configuration value"""
        corosync.set_value(path, value, index)
