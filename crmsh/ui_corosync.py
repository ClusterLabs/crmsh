# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.
import dataclasses
import io
import ipaddress
import json
import re
import subprocess
import os
import sys
import typing
import shutil

from . import command, sh, parallax, iproute2
from . import completers
from . import utils
from . import corosync
from . import log
from . import constants
from .prun import prun
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


@dataclasses.dataclass
class LinkArgumentParser:
    linknumber: int = -1
    nodes: list[tuple[str, str]] = dataclasses.field(default_factory=list)
    options: dict[str, str|None] = dataclasses.field(default_factory=dict)

    class SyntaxException(Exception):
        pass

    def parse(self, parse_linknumber: bool, allow_empty_options: bool, args: typing.Sequence[str]):
        if not args:
            raise LinkArgumentParser.SyntaxException('linknumber is required')
        i = 0
        if parse_linknumber:
            self.linknumber = self.__parse_linknumber(args, i)
            i += 1
        while i < len(args):
            if args[i] == 'options':
                i += 1
                break
            self.nodes.append(self.__parse_node_spec(args, i))
            i += 1
        if i == len(args):
            if args[i-1] == 'options':
                raise LinkArgumentParser.SyntaxException('no options are specified')
            else:
                return self
        # else args[i-1] == 'options'
        while i < len(args):
            k, v = self.__parse_option_spec(args, i)
            if not allow_empty_options and v is None:
                raise LinkArgumentParser.SyntaxException(f"invalid option specification: {args[i]}")
            self.options[k] = v
            i += 1
        return self

    @staticmethod
    def __parse_linknumber(args: typing.Sequence[str], i: int):
        if not args[i].isdecimal():
            raise LinkArgumentParser.SyntaxException(f'expected linknumber, actual {args[i]}')
        try:
            return int(args[i])
        except ValueError:
            raise LinkArgumentParser.SyntaxException(f'expected linknumber, actual {args[i]}')

    @staticmethod
    def __parse_node_spec(args: typing.Sequence[str], i: int):
        match args[i].split('=', 2):
            case [name, addr]:
                try:
                    utils.IP(addr).ip_address
                    return name, addr
                except ValueError:
                    raise LinkArgumentParser.SyntaxException(f'invalid node address: {addr}')
            case _:
                raise LinkArgumentParser.SyntaxException(f'invalid node address specification: {args[i]}')

    @staticmethod
    def __parse_option_spec(args: typing.Sequence[str], i: int):
        match args[i].split('=', 1):
            case [k, '']:
                return k, None
            case [k, v]:
                return k, v
            case _:
                raise LinkArgumentParser.SyntaxException(f'invalid option specification: {args[i]}')


class Link(command.UI):
    """This level provides subcommands for managing knet links."""

    name = 'link'

    def do_show(self, context):
        """
        Show link configurations.
        """
        lm = self.__load_and_validate_links()
        for link in lm.links():
            if link is None:
                continue
            print(f'Link {link.linknumber}:\n  Node addresses:')
            for node in link.nodes:
                print(f'    Node {node.nodeid}: {node.name}\t{node.addr}')
            print('\n  Options:')
            for name, value in dataclasses.asdict(link).items():
                if name == 'linknumber' or name == 'nodes':
                    continue
                if value is None:
                    continue
                print(f'    {name}:\t{value}')
            print('')

    def do_update(self, context, *argv):
        lm = self.__load_and_validate_links()
        try:
            args = LinkArgumentParser().parse(True, True, argv)
        except LinkArgumentParser.SyntaxException as e:
            logger.error('%s', str(e))
            print('Usage: link update <linknumber> [<node>=<addr> ...] [options <option>=[<value>] ...] ', file=sys.stderr)
            return False
        self._validate_node_addresses(dict(args.nodes))
        lm.update_link(args.linknumber, args.options)   # this also verifies if args.linknumber is valid
        nodes = lm.links()[args.linknumber].nodes
        node_addresses: dict[int, str] = dict()
        for name, addr in args.nodes:
            nodeid = next((x.nodeid for x in nodes if x.name == name), -1)
            if nodeid == -1:
                logger.error(f'Unknown node {name}.')
            node_addresses[nodeid] = addr
        if not args.nodes and not args.options:
            logger.info("Nothing is updated.")
        else:
            try:
                self.__save_changed_config(
                    lm,
                    lm.update_node_addr(args.linknumber, node_addresses),
                    reload=not args.nodes,    # changes to node addresses are not hot reloadable
                )
            except corosync.LinkManager.DuplicatedNodeAddressException as e:
                node1 = next(x.name for x in nodes if x.nodeid == e.node1)
                node2 = next(x.name for x in nodes if x.nodeid == e.node2)
                logger.error('Duplicated ip address %s: used for both %s and %s.', e.address, node1, node2)
                return False

    def do_add(self, context, *argv):
        lm = self.__load_and_validate_links()
        try:
            args = LinkArgumentParser().parse(False, False, argv)
        except LinkArgumentParser.SyntaxException as e:
            logger.error('%s', str(e))
            print('Usage: link add <node>=<addr> ... [options <option>=<value> ...] ', file=sys.stderr)
            return False
        self._validate_node_addresses(dict(args.nodes))
        nodes = next(x for x in lm.links() if x is not None).nodes
        node_addresses: dict[int, str] = dict()
        for name, addr in args.nodes:
            nodeid = next((x.nodeid for x in nodes if x.name == name), -1)
            if nodeid == -1:
                logger.error(f'Unknown node {name}.')
            node_addresses[nodeid] = addr
        try:
            self.__save_changed_config(
                lm,
                lm.add_link(node_addresses, args.options),
                reload=True,
            )
        except corosync.LinkManager.MissingNodesException as e:
            for nodeid in e.nodeids:
                name = next(x.name for x in nodes if x.nodeid == nodeid)
                logger.error('The address of node %s is not specified.', name)
            logger.error('The address of all nodes must be specified when adding a new link.')
            return False
        except corosync.LinkManager.DuplicatedNodeAddressException as e:
            node1 = next(x.name for x in nodes if x.nodeid == e.node1)
            node2 = next(x.name for x in nodes if x.nodeid == e.node2)
            logger.error('Duplicated ip address %s=%s: already used for %s=%s.', node1, e.address, node2, e.address)
            return False


    @command.completer(completers.call(lambda: [
        str(link.linknumber)
        for link in corosync.LinkManager.load_config_file().links()
        if link and link.linknumber != 0
    ]))
    def do_remove(self, context, linknumber: str):
        if not linknumber.isdecimal():
            raise ValueError(f'Invalid linknumber: {linknumber}')
        linknumber = int(linknumber)
        lm = self.__load_and_validate_links()
        self._check_link_removable(lm, linknumber)
        self.__save_changed_config(
            lm,
            lm.remove_link(linknumber),
            reload=True,
        )

    @staticmethod
    def _check_link_removable(lm: corosync.LinkManager, linknumber):
        if not ServiceManager().service_is_active("corosync.service"):
            return
        nodes = utils.list_cluster_nodes()
        for host, result in prun.prun({node: 'corosync-cfgtool -s' for node in nodes}).items():
            # for each node <host> in the cluster
            match result:
                case prun.SSHError() as e:
                    raise ValueError(str(e))
                case prun.ProcessResult() as x:
                    if x.returncode != 0:
                        raise ValueError(f'{host}: {x.returncode}, {sh.Utils.decode_str(x.stderr)}')
                    connected_nodes = set()
                    ln = -1
                    for line in io.StringIO(sh.Utils.decode_str(x.stdout)):
                        mo = re.match('^(?:LINK ID (\\d+)|\\s*nodeid:\\s*(\\d+):\\s*(?:localhost|connected)$)', line)
                        if mo is None:
                            continue
                        if mo.group(1):
                            ln = int(mo.group(1))
                            continue
                        if ln == linknumber:
                            # filter out the link to be removed
                            continue
                        if mo.group(2):
                            connected_nodes.add(mo.group(2))
                    if len(connected_nodes) < len(next(link for link in lm.links() if link is not None).nodes):
                        # or <host> will lose quorum
                        raise ValueError(f'Cannot remove link {linknumber}. Removing this link makes the cluster to lose quorum.')


    @staticmethod
    def _validate_node_addresses(node_addrs: typing.Mapping[str, str]):
        node_interfaces = {
            node: iproute2.IPAddr(json.loads(stdout)).interfaces()
            for node, (_, stdout, _) in parallax.parallax_call(node_addrs.keys(), 'ip -j addr')
        }
        for node, addr in node_addrs.items():
            ip_addr = ipaddress.ip_address(addr)
            if not any(
                ip_addr == addr.ip
                for interface in node_interfaces[node]
                for addr in interface.addr_info
            ):
                raise ValueError(f'{addr} is not a configured interface address on node {node}.')

    @staticmethod
    def __load_and_validate_links():
        lm = corosync.LinkManager.load_config_file()
        if lm.totem_transport() != 'knet':
            raise ValueError('Corosync is not using knet transport')
        return lm

    @staticmethod
    def __save_changed_config(linkmanager, dom, reload: bool):
        linkmanager.write_config_file(dom)
        nodes = utils.list_cluster_nodes()
        nodes.remove(utils.this_node())
        logger.info('Synchronizing corosync.conf in the cluster...')
        if not corosync.push_configuration(nodes):
            raise ValueError('Failed to synchronize corosync.conf in the cluster.')
        if not ServiceManager().service_is_active("corosync.service"):
            return
        elif reload:
            result = subprocess.run(['corosync-cfgtool', '-R'])
            if 0 != result.returncode:
                raise ValueError('Failed to reload corosync.conf.')
        else:
            logger.warning('Restarting corosync.service is needed to apply the changes, ie. crm cluster restart --all')


class Corosync(command.UI):
    '''
    Corosync is the underlying messaging layer for most HA clusters.
    This level provides commands for editing and managing the corosync
    configuration.
    '''
    name = "corosync"

    def requires(self):
        return corosync.check_tools()

    @command.completers(completers.choice(constants.COROSYNC_STATUS_TYPES))
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

    @staticmethod
    def _note_for_push():
        if len(utils.list_cluster_nodes()) > 1:
            logger.warning("\"%s\" has changed, should be synced with other nodes", corosync.conf())
            logger.info("Use \"crm corosync diff\" to show the difference")
            logger.info("Use \"crm corosync push\" to sync")

    @command.skill_level('administrator')
    def do_edit(self, context):
        '''
        Edit the corosync configuration.
        '''
        cfg = corosync.conf()
        try:
            rc = utils.edit_file_ext(cfg, corosync.is_valid_corosync_conf)
            if rc:
                self._note_for_push()
        except IOError as e:
            context.fatal_error(str(e))

    def do_show(self, context):
        '''
        Display the corosync configuration.
        '''
        if not corosync.is_valid_corosync_conf():
            return False
        utils.page_file(corosync.conf())

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
        corosync_conf_file = corosync.conf()
        with utils.create_tempfile(dir=os.path.dirname(corosync_conf_file)) as temp_file:
            shutil.copyfile(corosync_conf_file, temp_file)
            corosync.ConfParser.set_value(path, value, index=index, config_file=temp_file)
            if corosync.is_valid_corosync_conf(temp_file):
                os.rename(temp_file, corosync_conf_file)
                self._note_for_push()
                return True
            else:
                return False

    @command.level(Link)
    def do_link(self):
        pass
