# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.
'''
Functions that abstract creating and editing the corosync.conf
configuration file, and also the corosync-* utilities.
'''

import os
import re
import typing

from . import utils, sh
from . import tmpfiles
from . import parallax
from . import log
from . import conf_parser
from .sh import ShellUtils


logger = log.setup_logger(__name__)


COROSYNC_TOKEN_DEFAULT = 1000  # in ms units


def is_knet() -> bool:
    res = get_value("totem.transport")
    return res and res == "knet"


def is_using_ipv6() -> bool:
    res = get_value("totem.ip_version")
    return res and res == "ipv6"


def get_link_number() -> int:
    link_num = 1
    for key, value in conf_parser.ConfParser.get_value("nodelist.node").items():
        if re.search("ring[1-7]_addr", key) and value:
            link_num += 1
    return link_num


def is_qdevice_configured() -> bool:
    return get_value("quorum.device.model") == "net"


def is_qdevice_tls_on() -> bool:
    return get_value("quorum.device.net.tls") == "on"


def configure_two_node(removing: bool = False, qdevice_adding: bool = False) -> None:
    """
    Enable or disable two_node in corosync.conf
    """
    quorum_votes_dict = utils.get_quorum_votes_dict()
    expected_votes = int(quorum_votes_dict["Expected"])
    if removing:
        expected_votes -= 1
    if qdevice_adding and expected_votes > 1:
        expected_votes += 1
    set_value("quorum.two_node", 1 if expected_votes == 2 else 0)


def conf():
    return os.getenv('COROSYNC_MAIN_CONFIG_FILE', '/etc/corosync/corosync.conf')


def check_tools():
    return all(utils.is_program(p)
               for p in ['corosync-cfgtool', 'corosync-quorumtool', 'corosync-cmapctl'])


def cfgtool(*args):
    return ShellUtils().get_stdout(['corosync-cfgtool'] + list(args), shell=False)


def query_status(status_type):
    """
    Query status of corosync

    Possible types could be ring/quorum/qdevice/qnetd
    """
    status_func_dict = {
            "ring": query_ring_status,
            "quorum": query_quorum_status,
            "qdevice": query_qdevice_status,
            "qnetd": query_qnetd_status
            }
    if status_type in status_func_dict:
        out = sh.cluster_shell().get_stdout_or_raise_error("crm_node -l")
        print(f"{out}\n")
        print(status_func_dict[status_type]())
    else:
        raise ValueError("Wrong type \"{}\" to query status".format(status_type))


def query_ring_status():
    """
    Query corosync ring status
    """
    rc, out, err = ShellUtils().get_stdout_stderr("corosync-cfgtool -s")
    if rc != 0 and err:
        raise ValueError(err)
    return out


def query_quorum_status():
    """
    Query corosync quorum status

    """
    rc, out, err = ShellUtils().get_stdout_stderr("corosync-quorumtool -s")
    if rc != 0 and err:
        raise ValueError(err)
    # If the return code of corosync-quorumtool is 2,
    # that means no problem appeared but node is not quorate
    if rc in [0, 2] and out:
        return out


def query_qdevice_status():
    """
    Query qdevice status
    """
    if not is_qdevice_configured():
        raise ValueError("QDevice/QNetd not configured!")
    cmd = "corosync-qdevice-tool -sv"
    out = sh.cluster_shell().get_stdout_or_raise_error(cmd)
    return out


def query_qnetd_status():
    """
    Query qnetd status
    """
    import crmsh.bootstrap  # workaround for circular dependencies
    if not is_qdevice_configured():
        raise ValueError("QDevice/QNetd not configured!")
    cluster_name = get_value('totem.cluster_name')
    if not cluster_name:
        raise ValueError("cluster_name not configured!")
    qnetd_addr = get_value('quorum.device.net.host')
    if not qnetd_addr:
        raise ValueError("host for qnetd not configured!")

    cmd = "corosync-qnetd-tool -lv -c {}".format(cluster_name)
    result = parallax.parallax_call([qnetd_addr], cmd)
    _, qnetd_result_stdout, _ = result[0][1]
    if qnetd_result_stdout:
        return utils.to_ascii(qnetd_result_stdout)


def push_configuration(nodes):
    '''
    Push the local configuration to the list of remote nodes
    '''
    return utils.cluster_copy_file(conf(), nodes)


def pull_configuration(from_node):
    '''
    Copy the configuration from the given node to this node
    '''
    local_path = conf()
    _, fname = tmpfiles.create()
    print("Retrieving %s:%s..." % (from_node, local_path))
    cmd = ['scp', '-qC',
           '-o', 'PasswordAuthentication=no',
           '-o', 'StrictHostKeyChecking=no',
           '%s:%s' % (from_node, local_path),
           fname]
    rc = utils.ext_cmd_nosudo(cmd, shell=False)
    if rc == 0:
        data = open(fname).read()
        newhash = hash(data)
        if os.path.isfile(local_path):
            oldata = open(local_path).read()
            oldhash = hash(oldata)
            if newhash == oldhash:
                print("No change.")
                return
        print("Writing %s:%s..." % (utils.this_node(), local_path))
        local_file = open(local_path, 'w')
        local_file.write(data)
        local_file.close()
    else:
        raise ValueError("Failed to retrieve %s from %s" % (local_path, from_node))


def diff_configuration(nodes, checksum=False):
    local_path = conf()
    this_node = utils.this_node()
    nodes = list(nodes)
    if checksum:
        utils.remote_checksum(local_path, nodes, this_node)
    elif len(nodes) == 1:
        utils.remote_diff_this(local_path, nodes, this_node)
    elif this_node in nodes:
        nodes.remove(this_node)
        utils.remote_diff_this(local_path, nodes, this_node)
    elif nodes:
        utils.remote_diff(local_path, nodes)


def get_free_nodeid():
    ids = get_values('nodelist.node.nodeid')
    if not ids:
        return 1
    ids = [int(i) for i in ids]
    max_id = max(ids) + 1
    for i in range(1, max_id):
        if i not in ids:
            return i
    return max_id


def get_value(path, index: int = 0):
    return conf_parser.ConfParser.get_value(path, index)


def get_values(path):
    return conf_parser.ConfParser.get_values(path)


def set_value(path, value, index: int = 0):
    conf_parser.ConfParser.set_value(path, value, index)


class IPAlreadyConfiguredError(Exception):
    pass


def find_configured_ip(ip_list):
    """
    find if the same IP already configured
    If so, raise IPAlreadyConfiguredError
    """
    data = utils.read_from_file(conf())
    corosync_iplist = re.findall('ring[0-7]_addr:\s*(.*?)\n', data)

    # all_possible_ip is a ip set to check whether one of them already configured
    all_possible_ip = set(ip_list)
    # get local ip list
    is_ipv6 = utils.IP.is_ipv6(ip_list[0])
    local_ip_list = utils.InterfacesInfo.get_local_ip_list(is_ipv6)
    # extend all_possible_ip if ip_list contain local ip
    # to avoid this scenarios in join node:
    #   eth0's ip already configured in corosync.conf
    #   eth1's ip also want to add in nodelist
    # if this scenarios happened, raise IPAlreadyConfiguredError
    if bool(set(ip_list) & set(local_ip_list)):
        all_possible_ip |= set(local_ip_list)
    configured_ip = list(all_possible_ip & set(corosync_iplist))
    if configured_ip:
        raise IPAlreadyConfiguredError("IP {} was already configured".format(','.join(configured_ip)))


def add_node_config(ip_list: typing.List[str]) -> None:
    """
    Add nodelist in corosync.conf
    """
    find_configured_ip(ip_list)
    inst = conf_parser.ConfParser()
    node_index = len(inst.get_all("nodelist.node"))
    for i, addr in enumerate(ip_list):
        inst.set("nodelist.node.ring{}_addr".format(i), addr, node_index)
    inst.set("nodelist.node.name", utils.this_node(), node_index)
    inst.set("nodelist.node.nodeid", get_free_nodeid(), node_index)
    inst.save()


def del_node(addr: str) -> None:
    '''
    Remove node from corosync
    '''
    inst = conf_parser.ConfParser()
    name_list = inst.get_all("nodelist.node.ring0_addr")
    index = name_list.index(addr)
    inst.remove("nodelist.node", index)
    inst.save()


def get_corosync_value(key):
    """
    Get corosync configuration value from corosync-cmapctl or corosync.conf
    """
    try:
        out = sh.cluster_shell().get_stdout_or_raise_error("corosync-cmapctl {}".format(key))
        res = re.search(r'{}\s+.*=\s+(.*)'.format(key), out)
        return res.group(1) if res else None
    except ValueError:
        out = get_value(key)
        return out


def get_corosync_value_dict():
    """
    Get corosync value, then return these values as dict
    """
    value_dict = {}

    token = get_corosync_value("totem.token")
    value_dict["token"] = int(int(token)/1000) if token else int(COROSYNC_TOKEN_DEFAULT/1000)

    consensus = get_corosync_value("totem.consensus")
    value_dict["consensus"] = int(int(consensus)/1000) if consensus else int(value_dict["token"]*1.2)

    return value_dict


def token_and_consensus_timeout():
    """
    Get corosync token plus consensus timeout
    """
    _dict = get_corosync_value_dict()
    return _dict["token"] + _dict["consensus"]
