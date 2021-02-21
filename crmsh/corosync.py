# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.
'''
Functions that abstract creating and editing the corosync.conf
configuration file, and also the corosync-* utilities.
'''

import os
import re
import socket
import tokenize
from tokenize import COMMENT, NL, LBRACE, RBRACE, NEWLINE, NAME
from contextlib import contextmanager
from . import utils
from . import tmpfiles
from . import parallax
from . import bootstrap
from .msg import err_buf, common_debug


def conf():
    return os.getenv('COROSYNC_MAIN_CONFIG_FILE', '/etc/corosync/corosync.conf')


def is_corosync_stack():
    return utils.cluster_stack() == 'corosync'


def check_tools():
    return all(utils.is_program(p)
               for p in ['corosync-cfgtool', 'corosync-quorumtool', 'corosync-cmapctl'])


def cfgtool(*args):
    return utils.get_stdout(['corosync-cfgtool'] + list(args), shell=False)


def quorumtool(*args):
    return utils.get_stdout(['corosync-quorumtool'] + list(args), shell=False)


def query_status(status_type):
    """
    Query status of corosync

    Possible types could be ring/quorum/qnetd
    """
    if status_type == "ring":
        query_ring_status()
    elif status_type == "quorum":
        query_quorum_status()
    elif status_type == "qnetd":
        query_qnetd_status()
    else:
        raise ValueError("Wrong type \"{}\" to query status".format(status_type))


def query_ring_status():
    """
    Query corosync ring status
    """
    rc, out, err = utils.get_stdout_stderr("corosync-cfgtool -s")
    if rc != 0 and err:
        raise ValueError(err)
    if rc == 0 and out:
        print(out)


def query_quorum_status():
    """
    Query corosync quorum status

    """
    utils.print_cluster_nodes()
    rc, out, err = utils.get_stdout_stderr("corosync-quorumtool -s")
    if rc != 0 and err:
        raise ValueError(err)
    # If the return code of corosync-quorumtool is 2,
    # that means no problem appeared but node is not quorate
    if rc in [0, 2] and out:
        print(out)


def query_qnetd_status():
    """
    Query qnetd status
    """
    if not utils.is_qdevice_configured():
        raise ValueError("QDevice/QNetd not configured!")
    cluster_name = get_value('totem.cluster_name')
    if not cluster_name:
        raise ValueError("cluster_name not configured!")
    qnetd_addr = get_value('quorum.device.net.host')
    if not qnetd_addr:
        raise ValueError("host for qnetd not configured!")

    # Configure ssh passwordless to qnetd if detect password is needed
    if utils.check_ssh_passwd_need(qnetd_addr):
        print("Copy ssh key to qnetd node({})".format(qnetd_addr))
        rc, _, err = utils.get_stdout_stderr("ssh-copy-id -i /root/.ssh/id_rsa.pub root@{}".format(qnetd_addr))
        if rc != 0:
            raise ValueError(err)

    cmd = "corosync-qnetd-tool -lv -c {}".format(cluster_name)
    result = parallax.parallax_call([qnetd_addr], cmd)
    _, qnetd_result_stdout, _ = result[0][1]
    if qnetd_result_stdout:
        utils.print_cluster_nodes()
        print(utils.to_ascii(qnetd_result_stdout))


def add_nodelist_from_cmaptool():
    for nodeid, iplist in utils.get_nodeinfo_from_cmaptool().items():
        try:
            add_node_ucast(iplist, nodeid)
        except IPAlreadyConfiguredError:
            continue


def is_unicast():
    return get_value("totem.transport") == "udpu"


class QDevice(object):
    """
    Class to manage qdevice configuration and services

    Whole certification process:
    For init
    Step 1:  init_db_on_qnetd
    Step 2:  fetch_qnetd_crt_from_qnetd
    Step 3:  copy_qnetd_crt_to_cluster
    Step 4:  init_db_on_cluster
    Step 5:  create_ca_request
    Step 6:  copy_crq_to_qnetd
    Step 7:  sign_crq_on_qnetd
    Step 8:  fetch_cluster_crt_from_qnetd
    Step 9:  import_cluster_crt
    Step 10: copy_p12_to_cluster
    Step 11: import_p12_on_cluster

    For join
    Step 1:  fetch_qnetd_crt_from_cluster
    Step 2:  init_db_on_local
    Step 3:  fetch_p12_from_cluster
    Step 4:  import_p12_on_local
    """
    qnetd_service = "corosync-qnetd.service"
    qnetd_cacert_filename = "qnetd-cacert.crt"
    qdevice_crq_filename = "qdevice-net-node.crq"
    qdevice_p12_filename = "qdevice-net-node.p12"
    qnetd_path = "/etc/corosync/qnetd"
    qdevice_path = "/etc/corosync/qdevice/net"
    qdevice_db_path = "/etc/corosync/qdevice/net/nssdb"

    def __init__(self, qnetd_addr, port=5403, algo="ffsplit", tie_breaker="lowest",
            tls="on", cluster_node=None, cmds=None, mode=None):
        """
        Init function
        """
        self.qnetd_addr = qnetd_addr
        self.port = port
        self.algo = algo
        self.tie_breaker = tie_breaker
        self.tls = tls
        self.cluster_node = cluster_node
        self.askpass = False
        self.cmds = cmds
        self.mode = mode

    @property
    def qnetd_cacert_on_qnetd(self):
        """
        Return path of qnetd-cacert.crt on qnetd node
        """
        return "{}/nssdb/{}".format(self.qnetd_path, self.qnetd_cacert_filename)

    @property
    def qnetd_cacert_on_local(self):
        """
        Return path of qnetd-cacert.crt on local node
        """
        return "{}/{}/{}".format(self.qdevice_path, self.qnetd_addr, self.qnetd_cacert_filename)

    @property
    def qnetd_cacert_on_cluster(self):
        """
        Return path of qnetd-cacert.crt on cluster node
        """
        return "{}/{}/{}".format(self.qdevice_path, self.cluster_node, self.qnetd_cacert_filename)

    @property
    def qdevice_crq_on_qnetd(self):
        """
        Return path of qdevice-net-node.crq on qnetd node
        """
        return "{}/nssdb/{}".format(self.qnetd_path, self.qdevice_crq_filename)
    
    @property
    def qdevice_crq_on_local(self):
        """
        Return path of qdevice-net-node.crq on local node
        """
        return "{}/nssdb/{}".format(self.qdevice_path, self.qdevice_crq_filename)

    @property
    def qnetd_cluster_crt_on_qnetd(self):
        """
        Return path of cluster-cluster_name.crt on qnetd node
        """
        return "{}/nssdb/cluster-{}.crt".format(self.qnetd_path, self.cluster_name)

    @property
    def qnetd_cluster_crt_on_local(self):
        """
        Return path of cluster-cluster_name.crt on local node
        """
        return "{}/{}/{}".format(self.qdevice_path, self.qnetd_addr, os.path.basename(self.qnetd_cluster_crt_on_qnetd))

    @property
    def qdevice_p12_on_local(self):
        """
        Return path of qdevice-net-node.p12 on local node
        """
        return "{}/nssdb/{}".format(self.qdevice_path, self.qdevice_p12_filename)

    @property
    def qdevice_p12_on_cluster(self):
        """
        Return path of qdevice-net-node.p12 on cluster node
        """
        return "{}/{}/{}".format(self.qdevice_path, self.cluster_node, self.qdevice_p12_filename)

    def valid_attr(self):
        """
        Validate qdevice related options
        """
        qnetd_ip = None

        if not utils.package_is_installed("corosync-qdevice"):
            raise ValueError("Package \"corosync-qdevice\" not installed on this node")

        try:
            # socket.getaddrinfo works for both ipv4 and ipv6 address
            # The function returns a list of 5-tuples with the following structure:
            # (family, type, proto, canonname, sockaddr)
            # sockaddr is a tuple describing a socket address, whose format depends on the returned family
            # (a (address, port) 2-tuple for AF_INET, a (address, port, flow info, scope id) 4-tuple for AF_INET6)
            res = socket.getaddrinfo(self.qnetd_addr, None)
            qnetd_ip = res[0][-1][0]
        except socket.error:
            raise ValueError("host \"{}\" is unreachable".format(self.qnetd_addr))

        utils.ping_node(self.qnetd_addr)

        if utils.InterfacesInfo.ip_in_local(qnetd_ip):
            raise ValueError("host for qnetd must be a remote one")

        if not utils.check_port_open(qnetd_ip, 22):
            raise ValueError("ssh service on \"{}\" not available".format(self.qnetd_addr))

        if not utils.valid_port(self.port):
            raise ValueError("invalid qdevice port range(1024 - 65535)")

        if self.tie_breaker not in ["lowest", "highest"] and not utils.valid_nodeid(self.tie_breaker):
            raise ValueError("invalid qdevice tie_breaker(lowest/highest/valid_node_id)")

        if self.cmds:
            for cmd in self.cmds.strip(';').split(';'):
                if not cmd.startswith('/'):
                    raise ValueError("commands for heuristics should be absolute path")
                if not os.path.exists(cmd.split()[0]):
                    raise ValueError("command {} not exist".format(cmd.split()[0]))

    def valid_qnetd(self):
        """
        Validate on qnetd node
        """
        if utils.check_ssh_passwd_need(self.qnetd_addr):
            self.askpass = True

        exception_msg = ""
        suggest = ""
        if utils.service_is_active("pacemaker", self.qnetd_addr):
            exception_msg = "host for qnetd must be a non-cluster node"
            suggest = "change to another host or stop cluster service on {}".format(self.qnetd_addr)
        elif not utils.package_is_installed("corosync-qnetd", self.qnetd_addr):
            exception_msg = "Package \"corosync-qnetd\" not installed on {}".format(self.qnetd_addr)
            suggest = "install \"corosync-qnetd\" on {}".format(self.qnetd_addr)

        if exception_msg:
            exception_msg += "\nCluster service already successfully started on this node except qdevice service\nIf you still want to use qdevice, {}\nThen run command \"crm cluster init\" with \"qdevice\" stage, like:\n  crm cluster init qdevice qdevice_related_options\nThat command will setup qdevice separately".format(suggest)
            raise ValueError(exception_msg)

    def manage_qnetd(self, action):
        cmd = "systemctl {} {}".format(action, self.qnetd_service)
        if self.askpass:
            print("{} {} on {}".format(action.capitalize(), self.qnetd_service, self.qnetd_addr))
        parallax.parallax_call([self.qnetd_addr], cmd, self.askpass)

    def enable_qnetd(self):
        self.manage_qnetd("enable")

    def disable_qnetd(self):
        self.manage_qnetd("disable")

    def start_qnetd(self):
        self.manage_qnetd("start")

    def stop_qnetd(self):
        self.manage_qnetd("stop")

    def debug_and_log_to_bootstrap(self, msg):
        common_debug(msg)
        bootstrap.log("# " + msg)

    def init_db_on_qnetd(self):
        """
        Certificate process for init
        Step 1
        Initialize database on QNetd server by running corosync-qnetd-certutil -i
        """
        cmd = "test -f {}".format(self.qnetd_cacert_on_qnetd)
        if self.askpass:
            print("Test whether {} exists on QNetd server({})".format(self.qnetd_cacert_on_qnetd, self.qnetd_addr))
        try:
            parallax.parallax_call([self.qnetd_addr], cmd, self.askpass)
        except ValueError:
            # target file not exist
            pass
        else:
            return

        cmd = "corosync-qnetd-certutil -i"
        desc = "Step 1: Initialize database on {}".format(self.qnetd_addr)
        self.debug_and_log_to_bootstrap(desc)
        if self.askpass:
            print(desc)
        parallax.parallax_call([self.qnetd_addr], cmd, self.askpass)

    def fetch_qnetd_crt_from_qnetd(self):
        """
        Certificate process for init
        Step 2
        Fetch QNetd CA certificate(qnetd-cacert.crt) from QNetd server
        """
        if os.path.exists(self.qnetd_cacert_on_local):
            return

        desc = "Step 2: Fetch {} from {}".format(self.qnetd_cacert_filename, self.qnetd_addr)
        self.debug_and_log_to_bootstrap(desc)
        if self.askpass:
            print(desc)
        parallax.parallax_slurp([self.qnetd_addr], self.qdevice_path, self.qnetd_cacert_on_qnetd, self.askpass)

    def copy_qnetd_crt_to_cluster(self):
        """
        Certificate process for init
        Step 3
        Copy exported QNetd CA certificate (qnetd-cacert.crt) to every node
        """
        node_list = utils.list_cluster_nodes_except_me()
        if not node_list:
            return

        desc = "Step 3: Copy exported {} to {}".format(self.qnetd_cacert_filename, node_list)
        self.debug_and_log_to_bootstrap(desc)
        if self.askpass:
            print(desc)
        parallax.parallax_copy(
                node_list,
                os.path.dirname(self.qnetd_cacert_on_local),
                self.qdevice_path,
                self.askpass)

    def init_db_on_cluster(self):
        """
        Certificate process for init
        Step 4
        On one of cluster node initialize database by running
        /usr/sbin/corosync-qdevice-net-certutil -i -c qnetd-cacert.crt
        """
        node_list = utils.list_cluster_nodes()
        cmd = "corosync-qdevice-net-certutil -i -c {}".format(self.qnetd_cacert_on_local)
        desc = "Step 4: Initialize database on {}".format(node_list)
        self.debug_and_log_to_bootstrap(desc)
        if self.askpass:
            print(desc)
        parallax.parallax_call(node_list, cmd, self.askpass)

    def create_ca_request(self):
        """
        Certificate process for init
        Step 5
        Generate certificate request:
        /usr/sbin/corosync-qdevice-net-certutil -r -n Cluster
        (Cluster name must match cluster_name key in the corosync.conf)
        """
        self.debug_and_log_to_bootstrap("Step 5: Generate certificate request {}".format(self.qdevice_crq_filename))
        self.cluster_name = get_value('totem.cluster_name')
        if not self.cluster_name:
            raise ValueError("No cluster_name found in {}".format(conf()))
        cmd = "corosync-qdevice-net-certutil -r -n {}".format(self.cluster_name)
        rc, _, err = utils.get_stdout_stderr(cmd)
        if rc != 0:
            raise ValueError(err)

    def copy_crq_to_qnetd(self):
        """
        Certificate process for init
        Step 6
        Copy exported CRQ to QNetd server
        """
        desc = "Step 6: Copy {} to {}".format(self.qdevice_crq_filename, self.qnetd_addr)
        self.debug_and_log_to_bootstrap(desc)
        if self.askpass:
            print(desc)
        parallax.parallax_copy(
                [self.qnetd_addr],
                self.qdevice_crq_on_local,
                os.path.dirname(self.qdevice_crq_on_qnetd),
                self.askpass)

    def sign_crq_on_qnetd(self):
        """
        Certificate process for init
        Step 7
        On QNetd server sign and export cluster certificate by running
        corosync-qnetd-certutil -s -c qdevice-net-node.crq -n Cluster
        """
        desc = "Step 7: Sign and export cluster certificate on {}".format(self.qnetd_addr)
        self.debug_and_log_to_bootstrap(desc)
        cmd = "corosync-qnetd-certutil -s -c {} -n {}".\
                format(self.qdevice_crq_on_qnetd, self.cluster_name)
        if self.askpass:
            print(desc)
        parallax.parallax_call([self.qnetd_addr], cmd, self.askpass)

    def fetch_cluster_crt_from_qnetd(self):
        """
        Certificate process for init
        Step 8
        Copy exported CRT to node where certificate request was created
        """
        desc = "Step 8: Fetch {} from {}".format(os.path.basename(self.qnetd_cluster_crt_on_qnetd), self.qnetd_addr)
        self.debug_and_log_to_bootstrap(desc)
        if self.askpass:
            print(desc)
        parallax.parallax_slurp(
                [self.qnetd_addr],
                self.qdevice_path,
                self.qnetd_cluster_crt_on_qnetd,
                self.askpass)

    def import_cluster_crt(self):
        """
        Certificate process for init
        Step 9
        Import certificate on node where certificate request was created by
        running /usr/sbin/corosync-qdevice-net-certutil -M -c cluster-Cluster.crt
        """
        self.debug_and_log_to_bootstrap("Step 9: Import certificate file {} on local".format(os.path.basename(self.qnetd_cluster_crt_on_local)))
        cmd = "corosync-qdevice-net-certutil -M -c {}".format(self.qnetd_cluster_crt_on_local)
        rc, _, err = utils.get_stdout_stderr(cmd)
        if rc != 0:
            raise ValueError(err)

    def copy_p12_to_cluster(self):
        """
        Certificate process for init
        Step 10
        Copy output qdevice-net-node.p12 to all other cluster nodes
        """
        node_list = utils.list_cluster_nodes_except_me()
        if not node_list:
            return

        desc = "Step 10: Copy {} to {}".format(self.qdevice_p12_filename, node_list)
        self.debug_and_log_to_bootstrap(desc)
        if self.askpass:
            print(desc)
        parallax.parallax_copy(
                node_list,
                self.qdevice_p12_on_local,
                os.path.dirname(self.qdevice_p12_on_local),
                self.askpass)

    def import_p12_on_cluster(self):
        """
        Certificate process for init
        Step 11
        Import cluster certificate and key on all other cluster nodes:
        /usr/sbin/corosync-qdevice-net-certutil -m -c qdevice-net-node.p12
        """
        node_list = utils.list_cluster_nodes_except_me()
        if not node_list:
            return

        desc = "Step 11: Import {} on {}".format(self.qdevice_p12_filename, node_list)
        self.debug_and_log_to_bootstrap(desc)
        if self.askpass:
            print(desc)
        cmd = "corosync-qdevice-net-certutil -m -c {}".format(self.qdevice_p12_on_local)
        parallax.parallax_call(node_list, cmd, self.askpass)

    def certificate_process_on_init(self):
        """
        The qdevice certificate process on init node
        """
        self.init_db_on_qnetd()
        self.fetch_qnetd_crt_from_qnetd()
        self.copy_qnetd_crt_to_cluster()
        self.init_db_on_cluster()
        self.create_ca_request()
        self.copy_crq_to_qnetd()
        self.sign_crq_on_qnetd()
        self.fetch_cluster_crt_from_qnetd()
        self.import_cluster_crt()
        self.copy_p12_to_cluster()
        self.import_p12_on_cluster()

    def fetch_qnetd_crt_from_cluster(self):
        """
        Certificate process for join
        Step 1
        Fetch QNetd CA certificate(qnetd-cacert.crt) from init node
        """
        if os.path.exists(self.qnetd_cacert_on_cluster):
            return

        desc = "Step 1: Fetch {} from {}".format(self.qnetd_cacert_filename, self.cluster_node)
        self.debug_and_log_to_bootstrap(desc)
        if self.askpass:
            print(desc)
        parallax.parallax_slurp(
                [self.cluster_node],
                self.qdevice_path,
                self.qnetd_cacert_on_local,
                self.askpass)

    def init_db_on_local(self):
        """
        Certificate process for join
        Step 2
        Initialize database by running
        /usr/sbin/corosync-qdevice-net-certutil -i -c qnetd-cacert.crt
        """
        if os.path.exists(self.qdevice_db_path):
            utils.rmdir_r(self.qdevice_db_path)

        self.debug_and_log_to_bootstrap("Step 2: Initialize database on local")
        cmd = "corosync-qdevice-net-certutil -i -c {}".format(self.qnetd_cacert_on_cluster)
        rc, _, err = utils.get_stdout_stderr(cmd)
        if rc != 0:
            raise ValueError(err)

    def fetch_p12_from_cluster(self):
        """
        Certificate process for join
        Step 3
        Fetch p12 key file from init node
        """
        if os.path.exists(self.qdevice_p12_on_cluster):
            return

        desc = "Step 3: Fetch {} from {}".format(self.qdevice_p12_filename, self.cluster_node)
        self.debug_and_log_to_bootstrap(desc)
        if self.askpass:
            print(desc)
        parallax.parallax_slurp(
                [self.cluster_node],
                self.qdevice_path,
                self.qdevice_p12_on_local,
                self.askpass)

    def import_p12_on_local(self):
        """
        Certificate process for join
        Step 4
        Import cluster certificate and key
        """
        self.debug_and_log_to_bootstrap("Step 4: Import cluster certificate and key")
        cmd = "corosync-qdevice-net-certutil -m -c {}".format(self.qdevice_p12_on_cluster)
        rc, _, err = utils.get_stdout_stderr(cmd)
        if rc != 0:
            raise ValueError(err)

    def certificate_process_on_join(self):
        """
        The qdevice certificate process on join node
        """
        self.fetch_qnetd_crt_from_cluster()
        self.init_db_on_local()
        self.fetch_p12_from_cluster()
        self.import_p12_on_local()

    def write_qdevice_config(self):
        """
        Write qdevice attributes to config file
        """
        with open(conf()) as f:
            p = Parser(f.read())

        p.remove("quorum.device")
        p.add('quorum', make_section('quorum.device', []))
        p.set('quorum.device.votes', '1')
        p.set('quorum.device.model', 'net')
        p.add('quorum.device', make_section('quorum.device.net', []))
        p.set('quorum.device.net.tls', self.tls)
        p.set('quorum.device.net.host', self.qnetd_addr)
        p.set('quorum.device.net.port', self.port)
        p.set('quorum.device.net.algorithm', self.algo)
        p.set('quorum.device.net.tie_breaker', self.tie_breaker)
        if self.cmds:
            p.add('quorum.device', make_section('quorum.device.heuristics', []))
            p.set('quorum.device.heuristics.mode', self.mode)
            for i, cmd in enumerate(self.cmds.strip(';').split(';')):
                cmd_name = re.sub("[.-]", "_", os.path.basename(cmd.split()[0]))
                exec_name = "exec_{}{}".format(cmd_name, i)
                p.set('quorum.device.heuristics.{}'.format(exec_name), cmd)

        with open(conf(), 'w') as f:
            f.write(p.to_string())
            f.flush()
            os.fsync(f)

    def remove_qdevice_config(self):
        """
        Remove configuration of qdevice
        """
        with open(conf()) as f:
            p = Parser(f.read())
            p.remove("quorum.device")
        with open(conf(), 'w') as f:
            f.write(p.to_string())
            f.flush()
            os.fsync(f)

    def remove_qdevice_db(self):
        """
        Remove qdevice database
        """
        if not os.path.exists(self.qdevice_db_path):
            return
        node_list = utils.list_cluster_nodes()
        cmd = "rm -rf {}/*".format(self.qdevice_path)
        if self.askpass:
            print("Remove database on cluster nodes")
        parallax.parallax_call(node_list, cmd, self.askpass)


class Parser(object):
    """
    Class to parse config file which syntax is similar with corosync.conf
    Parse corosync.conf by default
    """
    INDENT = 4

    def __init__(self, config_file=None):
        """
        Init function
        """
        self._config_file = config_file if config_file else conf()
        self._config_dict = {}
        self._config_list = []

    @staticmethod
    def _inner_key(path, index):
        """
        Generate inner key by combining path and index
        """
        return "{}__{}".format(path, index)

    @staticmethod
    def _matched_inner_key(path, inner_key):
        """
        Check if given path matched an inner key
        """
        # example of inner key:
        #   totem.interface.ringnumber__0
        #   quorum.two_node__0
        return re.search("{}__[0-9]+$".format(path), inner_key)

    @staticmethod
    def _matched_inner_section_end(path, inner_sec_end):
        """
        Check if given path matched an inner end section
        """
        # example of inner section end:
        #   totem.interface__0__END
        #   nodelist.node__1__END
        #   quorum__0__END
        return re.search("{}__[0-9]+__END$".format(path), inner_sec_end)

    @staticmethod
    def _inner_section_name(inner_key):
        """
        Extract inner section name from an inner key
        """
        # nodelist.node.nodeid__1 -> nodelist.node__1
        return re.sub("(.*)\.\w+(__[0-9])", "\\1\\2", inner_key)

    @staticmethod
    def _section_name(inner_key):
        """
        Extract section name from an inner key
        """
        # nodelist.node.nodeid__1 -> nodelist.node
        return re.sub("(.*)\.\w+(__[0-9])", "\\1", inner_key)

    @staticmethod
    def _key_name(inner_key):
        """
        Extract key name from an inner key
        """
        # nodelist.node.nodeid__1 -> nodelist.node.nodeid
        return re.sub("__[0-9]+", "", inner_key)

    @property
    def _inner_section_name_list(self):
        """
        Get list of inner section name
        """
        return [key for key, value in self._config_dict.items() if value == "{"]

    @property
    def _inner_section_end_list(self):
        """
        Get list of inner section end
        """
        return [key for key, value in self._config_dict.items() if value == "}"]

    def _is_inner_section(self, inner_key):
        """
        Check if an inner key is an inner section name
        """
        return inner_key in self._inner_section_name_list

    def _unused_inner_key(self, path):
        """
        Generate unused inner key
        """
        index = 0
        key = self._inner_key(path, index)
        while key in self._config_dict:
            index += 1
            key = re.sub("__[0-9]+", "__{}".format(index), key)
        return key

    def _verify_config_file(self):
        """
        """
        with open(self._config_file) as f:
            data = f.read()
            if len(re.findall("[{}]", data)) % 2 != 0:
                raise ValueError("Missing closing brace")

    def load_config_file(self):
        """
        Use tokenize.generate_tokens to generate dict self._config_dict
        """
        self._verify_config_file()

        key_prefix = ""
        key_prefix_list = []
        section_key_list = []
        prev_token_string, prev_content_line = None, None
 
        with tokenize.open(self._config_file) as f:
            tokens = tokenize.generate_tokens(f.readline)
            for token in tokens:
                token_type = token.exact_type
                if token_type in [COMMENT, NL, NEWLINE]:
                    continue

                # like: cluster_name
                token_string = token.string
                # like: cluster_name: hacluster
                content_line = token.line

                new_line = False
                if prev_content_line and prev_content_line != content_line:
                    new_line = True

                # current token is: {
                if token_type == LBRACE:
                    key_prefix_list.append(prev_token_string)
                    key_prefix = '.'.join(key_prefix_list)
                    section_key = self._unused_inner_key(key_prefix)
                    section_key_list.append(section_key)
                    self._config_dict[section_key] = "{"

                # restore prev line into dict
                if new_line and ':' in prev_content_line:
                    key, *value = prev_content_line.split(':')
                    key = "{}.{}".format(key_prefix, key.strip())
                    self._config_dict[self._unused_inner_key(key)] = ':'.join(value).strip()

                # current token is: }
                if token_type == RBRACE:
                    section_key = section_key_list.pop()
                    self._config_dict[section_key+"__END"] = "}"
                    key_prefix_list.pop()
                    key_prefix = '.'.join(key_prefix_list)

                prev_token_string = token_string
                prev_content_line = content_line

    def get(self, path, index=0):
        """
        Gets the value for the path
        path: config path
        index: known index in section
        """
        key = self._inner_key(path, index)
        if key not in self._config_dict or self._is_inner_section(key):
            return None
        return self._config_dict[key]

    def get_all(self, path):
        """
        Returns all values matching path
        """
        ret = []
        for key, value in self._config_dict.items():
            if self._matched_inner_key(path, key) and not self._is_inner_section(key):
                ret.append(value)
        return ret
        
    def count(self, path):
        """
        Returns the number of elements matching path
        """
        n = 0
        for key, value in self._config_dict.items():
            if self._matched_inner_key(path, key) and value != "}":
                n += 1
        return n

    @contextmanager
    def _operate_config_list(self):
        """
        The contextmanager for convert between config dict and list
        """
        self._config_list = list(self._config_dict.items())
        yield
        self._config_dict = dict(self._config_list)

    @staticmethod
    def _section_item(key):
        return (key, "{")

    @staticmethod
    def _section_end_item(key):
        if key.endswith("__END"):
            return (key, "}")
        return (key+"__END", "}")

    def _find_last_match(self, section_path):
        """
        When adding seciton, need to find an anchor
        Then the new section name will insert just after or before this anchor

        Example:
          section_path  |        anchor        |  after/before anchor
          ===========================================================
          quorum.device |        quorum        |  before
          nodelist      |  <last section name> |  after
          nodelist.node |     nodelist.node    |  after
        """
        after = True
        two_levels = False

        while True:
            for key in self._inner_section_end_list[::-1]:
                if self._matched_inner_section_end(section_path, key):
                    return key, after

            if two_levels:
                raise ValueError("No section {} exist".format(section_path))

            section_path = '.'.join(section_path.split('.')[:-1])
            if section_path:
                after = False
                two_levels = True
            else:
                # e.g, add new nodelist section in mcast mode
                after = True
                return self._inner_section_end_list[-1], after


    def add_section(self, section_path):
        """
        Add section
        Need to find the index where to insert
        """
        last_match, after = self._find_last_match(section_path)
        offset = 1 if after else 0

        with self._operate_config_list():
            key = self._unused_inner_key(section_path)
            index = self._config_list.index(self._section_end_item(last_match))

            self._config_list.insert(index+offset, self._section_item(key))
            self._config_list.insert(index+1+offset, self._section_end_item(key))

    def _find_and_insert(self, inner_key, value):
        """
        When set value, find the index then insert
        """
        with self._operate_config_list():
            section_name = self._inner_section_name(inner_key)
            section_end_index = self._config_list.index(self._section_end_item(section_name))
            self._config_list.insert(section_end_index, (inner_key, value))

    def set(self, path, value, index=0):
        """
        Set the value for the path
        index: known index in section
        """
        key = self._inner_key(path, index)
        # try to update exists key
        if key in self._config_dict:
            # shouldn't be a section name
            if self._is_inner_section(key):
                raise ValueError("{} is a section name".format(path))
            self._config_dict[key] = value
        # try to set a new key
        else:
            # must contain a known section name
            if not self._is_inner_section(self._inner_section_name(key)):
                raise ValueError("No section {} exist at index {}".format(self._section_name(key), index))
            self._find_and_insert(key, value)

    def remove(self, path, index=0):
        key = self._inner_key(path, index)
        del self._config_dict[key]

    def remove_section(self, section_path, index=0):
        with self._operate_config_list():
            inner_sec_name = self._inner_key(section_path, index)
            section_start_index = self._config_list.index(self._section_item(inner_sec_name))
            section_end_index = self._config_list.index(self._section_end_item(inner_sec_name))
            self._config_list = self._config_list[:section_start_index] + self._config_list[section_end_index+1:]

    def write_to_file(self):
        """
        Write back to config file
        """
        with open(self._config_file, 'w') as f:
            f.write(self.to_string())

    @staticmethod
    def _token_item(line, row, col, token_type=NAME, orig_line=''):
        """
        Generate tuple for untokenize
        Details see https://github.com/python/cpython/blob/3.9/Lib/tokenize.py
        """
        return (token_type, line, (row, col), (row, col+len(line)), orig_line)

    def to_string(self):
        """
        Use tokenize.untokenize to convert self._config_dit to string
        """
        token_list = []
        for index, (key, value) in enumerate(self._config_dict.items()):

            key = self._key_name(key)
            # section begin
            if value == "{":
                line = key.split('.')[-1] + " {"
            # section end
            elif value == "}":
                line = "}\n"
            # content line
            else:
                *_, name = key.split('.')
                line = "{}: {}".format(name, value)

            row = index + 1
            col = (len(key.split('.'))-1) * self.INDENT
            token_list.append(self._token_item(line, row, col))

        res = tokenize.untokenize(token_list)
        return res.replace('\\\n', '\n')

    @classmethod
    def get_value(cls, path, index=0):
        """
        Class method to get value
        Return None if not found
        """
        inst = cls()
        inst.load_config_file()
        return inst.get(path, index)

    @classmethod
    def get_values(cls, path):
        """
        Class method to get value list matched by path
        Return [] if not matched
        """
        inst = cls()
        inst.load_config_file()
        return inst.get_all(path)

    @classmethod
    def set_value(cls, path, value, index=0):
        """
        Class method to set value and write back to file
        """
        inst = cls()
        inst.load_config_file()
        inst.set(path, value, index)
        inst.write_to_file()


def logfile(conftext):
    '''
    Return corosync logfile (if set)
    '''
    return Parser(conftext).get('logging.logfile')


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


def get_free_nodeid(parser):
    ids = parser.get_all('nodelist.node.nodeid')
    if not ids:
        return 1
    ids = [int(i) for i in ids]
    max_id = max(ids) + 1
    for i in range(1, max_id):
        if i not in ids:
            return i
    return max_id


def get_ip(node):
    try:
        return socket.gethostbyname(node)
    except socket.error:
        return None


class IPAlreadyConfiguredError(Exception):
    pass


def find_configured_ip(ip_list):
    """
    find if the same IP already configured
    If so, raise IPAlreadyConfiguredError
    """
    with open(conf()) as f:
        p = Parser(f.read())

    # get exist ip list from corosync.conf
    corosync_iplist = []
    for path in set(Parser.get_all_paths()):
        if re.search('nodelist.node.ring[0-9]*_addr', path):
            corosync_iplist.extend(p.get_all(path))

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


def add_node_ucast(ip_list, node_id=None):

    find_configured_ip(ip_list)

    with open(conf()) as f:
        p = Parser(f.read())

    if node_id is None:
        node_id = get_free_nodeid(p)
    node_value = []
    for i, addr in enumerate(ip_list):
        node_value += make_value('nodelist.node.ring{}_addr'.format(i), addr)
    node_value += make_value('nodelist.node.nodeid', str(node_id))

    if get_values("nodelist.node.ring0_addr") == []:
        p.add('', make_section('nodelist', []))
    p.add('nodelist', make_section('nodelist.node', node_value))

    num_nodes = p.count('nodelist.node')
    p.set('quorum.two_node', '1' if num_nodes == 2 else '0')
    if p.get("quorum.device.model") == "net":
        p.set('quorum.two_node', '0')

    with open(conf(), 'w') as f:
        f.write(p.to_string())


def add_node(addr, name=None):
    '''
    Add node to corosync.conf
    '''
    coronodes = None
    nodes = None
    nodenames = None
    coronodes = utils.list_corosync_nodes()
    nodenames = utils.list_corosync_node_names()
    try:
        nodes = utils.list_cluster_nodes()
    except Exception:
        nodes = []
    ipaddr = get_ip(addr)
    if addr in nodenames + coronodes or (ipaddr and ipaddr in coronodes):
        err_buf.warning("%s already in corosync.conf" % (addr))
        return
    if name and name in nodenames + coronodes:
        err_buf.warning("%s already in corosync.conf" % (name))
        return
    if addr in nodes:
        err_buf.warning("%s already in configuration" % (addr))
        return
    if name and name in nodes:
        err_buf.warning("%s already in configuration" % (name))
        return

    f = open(conf()).read()
    p = Parser(f)

    node_addr = addr
    node_id = get_free_nodeid(p)
    node_name = name
    node_value = (make_value('nodelist.node.ring0_addr', node_addr) +
                  make_value('nodelist.node.nodeid', str(node_id)))
    if node_name:
        node_value += make_value('nodelist.node.name', node_name)

    p.add('nodelist', make_section('nodelist.node', node_value))

    num_nodes = p.count('nodelist.node')
    p.set('quorum.two_node', '1' if num_nodes == 2 else '0')
    if p.get("quorum.device.model") == "net":
        p.set('quorum.two_node', '0')

    f = open(conf(), 'w')
    f.write(p.to_string())
    f.close()

    # update running config (if any)
    if nodes:
        utils.ext_cmd(["corosync-cmapctl",
                       "-s", "nodelist.node.%s.nodeid" % (num_nodes - 1),
                       "u32", str(node_id)], shell=False)
        utils.ext_cmd(["corosync-cmapctl",
                       "-s", "nodelist.node.%s.ring0_addr" % (num_nodes - 1),
                       "str", node_addr], shell=False)
        if node_name:
            utils.ext_cmd(["corosync-cmapctl",
                           "-s", "nodelist.node.%s.name" % (num_nodes - 1),
                           "str", node_name], shell=False)


def del_node(addr):
    '''
    Remove node from corosync
    '''
    f = open(conf()).read()
    p = Parser(f)
    nth = p.remove_section_where('nodelist.node', 'ring0_addr', addr)
    if nth == -1:
        return

    num_nodes = p.count('nodelist.node')
    p.set('quorum.two_node', '1' if num_nodes == 2 else '0')
    if p.get("quorum.device.model") == "net":
        p.set('quorum.two_node', '0')

    f = open(conf(), 'w')
    f.write(p.to_string())
    f.close()


_COROSYNC_CONF_TEMPLATE_HEAD = """# Please read the corosync.conf.5 manual page

totem {
    version:    2
    secauth:    on
    crypto_hash:    sha1
    crypto_cipher:  aes256
    cluster_name:   %(clustername)s
    clear_node_high_bit: yes

    token:      5000
    token_retransmits_before_loss_const: 10
    join:       60
    consensus:  6000
    max_messages:   20
"""
_COROSYNC_CONF_TEMPLATE_TAIL = """
    %(rrp_mode)s
    %(transport)s
    %(ipv6)s
    %(ipv6_nodeid)s
}

logging {
    fileline:   off
    to_stderr:  no
    to_logfile:     no
    logfile:    /var/log/cluster/corosync.log
    to_syslog:  yes
    debug:      off
    timestamp:  on
    logger_subsys {
        subsys:     QUORUM
        debug:  off
    }
}

%(nodelist)s
%(quorum)s
"""
_COROSYNC_CONF_TEMPLATE_RING = """
    interface {
        ringnumber: %(number)d
        %(bindnetaddr)s
%(mcast)s
        ttl: 1
    }
"""


def create_configuration(clustername="hacluster",
                         bindnetaddr=None,
                         mcastaddr=None,
                         mcastport=None,
                         ringXaddr=None,
                         transport=None,
                         ipv6=False,
                         nodeid=None,
                         two_rings=False,
                         qdevice=None):

    if transport == "udpu":
        ring_tmpl = ""
        for i in 0, 1:
            ring_tmpl += "        ring{}_addr: {}\n".format(i, ringXaddr[i])
            if not two_rings:
                break

        nodelist_tmpl = """nodelist {
    node {
%(ringaddr)s
        nodeid: 1
    }
}
""" % {"ringaddr": ring_tmpl}
    else:
        nodelist_tmpl = ""

    transport_tmpl = ""
    if transport is not None:
        transport_tmpl = "transport: {}\n".format(transport)

    rrp_mode_tmp = ""
    if two_rings:
        rrp_mode_tmp = "rrp_mode:  passive"

    ipv6_tmpl = ""
    ipv6_nodeid = ""
    if ipv6:
        ipv6_tmpl = "ip_version:  ipv6"
        if transport != "udpu":
            ipv6_nodeid = "nodeid:  %d" % nodeid

    quorum_tmpl = """quorum {
    # Enable and configure quorum subsystem (default: off)
    # see also corosync.conf.5 and votequorum.5
    provider: corosync_votequorum
    expected_votes: 1
    two_node: 0
}
"""
    if qdevice is not None:
        quorum_tmpl = """quorum {
    # Enable and configure quorum subsystem (default: off)
    # see also corosync.conf.5 and votequorum.5
    provider: corosync_votequorum
    expected_votes: 1
    two_node: 0
    device {
      votes: 0
      model: net
      net {
        tls: %(tls)s
        host: %(ip)s
        port: %(port)s
        algorithm: %(algo)s
        tie_breaker: %(tie_breaker)s
      }
    }
}
""" % qdevice.__dict__

    config_common = {
        "clustername": clustername,
        "nodelist": nodelist_tmpl,
        "quorum": quorum_tmpl,
        "ipv6": ipv6_tmpl,
        "ipv6_nodeid": ipv6_nodeid,
        "rrp_mode": rrp_mode_tmp,
        "transport": transport_tmpl
    }

    _COROSYNC_CONF_TEMPLATE_RING_ALL = ""
    mcast_tmp = []
    bindnetaddr_tmp = []
    config_ring = []
    for i in 0, 1:
        mcast_tmp.append("")
        if mcastaddr is not None:
            mcast_tmp[i] += "        mcastaddr:   {}\n".format(mcastaddr[i])
        if mcastport is not None:
            mcast_tmp[i] += "        mcastport:   {}".format(mcastport[i])

        bindnetaddr_tmp.append("")
        if bindnetaddr is None:
            bindnetaddr_tmp[i] = ""
        else:
            bindnetaddr_tmp[i] = "bindnetaddr: {}".format(bindnetaddr[i])

        config_ring.append("")
        config_ring[i] = {
            "bindnetaddr": bindnetaddr_tmp[i],
            "mcast": mcast_tmp[i],
            "number": i
        }
        _COROSYNC_CONF_TEMPLATE_RING_ALL += _COROSYNC_CONF_TEMPLATE_RING % config_ring[i]

        if not two_rings:
            break

    _COROSYNC_CONF_TEMPLATE = _COROSYNC_CONF_TEMPLATE_HEAD + \
                              _COROSYNC_CONF_TEMPLATE_RING_ALL + \
                              _COROSYNC_CONF_TEMPLATE_TAIL
    utils.str2file(_COROSYNC_CONF_TEMPLATE % config_common, conf())
