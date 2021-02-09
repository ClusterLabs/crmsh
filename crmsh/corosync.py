# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.
'''
Functions that abstract creating and editing the corosync.conf
configuration file, and also the corosync-* utilities.
'''

import os
import re
import socket
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


_tCOMMENT = 0
_tBEGIN = 1
_tEND = 2
_tVALUE = 3


class Token(object):
    def __init__(self, token, path, key=None, value=None):
        self.token = token
        self.path = '.'.join(path)
        self.key = key
        self.value = value

    def __repr__(self):
        if self.token == _tCOMMENT:
            return self.key
        elif self.token == _tBEGIN:
            return "%s {" % (self.key)
        elif self.token == _tEND:
            return '}'
        return '%s: %s' % (self.key, self.value)


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


def corosync_tokenizer(stream):
    """Parses the corosync config file into a token stream"""
    section_re = re.compile(r'(\w+)\s*{')
    value_re = re.compile(r'(\w+):\s*([\S ]+)')
    path = []
    while stream:
        stream = stream.lstrip()
        if not stream:
            break
        if stream[0] == '#':
            end = stream.find('\n')
            t = Token(_tCOMMENT, [], stream[:end])
            stream = stream[end:]
            yield t
            continue
        if stream[0] == '}':
            t = Token(_tEND, [])
            stream = stream[1:]
            yield t
            path = path[:-1]
            continue
        m = section_re.match(stream)
        if m:
            path.append(m.group(1))
            t = Token(_tBEGIN, path, m.group(1))
            stream = stream[m.end():]
            yield t
            continue
        m = value_re.match(stream)
        if m:
            t = Token(_tVALUE, path + [m.group(1)], m.group(1), m.group(2))
            stream = stream[m.end():]
            yield t
            continue
        raise ValueError("Parse error at [..%s..]" % (stream[:16]))


def make_section(path, contents=None):
    "Create a token sequence representing a section"
    if not contents:
        contents = []
    sp = path.split('.')
    name = sp[-1]
    for t in contents:
        if t.path and not t.path.startswith(path):
            raise ValueError("%s (%s) not in path %s" % (t.path, t.key, path))
    return [Token(_tBEGIN, sp, name)] + contents + [Token(_tEND, [])]


def make_value(path, value):
    "Create a token sequence representing a value"
    sp = path.split('.')
    name = sp[-1]
    return [Token(_tVALUE, sp, name, value)]


class Parser(object):
    def __init__(self, data):
        self._tokens = list(corosync_tokenizer(data))

    def find(self, name, start=0):
        """Gets the index of the element with the given path"""
        for i, t in enumerate(self._tokens[start:]):
            if t.path == name:
                return i + start
        return -1

    def find_bounds(self, name, start=0):
        """find the (start, end) of the next instance of name found at start"""
        i = self.find(name, start)
        if i < 0:
            return -1, -1
        if self._tokens[i].token != _tBEGIN:
            return i, i
        e = i + 1
        depth = 0
        while e < len(self._tokens):
            t = self._tokens[e]
            if t.token == _tBEGIN:
                depth += 1
            if t.token == _tEND:
                depth -= 1
            if depth < 0:
                break
            e += 1
        if e == len(self._tokens):
            raise ValueError("Unclosed section")
        return i, e

    def get(self, path):
        """Gets the value for the key (if any)"""
        for t in self._tokens:
            if t.token == _tVALUE and t.path == path:
                return t.value
        return None

    def get_all(self, path):
        """Returns all values matching path"""
        ret = []
        for t in self._tokens:
            if t.token == _tVALUE and t.path == path:
                ret.append(t.value)
        return ret

    def all_paths(self):
        """Returns all value paths"""
        ret = []
        for t in self._tokens:
            if t.token == _tVALUE:
                ret.append(t.path)
        return ret

    def count(self, path):
        """Returns the number of elements matching path"""
        n = 0
        for t in self._tokens:
            if t.path == path:
                n += 1
        return n

    def remove(self, path):
        """Removes the given section or value"""
        i, e = self.find_bounds(path)
        if i < 0:
            return
        self._tokens = self._tokens[:i] + self._tokens[(e+1):]

    def remove_section_where(self, path, key, value):
        """
        Remove section which contains key: value
        Used to remove node definitions
        """
        nth = -1
        start = 0
        keypath = '.'.join([path, key])
        while True:
            nth += 1
            i, e = self.find_bounds(path, start)
            start = e + 1
            if i < 0:
                break
            k = self.find(keypath, i)
            if k < 0 or k > e:
                continue
            vt = self._tokens[k]
            if vt.token == _tVALUE and vt.value == value:
                self._tokens = self._tokens[:i] + self._tokens[(e+1):]
                return nth
        return -1

    def add(self, path, tokens):
        """Adds tokens to a section"""
        common_debug("corosync.add (%s) (%s)" % (path, tokens))
        if not path:
            self._tokens += tokens
            return
        start = self.find(path)
        if start < 0:
            return None
        depth = 0
        end = None
        for i, t in enumerate(self._tokens[start + 1:]):
            if t.token == _tBEGIN:
                depth += 1
            elif t.token == _tEND:
                depth -= 1
            if depth < 0:
                end = start + i + 1
                break
        if end is None:
            raise ValueError("Unterminated section at %s" % (start))
        self._tokens = self._tokens[:end] + tokens + self._tokens[end:]

    def set(self, path, value):
        """Sets a key: value entry. sections are given
        via dot-notation."""
        i = self.find(path)
        if i < 0:
            spath = path.split('.')
            return self.add('.'.join(spath[:-1]),
                            make_value(path, value))
        if self._tokens[i].token != _tVALUE:
            raise ValueError("%s is not a value" % (path))
        self._tokens[i].value = value

    def to_string(self):
        '''
        Serialize tokens into the corosync.conf
        file format
        '''
        def joiner(tstream):
            indent = 0
            last = None
            while tstream:
                t = tstream[0]
                if indent and t.token == _tEND:
                    indent -= 1
                s = ''
                if t.token == _tCOMMENT and (last and last.token != _tCOMMENT):
                    s += '\n'
                s += ('\t'*indent) + str(t) + '\n'
                if t.token == _tEND:
                    s += '\n'
                yield s
                if t.token == _tBEGIN:
                    indent += 1
                last = t
                tstream = tstream[1:]
        return ''.join(joiner(self._tokens))


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


def get_all_paths():
    f = open(conf()).read()
    p = Parser(f)
    return p.all_paths()


def get_value(path):
    f = open(conf()).read()
    p = Parser(f)
    return p.get(path)


def get_values(path):
    f = open(conf()).read()
    p = Parser(f)
    return p.get_all(path)


def set_value(path, value):
    f = open(conf()).read()
    p = Parser(f)
    p.set(path, value)
    f = open(conf(), 'w')
    f.write(p.to_string())
    f.close()


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
    for path in set(p.all_paths()):
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
