import os
import re
import socket
from . import utils
from . import parallax
from . import corosync
from . import log


logger = log.setup_logger(__name__)
logger_utils = log.LoggerUtils(logger)


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
            tls="on", cluster_node=None, cmds=None, mode=None, cluster_name=None):
        """
        Init function
        """
        self.qnetd_addr = qnetd_addr
        self.port = port
        self.algo = algo
        self.tie_breaker = tie_breaker
        self.tls = tls
        self.cluster_node = cluster_node
        self.cmds = cmds
        self.mode = mode
        self.cluster_name = cluster_name

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
        return "{}/nssdb/{}.{}".format(self.qnetd_path, self.qdevice_crq_filename, self.cluster_name)
    
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

    def valid_qdevice_options(self):
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

        if self.algo not in ("ffsplit", "lms"):
            raise ValueError("invalid ALGORITHM choice: '{}' (choose from 'ffsplit', 'lms')".format(self.algo))

        if self.tie_breaker not in ("lowest", "highest") and not utils.valid_nodeid(self.tie_breaker):
            raise ValueError("invalid qdevice tie_breaker(lowest/highest/valid_node_id)")

        if self.tls not in ("on", "off", "required"):
            raise ValueError("invalid TLS choice: '{}' (choose from 'on', 'off', 'required')".format(self.tls))

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

        if not self.cluster_name:
            self.cluster_name = corosync.get_value('totem.cluster_name')
        if not self.cluster_name:
            raise ValueError("No cluster_name found in {}".format(corosync.conf()))

    def enable_qnetd(self):
        utils.enable_service(self.qnetd_service, remote_addr=self.qnetd_addr)

    def disable_qnetd(self):
        utils.disable_service(self.qnetd_service, remote_addr=self.qnetd_addr)

    def start_qnetd(self):
        utils.start_service(self.qnetd_service, remote_addr=self.qnetd_addr)

    def stop_qnetd(self):
        utils.stop_service(self.qnetd_service, remote_addr=self.qnetd_addr)

    def init_db_on_qnetd(self):
        """
        Certificate process for init
        Step 1
        Initialize database on QNetd server by running corosync-qnetd-certutil -i
        """
        cmd = "test -f {}".format(self.qnetd_cacert_on_qnetd)
        try:
            parallax.parallax_call([self.qnetd_addr], cmd)
        except ValueError:
            # target file not exist
            pass
        else:
            return

        cmd = "corosync-qnetd-certutil -i"
        desc = "Step 1: Initialize database on {}".format(self.qnetd_addr)
        logger_utils.log_only_to_file(desc)
        parallax.parallax_call([self.qnetd_addr], cmd)

    def fetch_qnetd_crt_from_qnetd(self):
        """
        Certificate process for init
        Step 2
        Fetch QNetd CA certificate(qnetd-cacert.crt) from QNetd server
        """
        if os.path.exists(self.qnetd_cacert_on_local):
            return

        desc = "Step 2: Fetch {} from {}".format(self.qnetd_cacert_filename, self.qnetd_addr)
        logger_utils.log_only_to_file(desc)
        parallax.parallax_slurp([self.qnetd_addr], self.qdevice_path, self.qnetd_cacert_on_qnetd)

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
        logger_utils.log_only_to_file(desc)
        parallax.parallax_copy(
                node_list,
                os.path.dirname(self.qnetd_cacert_on_local),
                self.qdevice_path)

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
        logger_utils.log_only_to_file(desc)
        parallax.parallax_call(node_list, cmd)

    def create_ca_request(self):
        """
        Certificate process for init
        Step 5
        Generate certificate request:
        /usr/sbin/corosync-qdevice-net-certutil -r -n Cluster
        (Cluster name must match cluster_name key in the corosync.conf)
        """
        logger_utils.log_only_to_file("Step 5: Generate certificate request {}".format(self.qdevice_crq_filename))
        cmd = "corosync-qdevice-net-certutil -r -n {}".format(self.cluster_name)
        utils.get_stdout_or_raise_error(cmd)

    def copy_crq_to_qnetd(self):
        """
        Certificate process for init
        Step 6
        Copy exported CRQ to QNetd server
        """
        desc = "Step 6: Copy {} to {}".format(self.qdevice_crq_filename, self.qnetd_addr)
        logger_utils.log_only_to_file(desc)
        parallax.parallax_copy(
                [self.qnetd_addr],
                self.qdevice_crq_on_local,
                self.qdevice_crq_on_qnetd)

    def sign_crq_on_qnetd(self):
        """
        Certificate process for init
        Step 7
        On QNetd server sign and export cluster certificate by running
        corosync-qnetd-certutil -s -c qdevice-net-node.crq -n Cluster
        """
        desc = "Step 7: Sign and export cluster certificate on {}".format(self.qnetd_addr)
        logger_utils.log_only_to_file(desc)
        cmd = "corosync-qnetd-certutil -s -c {} -n {}".\
                format(self.qdevice_crq_on_qnetd, self.cluster_name)
        parallax.parallax_call([self.qnetd_addr], cmd)

    def fetch_cluster_crt_from_qnetd(self):
        """
        Certificate process for init
        Step 8
        Copy exported CRT to node where certificate request was created
        """
        desc = "Step 8: Fetch {} from {}".format(os.path.basename(self.qnetd_cluster_crt_on_qnetd), self.qnetd_addr)
        logger_utils.log_only_to_file(desc)
        parallax.parallax_slurp(
                [self.qnetd_addr],
                self.qdevice_path,
                self.qnetd_cluster_crt_on_qnetd)

    def import_cluster_crt(self):
        """
        Certificate process for init
        Step 9
        Import certificate on node where certificate request was created by
        running /usr/sbin/corosync-qdevice-net-certutil -M -c cluster-Cluster.crt
        """
        logger_utils.log_only_to_file("Step 9: Import certificate file {} on local".format(os.path.basename(self.qnetd_cluster_crt_on_local)))
        cmd = "corosync-qdevice-net-certutil -M -c {}".format(self.qnetd_cluster_crt_on_local)
        utils.get_stdout_or_raise_error(cmd)

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
        logger_utils.log_only_to_file(desc)
        parallax.parallax_copy(
                node_list,
                self.qdevice_p12_on_local,
                os.path.dirname(self.qdevice_p12_on_local))

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
        logger_utils.log_only_to_file(desc)
        cmd = "corosync-qdevice-net-certutil -m -c {}".format(self.qdevice_p12_on_local)
        parallax.parallax_call(node_list, cmd)

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
        logger_utils.log_only_to_file(desc)
        parallax.parallax_slurp(
                [self.cluster_node],
                self.qdevice_path,
                self.qnetd_cacert_on_local)

    def init_db_on_local(self):
        """
        Certificate process for join
        Step 2
        Initialize database by running
        /usr/sbin/corosync-qdevice-net-certutil -i -c qnetd-cacert.crt
        """
        if os.path.exists(self.qdevice_db_path):
            utils.rmdir_r(self.qdevice_db_path)

        logger_utils.log_only_to_file("Step 2: Initialize database on local")
        cmd = "corosync-qdevice-net-certutil -i -c {}".format(self.qnetd_cacert_on_cluster)
        utils.get_stdout_or_raise_error(cmd)

    def fetch_p12_from_cluster(self):
        """
        Certificate process for join
        Step 3
        Fetch p12 key file from init node
        """
        if os.path.exists(self.qdevice_p12_on_cluster):
            return

        desc = "Step 3: Fetch {} from {}".format(self.qdevice_p12_filename, self.cluster_node)
        logger_utils.log_only_to_file(desc)
        parallax.parallax_slurp(
                [self.cluster_node],
                self.qdevice_path,
                self.qdevice_p12_on_local)

    def import_p12_on_local(self):
        """
        Certificate process for join
        Step 4
        Import cluster certificate and key
        """
        logger_utils.log_only_to_file("Step 4: Import cluster certificate and key")
        cmd = "corosync-qdevice-net-certutil -m -c {}".format(self.qdevice_p12_on_cluster)
        utils.get_stdout_or_raise_error(cmd)

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
        with open(corosync.conf()) as f:
            p = corosync.Parser(f.read())

        p.remove("quorum.device")
        p.add('quorum', corosync.make_section('quorum.device', []))
        p.set('quorum.device.votes', '1')
        p.set('quorum.device.model', 'net')
        p.add('quorum.device', corosync.make_section('quorum.device.net', []))
        p.set('quorum.device.net.tls', self.tls)
        p.set('quorum.device.net.host', self.qnetd_addr)
        p.set('quorum.device.net.port', self.port)
        p.set('quorum.device.net.algorithm', self.algo)
        p.set('quorum.device.net.tie_breaker', self.tie_breaker)
        if self.cmds:
            p.add('quorum.device', corosync.make_section('quorum.device.heuristics', []))
            p.set('quorum.device.heuristics.mode', self.mode)
            for i, cmd in enumerate(self.cmds.strip(';').split(';')):
                cmd_name = re.sub("[.-]", "_", os.path.basename(cmd.split()[0]))
                exec_name = "exec_{}{}".format(cmd_name, i)
                p.set('quorum.device.heuristics.{}'.format(exec_name), cmd)
        utils.str2file(p.to_string(), corosync.conf())

    def remove_qdevice_config(self):
        """
        Remove configuration of qdevice
        """
        with open(corosync.conf()) as f:
            p = corosync.Parser(f.read())
            p.remove("quorum.device")
        utils.str2file(p.to_string(), corosync.conf())

    def remove_qdevice_db(self):
        """
        Remove qdevice database
        """
        if not os.path.exists(self.qdevice_db_path):
            return
        node_list = utils.list_cluster_nodes()
        cmd = "rm -rf {}/*".format(self.qdevice_path)
        parallax.parallax_call(node_list, cmd)

    def remove_certification_files_on_qnetd(self):
        """
        Remove this cluster related .crq and .crt files on qnetd
        """
        cmd = "test -f {crt_file} && rm -f {crt_file}".format(crt_file=self.qnetd_cluster_crt_on_qnetd)
        utils.get_stdout_or_raise_error(cmd, remote=self.qnetd_addr)
        cmd = "test -f {crq_file} && rm -f {crq_file}".format(crq_file=self.qdevice_crq_on_qnetd)
        utils.get_stdout_or_raise_error(cmd, remote=self.qnetd_addr)
