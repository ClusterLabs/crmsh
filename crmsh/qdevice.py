import os
import re
import socket
import functools
import typing
from enum import Enum

import crmsh.parallax
from . import sh
from . import utils
from . import parallax
from . import corosync
from . import xmlutil
from . import bootstrap
from . import lock
from . import log
from . import sbd
from .service_manager import ServiceManager


logger = log.setup_logger(__name__)
logger_utils = log.LoggerUtils(logger)


QDEVICE_ADD = "add"
QDEVICE_REMOVE = "remove"


class QdevicePolicy(Enum):
    QDEVICE_RELOAD = 0
    QDEVICE_RESTART = 1
    QDEVICE_RESTART_LATER = 2


def evaluate_qdevice_quorum_effect(mode, diskless_sbd=False, is_stage=False):
    """
    While adding/removing qdevice, get current expected votes and actual total votes,
    to calculate after adding/removing qdevice, whether cluster has quorum
    return different policy
    """
    quorum_votes_dict = utils.get_quorum_votes_dict()
    expected_votes = int(quorum_votes_dict["Expected"])
    actual_votes = int(quorum_votes_dict["Total"])
    if mode == QDEVICE_ADD:
        expected_votes += 1
    elif mode == QDEVICE_REMOVE:
        actual_votes -= 1

    if utils.calculate_quorate_status(expected_votes, actual_votes) and not diskless_sbd:
        # safe to use reload
        return QdevicePolicy.QDEVICE_RELOAD
    elif xmlutil.CrmMonXmlParser().is_non_stonith_resource_running():
        # will lose quorum, with non-stonith resource running
        # no reload, no restart cluster service
        # just leave a warning
        return QdevicePolicy.QDEVICE_RESTART_LATER
    else:
        # will lose quorum, without resource running or just stonith resource running
        # safe to restart cluster service
        return QdevicePolicy.QDEVICE_RESTART


def qnetd_lock_for_same_cluster_name(func):
    """
    Decorator to claim lock on qnetd, to avoid the same cluster name added in qnetd
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        cluster_name = args[0].cluster_name
        lock_dir = "/run/.crmsh_qdevice_lock_for_{}".format(cluster_name)
        lock_inst = lock.RemoteLock(args[0].qnetd_addr, for_join=False, lock_dir=lock_dir, wait=False)
        try:
            with lock_inst.lock():
                func(*args, **kwargs)
        except lock.ClaimLockError:
            utils.fatal("Duplicated cluster name \"{}\"!".format(cluster_name))
        except lock.SSHError as err:
            utils.fatal(err)
    return wrapper


def qnetd_lock_for_multi_cluster(func):
    """
    Decorator to claim lock on qnetd, to avoid possible race condition
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        lock_inst = lock.RemoteLock(args[0].qnetd_addr, for_join=False, no_warn=True)
        try:
            with lock_inst.lock():
                func(*args, **kwargs)
        except (lock.SSHError, lock.ClaimLockError) as err:
            utils.fatal(err)
    return wrapper


def get_node_list(is_stage: bool) -> list[str]:
    me = utils.this_node()
    if is_stage:
        return utils.list_cluster_nodes() or [me]
    else:
        return [me]


class QDevice(object):
    """Class to manage qdevice configuration and services

    Call `certificate_process_on_init` to generate all of CA, server, and client certs.
    Call `certificate_process_on_join` to generate a single client cert for the local node.
    """

    qnetd_service = "corosync-qnetd.service"
    qnetd_cacert_filename = "qnetd-cacert.crt"
    qdevice_crq_filename = "qdevice-net-node.crq"
    qdevice_p12_filename = "qdevice-net-node.p12"
    qnetd_path = "/etc/corosync/qnetd"
    qdevice_path = "/etc/corosync/qdevice/net"
    qdevice_db_path = "/etc/corosync/qdevice/net/nssdb"

    def __init__(self, qnetd_addr, port=5403, algo="ffsplit", tie_breaker="lowest",
            tls="on", ssh_user=None, cluster_node=None, cmds=None, mode=None, cluster_name=None, is_stage=False):
        """
        Init function
        """
        self.qnetd_addr = qnetd_addr
        self.port = port
        self.algo = algo
        self.tie_breaker = tie_breaker
        self.tls = tls
        self.ssh_user = ssh_user
        self.cluster_node = cluster_node
        self.cmds = cmds
        self.mode = mode
        self.cluster_name = cluster_name
        self.qdevice_reload_policy = QdevicePolicy.QDEVICE_RESTART
        self.is_stage = is_stage

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

    @staticmethod
    def check_qnetd_addr(qnetd_addr):
        qnetd_ip = None
        try:
            # socket.getaddrinfo works for both ipv4 and ipv6 address
            # The function returns a list of 5-tuples with the following structure:
            # (family, type, proto, canonname, sockaddr)
            # sockaddr is a tuple describing a socket address, whose format depends on the returned family
            # (a (address, port) 2-tuple for AF_INET, a (address, port, flow info, scope id) 4-tuple for AF_INET6)
            res = socket.getaddrinfo(qnetd_addr, None)
            qnetd_ip = res[0][-1][0]
        except socket.error:
            raise ValueError("host \"{}\" is unreachable".format(qnetd_addr))

        utils.ssh_port_reachable_check(qnetd_addr)

        if utils.InterfacesInfo.ip_in_local(qnetd_ip):
            raise ValueError("host for qnetd must be a remote one")

    @staticmethod
    def check_qdevice_port(qdevice_port):
        if not utils.valid_port(qdevice_port):
            raise ValueError("invalid qdevice port range(1024 - 65535)")

    @staticmethod
    def check_qdevice_algo(qdevice_algo):
        if qdevice_algo not in ("ffsplit", "lms"):
            raise ValueError("invalid ALGORITHM choice: '{}' (choose from 'ffsplit', 'lms')".format(qdevice_algo))

    @staticmethod
    def check_qdevice_tie_breaker(qdevice_tie_breaker):
        if qdevice_tie_breaker not in ("lowest", "highest") and not utils.valid_nodeid(qdevice_tie_breaker):
            raise ValueError("invalid qdevice tie_breaker(lowest/highest/valid_node_id)")

    @staticmethod
    def check_qdevice_tls(qdevice_tls):
        if qdevice_tls not in ("on", "off", "required"):
            raise ValueError("invalid TLS choice: '{}' (choose from 'on', 'off', 'required')".format(qdevice_tls))

    @staticmethod
    def check_qdevice_heuristics_mode(mode):
        if not mode:
            return
        if mode not in ("on", "sync", "off"):
            raise ValueError("invalid MODE choice: '{}' (choose from 'on', 'sync', 'off')".format(mode))

    @staticmethod
    def check_qdevice_heuristics(cmds):
        if not cmds:
            return
        for cmd in cmds.strip(';').split(';'):
            if not cmd.startswith('/'):
                raise ValueError("commands for heuristics should be absolute path")
            if not os.path.exists(cmd.split()[0]):
                raise ValueError("command {} not exist".format(cmd.split()[0]))

    def check_corosync_qdevice_available(self):
        service_manager = ServiceManager()
        for node in get_node_list(self.is_stage):
            if not service_manager.service_is_available("corosync-qdevice.service", remote_addr=node):
                raise ValueError(f"corosync-qdevice.service is not available on {node}")

    def valid_qdevice_options(self):
        """
        Validate qdevice related options
        """
        if self.is_stage:
            utils.check_all_nodes_reachable("setup Qdevice")
        self.check_corosync_qdevice_available()
        self.check_qnetd_addr(self.qnetd_addr)
        self.check_qdevice_port(self.port)
        self.check_qdevice_algo(self.algo)
        self.check_qdevice_tie_breaker(self.tie_breaker)
        self.check_qdevice_tls(self.tls)
        self.check_qdevice_heuristics(self.cmds)
        self.check_qdevice_heuristics_mode(self.mode)

    def validate_and_start_qnetd(self):
        exception_msg = ""
        suggestion_msg= ""
        shell = sh.cluster_shell()
        if utils.package_is_installed("corosync-qnetd", remote_addr=self.qnetd_addr):
            self.init_tls_certs_on_qnetd()
            self.config_qnetd_port()
            self.start_qnetd()
            cmd = f"corosync-qnetd-tool -l -c {self.cluster_name}"
            if shell.get_stdout_or_raise_error(cmd, self.qnetd_addr):
                exception_msg = f"This cluster's name \"{self.cluster_name}\" already exists on qnetd server!"
                suggestion_msg = "Please consider to use the different cluster-name property"
        else:
            exception_msg = f"Package \"corosync-qnetd\" not installed on {self.qnetd_addr}!"
            suggestion_msg = f"Please install \"corosync-qnetd\" on {self.qnetd_addr}"

        if exception_msg:
            raise ValueError(f"{exception_msg}\n{suggestion_msg}")

    def enable_qnetd(self):
        ServiceManager().enable_service(self.qnetd_service, remote_addr=self.qnetd_addr)

    def disable_qnetd(self):
        ServiceManager().disable_service(self.qnetd_service, remote_addr=self.qnetd_addr)

    def start_qnetd(self):
        ServiceManager().start_service(self.qnetd_service, remote_addr=self.qnetd_addr)

    def stop_qnetd(self):
        ServiceManager().stop_service(self.qnetd_service, remote_addr=self.qnetd_addr)

    def set_cluster_name(self):
        if not self.cluster_name:
            self.cluster_name = corosync.get_value('totem.cluster_name')
        if not self.cluster_name:
            raise ValueError("No cluster_name found in {}".format(corosync.conf()))

    @qnetd_lock_for_multi_cluster
    def init_tls_certs_on_qnetd(self):
        """Initialize NSS database and generates CA and server certs on QNetd server."""
        cmd = "test -f {}".format(self.qnetd_cacert_on_qnetd)
        try:
            parallax.parallax_call([self.qnetd_addr], cmd)
            return
        except ValueError:
            # target file not exist
            pass

        logger.info('Generating QNetd CA and server certificates on %s', self.qnetd_addr)
        cmd = "corosync-qnetd-certutil -i"
        parallax.parallax_call([self.qnetd_addr], cmd)

    def fetch_qnetd_crt_from_qnetd(self, log: typing.Callable[[str, typing.Optional[str]], None]):
        """Fetch QNetd CA certificate(qnetd-cacert.crt) from QNetd server"""
        if os.path.exists(self.qnetd_cacert_on_local):
            return

        desc = "Fetch {} from {}".format(self.qnetd_cacert_filename, self.qnetd_addr)
        log(desc)
        crmsh.parallax.parallax_slurp([self.qnetd_addr], self.qdevice_path, self.qnetd_cacert_on_qnetd)

    def copy_qnetd_crt_to_cluster(self, log: typing.Callable[[str, typing.Optional[str]], None]):
        """Copy exported QNetd CA certificate (qnetd-cacert.crt) to every node"""
        if not self.is_stage:
            return
        node_list = utils.list_cluster_nodes_except_me()
        if not node_list:
            return

        desc = "Copy exported {} to {}".format(self.qnetd_cacert_filename, node_list)
        log(desc)
        self._copy_file_to_remote_hosts(
            os.path.dirname(self.qnetd_cacert_on_local),
            node_list, self.qdevice_path,
            recursive=True,
        )

    @staticmethod
    def _enclose_inet6_addr(addr: str):
        if ':' in addr:
            return f'[{addr}]'
        else:
            return addr

    @classmethod
    def _copy_file_to_remote_hosts(cls, local_file, remote_hosts: typing.Iterable[str], remote_path, recursive=False):
        crmsh.parallax.parallax_copy(remote_hosts, local_file, remote_path, recursive)

    def init_db_on_cluster(self, log: typing.Callable[[str, typing.Optional[str]], None]):
        """
        On one of cluster node initialize database by running
        /usr/sbin/corosync-qdevice-net-certutil -i -c qnetd-cacert.crt
        """
        node_list = get_node_list(self.is_stage)
        cmd = f"corosync-qdevice-net-certutil -i -c {self.qnetd_cacert_on_local}"
        desc = f"Initialize database on {node_list}"
        log(desc, cmd)
        crmsh.parallax.parallax_call(node_list, cmd)

    def create_ca_request(self, log: typing.Callable[[str, typing.Optional[str]], None]):
        """Generate certificate request:
        /usr/sbin/corosync-qdevice-net-certutil -r -n Cluster
        (Cluster name must match cluster_name key in the corosync.conf)
        """
        cmd = "corosync-qdevice-net-certutil -r -n {}".format(self.cluster_name)
        log("Generate certificate request {}".format(self.qdevice_crq_filename), cmd)
        sh.cluster_shell().get_stdout_or_raise_error(cmd)

    def copy_crq_to_qnetd(self, log: typing.Callable[[str, typing.Optional[str]], None]):
        """Copy exported CRQ to QNetd server"""
        desc = "Copy {} to {}".format(self.qdevice_crq_filename, self.qnetd_addr)
        log(desc)
        self._copy_file_to_remote_hosts(self.qdevice_crq_on_local, [self.qnetd_addr], self.qdevice_crq_on_qnetd)

    def sign_crq_on_qnetd(self, log: typing.Callable[[str, typing.Optional[str]], None]):
        """On QNetd server sign and export cluster certificate by running
        corosync-qnetd-certutil -s -c qdevice-net-node.crq -n Cluster
        """
        desc = "Sign and export cluster certificate on {}".format(self.qnetd_addr)
        cmd = "corosync-qnetd-certutil -s -c {} -n {}".\
                format(self.qdevice_crq_on_qnetd, self.cluster_name)
        log(desc, cmd)
        parallax.parallax_call([self.qnetd_addr], cmd)

    def fetch_cluster_crt_from_qnetd(self, log: typing.Callable[[str, typing.Optional[str]], None]):
        """Copy exported CRT to node where certificate request was created"""
        desc = "Fetch {} from {}".format(os.path.basename(self.qnetd_cluster_crt_on_qnetd), self.qnetd_addr)
        log(desc)
        crmsh.parallax.parallax_slurp([self.qnetd_addr], self.qdevice_path, self.qnetd_cluster_crt_on_qnetd)

    def import_cluster_crt(self, log: typing.Callable[[str, typing.Optional[str]], None]):
        """Import certificate on node where certificate request was created by
        running /usr/sbin/corosync-qdevice-net-certutil -M -c cluster-Cluster.crt
        """
        cmd = "corosync-qdevice-net-certutil -M -c {}".format(self.qnetd_cluster_crt_on_local)
        log("Import certificate file {} on local".format(os.path.basename(self.qnetd_cluster_crt_on_local)), cmd)
        sh.cluster_shell().get_stdout_or_raise_error(cmd)

    def copy_p12_to_cluster(self, log: typing.Callable[[str, typing.Optional[str]], None]):
        """Copy output qdevice-net-node.p12 to all other cluster nodes"""
        if not self.is_stage:
            return
        node_list = utils.list_cluster_nodes_except_me()
        if not node_list:
            return

        desc = "Copy {} to {}".format(self.qdevice_p12_filename, node_list)
        log(desc)
        self._copy_file_to_remote_hosts(self.qdevice_p12_on_local, node_list, self.qdevice_p12_on_local)

    def import_p12_on_cluster(self, log: typing.Callable[[str, typing.Optional[str]], None]):
        """Import cluster certificate and key on all other cluster nodes:
        /usr/sbin/corosync-qdevice-net-certutil -m -c qdevice-net-node.p12
        """
        if not self.is_stage:
            return
        node_list = utils.list_cluster_nodes_except_me()
        if not node_list:
            return

        desc = "Import {} on {}".format(self.qdevice_p12_filename, node_list)
        cmd = "corosync-qdevice-net-certutil -m -c {}".format(self.qdevice_p12_on_local)
        log(desc, cmd)
        QDevice.log_only_to_file(desc, cmd)
        parallax.parallax_call(node_list, cmd)

    def certificate_process_on_init(self):
        """
        The qdevice certificate process on init node
        """
        for i, step in enumerate([
            self.fetch_qnetd_crt_from_qnetd,
            self.copy_qnetd_crt_to_cluster,
            self.init_db_on_cluster,
            self.create_ca_request,
            self.copy_crq_to_qnetd,
            self.sign_crq_on_qnetd,
            self.fetch_cluster_crt_from_qnetd,
            self.import_cluster_crt,
            self.copy_p12_to_cluster,
            self.import_p12_on_cluster,
        ]):
            step(lambda s, cmd=None: self.log_only_to_file(f'Step {i+1}: {s}', cmd))

    def fetch_qnetd_crt_from_cluster(self):
        """
        Certificate process for join
        Step 1
        Fetch QNetd CA certificate(qnetd-cacert.crt) from init node
        """
        if os.path.exists(self.qnetd_cacert_on_cluster):
            return

        desc = "Step 1: Fetch {} from {}".format(self.qnetd_cacert_filename, self.cluster_node)
        QDevice.log_only_to_file(desc)
        crmsh.parallax.parallax_slurp([self.cluster_node], self.qdevice_path, self.qnetd_cacert_on_local)

    def init_db_on_local(self):
        """
        Certificate process for join
        Step 2
        Initialize database by running
        /usr/sbin/corosync-qdevice-net-certutil -i -c qnetd-cacert.crt
        """
        if os.path.exists(self.qdevice_db_path):
            utils.rmdir_r(self.qdevice_db_path)

        cmd = "corosync-qdevice-net-certutil -i -c {}".format(self.qnetd_cacert_on_cluster)
        QDevice.log_only_to_file("Step 2: Initialize database on local", cmd)
        sh.cluster_shell().get_stdout_or_raise_error(cmd)

    def fetch_p12_from_cluster(self):
        """
        Certificate process for join
        Step 3
        Fetch p12 key file from init node
        """
        if os.path.exists(self.qdevice_p12_on_cluster):
            return

        desc = "Step 3: Fetch {} from {}".format(self.qdevice_p12_filename, self.cluster_node)
        QDevice.log_only_to_file(desc)
        crmsh.parallax.parallax_slurp([self.cluster_node], self.qdevice_path, self.qdevice_p12_on_local)

    def import_p12_on_local(self):
        """
        Certificate process for join
        Step 4
        Import cluster certificate and key
        """
        cmd = "corosync-qdevice-net-certutil -m -c {}".format(self.qdevice_p12_on_cluster)
        QDevice.log_only_to_file("Step 4: Import cluster certificate and key", cmd)
        sh.cluster_shell().get_stdout_or_raise_error(cmd)

    def certificate_process_on_join(self):
        """
        The qdevice certificate process on join node
        """
        self.fetch_qnetd_crt_from_cluster()
        self.init_db_on_local()
        self.fetch_p12_from_cluster()
        self.import_p12_on_local()

    def write_qdevice_config(self) -> None:
        """
        Write qdevice attributes to config file
        """
        inst = corosync.ConfParser()
        qdevice_config_dict = {
                "model": "net",
                "net": {
                    "tls": self.tls,
                    "host": self.qnetd_addr,
                    "port": self.port,
                    "algorithm": self.algo,
                    "tie_breaker": self.tie_breaker
                    }
                }
        if self.algo == "ffsplit":
            # According to man corosync-qdevice, if the algorithm is lms, do not set votes
            qdevice_config_dict['votes'] = 1
        inst.set("quorum.device", qdevice_config_dict)
        if self.cmds:
            heuristics_dict = {"mode": self.mode}
            for i, cmd in enumerate(self.cmds.strip(';').split(';')):
                cmd_name = re.sub("[.-]", "_", os.path.basename(cmd.split()[0]))
                exec_name = "exec_{}{}".format(cmd_name, i)
                heuristics_dict[exec_name] = cmd
            inst.set("quorum.device.heuristics", heuristics_dict)
        inst.save()

    @staticmethod
    def remove_qdevice_config():
        """
        Remove configuration of qdevice
        """
        inst = corosync.ConfParser()
        inst.remove("quorum.device")
        inst.save()

    @staticmethod
    def remove_qdevice_db(addr_list=[], is_stage=True):
        """
        Remove qdevice database
        """
        if not os.path.exists(QDevice.qdevice_db_path):
            return

        cmd = f"rm -rf {QDevice.qdevice_path}/*"
        QDevice.log_only_to_file("Remove qdevice database", cmd)
        node_list = addr_list or get_node_list(is_stage)
        parallax.parallax_call(node_list, cmd)

    @classmethod
    def remove_certification_files_on_qnetd(cls) -> None:
        """
        Remove this cluster related .crq and .crt files on qnetd
        """
        if not corosync.is_qdevice_configured():
            return
        qnetd_host = corosync.get_value('quorum.device.net.host')
        cluster_name = corosync.get_value('totem.cluster_name')
        cls_inst = cls(qnetd_host, cluster_name=cluster_name)
        shell = sh.cluster_shell()
        cmd = "test -f {crt_file} && rm -f {crt_file}".format(crt_file=cls_inst.qnetd_cluster_crt_on_qnetd)
        shell.get_stdout_or_raise_error(cmd, qnetd_host)
        cmd = "test -f {crq_file} && rm -f {crq_file}".format(crq_file=cls_inst.qdevice_crq_on_qnetd)
        shell.get_stdout_or_raise_error(cmd, qnetd_host)

    def config_qnetd_port(self):
        """
        Enable qnetd port in firewalld
        """
        if not ServiceManager().service_is_active("firewalld.service", self.qnetd_addr):
            return
        if utils.check_port_open(self.qnetd_addr, self.port):
            return
        shell = sh.cluster_shell()
        cmd = f"firewall-cmd --add-port={self.port}/tcp --permanent"
        rc, out, err = shell.get_rc_stdout_stderr_without_input(self.qnetd_addr, cmd)
        if rc != 0 and err:
            logger.error("Failed to add port {} to firewalld on {}: {}".format(self.port, self.qnetd_addr, err))
            return
        logger.info("Add port {} to firewalld on {}".format(self.port, self.qnetd_addr))
        shell.get_stdout_or_raise_error("firewall-cmd --reload", self.qnetd_addr)

    def start_qdevice_service(self):
        """
        Start qdevice and qnetd service
        """
        using_diskless_sbd = sbd.SBDUtils.is_using_diskless_sbd()
        self.qdevice_reload_policy = evaluate_qdevice_quorum_effect(QDEVICE_ADD, using_diskless_sbd, self.is_stage)
        logger.info("Enable corosync-qdevice.service in cluster")
        utils.cluster_run_cmd("systemctl enable corosync-qdevice")
        if self.qdevice_reload_policy == QdevicePolicy.QDEVICE_RELOAD:
            sh.cluster_shell().get_stdout_or_raise_error("corosync-cfgtool -R")
            logger.info("Starting corosync-qdevice.service in cluster")
            utils.cluster_run_cmd("systemctl restart corosync-qdevice")
        elif self.qdevice_reload_policy == QdevicePolicy.QDEVICE_RESTART:
            bootstrap.restart_cluster()
        else: # QdevicePolicy.QDEVICE_RESTART_LATER
            logger.warning("To use qdevice service, need to restart cluster service manually on each node")

        logger.info("Enable corosync-qnetd.service on {}".format(self.qnetd_addr))
        self.enable_qnetd()
        logger.info("Starting corosync-qnetd.service on {}".format(self.qnetd_addr))
        self.start_qnetd()

    def adjust_sbd_watchdog_timeout_with_qdevice(self):
        """
        Adjust SBD_WATCHDOG_TIMEOUT when configuring qdevice and diskless SBD
        """
        sbd_service_enabled = ServiceManager().service_is_enabled("sbd.service")
        sbd_device = sbd.SBDUtils.get_sbd_device_from_config()
        if sbd_service_enabled and not sbd_device: # configured diskless SBD
            res = sbd.SBDUtils.get_sbd_value_from_config("SBD_WATCHDOG_TIMEOUT")
            if not res or int(res) < sbd.SBDTimeout.SBD_WATCHDOG_TIMEOUT_DEFAULT_WITH_QDEVICE:
                sbd_watchdog_timeout_qdevice = sbd.SBDTimeout.SBD_WATCHDOG_TIMEOUT_DEFAULT_WITH_QDEVICE
                sbd.SBDManager.update_sbd_configuration({"SBD_WATCHDOG_TIMEOUT": str(sbd_watchdog_timeout_qdevice)})
                if self.is_stage:
                    utils.set_property("stonith-watchdog-timeout", 2*sbd_watchdog_timeout_qdevice)

    @qnetd_lock_for_same_cluster_name
    def certificate_and_config_qdevice(self):
        QDevice.remove_qdevice_db(is_stage=self.is_stage)

        if self.tls == "on" or self.tls == 'required':
            with logger_utils.status_long("Qdevice certification process"):
                self.certificate_process_on_init()

        self.adjust_sbd_watchdog_timeout_with_qdevice()
        self.write_qdevice_config()
        if self.is_stage:
            with logger_utils.status_long("Updating and syncing qdevice configuration"):
                corosync.configure_two_node(qdevice_adding=True)
                bootstrap.sync_path(corosync.conf())

    @staticmethod
    def check_qdevice_vote():
        """
        Check if qdevice can contribute vote
        """
        out = sh.cluster_shell().get_stdout_or_raise_error("corosync-quorumtool -s", success_exit_status={0, 2})
        res = re.search(r'\s+0\s+0\s+Qdevice', out)
        if res:
            qnetd_host = corosync.get_value('quorum.device.net.host')
            logger.warning("Qdevice's vote is 0, which simply means Qdevice can't talk to Qnetd({}) for various reasons.".format(qnetd_host))

    @staticmethod
    def log_only_to_file(desc, cmd=None):
        logger_utils.log_only_to_file(desc)
        if cmd:
            logger_utils.log_only_to_file(f"Run: {cmd}")
