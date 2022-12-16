# Copyright (C) 2016 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.
#
# Bootstrap:
#
# Supersedes and replaces both the init/add/remove cluster scripts,
# and the ha-cluster-bootstrap scripts.
#
# Implemented as a straight-forward set of python functions for
# simplicity and flexibility.
#
# TODO: Make csync2 usage optional
# TODO: Configuration file for bootstrap?

import os
import sys
import random
import re
import time
import readline
import shutil
import yaml
import socket
from string import Template
from lxml import etree
from pathlib import Path
from contextlib import contextmanager
from . import config
from . import upgradeutil
from . import utils
from . import xmlutil
from .cibconfig import mkset_obj, cib_factory
from . import corosync
from . import tmpfiles
from . import lock
from . import userdir
from .constants import SSH_OPTION, QDEVICE_HELP_INFO, STONITH_TIMEOUT_DEFAULT,\
        REJOIN_COUNT, REJOIN_INTERVAL, PCMK_DELAY_MAX, CSYNC2_SERVICE, WAIT_TIMEOUT_MS_DEFAULT
from . import ocfs2
from . import qdevice
from . import parallax
from . import log
from .ui_node import NodeMgmt

logger = log.setup_logger(__name__)
logger_utils = log.LoggerUtils(logger)


CSYNC2_KEY = "/etc/csync2/key_hagroup"
CSYNC2_CFG = "/etc/csync2/csync2.cfg"
COROSYNC_AUTH = "/etc/corosync/authkey"
CRM_CFG = "/etc/crm/crm.conf"
PROFILES_FILE = "/etc/crm/profiles.yml"
SYSCONFIG_SBD = "/etc/sysconfig/sbd"
SYSCONFIG_PCMK = "/etc/sysconfig/pacemaker"
SYSCONFIG_NFS = "/etc/sysconfig/nfs"
SYSCONFIG_FW = "/etc/sysconfig/SuSEfirewall2"
SYSCONFIG_FW_CLUSTER = "/etc/sysconfig/SuSEfirewall2.d/services/cluster"
PCMK_REMOTE_AUTH = "/etc/pacemaker/authkey"
COROSYNC_CONF_ORIG = tmpfiles.create()[1]
SERVICES_STOP_LIST = ["corosync-qdevice.service", "corosync.service", "hawk.service", CSYNC2_SERVICE]
USER_LIST = ["root", "hacluster"]
WATCHDOG_CFG = "/etc/modules-load.d/watchdog.conf"
BOOTH_DIR = "/etc/booth"
BOOTH_CFG = "/etc/booth/booth.conf"
BOOTH_AUTH = "/etc/booth/authkey"
SBD_SYSTEMD_DELAY_START_DIR = "/etc/systemd/system/sbd.service.d"
FILES_TO_SYNC = (BOOTH_DIR, corosync.conf(), COROSYNC_AUTH, CSYNC2_CFG, CSYNC2_KEY, "/etc/ctdb/nodes",
        "/etc/drbd.conf", "/etc/drbd.d", "/etc/ha.d/ldirectord.cf", "/etc/lvm/lvm.conf", "/etc/multipath.conf",
        "/etc/samba/smb.conf", SYSCONFIG_NFS, SYSCONFIG_PCMK, SYSCONFIG_SBD, PCMK_REMOTE_AUTH, WATCHDOG_CFG,
        PROFILES_FILE, CRM_CFG, SBD_SYSTEMD_DELAY_START_DIR)
INIT_STAGES = ("ssh", "ssh_remote", "csync2", "csync2_remote", "corosync", "remote_auth", "sbd", "cluster", "ocfs2", "admin", "qdevice")


class Context(object):
    """
    Context object used to avoid having to pass these variables
    to every bootstrap method.
    """
    DEFAULT_PROFILE_NAME = "default"
    S390_PROFILE_NAME = "s390"

    def __init__(self):
        '''
        Initialize attributes
        '''
        self.type = None # init or join
        self.quiet = None
        self.yes_to_all = None
        self.cluster_name = None
        self.watchdog = None
        self.no_overwrite_sshkey = None
        self.nic_list = []
        self.node_list = []
        self.node_list_in_cluster = []
        self.unicast = None
        self.multicast = None
        self.admin_ip = None
        self.second_heartbeat = None
        self.ipv6 = None
        self.qdevice_inst = None
        self.qnetd_addr = None
        self.qdevice_port = None
        self.qdevice_algo = None
        self.qdevice_tie_breaker = None
        self.qdevice_tls = None
        self.qdevice_heuristics = None
        self.qdevice_heuristics_mode = None
        self.qdevice_rm_flag = None
        self.ocfs2_devices = []
        self.use_cluster_lvm2 = None
        self.mount_point = None
        self.cluster_node = None
        self.cluster_node_ip = None
        self.force = None
        self.arbitrator = None
        self.clusters = None
        self.tickets = None
        self.sbd_manager = None
        self.sbd_devices = []
        self.diskless_sbd = None
        self.stage = None
        self.args = None
        self.ui_context = None
        self.interfaces_inst = None
        self.with_other_user = True
        self.cluster_is_running = None
        self.cloud_type = None
        self.is_s390 = False
        self.profiles_data = None
        self.skip_csync2 = None
        self.profiles_dict = {}
        self.default_nic_list = []
        self.default_ip_list = []
        self.local_ip_list = []
        self.local_network_list = []
        self.rm_list = [SYSCONFIG_SBD, CSYNC2_CFG, corosync.conf(), CSYNC2_KEY,
                COROSYNC_AUTH, "/var/lib/heartbeat/crm/*", "/var/lib/pacemaker/cib/*",
                "/var/lib/corosync/*", "/var/lib/pacemaker/pengine/*", PCMK_REMOTE_AUTH,
                "/var/lib/csync2/*"]

    @classmethod
    def set_context(cls, options):
        ctx = cls()
        for opt in vars(options):
            setattr(ctx, opt, getattr(options, opt))
        return ctx

    def initialize_qdevice(self):
        """
        Initialize qdevice instance
        """
        if not self.qnetd_addr:
            return
        self.qdevice_inst = qdevice.QDevice(
                self.qnetd_addr,
                port=self.qdevice_port,
                algo=self.qdevice_algo,
                tie_breaker=self.qdevice_tie_breaker,
                tls=self.qdevice_tls,
                cmds=self.qdevice_heuristics,
                mode=self.qdevice_heuristics_mode,
                is_stage=self.stage == "qdevice")

    def _validate_sbd_option(self):
        """
        Validate sbd options
        """
        if self.sbd_devices and self.diskless_sbd:
            utils.fatal("Can't use -s and -S options together")
        if self.stage == "sbd":
            if not self.sbd_devices and not self.diskless_sbd and self.yes_to_all:
                utils.fatal("Stage sbd should specify sbd device by -s or diskless sbd by -S option")
            if utils.service_is_active("sbd.service"):
                utils.fatal("Cannot configure stage sbd: sbd.service already running!")
            if self.cluster_is_running:
                utils.check_all_nodes_reachable()

    def _validate_nodes_option(self):
        """
        Validate -N/--nodes option
        """
        if not self.node_list:
            return
        self.node_list = utils.parse_append_action_argument(self.node_list)
        me = utils.this_node()
        if me in self.node_list:
            self.node_list.remove(me)
        if self.node_list and self.stage:
            utils.fatal("Can't use -N/--nodes option and stage({}) together".format(self.stage))
        if utils.has_dup_value(self.node_list):
            utils.fatal("Duplicated input for -N/--nodes option")
        for node in self.node_list:
            utils.ping_node(node)

    def _validate_cluster_node(self):
        """
        Validate cluster_node on join side
        """
        if self.cluster_node and self.type == 'join':
            try:
                # self.cluster_node might be hostname or IP address
                ip_addr = socket.gethostbyname(self.cluster_node)
                if utils.InterfacesInfo.ip_in_local(ip_addr):
                    utils.fatal("Please specify peer node's hostname or IP address")
            except socket.gaierror as err:
                utils.fatal("\"{}\": {}".format(self.cluster_node, err))

    def validate_option(self):
        """
        Validate options
        """
        if self.admin_ip:
            Validation.valid_admin_ip(self.admin_ip)
        if self.qdevice_inst:
            self.qdevice_inst.valid_qdevice_options()
        if self.nic_list:
            if len(self.nic_list) > 2:
                utils.fatal("Maximum number of interface is 2")
            if utils.has_dup_value(self.nic_list):
                utils.fatal("Duplicated input for -i/--interface option")
        if self.no_overwrite_sshkey:
            logger.warning("--no-overwrite-sshkey option is deprecated since crmsh does not overwrite ssh keys by default anymore and will be removed in future versions")
        if self.type == "join" and self.watchdog:
            logger.warning("-w option is deprecated and will be removed in future versions")
        if self.ocfs2_devices or self.stage == "ocfs2":
            ocfs2.OCFS2Manager.verify_ocfs2(self)
        if not self.skip_csync2 and self.type == "init":
            self.skip_csync2 = utils.get_boolean(os.getenv("SKIP_CSYNC2_SYNC"))
        if self.skip_csync2 and self.stage:
            utils.fatal("-x option or SKIP_CSYNC2_SYNC can't be used with any stage")
        self._validate_cluster_node()
        self._validate_nodes_option()
        self._validate_sbd_option()

    def init_sbd_manager(self):
        from .sbd import SBDManager
        self.sbd_manager = SBDManager(self)

    def detect_platform(self):
        """
        Detect platform
        Return profile type for different platform
        """
        profile_type = None

        self.is_s390 = "390" in os.uname().machine
        if self.is_s390:
            profile_type = self.S390_PROFILE_NAME
        else:
            self.cloud_type = utils.detect_cloud()
            if self.cloud_type:
                profile_type = self.cloud_type

        if profile_type:
            logger.info("Detected \"{}\" platform".format(profile_type))
        return profile_type

    def load_specific_profile(self, profile_type):
        """
        Load specific profile
        """
        profile_dict = {}
        if not profile_type:
            return profile_dict

        if profile_type in self.profiles_data:
            logger.info("Loading \"{}\" profile from {}".format(profile_type, PROFILES_FILE))
            profile_dict = self.profiles_data[profile_type]
        else:
            logger.info("\"{}\" profile does not exist in {}".format(profile_type, PROFILES_FILE))
        return profile_dict

    def load_profiles(self):
        """
        Load profiles data for different environment
        """
        profile_type = self.detect_platform()

        if not os.path.exists(PROFILES_FILE):
            return
        with open(PROFILES_FILE) as f:
            self.profiles_data = yaml.load(f, Loader=yaml.SafeLoader)
        # empty file
        if not self.profiles_data:
            return

        default_profile_dict = self.load_specific_profile(self.DEFAULT_PROFILE_NAME)
        specific_profile_dict = self.load_specific_profile(profile_type)
        # merge two dictionaries
        self.profiles_dict = {**default_profile_dict, **specific_profile_dict}


_context = None


def drop_last_history():
    hlen = readline.get_current_history_length()
    if hlen > 0:
        readline.remove_history_item(hlen - 1)


def prompt_for_string(msg, match=None, default='', valid_func=None, prev_value=[], allow_empty=False):
    if _context.yes_to_all:
        return default

    while True:
        disable_completion()
        val = logger_utils.wait_input("{} [{}]".format(msg, default), default)
        enable_completion()
        if val:
            drop_last_history()
        elif allow_empty:
            return None
        else:
            continue
        if not match and not valid_func:
            return val
        if match and not re.match(match, val):
            logger.error("Invalid value entered")
            continue
        if valid_func:
            try:
                if prev_value:
                    valid_func(val, prev_value)
                else:
                    valid_func(val)
            except ValueError as err:
                logger.error(err)
                continue

        return val


def confirm(msg):
    if _context.yes_to_all:
        return True
    disable_completion()
    rc = logger_utils.confirm(msg)
    enable_completion()
    drop_last_history()
    return rc


def disable_completion():
    if _context.ui_context:
        _context.ui_context.disable_completion()


def enable_completion():
    if _context.ui_context:
        _context.ui_context.setup_readline()


def invoke(*args):
    """
    Log command execution to log file.
    Log output from command to log file.
    Return (boolean, stdout, stderr)
    """
    logger_utils.log_only_to_file("invoke: " + " ".join(args))
    rc, stdout, stderr = utils.get_stdout_stderr(" ".join(args))
    if stdout:
        logger_utils.log_only_to_file("stdout: {}".format(stdout))
    if stderr:
        logger_utils.log_only_to_file("stderr: {}".format(stderr))
    return rc == 0, stdout, stderr


def invokerc(*args):
    """
    Calling invoke, return True/False
    """
    rc, _, _ = invoke(*args)
    return rc


def crm_configure_load(action, configuration):
    logger_utils.log_only_to_file("Loading crm config (%s), content is:" % (action))
    logger_utils.log_only_to_file(configuration)
    if not cib_factory.initialize():
        utils.fatal("Failed to load cluster configuration")
    set_obj = mkset_obj()
    if action == 'replace':
        cib_factory.erase()
    if not set_obj.save(configuration, remove=False, method=action):
        utils.fatal("Failed to load cluster configuration")
    if not cib_factory.commit():
        utils.fatal("Failed to commit cluster configuration")


def wait_for_resource(message, resource, timeout_ms=WAIT_TIMEOUT_MS_DEFAULT):
    """
    Wait for resource started
    """
    with logger_utils.status_long(message) as progress_bar:
        start_time = int(time.clock_gettime(time.CLOCK_MONOTONIC) * 1000)
        while True:
            if xmlutil.CrmMonXmlParser.is_resource_started(resource):
                break
            status_progress(progress_bar)
            if 0 < timeout_ms <= (int(time.clock_gettime(time.CLOCK_MONOTONIC) * 1000) - start_time):
                utils.fatal('Time out waiting for resource.')
            sleep(1)


def wait_for_cluster(timeout_ms=WAIT_TIMEOUT_MS_DEFAULT):
    with logger_utils.status_long("Waiting for cluster") as progress_bar:
        start_time = int(time.clock_gettime(time.CLOCK_MONOTONIC) * 1000)
        while True:
            if is_online():
                break
            status_progress(progress_bar)
            if 0 < timeout_ms <= (int(time.clock_gettime(time.CLOCK_MONOTONIC) * 1000) - start_time):
                utils.fatal('Time out waiting for cluster.')
            sleep(2)


def get_cluster_node_hostname():
    """
    Get the hostname of the cluster node
    """
    peer_node = None
    if _context.cluster_node:
        rc, out, err = utils.get_stdout_stderr("ssh {} {} crm_node --name".format(SSH_OPTION, _context.cluster_node))
        if rc != 0:
            utils.fatal(err)
        peer_node = out
    return peer_node


def is_online():
    """
    Check whether local node is online
    Besides that, in join process, check whether init node is online
    """
    if not xmlutil.CrmMonXmlParser.is_node_online(utils.this_node()):
        return False

    # if peer_node is None, this is in the init process
    peer_node = get_cluster_node_hostname()
    if peer_node is None:
        return True
    # In join process
    # If the joining node is already online but can't find the init node
    # The communication IP maybe mis-configured
    if not xmlutil.CrmMonXmlParser.is_node_online(peer_node):
        shutil.copy(COROSYNC_CONF_ORIG, corosync.conf())
        sync_file(corosync.conf())
        utils.stop_service("corosync")
        print()
        utils.fatal("Cannot see peer node \"{}\", please check the communication IP".format(peer_node))
    return True


def pick_default_value(default_list, prev_list):
    """
    Provide default value for function 'prompt_for_string'.
    Make sure give different default value in multi-ring mode.

    Parameters:
    * default_list - default value list for config item
    * prev_list    - previous value for config item in multi-ring mode
    """
    for value in default_list:
        if value not in prev_list:
            return value
    return ""


def sleep(t):
    """
    Sleep for t seconds.
    """
    t = float(t)
    time.sleep(t)


def status_progress(progress_bar):
    if not _context or not _context.quiet:
        progress_bar.progress()


def partprobe():
    # This function uses fdisk to create a list of valid devices for probing
    # with partprobe.  This prevents partprobe from failing on read-only mounted
    # devices such as /dev/sr0 (etc) that might cause it to return an error when
    # it exits.  This allows partprobe to run without forcing _die to bail out.
    # -Brandon Heaton
    #  ATT Training Engineer
    #  Data Center Engineer
    #  bheaton@suse.com
    _rc, out, _err = utils.get_stdout_stderr("sfdisk -l")
    disks = re.findall(r'^Disk\s*(/.+):', out, re.M)
    invoke("partprobe", *disks)


def probe_partitions():
    # Need to do this if second (or subsequent) node happens to be up and
    # connected to storage while it's being repartitioned on the first node.
    with logger_utils.status_long("Probing for new partitions"):
        partprobe()
        sleep(5)


def check_tty():
    """
    Check for pseudo-tty: Cannot display read prompts without a TTY (bnc#892702)
    """
    if _context.yes_to_all:
        return
    if not sys.stdin.isatty():
        utils.fatal("No pseudo-tty detected! Use -t option to ssh if calling remotely.")


def my_hostname_resolves():
    import socket
    hostname = utils.this_node()
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.error:
        return False


def check_prereqs(stage):
    warned = False

    if not my_hostname_resolves():
        logger.warning("Hostname '{}' is unresolvable. {}".format(
            utils.this_node(),
            "Please add an entry to /etc/hosts or configure DNS."))
        warned = True

    timekeepers = ('chronyd.service', 'ntp.service', 'ntpd.service')
    timekeeper = None
    for tk in timekeepers:
        if utils.service_is_available(tk):
            timekeeper = tk
            break

    if timekeeper is None:
        logger.warning("No NTP service found.")
        warned = True
    elif not utils.service_is_enabled(timekeeper):
        logger.warning("{} is not configured to start at system boot.".format(timekeeper))
        warned = True

    if warned:
        if not confirm("Do you want to continue anyway?"):
            return False

    firewall_open_basic_ports()
    return True


def log_start():
    """
    Convenient side-effect: this will die immediately if the log file
    is not writable (e.g. if not running as root)
    """
    logger_utils.log_only_to_file('================================================================')
    logger_utils.log_only_to_file(" ".join(sys.argv))
    logger_utils.log_only_to_file('----------------------------------------------------------------')


def init_network():
    """
    Get all needed network information through utils.InterfacesInfo
    """
    interfaces_inst = utils.InterfacesInfo(_context.ipv6, _context.second_heartbeat, _context.nic_list)
    interfaces_inst.get_interfaces_info()
    _context.default_nic_list = interfaces_inst.get_default_nic_list_from_route()
    _context.default_ip_list = interfaces_inst.get_default_ip_list()

    # local_ip_list and local_network_list are for validation
    _context.local_ip_list = interfaces_inst.ip_list
    _context.local_network_list = interfaces_inst.network_list
    _context.interfaces_inst = interfaces_inst
    # use two "-i" options equal to use "-M" option
    if len(_context.default_nic_list) == 2 and not _context.second_heartbeat:
        _context.second_heartbeat = True


def configure_firewall(tcp=None, udp=None):
    if tcp is None:
        tcp = []
    if udp is None:
        udp = []

    def init_firewall_suse(tcp, udp):
        if os.path.exists(SYSCONFIG_FW_CLUSTER):
            cluster = utils.parse_sysconfig(SYSCONFIG_FW_CLUSTER)
            tcpcurr = set(cluster.get("TCP", "").split())
            tcpcurr.update(tcp)
            tcp = list(tcpcurr)
            udpcurr = set(cluster.get("UDP", "").split())
            udpcurr.update(udp)
            udp = list(udpcurr)

        utils.sysconfig_set(SYSCONFIG_FW_CLUSTER, TCP=" ".join(tcp), UDP=" ".join(udp))

        ext = ""
        if os.path.exists(SYSCONFIG_FW):
            fw = utils.parse_sysconfig(SYSCONFIG_FW)
            ext = fw.get("FW_CONFIGURATIONS_EXT", "")
            if "cluster" not in ext.split():
                ext = ext + " cluster"
        utils.sysconfig_set(SYSCONFIG_FW, FW_CONFIGURATIONS_EXT=ext)

        # No need to do anything else if the firewall is inactive
        if not utils.service_is_active("SuSEfirewall2"):
            return

        # Firewall is active, either restart or complain if we couldn't tweak it
        logger.info("Restarting firewall (tcp={}, udp={})".format(" ".join(tcp), " ".join(udp)))
        if not invokerc("rcSuSEfirewall2 restart"):
            utils.fatal("Failed to restart firewall (SuSEfirewall2)")

    def init_firewall_firewalld(tcp, udp):
        has_firewalld = utils.service_is_active("firewalld")
        cmdbase = 'firewall-cmd --zone=public --permanent ' if has_firewalld else 'firewall-offline-cmd --zone=public '

        def cmd(args):
            if not invokerc(cmdbase + args):
                utils.fatal("Failed to configure firewall.")

        for p in tcp:
            cmd("--add-port={}/tcp".format(p))

        for p in udp:
            cmd("--add-port={}/udp".format(p))

        if has_firewalld:
            if not invokerc("firewall-cmd --reload"):
                utils.fatal("Failed to reload firewall configuration.")

    def init_firewall_ufw(tcp, udp):
        """
        try configuring firewall with ufw
        """
        for p in tcp:
            if not invokerc("ufw allow {}/tcp".format(p)):
                utils.fatal("Failed to configure firewall (ufw)")
        for p in udp:
            if not invokerc("ufw allow {}/udp".format(p)):
                utils.fatal("Failed to configure firewall (ufw)")

    if utils.package_is_installed("firewalld"):
        init_firewall_firewalld(tcp, udp)
    elif utils.package_is_installed("SuSEfirewall2"):
        init_firewall_suse(tcp, udp)
    elif utils.package_is_installed("ufw"):
        init_firewall_ufw(tcp, udp)


def firewall_open_basic_ports():
    """
    Open ports for csync2, hawk & dlm respectively
    """
    configure_firewall(tcp=["30865", "7630", "21064"])


def firewall_open_corosync_ports():
    """
    Have to do this separately, as we need general firewall config early
    so csync2 works, but need corosync config *after* corosync.conf has
    been created/updated.

    Please note corosync uses two UDP ports mcastport (for mcast
    receives) and mcastport - 1 (for mcast sends).

    Also open QNetd/QDevice port if configured.
    """
    # all mcastports defined in corosync config
    udp = corosync.get_values("totem.interface.mcastport")
    udp.extend([str(int(p) - 1) for p in udp])

    tcp = corosync.get_values("totem.quorum.device.net.port")

    configure_firewall(tcp=tcp, udp=udp)


def init_cluster_local():
    # Caller should check this, but I'm paranoid...
    if utils.service_is_active("corosync.service"):
        utils.fatal("corosync service is running!")

    firewall_open_corosync_ports()

    # reset password, but only if it's not already set
    _rc, outp = utils.get_stdout("passwd -S hacluster")
    ps = outp.strip().split()[1]
    pass_msg = ""
    if ps not in ("P", "PS"):
        logger_utils.log_only_to_file(': Resetting password of hacluster user')
        rc, outp, errp = utils.get_stdout_stderr("passwd hacluster", input_s=b"linux\nlinux\n")
        if rc != 0:
            logger.warning("Failed to reset password of hacluster user: %s" % (outp + errp))
        else:
            pass_msg = ", password 'linux'"

    # evil, but necessary
    invoke("rm -f /var/lib/heartbeat/crm/* /var/lib/pacemaker/cib/*")

    # only try to start hawk if hawk is installed
    if utils.service_is_available("hawk.service"):
        utils.start_service("hawk.service", enable=True)
        logger.info("Hawk cluster interface is now running. To see cluster status, open:")
        logger.info("  https://{}:7630/".format(_context.default_ip_list[0]))
        logger.info("Log in with username 'hacluster'{}".format(pass_msg))
    else:
        logger.warning("Hawk not installed - not configuring web management interface.")

    if pass_msg:
        logger.warning("You should change the hacluster password to something more secure!")

    start_pacemaker(enable_flag=True)
    wait_for_cluster()


def start_pacemaker(node_list=[], enable_flag=False):
    """
    Start pacemaker service with wait time for sbd
    When node_list set, start pacemaker service in parallel

    Return success node list
    """
    from .sbd import SBDTimeout
    # not _context means not in init or join process
    if not _context and \
            utils.package_is_installed("sbd") and \
            utils.service_is_enabled("sbd.service") and \
            SBDTimeout.is_sbd_delay_start():
        target_dir = "/run/systemd/system/sbd.service.d/"
        cmd1 = "mkdir -p {}".format(target_dir)
        target_file = "{}sbd_delay_start_disabled.conf".format(target_dir)
        cmd2 = "echo -e '[Service]\nUnsetEnvironment=SBD_DELAY_START' > {}".format(target_file)
        cmd3 = "systemctl daemon-reload"
        for cmd in [cmd1, cmd2, cmd3]:
            parallax.parallax_call(node_list, cmd)

    # To avoid possible JOIN flood in corosync
    if len(node_list) > 5:
        for node in node_list[:]:
            time.sleep(0.25)
            try:
                utils.start_service("corosync.service", remote_addr=node)
            except ValueError as err:
                node_list.remove(node)
                logger.error(err)
    return utils.start_service("pacemaker.service", enable=enable_flag, node_list=node_list)


def install_tmp(tmpfile, to):
    with open(tmpfile, "r") as src:
        with utils.open_atomic(to, "w") as dst:
            for line in src:
                dst.write(line)


def append(fromfile, tofile, remote=None):
    cmd = "cat {} >> {}".format(fromfile, tofile)
    utils.get_stdout_or_raise_error(cmd, remote=remote)


def append_unique(fromfile, tofile, remote=None, from_local=False):
    """
    Append unique content from fromfile to tofile
    
    if from_local and remote:
        append local fromfile to remote tofile
    elif remote:
        append remote fromfile to remote tofile
    if not remote:
        append fromfile to tofile, locally
    """
    if not utils.check_file_content_included(fromfile, tofile, remote=remote, source_local=from_local):
        if from_local and remote:
            append_to_remote_file(fromfile, remote, tofile)
        else:
            append(fromfile, tofile, remote=remote)


def rmfile(path, ignore_errors=False):
    """
    Try to remove the given file, and
    report an error on failure
    """
    try:
        os.remove(path)
    except os.error as err:
        if not ignore_errors:
            utils.fatal("Failed to remove {}: {}".format(path, err))


def mkdirs_owned(dirs, mode=0o777, uid=-1, gid=-1):
    """
    Create directory path, setting the mode and
    ownership of the leaf directory to mode/uid/gid.
    """
    if not os.path.exists(dirs):
        try:
            os.makedirs(dirs, mode)
        except OSError as err:
            utils.fatal("Failed to create {}: {}".format(dirs, err))
        if uid != -1 or gid != -1:
            utils.chown(dirs, uid, gid)


def init_ssh():
    """
    Configure passwordless SSH.
    """
    utils.start_service("sshd.service", enable=True)
    for user in USER_LIST:
        configure_ssh_key(user)

    # If not use -N/--nodes option
    if not _context.node_list:
        return

    print()
    node_list = _context.node_list
    # Swap public ssh key between remote node and local
    for node in node_list:
        swap_public_ssh_key(node, add=True)
        if utils.service_is_active("pacemaker.service", node):
            utils.fatal("Cluster is currently active on {} - can't run".format(node))
    # Swap public ssh key between one remote node and other remote nodes
    if len(node_list) > 1:
        _, _, authorized_file = key_files("root").values()
        for node in node_list:
            public_key_file_remote = fetch_public_key_from_remote_node(node)
            for other_node in node_list:
                if other_node == node:
                    continue
                append_unique(public_key_file_remote, authorized_file, remote=other_node, from_local=True)
    print()


def key_files(user):
    """
    Find home directory for user and return key files with abspath
    """
    keyfile_dict = {}
    home_dir = userdir.gethomedir(user)
    keyfile_dict['private'] = "{}/.ssh/id_rsa".format(home_dir)
    keyfile_dict['public'] = "{}/.ssh/id_rsa.pub".format(home_dir)
    keyfile_dict['authorized'] = "{}/.ssh/authorized_keys".format(home_dir)
    return keyfile_dict


def is_nologin(user):
    """
    Check if user's shell is /sbin/nologin
    """
    with open("/etc/passwd") as f:
        return re.search("{}:.*:/sbin/nologin".format(user), f.read())


def change_user_shell(user):
    """
    To change user's login shell
    """
    message = "The user '{}' will have the login shell configuration changed to /bin/bash"
    if user != "root" and is_nologin(user):
        if not _context.yes_to_all:
            logger.info(message.format(user))
            if not confirm("Continue?"):
                _context.with_other_user = False
                return
        invoke("usermod -s /bin/bash {}".format(user))


def configure_ssh_key(user="root", remote=None):
    """
    Configure ssh rsa key on local or remote

    If <home_dir>/.ssh/id_rsa not exist, generate a new one
    Add <home_dir>/.ssh/id_rsa.pub to <home_dir>/.ssh/authorized_keys anyway, make sure itself authorized
    """
    change_user_shell(user)

    cmd = ""
    private_key, public_key, authorized_file = key_files(user).values()
    if not utils.detect_file(private_key, remote=remote):
        logger.info("SSH key for {} does not exist, hence generate it now".format(user))
        cmd = "ssh-keygen -q -f {} -C 'Cluster Internal on {}' -N ''".format(private_key, remote if remote else utils.this_node())
    elif not utils.detect_file(public_key, remote=remote):
        cmd = "ssh-keygen -y -f {} > {}".format(private_key, public_key)
    if cmd:
        cmd = utils.add_su(cmd, user)
        utils.get_stdout_or_raise_error(cmd, remote=remote)

    if not utils.detect_file(authorized_file, remote=remote):
        cmd = "touch {}".format(authorized_file)
        utils.get_stdout_or_raise_error(cmd, remote=remote)

    append_unique(public_key, authorized_file, remote=remote)


def init_ssh_remote():
    """
    Called by ha-cluster-join
    """
    authorized_keys_file = "/root/.ssh/authorized_keys"
    if not os.path.exists(authorized_keys_file):
        open(authorized_keys_file, 'w').close()
    authkeys = open(authorized_keys_file, "r+")
    authkeys_data = authkeys.read()
    for key in ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"):
        fn = os.path.join("/root/.ssh", key)
        if not os.path.exists(fn):
            continue
        keydata = open(fn + ".pub").read()
        if keydata not in authkeys_data:
            append(fn + ".pub", authorized_keys_file)


def copy_ssh_key(source_key, user, remote_node):
    """
    Copy ssh key from local to remote's authorized_keys
    """
    err_details_string = """
    crmsh has no way to help you to setup up passwordless ssh among nodes at this time.
    As the hint, likely, `PasswordAuthentication` is 'no' in /etc/ssh/sshd_config.
    Given in this case, users must setup passwordless ssh beforehand, or change it to 'yes' and manage passwords properly
    """
    cmd = "ssh-copy-id -i {} {}@{}".format(source_key, user, remote_node)
    try:
        utils.get_stdout_or_raise_error(cmd)
    except ValueError as err:
        utils.fatal("{}\n{}".format(str(err), err_details_string))


def append_to_remote_file(fromfile, remote_node, tofile):
    """
    Append content of fromfile to tofile on remote_node
    """
    cmd = "cat {} | ssh {} root@{} 'cat >> {}'".format(fromfile, SSH_OPTION, remote_node, tofile)
    utils.get_stdout_or_raise_error(cmd)


def init_csync2():
    host_list = _context.node_list_in_cluster

    logger.info("Configuring csync2")
    if os.path.exists(CSYNC2_KEY):
        if not confirm("csync2 is already configured - overwrite?"):
            return

    invoke("rm", "-f", CSYNC2_KEY)
    logger.debug("Generating csync2 shared key")
    if not invokerc("csync2", "-k", CSYNC2_KEY):
        utils.fatal("Can't create csync2 key {}".format(CSYNC2_KEY))

    csync2_file_list = ""
    for f in FILES_TO_SYNC:
        csync2_file_list += "include {};\n".format(f)

    host_str = ""
    for host in host_list:
        host_str += 'host {};\n'.format(host)

    utils.str2file("""group ha_group
{{
key /etc/csync2/key_hagroup;
{}
{}
}}
    """.format(host_str, csync2_file_list), CSYNC2_CFG)

    if _context.skip_csync2:
        for f in [CSYNC2_CFG, CSYNC2_KEY]:
            sync_file(f)

    for host in host_list:
        logger.info("Starting {} service on {}".format(CSYNC2_SERVICE, host))
        utils.start_service(CSYNC2_SERVICE, enable=True, remote_addr=host)

    _msg = "syncing" if _context.skip_csync2 else "checking"
    with logger_utils.status_long("csync2 {} files".format(_msg)):
        if _context.skip_csync2:
            csync2_update("/")
        else:
            invoke("csync2", "-cr", "/")


def csync2_update(path):
    '''
    Sync path to all peers

    If there was a conflict, use '-f' to force this side to win
    '''
    invoke("csync2 -rm {}".format(path))
    if invokerc("csync2 -rxv {}".format(path)):
        return
    invoke("csync2 -rf {}".format(path))
    if not invokerc("csync2 -rxv {}".format(path)):
        logger.warning("{} was not synced".format(path))


def init_csync2_remote():
    """
    It would be nice if we could just have csync2.cfg include a directory,
    which in turn included one file per node which would be referenced via
    something like "group ha_group { ... config: /etc/csync2/hosts/*; }"
    That way, adding a new node would just mean adding a single new file
    to that directory.  Unfortunately, the 'config' statement only allows
    inclusion of specific individual files, not multiple files via wildcard.
    So we have this function which is called by ha-cluster-join to add the new
    remote node to csync2 config on some existing node.  It is intentionally
    not documented in ha-cluster-init's user-visible usage information.
    """
    newhost = _context.cluster_node
    if not newhost:
        utils.fatal("Hostname not specified")

    curr_cfg = open(CSYNC2_CFG).read()

    was_quiet = _context.quiet
    try:
        _context.quiet = True
        # if host doesn't already exist in csync2 config, add it
        if not re.search(r"^\s*host.*\s+%s\s*;" % (newhost), curr_cfg, flags=re.M):
            curr_cfg = re.sub(r"\bhost.*\s+\S+\s*;", r"\g<0>\n\thost %s;" % (utils.doublequote(newhost)), curr_cfg, count=1)
            utils.str2file(curr_cfg, CSYNC2_CFG)
        else:
            logger_utils.log_only_to_file(": Not updating %s - remote host %s already exists" % (CSYNC2_CFG, newhost))
    finally:
        _context.quiet = was_quiet


def init_corosync_auth():
    """
    Generate the corosync authkey
    """
    if os.path.exists(COROSYNC_AUTH):
        if not confirm("%s already exists - overwrite?" % (COROSYNC_AUTH)):
            return
        rmfile(COROSYNC_AUTH)
    invoke("corosync-keygen -l -k {}".format(COROSYNC_AUTH))


def init_remote_auth():
    """
    Generate the pacemaker-remote authkey
    """
    if os.path.exists(PCMK_REMOTE_AUTH):
        if not confirm("%s already exists - overwrite?" % (PCMK_REMOTE_AUTH)):
            return
        rmfile(PCMK_REMOTE_AUTH)

    pcmk_remote_dir = os.path.dirname(PCMK_REMOTE_AUTH)
    mkdirs_owned(pcmk_remote_dir, mode=0o750, gid="haclient")
    if not invokerc("dd if=/dev/urandom of={} bs=4096 count=1".format(PCMK_REMOTE_AUTH)):
        logger.warning("Failed to create pacemaker authkey: {}".format(PCMK_REMOTE_AUTH))
    utils.chown(PCMK_REMOTE_AUTH, "hacluster", "haclient")
    os.chmod(PCMK_REMOTE_AUTH, 0o640)


class Validation(object):
    """
    Class to validate values from interactive inputs
    """

    def __init__(self, value, prev_value_list=[]):
        """
        Init function
        """
        self.value = value
        self.prev_value_list = prev_value_list
        if self.value in self.prev_value_list:
            raise ValueError("Already in use: {}".format(self.value))

    def _is_mcast_addr(self):
        """
        Check whether the address is multicast address
        """
        if not utils.IP.is_mcast(self.value):
            raise ValueError("{} is not multicast address".format(self.value))

    def _is_local_addr(self, local_addr_list):
        """
        Check whether the address is in local
        """
        if self.value not in local_addr_list:
            raise ValueError("Address must be a local address (one of {})".format(local_addr_list))

    def _is_valid_port(self):
        """
        Check whether the port is valid
        """
        if self.prev_value_list and abs(int(self.value) - int(self.prev_value_list[0])) <= 1:
            raise ValueError("Port {} is already in use by corosync. Leave a gap between multiple rings.".format(self.value))
        if int(self.value) <= 1024 or int(self.value) > 65535:
            raise ValueError("Valid port range should be 1025-65535")

    @classmethod
    def valid_mcast_address(cls, addr, prev_value_list=[]):
        """
        Check whether the address is already in use and whether the address is for multicast
        """
        cls_inst = cls(addr, prev_value_list)
        cls_inst._is_mcast_addr()

    @classmethod
    def valid_ucast_ip(cls, addr, prev_value_list=[]):
        """
        Check whether the address is already in use and whether the address exists on local
        """
        cls_inst = cls(addr, prev_value_list)
        cls_inst._is_local_addr(_context.local_ip_list)

    @classmethod
    def valid_mcast_ip(cls, addr, prev_value_list=[]):
        """
        Check whether the address is already in use and whether the address exists on local address and network
        """
        cls_inst = cls(addr, prev_value_list)
        cls_inst._is_local_addr(_context.local_ip_list + _context.local_network_list)

    @classmethod
    def valid_port(cls, port, prev_value_list=[]):
        """
        Check whether the port is valid
        """
        cls_inst = cls(port, prev_value_list)
        cls_inst._is_valid_port()

    @staticmethod
    def valid_admin_ip(addr, prev_value_list=[]):
        """
        Validate admin IP address
        """
        ipv6 = utils.IP.is_ipv6(addr)

        # Check whether this IP already configured in cluster
        ping_cmd = "ping6" if ipv6 else "ping"
        if invokerc("{} -c 1 {}".format(ping_cmd, addr)):
            raise ValueError("Address already in use: {}".format(addr))


def init_corosync_unicast():

    if _context.yes_to_all:
        logger.info("Configuring corosync (unicast)")
    else:
        logger.info("""Configure Corosync (unicast):
  This will configure the cluster messaging layer.  You will need
  to specify a network address over which to communicate (default
  is {}'s network, but you can use the network address of any
  active interface).
""".format(_context.default_nic_list[0]))

    ringXaddr_res = []
    mcastport_res = []
    default_ports = ["5405", "5407"]
    two_rings = False

    for i in range(2):
        ringXaddr = prompt_for_string(
                'Address for ring{}'.format(i),
                default=pick_default_value(_context.default_ip_list, ringXaddr_res),
                valid_func=Validation.valid_ucast_ip,
                prev_value=ringXaddr_res)
        if not ringXaddr:
            utils.fatal("No value for ring{}".format(i))
        ringXaddr_res.append(ringXaddr)

        mcastport = prompt_for_string(
                'Port for ring{}'.format(i),
                match='[0-9]+',
                default=pick_default_value(default_ports, mcastport_res),
                valid_func=Validation.valid_port,
                prev_value=mcastport_res)
        if not mcastport:
            utils.fatal("Expected a multicast port for ring{}".format(i))
        mcastport_res.append(mcastport)

        if i == 1 or \
           not _context.second_heartbeat or \
           not confirm("\nAdd another heartbeat line?"):
            break
        two_rings = True

    corosync.create_configuration(
            clustername=_context.cluster_name,
            ringXaddr=ringXaddr_res,
            mcastport=mcastport_res,
            transport="udpu",
            ipv6=_context.ipv6,
            two_rings=two_rings)
    sync_file(corosync.conf())


def init_corosync_multicast():
    def gen_mcastaddr():
        if _context.ipv6:
            return "ff3e::%s:%d" % (
                ''.join([random.choice('0123456789abcdef') for _ in range(4)]),
                random.randint(0, 9))
        return "239.%d.%d.%d" % (
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(1, 255))

    if _context.yes_to_all:
        logger.info("Configuring corosync")
    else:
        logger.info("""Configure Corosync:
  This will configure the cluster messaging layer.  You will need
  to specify a network address over which to communicate (default
  is {}'s network, but you can use the network address of any
  active interface).
""".format(_context.default_nic_list[0]))

    bindnetaddr_res = []
    mcastaddr_res = []
    mcastport_res = []
    default_ports = ["5405", "5407"]
    two_rings = False

    for i in range(2):
        bindnetaddr = prompt_for_string(
                'IP or network address to bind to',
                default=pick_default_value(_context.default_ip_list, bindnetaddr_res),
                valid_func=Validation.valid_mcast_ip,
                prev_value=bindnetaddr_res)
        if not bindnetaddr:
            utils.fatal("No value for bindnetaddr")
        bindnetaddr_res.append(bindnetaddr)

        mcastaddr = prompt_for_string(
                'Multicast address',
                default=gen_mcastaddr(),
                valid_func=Validation.valid_mcast_address,
                prev_value=mcastaddr_res)
        if not mcastaddr:
            utils.fatal("No value for mcastaddr")
        mcastaddr_res.append(mcastaddr)

        mcastport = prompt_for_string(
                'Multicast port',
                match='[0-9]+',
                default=pick_default_value(default_ports, mcastport_res),
                valid_func=Validation.valid_port,
                prev_value=mcastport_res)
        if not mcastport:
            utils.fatal("No value for mcastport")
        mcastport_res.append(mcastport)

        if i == 1 or \
           not _context.second_heartbeat or \
           not confirm("\nConfigure a second multicast ring?"):
            break
        two_rings = True

    nodeid = None
    if _context.ipv6:
        nodeid = utils.gen_nodeid_from_ipv6(_context.default_ip_list[0])

    corosync.create_configuration(
        clustername=_context.cluster_name,
        bindnetaddr=bindnetaddr_res,
        mcastaddr=mcastaddr_res,
        mcastport=mcastport_res,
        ipv6=_context.ipv6,
        nodeid=nodeid,
        two_rings=two_rings)
    sync_file(corosync.conf())


def adjust_corosync_parameters_according_to_profiles():
    """
    Adjust corosync's parameters according profiles
    """
    if not _context.profiles_dict:
        return
    for k, v in _context.profiles_dict.items():
        if k.startswith("corosync."):
            corosync.set_value('.'.join(k.split('.')[1:]), v)


def init_corosync():
    """
    Configure corosync (unicast or multicast, encrypted?)
    """
    init_corosync_auth()

    if os.path.exists(corosync.conf()):
        if not confirm("%s already exists - overwrite?" % (corosync.conf())):
            return

    if _context.unicast or _context.cloud_type or not _context.multicast:
        init_corosync_unicast()
    else:
        init_corosync_multicast()
    adjust_corosync_parameters_according_to_profiles()


def init_sbd():
    """
    Configure SBD (Storage-based fencing).

    SBD can also run in diskless mode if no device
    is configured.
    """
    _context.sbd_manager.sbd_init()


def init_upgradeutil():
    upgradeutil.force_set_local_upgrade_seq()


def init_ocfs2():
    """
    OCFS2 configure process
    """
    if not _context.ocfs2_devices:
        return
    ocfs2_manager = ocfs2.OCFS2Manager(_context)
    ocfs2_manager.init_ocfs2()


def init_cluster():
    """
    Initial cluster configuration.
    """
    init_cluster_local()

    _rc, nnodes = utils.get_stdout("crm_node -l")
    nnodes = len(nnodes.splitlines())
    if nnodes < 1:
        utils.fatal("No nodes found in cluster")
    if nnodes > 1:
        utils.fatal("Joined existing cluster - will not reconfigure.")

    logger.info("Loading initial cluster configuration")

    rsc_defaults_str = "rsc_defaults rsc-options: migration-threshold=3"
    if not xmlutil.RscState().has_rsc_stickiness():
        rsc_defaults_str += " resource-stickiness=1"
    crm_configure_load("update", """property cib-bootstrap-options: stonith-enabled=false
op_defaults op-options: timeout=600 record-pending=true
{}
""".format(rsc_defaults_str))

    _context.sbd_manager.configure_sbd_resource_and_properties()


def init_admin():
    # Skip this section when -y is passed
    # unless $ADMIN_IP is set
    adminaddr = _context.admin_ip
    if _context.yes_to_all and not adminaddr:
        return

    if not adminaddr:
        logger.info("""Configure Administration IP Address:
  Optionally configure an administration virtual IP
  address. The purpose of this IP address is to
  provide a single IP that can be used to interact
  with the cluster, rather than using the IP address
  of any specific cluster node.
""")
        if not confirm("Do you wish to configure a virtual IP address?"):
            return

        adminaddr = prompt_for_string('Virtual IP', valid_func=Validation.valid_admin_ip)

    crm_configure_load("update", 'primitive admin-ip IPaddr2 ip=%s op monitor interval=10 timeout=20' % (utils.doublequote(adminaddr)))
    wait_for_resource("Configuring virtual IP ({})".format(adminaddr), "admin-ip")


def configure_qdevice_interactive():
    """
    Configure qdevice on interactive mode
    """
    if _context.yes_to_all:
        return
    logger.info("Configure Qdevice/Qnetd:\n" + QDEVICE_HELP_INFO + "\n")
    if not confirm("Do you want to configure QDevice?"):
        return
    while True:
        try:
            qdevice.QDevice.check_package_installed("corosync-qdevice")
            break
        except ValueError as err:
            logger.error(err)
            if confirm("Please install the package manually and press 'y' to continue"):
                continue
            else:
                return

    qnetd_addr = prompt_for_string("HOST or IP of the QNetd server to be used",
            valid_func=qdevice.QDevice.check_qnetd_addr)
    qdevice_port = prompt_for_string("TCP PORT of QNetd server", default=5403,
            valid_func=qdevice.QDevice.check_qdevice_port)
    qdevice_algo = prompt_for_string("QNetd decision ALGORITHM (ffsplit/lms)", default="ffsplit",
            valid_func=qdevice.QDevice.check_qdevice_algo)
    qdevice_tie_breaker = prompt_for_string("QNetd TIE_BREAKER (lowest/highest/valid node id)", default="lowest",
            valid_func=qdevice.QDevice.check_qdevice_tie_breaker)
    qdevice_tls = prompt_for_string("Whether using TLS on QDevice/QNetd (on/off/required)", default="on",
            valid_func=qdevice.QDevice.check_qdevice_tls)
    qdevice_heuristics = prompt_for_string("Heuristics COMMAND to run with absolute path; For multiple commands, use \";\" to separate",
            valid_func=qdevice.QDevice.check_qdevice_heuristics,
            allow_empty=True)
    qdevice_heuristics_mode = prompt_for_string("MODE of operation of heuristics (on/sync/off)", default="sync",
            valid_func=qdevice.QDevice.check_qdevice_heuristics_mode) if qdevice_heuristics else None

    _context.qdevice_inst = qdevice.QDevice(
            qnetd_addr,
            port=qdevice_port,
            algo=qdevice_algo,
            tie_breaker=qdevice_tie_breaker,
            tls=qdevice_tls,
            cmds=qdevice_heuristics,
            mode=qdevice_heuristics_mode,
            is_stage=_context.stage == "qdevice")


def init_qdevice():
    """
    Setup qdevice and qnetd service
    """
    if not _context.qdevice_inst:
        configure_qdevice_interactive()
    # If don't want to config qdevice, return
    if not _context.qdevice_inst:
        utils.disable_service("corosync-qdevice.service")
        return
    logger.info("""Configure Qdevice/Qnetd:""")
    for node in utils.list_cluster_nodes():
        if not utils.service_is_available("corosync-qdevice.service", node):
            utils.fatal("corosync-qdevice.service is not available on {}".format(node))
    qdevice_inst = _context.qdevice_inst
    qnetd_addr = qdevice_inst.qnetd_addr
    # Configure ssh passwordless to qnetd if detect password is needed
    if utils.check_ssh_passwd_need(qnetd_addr):
        logger.info("Copy ssh key to qnetd node({})".format(qnetd_addr))
        rc, _, err = invoke("ssh-copy-id -i /root/.ssh/id_rsa.pub root@{}".format(qnetd_addr))
        if not rc:
            utils.fatal("Failed to copy ssh key: {}".format(err))
    # Start qdevice service if qdevice already configured
    if utils.is_qdevice_configured() and not confirm("Qdevice is already configured - overwrite?"):
        qdevice_inst.start_qdevice_service()
        return
    qdevice_inst.set_cluster_name()
    # Validate qnetd node
    qdevice_inst.valid_qnetd()

    qdevice_inst.config_and_start_qdevice()

    if _context.stage == "qdevice":
        adjust_properties()


def init():
    """
    Basic init
    """
    if _context.quiet:
        logger_utils.disable_info_in_console()
    log_start()
    init_network()


def join_ssh(seed_host):
    """
    SSH configuration for joining node.
    """
    if not seed_host:
        utils.fatal("No existing IP/hostname specified (use -c option)")

    utils.start_service("sshd.service", enable=True)
    for user in USER_LIST:
        configure_ssh_key(user)
        swap_public_ssh_key(seed_host, user)

    # This makes sure the seed host has its own SSH keys in its own
    # authorized_keys file (again, to help with the case where the
    # user has done manual initial setup without the assistance of
    # ha-cluster-init).
    rc, _, err = invoke("ssh {} root@{} crm cluster init -i {} ssh_remote".format(SSH_OPTION, seed_host, _context.default_nic_list[0]))
    if not rc:
        utils.fatal("Can't invoke crm cluster init -i {} ssh_remote on {}: {}".format(_context.default_nic_list[0], seed_host, err))


def swap_public_ssh_key(remote_node, user="root", add=False):
    """
    Swap public ssh key between remote_node and local
    """
    if user != "root" and not _context.with_other_user:
        return

    _, public_key, authorized_file = key_files(user).values()
    # Detect whether need password to login to remote_node
    if utils.check_ssh_passwd_need(remote_node, user):
        # If no passwordless configured, paste /root/.ssh/id_rsa.pub to remote_node's /root/.ssh/authorized_keys
        logger.info("Configuring SSH passwordless with {}@{}".format(user, remote_node))
        # After this, login to remote_node is passwordless
        if user == "root":
            copy_ssh_key(public_key, user, remote_node)
        else:
            try:
                append_to_remote_file(public_key, remote_node, authorized_file)
            except ValueError:
                utils.get_stdout_or_raise_error(
                    '/usr/bin/env python3 -m crmsh.healthcheck fix-cluster PasswordlessHaclusterAuthenticationFeature',
                    remote_node,
                )
                append_to_remote_file(public_key, remote_node, authorized_file)

    if add:
        configure_ssh_key(remote=remote_node)

    try:
        # Fetch public key file from remote_node
        public_key_file_remote = fetch_public_key_from_remote_node(remote_node, user)
    except ValueError as err:
        logger.warning(err)
        return
    # Append public key file from remote_node to local's /root/.ssh/authorized_keys
    # After this, login from remote_node is passwordless
    # Should do this step even passwordless is True, to make sure we got two-way passwordless
    append_unique(public_key_file_remote, authorized_file)


def fetch_public_key_from_remote_node(node, user="root"):
    """
    Fetch public key file from remote node
    Return a temp file contains public key
    Return None if no key exist
    """

    # For dsa, might need to add PubkeyAcceptedKeyTypes=+ssh-dss to config file, see
    # https://superuser.com/questions/1016989/ssh-dsa-keys-no-longer-work-for-password-less-authentication
    home_dir = userdir.gethomedir(user)
    for key in ("id_rsa", "id_ecdsa", "id_ed25519", "id_dsa"):
        public_key_file = "{}/.ssh/{}.pub".format(home_dir, key)
        cmd = "ssh {} root@{} 'test -f {}'".format(SSH_OPTION, node, public_key_file)
        if not invokerc(cmd):
            continue
        _, temp_public_key_file = tmpfiles.create()
        cmd = "scp {} root@{}:{} {}".format(SSH_OPTION, node, public_key_file, temp_public_key_file)
        rc, _, err = invoke(cmd)
        if not rc:
            utils.fatal("Failed to run \"{}\": {}".format(cmd, err))
        return temp_public_key_file
    raise ValueError("No ssh key exist on {}".format(node))


def join_csync2(seed_host):
    """
    Csync2 configuration for joining node.
    """
    if not seed_host:
        utils.fatal("No existing IP/hostname specified (use -c option)")

    logger.info("Configuring csync2")
    # Necessary if re-running join on a node that's been configured before.
    rmfile("/var/lib/csync2/{}.db3".format(utils.this_node()), ignore_errors=True)

    # Not automatically updating /etc/hosts - risky in the general case.
    # etc_hosts_add_me
    # local hosts_line=$(etc_hosts_get_me)
    # [ -n "$hosts_line" ] || error "No valid entry for $(hostname) in /etc/hosts - csync2 can't work"

    # If we *were* updating /etc/hosts, the next line would have "\"$hosts_line\"" as
    # the last arg (but this requires re-enabling this functionality in ha-cluster-init)
    cmd = "crm cluster init -i {} csync2_remote {}".format(_context.default_nic_list[0], utils.this_node())
    rc, _, err = invoke("ssh {} root@{} {}".format(SSH_OPTION, seed_host, cmd))
    if not rc:
        utils.fatal("Can't invoke \"{}\" on {}: {}".format(cmd, seed_host, err))

    # This is necessary if syncing /etc/hosts (to ensure everyone's got the
    # same list of hosts)
    # local tmp_conf=/etc/hosts.$$
    # invoke scp root@seed_host:/etc/hosts $tmp_conf \
    #   || error "Can't retrieve /etc/hosts from seed_host"
    # install_tmp $tmp_conf /etc/hosts
    rc, _, err = invoke("scp root@%s:'/etc/csync2/{csync2.cfg,key_hagroup}' /etc/csync2" % (seed_host))
    if not rc:
        utils.fatal("Can't retrieve csync2 config from {}: {}".format(seed_host, err))

    logger.info("Starting {} service".format(CSYNC2_SERVICE))
    utils.start_service(CSYNC2_SERVICE, enable=True)

    # Sync new config out.  This goes to all hosts; csync2.cfg definitely
    # needs to go to all hosts (else hosts other than the seed and the
    # joining host won't have the joining host in their config yet).
    # Strictly, the rest of the files need only go to the new host which
    # could theoretically be effected using `csync2 -xv -P $(hostname)`,
    # but this still leaves all the other files in dirty state (becuase
    # they haven't gone to all nodes in the cluster, which means a
    # subseqent join of another node can fail its sync of corosync.conf
    # when it updates expected_votes.  Grrr...
    with logger_utils.status_long("csync2 syncing files in cluster"):
        if not invokerc('ssh {} root@{} "csync2 -rm /; csync2 -rxv || csync2 -rf / && csync2 -rxv"'.format(SSH_OPTION, seed_host)):
            print("")
            logger.warning("csync2 run failed - some files may not be sync'd")


def join_ssh_merge(_cluster_node):
    """
    Ensure known_hosts is the same in all nodes
    """
    logger.info("Merging known_hosts")

    hosts = _context.node_list_in_cluster or [_cluster_node]

    # To create local entry in known_hosts
    utils.get_stdout_or_raise_error("ssh {} {} true".format(SSH_OPTION, utils.this_node()))

    known_hosts_new = set()
    cat_cmd = "[ -e /root/.ssh/known_hosts ] && cat /root/.ssh/known_hosts || true"
    logger_utils.log_only_to_file("parallax.call {} : {}".format(hosts, cat_cmd))
    results = parallax.parallax_call(hosts, cat_cmd, strict=False)
    for host, result in results:
        if isinstance(result, parallax.Error):
            logger.warning("Failed to get known_hosts from {}: {}".format(host, str(result)))
        else:
            if result[1]:
                known_hosts_new.update((utils.to_ascii(result[1]) or "").splitlines())
    if known_hosts_new:
        hoststxt = "\n".join(sorted(known_hosts_new))
        tmpf = utils.str2tmp(hoststxt)
        logger_utils.log_only_to_file("parallax.copy {} : {}".format(hosts, hoststxt))
        results = parallax.parallax_copy(hosts, tmpf, "/root/.ssh/known_hosts", strict=False)
        for host, result in results:
            if isinstance(result, parallax.Error):
                logger.warning("scp to {} failed ({}), known_hosts update may be incomplete".format(host, str(result)))


def update_expected_votes():
    # get a list of nodes, excluding remote nodes
    nodelist = None
    loop_count = 0
    device_votes = 0
    nodecount = 0
    expected_votes = 0
    while True:
        rc, nodelist_text = utils.get_stdout("cibadmin -Ql --xpath '/cib/status/node_state'")
        if rc == 0:
            try:
                nodelist_xml = etree.fromstring(nodelist_text)
                nodelist = [n.get('uname') for n in nodelist_xml.xpath('//node_state') if n.get('remote_node') != 'true']
                if len(nodelist) >= 2:
                    break
            except Exception:
                break
        # timeout: 10 seconds
        if loop_count == 10:
            break
        loop_count += 1
        sleep(1)

    # Increase expected_votes
    # TODO: wait to adjust expected_votes until after cluster join,
    # so that we can ask the cluster for the current membership list
    # Have to check if a qnetd device is configured and increase
    # expected_votes in that case
    is_qdevice_configured = utils.is_qdevice_configured()
    if nodelist is None:
        for v in corosync.get_values("quorum.expected_votes"):
            expected_votes = v

            # For node >= 2, expected_votes = nodecount + device_votes
            # Assume nodecount is N, for ffsplit, qdevice only has one vote
            # which means that device_votes is 1, ie:expected_votes = N + 1;
            # while for lms, qdevice has N - 1 votes, ie: expected_votes = N + (N - 1)
            # and update quorum.device.net.algorithm based on device_votes

            if corosync.get_value("quorum.device.net.algorithm") == "lms":
                device_votes = int((expected_votes - 1) / 2)
                nodecount = expected_votes - device_votes
                # as nodecount will increase 1, and device_votes is nodecount - 1
                # device_votes also increase 1
                device_votes += 1
            elif corosync.get_value("quorum.device.net.algorithm") == "ffsplit":
                device_votes = 1
                nodecount = expected_votes - device_votes
            elif is_qdevice_configured:
                device_votes = 0
                nodecount = v

            nodecount += 1
            expected_votes = nodecount + device_votes
            corosync.set_value("quorum.expected_votes", str(expected_votes))
    else:
        nodecount = len(nodelist)
        expected_votes = 0
        # For node >= 2, expected_votes = nodecount + device_votes
        # Assume nodecount is N, for ffsplit, qdevice only has one vote
        # which means that device_votes is 1, ie:expected_votes = N + 1;
        # while for lms, qdevice has N - 1 votes, ie: expected_votes = N + (N - 1)
        if corosync.get_value("quorum.device.net.algorithm") == "ffsplit":
            device_votes = 1
        if corosync.get_value("quorum.device.net.algorithm") == "lms":
            device_votes = nodecount - 1

        if nodecount > 1:
            expected_votes = nodecount + device_votes

        if corosync.get_value("quorum.expected_votes"):
            corosync.set_value("quorum.expected_votes", str(expected_votes))
    if is_qdevice_configured:
        corosync.set_value("quorum.device.votes", device_votes)
    corosync.set_value("quorum.two_node", 1 if expected_votes == 2 else 0)

    sync_file(corosync.conf())


def setup_passwordless_with_other_nodes(init_node):
    """
    Setup passwordless with other cluster nodes

    Should fetch the node list from init node, then swap the key
    """
    init_hostname = utils.get_stdout_or_raise_error("hostname", remote=init_node)
    # Swap ssh public key between join node and other cluster nodes
    for node in _context.node_list_in_cluster:
        # Filter out init node
        if node == init_hostname:
            continue
        for user in USER_LIST:
            swap_public_ssh_key(node, user)


def sync_files_to_disk():
    """
    Sync file content to disk between cluster nodes
    """
    files_string = ' '.join(filter(lambda f: os.path.isfile(f), FILES_TO_SYNC))
    if files_string:
        utils.cluster_run_cmd("sync {}".format(files_string.strip()))


def join_cluster(seed_host):
    """
    Cluster configuration for joining node.
    """
    def get_local_nodeid():
        # for IPv6
        return utils.gen_nodeid_from_ipv6(_context.local_ip_list[0])

    def update_nodeid(nodeid, node=None):
        # for IPv6
        if node and node != utils.this_node():
            cmd = "crm corosync set totem.nodeid %d" % nodeid
            invoke("crm cluster run '{}' {}".format(cmd, node))
        else:
            corosync.set_value("totem.nodeid", nodeid)

    is_qdevice_configured = utils.is_qdevice_configured()
    if is_qdevice_configured and not utils.service_is_available("corosync-qdevice.service"):
        utils.fatal("corosync-qdevice.service is not available")

    shutil.copy(corosync.conf(), COROSYNC_CONF_ORIG)

    # check if use IPv6
    ipv6_flag = False
    ipv6 = corosync.get_value("totem.ip_version")
    if ipv6 and ipv6 == "ipv6":
        ipv6_flag = True
    _context.ipv6 = ipv6_flag

    init_network()

    # check whether have two rings
    rrp_flag = False
    rrp = corosync.get_value("totem.rrp_mode")
    if rrp in ('active', 'passive'):
        rrp_flag = True

    # It would be massively useful at this point if new nodes could come
    # up in standby mode, so we could query the CIB locally to see if
    # there was any further local setup that needed doing, e.g.: creating
    # mountpoints for clustered filesystems.  Unfortunately we don't have
    # that yet, so the following crawling horror takes a punt on the seed
    # node being up, then asks it for a list of mountpoints...
    if _context.cluster_node:
        _rc, outp, _ = utils.get_stdout_stderr("ssh {} root@{} 'cibadmin -Q --xpath \"//primitive\"'".format(SSH_OPTION, seed_host))
        if outp:
            xml = etree.fromstring(outp)
            mountpoints = xml.xpath(' and '.join(['//primitive[@class="ocf"',
                                                  '@provider="heartbeat"',
                                                  '@type="Filesystem"]']) +
                                    '/instance_attributes/nvpair[@name="directory"]/@value')
            for m in mountpoints:
                invoke("mkdir -p {}".format(m))
    else:
        logger.info("No existing IP/hostname specified - skipping mountpoint detection/creation")

    # Bump expected_votes in corosync.conf
    # TODO(must): this is rather fragile (see related code in ha-cluster-remove)

    # If corosync.conf() doesn't exist or is empty, we will fail here. (bsc#943227)
    if not os.path.exists(corosync.conf()):
        utils.fatal("{} is not readable. Please ensure that hostnames are resolvable.".format(corosync.conf()))

    # if unicast, we need to add our node to $corosync.conf()
    is_unicast = corosync.is_unicast()
    if is_unicast:
        ringXaddr_res = []
        for i in 0, 1:
            ringXaddr = prompt_for_string(
                    'Address for ring{}'.format(i),
                    default=pick_default_value(_context.default_ip_list, ringXaddr_res),
                    valid_func=Validation.valid_ucast_ip,
                    prev_value=ringXaddr_res)
            # The ringXaddr here still might be empty on non-interactive mode
            # when don't have default ip addresses(_context.default_ip_list is empty or just one)
            if not ringXaddr:
                utils.fatal("No value for ring{}".format(i))
            ringXaddr_res.append(ringXaddr)
            if not rrp_flag:
                break
        invoke("rm -f /var/lib/heartbeat/crm/* /var/lib/pacemaker/cib/*")
        try:
            corosync.add_node_ucast(ringXaddr_res)
        except corosync.IPAlreadyConfiguredError as e:
            logger.warning(e)
        sync_file(corosync.conf())
        invoke("ssh {} root@{} corosync-cfgtool -R".format(SSH_OPTION, seed_host))

    _context.sbd_manager.join_sbd(seed_host)

    if ipv6_flag and not is_unicast:
        # for ipv6 mcast
        # using ipv6 need nodeid configured
        local_nodeid = get_local_nodeid()
        update_nodeid(local_nodeid)

    if is_qdevice_configured and not is_unicast:
        # expected_votes here maybe is "0", set to "3" to make sure cluster can start
        corosync.set_value("quorum.expected_votes", "3")

    # Initialize the cluster before adjusting quorum. This is so
    # that we can query the cluster to find out how many nodes
    # there are (so as not to adjust multiple times if a previous
    # attempt to join the cluster failed)
    init_cluster_local()

    adjust_properties()

    with logger_utils.status_long("Reloading cluster configuration"):

        if ipv6_flag and not is_unicast:
            # for ipv6 mcast
            nodeid_dict = {}
            _rc, outp, _ = utils.get_stdout_stderr("crm_node -l")
            if _rc == 0:
                for line in outp.splitlines():
                    tokens = line.split()
                    if len(tokens) == 0:
                        pass  # Skip any spurious empty line.
                    elif len(tokens) < 3:
                        logger.warning("Unable to update configuration for nodeid {}. "
                             "The node has no known name and/or state "
                             "information".format(tokens[0]))
                    else:
                        nodeid_dict[tokens[1]] = tokens[0]

        # apply nodelist in cluster
        if is_unicast or is_qdevice_configured:
            invoke("crm cluster run 'crm corosync reload'")

        update_expected_votes()
        # Trigger corosync config reload to ensure expected_votes is propagated
        invoke("corosync-cfgtool -R")

        # Ditch no-quorum-policy=ignore
        _rc, outp = utils.get_stdout("crm configure show")
        if re.search('no-quorum-policy=.*ignore', outp):
            invoke("crm_attribute --attr-name no-quorum-policy --delete-attr")

        # if unicast, we need to reload the corosync configuration
        # on the other nodes
        if is_unicast:
            invoke("crm cluster run 'crm corosync reload'")

        if ipv6_flag and not is_unicast:
            # for ipv6 mcast
            # after csync2_update, all config files are same
            # but nodeid must be uniqe
            for node in list(nodeid_dict.keys()):
                if node == utils.this_node():
                    continue
                update_nodeid(int(nodeid_dict[node]), node)
            update_nodeid(local_nodeid)

        sync_files_to_disk()

    if is_qdevice_configured:
        start_qdevice_on_join_node(seed_host)
    else:
        utils.disable_service("corosync-qdevice.service")


def adjust_priority_in_rsc_defaults(is_2node_wo_qdevice):
    """
    Adjust priority in rsc_defaults

    Set priority=1 when current cluster is 2 nodes without qdevice;
    else set priority=0
    """
    if is_2node_wo_qdevice:
        utils.set_property("priority", 1, property_type="rsc_defaults", conditional=True)
    else:
        utils.set_property("priority", 0, property_type="rsc_defaults")


def adjust_priority_fencing_delay(is_2node_wo_qdevice):
    """
    Adjust priority-fencing-delay

    When pcmk_delay_max is set in fence agent,
    and the current cluster is 2 nodes without qdevice,
    set priority-fencing-delay=2*pcmk_delay_max
    """
    out = utils.get_stdout_or_raise_error("crm configure show related:stonith")
    if not out:
        return
    pcmk_delay_max_v_list = re.findall("pcmk_delay_max=(\w+)", out)
    if pcmk_delay_max_v_list:
        max_value = max([int(utils.crm_msec(v)/1000) for v in pcmk_delay_max_v_list])
    if pcmk_delay_max_v_list and is_2node_wo_qdevice:
        utils.set_property("priority-fencing-delay", 2*max_value, conditional=True)
    else:
        utils.set_property("priority-fencing-delay", 0)


def start_qdevice_on_join_node(seed_host):
    """
    Doing qdevice certificate process and start qdevice service on join node
    """
    with logger_utils.status_long("Starting corosync-qdevice.service"):
        if not corosync.is_unicast():
            corosync.add_nodelist_from_cmaptool()
            sync_file(corosync.conf())
            invoke("crm corosync reload")
        if utils.is_qdevice_tls_on():
            qnetd_addr = corosync.get_value("quorum.device.net.host")
            qdevice_inst = qdevice.QDevice(qnetd_addr, cluster_node=seed_host)
            qdevice_inst.certificate_process_on_join()
        utils.start_service("corosync-qdevice.service", enable=True)


def set_cluster_node_ip():
    """
    ringx_addr might be hostname or IP
    _context.cluster_node by now is always hostname

    If ring0_addr is IP, we should get the configured iplist which belong _context.cluster_node
    Then filter out which one is configured as ring0_addr
    At last assign that ip to _context.cluster_node_ip which will be removed later
    """
    node = _context.cluster_node
    addr_list = corosync.get_values('nodelist.node.ring0_addr')
    if node in addr_list:
        return

    ip_list = utils.get_iplist_from_name(node)
    for ip in ip_list:
        if ip in addr_list:
            _context.cluster_node_ip = ip
            break


def stop_services(stop_list, remote_addr=None):
    """
    Stop cluster related service
    """
    for service in stop_list:
        if utils.service_is_active(service, remote_addr=remote_addr):
            logger.info("Stopping the %s%s", service, " on {}".format(remote_addr) if remote_addr else "")
            utils.stop_service(service, disable=True, remote_addr=remote_addr)


def rm_configuration_files(remote=None):
    """
    Delete configuration files from the node to be removed
    """
    utils.get_stdout_or_raise_error("rm -f {}".format(' '.join(_context.rm_list)), remote=remote)
    # restore original sbd configuration file from /usr/share/fillup-templates/sysconfig.sbd
    if utils.package_is_installed("sbd", remote_addr=remote):
        from .sbd import SBDManager
        cmd = "cp {} {}".format(SBDManager.SYSCONFIG_SBD_TEMPLATE, SYSCONFIG_SBD)
        utils.get_stdout_or_raise_error(cmd, remote=remote)


def remove_node_from_cluster():
    """
    Remove node from running cluster and the corosync / pacemaker configuration.
    """
    node = _context.cluster_node
    set_cluster_node_ip()

    stop_services(SERVICES_STOP_LIST, remote_addr=node)
    qdevice.QDevice.remove_qdevice_db([node])
    rm_configuration_files(node)

    # execute the command : crm node delete $HOSTNAME
    logger.info("Removing the node {}".format(node))
    if not NodeMgmt.call_delnode(node):
        utils.fatal("Failed to remove {}.".format(node))

    if not invokerc("sed -i /{}/d {}".format(node, CSYNC2_CFG)):
        utils.fatal("Removing the node {} from {} failed".format(node, CSYNC2_CFG))

    # Remove node from nodelist
    if corosync.get_values("nodelist.node.ring0_addr"):
        del_target = _context.cluster_node_ip or node
        corosync.del_node(del_target)

    decrease_expected_votes()

    adjust_properties()

    logger.info("Propagating configuration changes across the remaining nodes")
    sync_file(CSYNC2_CFG)
    sync_file(corosync.conf())

    # Trigger corosync config reload to ensure expected_votes is propagated
    invoke("corosync-cfgtool -R")


def decrease_expected_votes():
    '''
    Decrement expected_votes in corosync.conf
    '''
    vote = corosync.get_value("quorum.expected_votes")
    if not vote:
        return
    quorum = int(vote)
    new_quorum = quorum - 1
    if utils.is_qdevice_configured():
        new_nodecount = 0
        device_votes = 0
        nodecount = 0

        if corosync.get_value("quorum.device.net.algorithm") == "lms":
            nodecount = int((quorum + 1)/2)
            new_nodecount = nodecount - 1
            device_votes = new_nodecount - 1

        elif corosync.get_value("quorum.device.net.algorithm") == "ffsplit":
            device_votes = 1
            nodecount = quorum - device_votes
            new_nodecount = nodecount - 1

        if new_nodecount > 1:
            new_quorum = new_nodecount + device_votes
        else:
            new_quorum = 0

        corosync.set_value("quorum.device.votes", device_votes)
    else:
        corosync.set_value("quorum.two_node", 1 if new_quorum == 2 else 0)
    corosync.set_value("quorum.expected_votes", str(new_quorum))


def bootstrap_init(context):
    """
    Init cluster process
    """
    global _context
    _context = context

    init()

    stage = _context.stage
    if stage is None:
        stage = ""

    # vgfs stage requires running cluster, everything else requires inactive cluster,
    # except ssh and csync2 (which don't care) and csync2_remote (which mustn't care,
    # just in case this breaks ha-cluster-join on another node).
    if stage in ("vgfs", "admin", "qdevice", "ocfs2"):
        if not _context.cluster_is_running:
            utils.fatal("Cluster is inactive - can't run %s stage" % (stage))
    elif stage == "":
        if _context.cluster_is_running:
            utils.fatal("Cluster is currently active - can't run")
    elif stage not in ("ssh", "ssh_remote", "csync2", "csync2_remote", "sbd", "ocfs2"):
        if _context.cluster_is_running:
            utils.fatal("Cluster is currently active - can't run %s stage" % (stage))

    _context.load_profiles()
    _context.init_sbd_manager()

    # Need hostname resolution to work, want NTP (but don't block ssh_remote or csync2_remote)
    if stage not in ('ssh_remote', 'csync2_remote'):
        check_tty()
        if not check_prereqs(stage):
            return
    elif stage == 'csync2_remote':
        args = _context.args
        logger_utils.log_only_to_file("args: {}".format(args))
        if len(args) != 2:
            utils.fatal("Expected NODE argument to csync2_remote")
        _context.cluster_node = args[1]

    if stage and _context.cluster_is_running and not utils.service_is_active(CSYNC2_SERVICE):
        _context.skip_csync2 = True
        _context.node_list_in_cluster = utils.list_cluster_nodes()
    elif not _context.cluster_is_running:
        _context.node_list_in_cluster = [utils.this_node()]

    if stage != "":
        globals()["init_" + stage]()
    else:
        init_ssh()
        if _context.skip_csync2:
            utils.stop_service(CSYNC2_SERVICE, disable=True)
        else:
            init_csync2()
        init_corosync()
        init_remote_auth()
        init_sbd()
        init_upgradeutil()

        lock_inst = lock.Lock()
        try:
            with lock_inst.lock():
                init_cluster()
                init_admin()
                init_qdevice()
                init_ocfs2()
        except lock.ClaimLockError as err:
            utils.fatal(err)

    bootstrap_finished()


def bootstrap_add(context):
    """
    Adds the given node to the cluster.
    """
    if not context.node_list:
        return

    global _context
    _context = context

    options = ""
    for nic in _context.nic_list:
        options += '-i {} '.format(nic)
    options = " {}".format(options.strip()) if options else ""

    for node in _context.node_list:
        print()
        logger.info("Adding node {} to cluster".format(node))
        cmd = "crm cluster join{} -c {}{}".format(" -y" if _context.yes_to_all else "", utils.this_node(), options)
        logger.info("Running command on {}: {}".format(node, cmd))
        utils.ext_cmd_nosudo("ssh{} root@{} {} '{}'".format("" if _context.yes_to_all else " -t", node, SSH_OPTION, cmd))


def bootstrap_join(context):
    """
    Join cluster process
    """
    global _context
    _context = context

    init()
    _context.init_sbd_manager()

    check_tty()

    corosync_active = utils.service_is_active("corosync.service")
    if corosync_active and _context.stage != "ssh":
        utils.fatal("Abort: Cluster is currently active. Run this command on a node joining the cluster.")

    if not check_prereqs("join"):
        return

    cluster_node = _context.cluster_node
    if _context.stage != "":
        globals()["join_" + _context.stage](cluster_node)
    else:
        if not _context.yes_to_all and cluster_node is None:
            logger.info("""Join This Node to Cluster:
  You will be asked for the IP address of an existing node, from which
  configuration will be copied.  If you have not already configured
  passwordless ssh between nodes, you will be prompted for the root
  password of the existing node.
""")
            cluster_node = prompt_for_string("IP address or hostname of existing node (e.g.: 192.168.1.1)", ".+")
            _context.cluster_node = cluster_node

        init_upgradeutil()
        utils.ping_node(cluster_node)

        join_ssh(cluster_node)

        n = 0
        while n < REJOIN_COUNT:
            if utils.service_is_active("pacemaker.service", cluster_node):
                break
            n += 1
            logger.warning("Cluster is inactive on %s. Retry in %d seconds", cluster_node, REJOIN_INTERVAL)
            sleep(REJOIN_INTERVAL)
        else:
            utils.fatal("Cluster is inactive on {}".format(cluster_node))

        lock_inst = lock.RemoteLock(cluster_node)
        try:
            with lock_inst.lock():
                _context.node_list_in_cluster = utils.fetch_cluster_node_list_from_node(cluster_node)
                setup_passwordless_with_other_nodes(cluster_node)
                join_remote_auth(cluster_node)
                _context.skip_csync2 = not utils.service_is_active(CSYNC2_SERVICE, cluster_node)
                if _context.skip_csync2:
                    utils.stop_service(CSYNC2_SERVICE, disable=True)
                    retrieve_all_config_files(cluster_node)
                    logger.warning("csync2 is not initiated yet. Before using csync2 for the first time, please run \"crm cluster init csync2 -y\" on any one node. Note, this may take a while.")
                else:
                    join_csync2(cluster_node)
                join_ssh_merge(cluster_node)
                probe_partitions()
                join_ocfs2(cluster_node)
                join_cluster(cluster_node)
        except (lock.SSHError, lock.ClaimLockError) as err:
            utils.fatal(err)

    bootstrap_finished()


def bootstrap_finished():
    logger.info("Done (log saved to %s)" % (log.CRMSH_LOG_FILE))


def join_ocfs2(peer_host):
    """
    If init node configured OCFS2 device, verify that device on join node
    """
    ocfs2_inst = ocfs2.OCFS2Manager(_context)
    ocfs2_inst.join_ocfs2(peer_host)


def join_remote_auth(node):
    if os.path.exists(PCMK_REMOTE_AUTH):
        rmfile(PCMK_REMOTE_AUTH)
    pcmk_remote_dir = os.path.dirname(PCMK_REMOTE_AUTH)
    mkdirs_owned(pcmk_remote_dir, mode=0o750, gid="haclient")
    invoke("touch {}".format(PCMK_REMOTE_AUTH))


def remove_qdevice():
    """
    Remove qdevice service and configuration from cluster
    """
    if not utils.is_qdevice_configured():
        utils.fatal("No QDevice configuration in this cluster")
    if not confirm("Removing QDevice service and configuration from cluster: Are you sure?"):
        return

    utils.check_all_nodes_reachable()
    qdevice_reload_policy = qdevice.evaluate_qdevice_quorum_effect(qdevice.QDEVICE_REMOVE)

    logger.info("Disable corosync-qdevice.service")
    invoke("crm cluster run 'systemctl disable corosync-qdevice'")
    if qdevice_reload_policy == qdevice.QdevicePolicy.QDEVICE_RELOAD:
        logger.info("Stopping corosync-qdevice.service")
        invoke("crm cluster run 'systemctl stop corosync-qdevice'")

    with logger_utils.status_long("Removing QDevice configuration from cluster"):
        qdevice.QDevice.remove_certification_files_on_qnetd()
        qdevice.QDevice.remove_qdevice_config()
        qdevice.QDevice.remove_qdevice_db()
        update_expected_votes()
    if qdevice_reload_policy == qdevice.QdevicePolicy.QDEVICE_RELOAD:
        invoke("crm cluster run 'crm corosync reload'")
    elif qdevice_reload_policy == qdevice.QdevicePolicy.QDEVICE_RESTART:
        logger.info("Restarting cluster service")
        utils.cluster_run_cmd("crm cluster restart")
        wait_for_cluster()
    else:
        logger.warning("To remove qdevice service, need to restart cluster service manually on each node")

    adjust_properties()


def bootstrap_remove(context):
    """
    Remove node from cluster, or remove qdevice configuration
    """
    global _context
    _context = context
    force_flag = config.core.force or _context.force

    init()

    if not utils.service_is_active("corosync.service"):
        utils.fatal("Cluster is not active - can't execute removing action")

    if _context.qdevice_rm_flag and _context.cluster_node:
        utils.fatal("Either remove node or qdevice")

    _context.skip_csync2 = not utils.service_is_active(CSYNC2_SERVICE)
    if _context.skip_csync2:
        _context.node_list_in_cluster = utils.fetch_cluster_node_list_from_node(utils.this_node())

    if _context.qdevice_rm_flag:
        remove_qdevice()
        return

    if not _context.yes_to_all and _context.cluster_node is None:
        logger.info("""Remove This Node from Cluster:
  You will be asked for the IP address or name of an existing node,
  which will be removed from the cluster. This command must be
  executed from a different node in the cluster.
""")
        _context.cluster_node = prompt_for_string("IP address or hostname of cluster node (e.g.: 192.168.1.1)", ".+")

    if not _context.cluster_node:
        utils.fatal("No existing IP/hostname specified (use -c option)")

    _context.cluster_node = get_cluster_node_hostname()

    if not force_flag and not confirm("Removing node \"{}\" from the cluster: Are you sure?".format(_context.cluster_node)):
        return

    if _context.cluster_node == utils.this_node():
        if not force_flag:
            utils.fatal("Removing self requires --force")
        remove_self(force_flag)
    elif _context.cluster_node in xmlutil.listnodes():
        remove_node_from_cluster()
    else:
        utils.fatal("Specified node {} is not configured in cluster! Unable to remove.".format(_context.cluster_node))

    bootstrap_finished()


def remove_self(force_flag=False):
    me = _context.cluster_node
    yes_to_all = _context.yes_to_all
    nodes = xmlutil.listnodes(include_remote_nodes=False)
    othernode = next((x for x in nodes if x != me), None)
    if othernode is not None:
        # remove from other node
        cmd = "crm{} cluster remove{} -c {}".format(" -F" if force_flag else "", " -y" if yes_to_all else "", me)
        rc = utils.ext_cmd_nosudo("ssh{} {} {} '{}'".format("" if yes_to_all else " -t", SSH_OPTION, othernode, cmd))
        if rc != 0:
            utils.fatal("Failed to remove this node from {}".format(othernode))
    else:
        # disable and stop cluster
        stop_services(SERVICES_STOP_LIST)
        qdevice.QDevice.remove_certification_files_on_qnetd()
        qdevice.QDevice.remove_qdevice_db([utils.this_node()])
        rm_configuration_files()


def init_common_geo():
    """
    Tasks to do both on first and other geo nodes.
    """
    if not utils.package_is_installed("booth"):
        utils.fatal("Booth not installed - Not configurable as a geo cluster node.")


def init_csync2_geo():
    """
    TODO: Configure csync2 for geo cluster
    That is, create a second sync group which
    syncs the geo configuration across the whole
    geo cluster.
    """


def create_booth_authkey():
    logger.info("Create authentication key for booth")
    if os.path.exists(BOOTH_AUTH):
        rmfile(BOOTH_AUTH)
    rc, _, err = invoke("booth-keygen {}".format(BOOTH_AUTH))
    if not rc:
        utils.fatal("Failed to generate booth authkey: {}".format(err))


def create_booth_config(arbitrator, clusters, tickets):
    logger.info("Configure booth")

    config_template = """# The booth configuration file is "/etc/booth/booth.conf". You need to
# prepare the same booth configuration file on each arbitrator and
# each node in the cluster sites where the booth daemon can be launched.

# "transport" means which transport layer booth daemon will use.
# Currently only "UDP" is supported.
transport="UDP"
port="9929"
"""
    cfg = [config_template]
    if arbitrator is not None:
        cfg.append("arbitrator=\"{}\"".format(arbitrator))
    for s in clusters.values():
        cfg.append("site=\"{}\"".format(s))
    cfg.append("authfile=\"{}\"".format(BOOTH_AUTH))
    for t in tickets:
        cfg.append("ticket=\"{}\"\nexpire=\"600\"".format(t))
    cfg = "\n".join(cfg) + "\n"

    if os.path.exists(BOOTH_CFG):
        rmfile(BOOTH_CFG)
    utils.str2file(cfg, BOOTH_CFG)
    utils.chown(BOOTH_CFG, "hacluster", "haclient")
    os.chmod(BOOTH_CFG, 0o644)


def bootstrap_init_geo(context):
    """
    Configure as a geo cluster member.
    """
    global _context
    _context = context

    if os.path.exists(BOOTH_CFG) and not confirm("This will overwrite {} - continue?".format(BOOTH_CFG)):
        return
    if os.path.exists(BOOTH_AUTH) and not confirm("This will overwrite {} - continue?".format(BOOTH_AUTH)):
        return

    init_common_geo()

    # TODO:
    # in /etc/drbd.conf or /etc/drbd.d/global_common.conf
    # set common.startup.wfc-timeout 100
    # set common.startup.degr-wfc-timeout 120

    create_booth_authkey()
    create_booth_config(_context.arbitrator, _context.clusters, _context.tickets)
    logger.info("Sync booth configuration across cluster")
    csync2_update(BOOTH_DIR)
    init_csync2_geo()
    geo_cib_config(_context.clusters)


def geo_fetch_config(node):
    # TODO: clean this up
    logger.info("Retrieving configuration - This may prompt for root@%s:" % (node))
    tmpdir = tmpfiles.create_dir()
    rc, _, err = invoke("scp -oStrictHostKeyChecking=no root@{}:'{}/*' {}/".format(node, BOOTH_DIR, tmpdir))
    if not rc:
        utils.fatal("Failed to retrieve configuration: {}".format(err))
    try:
        if os.path.isfile("%s/authkey" % (tmpdir)):
            invoke("mv %s/authkey %s" % (tmpdir, BOOTH_AUTH))
            os.chmod(BOOTH_AUTH, 0o600)
        if os.path.isfile("%s/booth.conf" % (tmpdir)):
            invoke("mv %s/booth.conf %s" % (tmpdir, BOOTH_CFG))
            os.chmod(BOOTH_CFG, 0o644)
    except OSError as err:
        raise ValueError("Problem encountered with booth configuration from {}: {}".format(node, err))


def geo_cib_config(clusters):
    cluster_name = corosync.get_values('totem.cluster_name')[0]
    if cluster_name not in list(clusters.keys()):
        utils.fatal("Local cluster name is {}, expected {}".format(cluster_name, "|".join(list(clusters.keys()))))

    logger.info("Configure cluster resources for booth")
    crm_template = Template("""
primitive booth-ip ocf:heartbeat:IPaddr2 $iprules
primitive booth-site ocf:pacemaker:booth-site \
  meta resource-stickiness="INFINITY" \
  params config=booth op monitor interval="10s"
group g-booth booth-ip booth-site meta target-role=Stopped
""")
    iprule = 'params rule #cluster-name eq {} ip="{}"'

    crm_configure_load("update", crm_template.substitute(iprules=" ".join(iprule.format(k, v) for k, v in clusters.items())))


def bootstrap_join_geo(context):
    """
    Run on second cluster to add to a geo configuration.
    It fetches its booth configuration from the other node (cluster node or arbitrator).
    """
    global _context
    _context = context
    init_common_geo()
    check_tty()
    geo_fetch_config(_context.cluster_node)
    logger.info("Sync booth configuration across cluster")
    csync2_update(BOOTH_DIR)
    geo_cib_config(_context.clusters)


def bootstrap_arbitrator(context):
    """
    Configure this machine as an arbitrator.
    It fetches its booth configuration from a cluster node already in the cluster.
    """
    global _context
    _context = context
    node = _context.cluster_node

    init_common_geo()
    check_tty()
    geo_fetch_config(node)
    if not os.path.isfile(BOOTH_CFG):
        utils.fatal("Failed to copy {} from {}".format(BOOTH_CFG, node))
    # TODO: verify that the arbitrator IP in the configuration is us?
    logger.info("Enabling and starting the booth arbitrator service")
    utils.start_service("booth@booth", enable=True)


def get_stonith_timeout_generally_expected():
    """
    Adjust stonith-timeout for all scenarios, formula is:

    stonith-timeout = STONITH_TIMEOUT_DEFAULT + token + consensus
    """
    stonith_enabled = utils.get_property("stonith-enabled")
    # When stonith disabled, return
    if utils.is_boolean_false(stonith_enabled):
        return None

    return STONITH_TIMEOUT_DEFAULT + corosync.token_and_consensus_timeout()


def adjust_pcmk_delay_max(is_2node_wo_qdevice):
    """
    For each fence agent,
    add parameter pcmk_delay_max when cluster is two-node cluster without qdevice
    else remove pcmk_delay_max
    """
    cib_factory.refresh()

    if is_2node_wo_qdevice:
        for res in cib_factory.fence_id_list_without_pcmk_delay():
            cmd = "crm resource param {} set pcmk_delay_max {}s".format(res, PCMK_DELAY_MAX)
            utils.get_stdout_or_raise_error(cmd)
            logger.debug("Add parameter 'pcmk_delay_max={}s' for resource '{}'".format(PCMK_DELAY_MAX, res))
    else:
        for res in cib_factory.fence_id_list_with_pcmk_delay():
            cmd = "crm resource param {} delete pcmk_delay_max".format(res)
            utils.get_stdout_or_raise_error(cmd)
            logger.debug("Delete parameter 'pcmk_delay_max' for resource '{}'".format(res))


def adjust_stonith_timeout():
    """
    Adjust stonith-timeout for sbd and other scenarios
    """
    if utils.service_is_active("sbd.service"):
        from .sbd import SBDTimeout
        SBDTimeout.adjust_sbd_timeout_related_cluster_configuration()
    else:
        value = get_stonith_timeout_generally_expected()
        if value:
            utils.set_property("stonith-timeout", value, conditional=True)


def adjust_properties():
    """
    Adjust properties for the cluster:
    - pcmk_delay_max
    - stonith-timeout
    - priority in rsc_defaults
    - priority-fencing-delay

    Call it when:
    - node join/remove
    - add qdevice via stage
    - remove qdevice
    - add sbd via stage
    """
    if not utils.service_is_active("pacemaker.service"):
        return
    is_2node_wo_qdevice = utils.is_2node_cluster_without_qdevice()
    adjust_pcmk_delay_max(is_2node_wo_qdevice)
    adjust_stonith_timeout()
    adjust_priority_in_rsc_defaults(is_2node_wo_qdevice)
    adjust_priority_fencing_delay(is_2node_wo_qdevice)


def retrieve_all_config_files(cluster_node):
    """
    Retrieve config files from cluster_node if exists
    """
    with logger_utils.status_long("Retrieve all config files"):
        for f in FILES_TO_SYNC:
            if f in [CSYNC2_KEY, CSYNC2_CFG]:
                continue
            rc, _, _ = utils.run_cmd_on_remote("test -f {}".format(f), cluster_node)
            if rc != 0:
                continue
            rc, _, err = utils.get_stdout_stderr("scp {} root@{}:{} {}".format(SSH_OPTION, cluster_node, f, os.path.dirname(f)))
            if rc != 0:
                utils.fatal("Can't retrieve {} from {}:{}".format(f, cluster_node, err))
            if f in [PCMK_REMOTE_AUTH]:
                utils.chown(f, "hacluster", "haclient")


def sync_file(path):
    """
    Sync files between cluster nodes
    """
    if _context.skip_csync2:
        utils.cluster_copy_file(path, nodes=_context.node_list_in_cluster, output=False)
    else:
        csync2_update(path)
# EOF
