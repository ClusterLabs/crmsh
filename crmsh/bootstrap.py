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
import codecs
import dataclasses
import io
import os
import subprocess
import sys
import re
import tempfile
import time
from time import sleep
import readline
import shutil
import typing
import shlex

import yaml
import socket
from string import Template
from lxml import etree

import crmsh.options

from . import config, constants, ssh_key, sh, cibquery, user_of_host
from . import utils
from . import xmlutil
from . import cibconfig
from . import corosync
from . import tmpfiles
from . import lock
from . import userdir
from .constants import QDEVICE_HELP_INFO, FENCING_TIMEOUT_DEFAULT,\
        REJOIN_COUNT, REJOIN_INTERVAL, PCMK_DELAY_MAX, CSYNC2_SERVICE, WAIT_TIMEOUT_MS_DEFAULT
from . import cluster_fs
from . import qdevice
from . import parallax
from . import log
from .service_manager import ServiceManager
from .sh import ShellUtils
from .ui_node import NodeMgmt
from .user_of_host import UserOfHost, UserNotFoundError
from . import sbd
from . import watchdog
import crmsh.healthcheck


logger = log.setup_logger(__name__)
logger_utils = log.LoggerUtils(logger)


CSYNC2_KEY = "/etc/csync2/key_hagroup"
CSYNC2_CFG = "/etc/csync2/csync2.cfg"
COROSYNC_AUTH = "/etc/corosync/authkey"
CRM_CFG = "/etc/crm/crm.conf"
PROFILES_FILE = "/etc/crm/profiles.yml"
SYSCONFIG_PCMK = "/etc/sysconfig/pacemaker"
SYSCONFIG_NFS = "/etc/sysconfig/nfs"
PCMK_REMOTE_AUTH = "/etc/pacemaker/authkey"
SERVICES_STOP_LIST = ["corosync-qdevice.service", "corosync.service", "hawk.service"]
SERVICES_DISABLE_LIST = ["pacemaker.service", "sbd.service"]
BOOTH_DIR = "/etc/booth"
BOOTH_CFG = "/etc/booth/booth.conf"
BOOTH_AUTH = "/etc/booth/authkey"
STATIC_FILES_TO_SYNC = (BOOTH_DIR, COROSYNC_AUTH, CSYNC2_CFG, CSYNC2_KEY, "/etc/ctdb/nodes",
        "/etc/drbd.conf", "/etc/drbd.d", "/etc/ha.d/ldirectord.cf", "/etc/lvm/lvm.conf", "/etc/multipath.conf",
        "/etc/samba/smb.conf", SYSCONFIG_NFS, SYSCONFIG_PCMK, PCMK_REMOTE_AUTH, PROFILES_FILE, CRM_CFG)

INIT_STAGES_EXTERNAL = ("ssh", "firewalld", "csync2", "corosync", "cluster", "ocfs2", "gfs2", "admin", "sbd", "qdevice")
INIT_STAGES_INTERNAL = ("qnetd_remote", )
INIT_STAGES_ALL = INIT_STAGES_EXTERNAL + INIT_STAGES_INTERNAL
JOIN_STAGES_EXTERNAL = ("ssh", "firewalld", "ssh_merge", "cluster")


class Context(object):
    """
    Context object used to avoid having to pass these variables
    to every bootstrap method.
    """
    DEFAULT_PROFILE_NAME = "default"
    KNET_DEFAULT_PROFILE_NAME = "knet-default"
    S390_PROFILE_NAME = "s390"
    CORE_PACKAGES = ("corosync", "pacemaker")

    def __init__(self):
        '''
        Initialize attributes
        '''
        self.type = None # init or join
        self.quiet = None
        self.yes_to_all = None
        self.cluster_name = None
        self.watchdog = None
        self.nic_addr_list = []
        self.transport = None
        self.nic_list = []
        self.user_at_node_list = []
        self.current_user = None
        self.admin_ip = None
        self.ipv6 = None
        self.qdevice_inst = None
        self.qnetd_addr_input = None
        self.qdevice_port = None
        self.qdevice_algo = None
        self.qdevice_tie_breaker = None
        self.qdevice_tls = None
        self.qdevice_heuristics = None
        self.qdevice_heuristics_mode = None
        self.qdevice_rm_flag = None
        self.ocfs2_devices = []
        self.gfs2_devices = []
        self.use_cluster_lvm2 = None
        self.mount_point = None
        self.cluster_node = None
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
        self.cluster_is_running = None
        self.cloud_type = None
        self.is_s390 = False
        self.profiles_data = None
        self.profiles_dict = {}
        self.default_nic = None
        self.default_ip_list = []
        self.corosync_conf_orig = None
        self.rm_list = [corosync.conf(), COROSYNC_AUTH, "/var/lib/pacemaker/cib/*",
                "/var/lib/corosync/*", "/var/lib/pacemaker/pengine/*", PCMK_REMOTE_AUTH, "~/.config/crm/*"]
        self.use_ssh_agent = None
        self.skip_csync2 = None

    @classmethod
    def set_context(cls, options):
        ctx = cls()
        for opt in vars(options):
            setattr(ctx, opt, getattr(options, opt))
        ctx.initialize_user()
        return ctx

    def _initialize_qdevice(self):
        """
        Initialize qdevice instance
        """
        if not self.qnetd_addr_input:
            return
        ssh_user, qnetd_host = utils.parse_user_at_host(self.qnetd_addr_input)
        self.qdevice_inst = qdevice.QDevice(
                qnetd_addr=qnetd_host,
                port=self.qdevice_port,
                algo=self.qdevice_algo,
                tie_breaker=self.qdevice_tie_breaker,
                tls=self.qdevice_tls,
                ssh_user=ssh_user,
                cmds=self.qdevice_heuristics,
                mode=self.qdevice_heuristics_mode,
                is_stage=self.stage == "qdevice")

    def initialize_user(self):
        """
        users_of_specified_hosts: 'not_specified', 'specified', 'no_hosts'
        """
        sudoer = userdir.get_sudoer()
        if self.cluster_node is not None:
            match self.cluster_node.split('@', 1):
                case [user, host]:
                    cluster_node_user = user
                case [host]:
                    cluster_node_user = 'root'
            if cluster_node_user == 'root':
                assert userdir.getuser() == 'root'
                self.current_user = 'root'
            elif sudoer is None:
                utils.fatal("Unsupported config: local node is using root and remote nodes is using non-root users.")
            else:
                self.current_user = sudoer
        elif self.user_at_node_list:
            has_root = False
            has_non_root = False
            for item in self.user_at_node_list:
                match item.split('@', 1):
                    case [user, host]:
                        has_root = has_root or user == 'root'
                        has_non_root = has_non_root or user != 'root'
                    case [host]:
                            has_root = True
            if has_root and has_non_root:
                utils.fatal("Unsupported config: mixing root and non-root users in a cluster.")
            elif has_root:
                assert userdir.getuser() == 'root'
                self.current_user = 'root'
            else:
                if sudoer is None:
                    utils.fatal("Unsupported config: local node is using root and remote nodes is using non-root users.")
                else:
                    self.current_user = sudoer
        else:
            assert userdir.getuser() == 'root'
            self.current_user = 'root'

    def _validate_network_options(self):
        """
        Validate network related options -A/-i/-t
        """
        if self.admin_ip:
            Validation.valid_admin_ip(self.admin_ip)
        if self.type == "init" and self.transport != "knet" and len(self.nic_addr_list) > 1:
            utils.fatal(f"Only one link is allowed for the '{self.transport}' transport type")
        if len(self.nic_addr_list) > corosync.KNET_LINK_NUM_LIMIT:
            utils.fatal(f"Maximum number of interfaces is {corosync.KNET_LINK_NUM_LIMIT}")
        if self.transport == "udp":
            cloud_type = utils.detect_cloud()
            if cloud_type:
                utils.fatal(f"Transport udp(multicast) cannot be used in {cloud_type} platform")

    def _validate_sbd_option(self):
        """
        Validate sbd options
        """
        if self.sbd_devices and self.diskless_sbd:
            utils.fatal("Can't use -s and -S options together")
        if self.sbd_devices:
            sbd.SBDUtils.verify_sbd_device(self.sbd_devices)

        with_sbd_option = self.sbd_devices or self.diskless_sbd

        if self.stage == "sbd":
            if self.cluster_is_running:
                utils.check_all_nodes_reachable("setup SBD")
                node_list = utils.list_cluster_nodes()
            else:
                node_list = [utils.this_node()]
            for node in node_list:
                if not utils.package_is_installed("sbd", node):
                    utils.fatal(sbd.SBDManager.SBD_NOT_INSTALLED_MSG + f" on {node}")
                if self.sbd_devices and not utils.package_is_installed("fence-agents-sbd", node):
                    utils.fatal(sbd.SBDManager.FENCE_SBD_NOT_INSTALLED_MSG + f" on {node}")

            if not with_sbd_option and self.yes_to_all:
                utils.fatal("Stage sbd should specify sbd device by -s or diskless sbd by -S option")
            if ServiceManager().service_is_active(constants.SBD_SERVICE) and not crmsh.options.force:
                utils.fatal("Can't configure stage sbd: sbd.service already running! Please use crm option '-F' if need to redeploy")

        elif with_sbd_option:
            if not utils.package_is_installed("sbd"):
                utils.fatal(sbd.SBDManager.SBD_NOT_INSTALLED_MSG)
            if self.sbd_devices and not utils.package_is_installed("fence-agents-sbd"):
                utils.fatal(sbd.SBDManager.FENCE_SBD_NOT_INSTALLED_MSG)

    def _validate_nodes_option(self):
        """
        Validate -N/--nodes option
        """
        if self.user_at_node_list and not self.yes_to_all:
            utils.fatal("Can't use -N/--nodes option without -y/--yes option")
        if self.user_at_node_list and self.stage:
            utils.fatal("Can't use -N/--nodes option and stage({}) together".format(self.stage))
        me = utils.this_node()
        li = [utils.parse_user_at_host(x) for x in self.user_at_node_list]
        for user in (user for user, node in li if node == me and user is not None and user != self.current_user):
            utils.fatal(f"Overriding current user '{self.current_user}' by '{user}'. Ouch, don't do it.")
        self.user_at_node_list = [value for (user, node), value in zip(li, self.user_at_node_list) if node != me]
        for user, node in (utils.parse_user_at_host(x) for x in self.user_at_node_list):
            utils.ssh_port_reachable_check(node)

    def _validate_cluster_node(self):
        """
        Validate cluster_node on join side
        """
        if self.type == "join" and self.cluster_node:
            user, node = _parse_user_at_host(self.cluster_node, None)
            try:
                # self.cluster_node might be hostname or IP address
                ip_addr = socket.gethostbyname(node)
                if utils.InterfacesInfo.ip_in_local(ip_addr):
                    utils.fatal(f"\"{node}\" is the local node. Please specify peer node's hostname or IP address")
            except socket.gaierror as err:
                utils.fatal(f"\"{node}\": {err}")

    def _validate_stage(self):
        """
        Validate stage argument
        """
        if not self.stage:
            if self.cluster_is_running:
                utils.fatal("Cluster is already running!")
            return

        if self.type == "init":
            if self.stage not in INIT_STAGES_ALL:
                utils.fatal(f"Invalid stage: {self.stage}(available stages: {', '.join(INIT_STAGES_EXTERNAL)})")
            if self.stage in ("admin", "sbd", "qdevice", "ocfs2") and not self.cluster_is_running:
                utils.fatal(f"Cluster is inactive, can't run '{self.stage}' stage")
            if self.stage in ("corosync", "cluster") and self.cluster_is_running:
                utils.fatal(f"Cluster is active, can't run '{self.stage}' stage")

        elif self.type == "join":
            if self.stage not in JOIN_STAGES_EXTERNAL:
                utils.fatal(f"Invalid stage: {self.stage}(available stages: {', '.join(JOIN_STAGES_EXTERNAL)})")
            if self.stage and self.cluster_node is None:
                utils.fatal(f"Can't use stage({self.stage}) without specifying cluster node")
            if self.stage in ("cluster", ) and self.cluster_is_running:
                utils.fatal(f"Cluster is active, can't run '{self.stage}' stage")

    def validate(self):
        """
        Validate packages and options
        """
        for package in self.CORE_PACKAGES:
            if not utils.package_is_installed(package):
                utils.fatal(f"Package '{package}' is not installed")
        self._initialize_qdevice()
        if self.qdevice_inst:
            self.qdevice_inst.valid_qdevice_options()
        if self.ocfs2_devices or self.gfs2_devices or self.stage in ("ocfs2", "gfs2"):
            cluster_fs.ClusterFSManager.pre_verify(self)
        if self.skip_csync2:
            logger.warning("-x option is deprecated and will be removed in future releases")
        self._validate_stage()
        self._validate_network_options()
        self._validate_cluster_node()
        self._validate_nodes_option()
        self._validate_sbd_option()

    def init_sbd_manager(self):
        self.sbd_manager = sbd.SBDManager(bootstrap_context=self)

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
            if not self.quiet:
                logger.info("Loading \"%s\" profile from %s", profile_type, PROFILES_FILE)
            profile_dict = self.profiles_data[profile_type]
        else:
            logger.warning("\"%s\" profile does not exist in %s", profile_type, PROFILES_FILE)
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
        if self.transport == "knet":
            knet_profile_dict = self.load_specific_profile(self.KNET_DEFAULT_PROFILE_NAME)
            # merge two dictionaries
            default_profile_dict = {**default_profile_dict, **knet_profile_dict}
        specific_profile_dict = self.load_specific_profile(profile_type)
        # merge two dictionaries
        self.profiles_dict = {**default_profile_dict, **specific_profile_dict}

    def get_corosync_conf_orig(self):
        if self.corosync_conf_orig is None:
            self.corosync_conf_orig = tmpfiles.create()[1]
        return self.corosync_conf_orig


_context: typing.Optional[Context] = None


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
    if crmsh.options.force or (_context and _context.yes_to_all):
        return True
    disable_completion()
    rc = logger_utils.confirm(msg)
    enable_completion()
    drop_last_history()
    return rc


def disable_completion():
    if _context and _context.ui_context:
        _context.ui_context.disable_completion()


def enable_completion():
    if _context and _context.ui_context:
        _context.ui_context.setup_readline()


def invoke(*args):
    """
    Log command execution to log file.
    Log output from command to log file.
    Return (boolean, stdout, stderr)
    """
    logger_utils.log_only_to_file("invoke: " + " ".join(args))
    rc, stdout, stderr = ShellUtils().get_stdout_stderr(" ".join(args))
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
    action_types = ("update", "replace", "push")
    if action not in action_types:
        utils.fatal(f"Action type should be: {action_types}")
    logger_utils.log_only_to_file("Loading crm config (%s), content is:" % (action))
    logger_utils.log_only_to_file(configuration)

    configuration_tmpfile = utils.str2tmp(configuration)
    tmpfiles.add(configuration_tmpfile)
    sh.cluster_shell().get_stdout_or_raise_error(f"crm -F configure load {action} {configuration_tmpfile}")


def wait_for_resource(message, resource, timeout_ms=WAIT_TIMEOUT_MS_DEFAULT, fatal_on_timeout=True):
    """
    Wait for resource started
    """
    with logger_utils.status_long(message) as progress_bar:
        start_time = int(time.clock_gettime(time.CLOCK_MONOTONIC) * 1000)
        while True:
            if xmlutil.CrmMonXmlParser().is_resource_started(resource):
                break
            status_progress(progress_bar)
            if 0 < timeout_ms <= (int(time.clock_gettime(time.CLOCK_MONOTONIC) * 1000) - start_time):
                error_msg = f'Time out waiting for resource "{resource}" to start.'
                if fatal_on_timeout:
                    utils.fatal(error_msg)
                else:
                    logger.error(error_msg)
                    break
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


def get_node_canonical_hostname(host: str) -> str:
    """
    Get the canonical hostname of the cluster node
    """
    rc, out, err = sh.cluster_shell().get_rc_stdout_stderr_without_input(host, 'crm_node --name')
    if rc != 0:
        utils.fatal(err)
    return out


def is_online():
    """
    Check whether local node is online
    Besides that, in join process, check whether init node is online
    """
    if not xmlutil.CrmMonXmlParser().is_node_online(utils.this_node()):
        return False

    # if peer_node is None, this is in the init process
    if not _context or _context.cluster_node is None:
        return True
    # In join process
    # If the joining node is already online but can't find the init node
    # The communication IP maybe mis-configured
    user, cluster_node = _parse_user_at_host(_context.cluster_node, None)
    cluster_node = get_node_canonical_hostname(cluster_node)
    if not xmlutil.CrmMonXmlParser().is_node_online(cluster_node):
        shutil.copy(_context.get_corosync_conf_orig(), corosync.conf())
        sync_path(corosync.conf(), cluster_node)
        sh.cluster_shell().get_stdout_or_raise_error("corosync-cfgtool -R", cluster_node)
        ServiceManager(sh.ClusterShellAdaptorForLocalShell(sh.LocalShell())).stop_service("corosync")
        print()
        utils.fatal("Cannot see peer node \"{}\", please check the communication IP".format(cluster_node))
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
    _rc, out, _err = ShellUtils().get_stdout_stderr("sfdisk -l")
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


def check_prereqs():
    warned = False

    if not my_hostname_resolves():
        logger.warning("Hostname '{}' is unresolvable. {}".format(
            utils.this_node(),
            "Please add an entry to /etc/hosts or configure DNS."))
        warned = True

    timekeepers = ('chronyd.service', 'ntp.service', 'ntpd.service')
    timekeeper = None
    service_manager = ServiceManager()
    for tk in timekeepers:
        if service_manager.service_is_available(tk):
            timekeeper = tk
            break

    if timekeeper is None:
        logger.warning("No NTP service found.")
        warned = True
    elif not service_manager.service_is_enabled(timekeeper):
        logger.warning("{} is not configured to start at system boot.".format(timekeeper))
        warned = True

    if warned:
        if not confirm("Do you want to continue anyway?"):
            return False

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
    _context.interfaces_inst = utils.InterfacesInfo(_context.ipv6, _context.nic_addr_list)
    _context.interfaces_inst.get_interfaces_info()
    _context.interfaces_inst.flatten_custom_nic_addr_list()

    if _context.interfaces_inst.input_nic_list:
        _context.default_nic = _context.interfaces_inst.input_nic_list[0]
        _context.default_ip_list = _context.interfaces_inst.input_addr_list
    else:
        _context.default_nic = _context.interfaces_inst.get_default_nic_from_route()
        _context.default_ip_list = [_context.interfaces_inst.nic_first_ip(_context.default_nic)]


def init_cluster_local():
    # Caller should check this, but I'm paranoid...
    if ServiceManager().service_is_active("corosync.service"):
        utils.fatal("corosync service is running!")

    # reset password, but only if it's not already set
    # (We still need the hacluster for the hawk).
    _rc, outp = ShellUtils().get_stdout("passwd -S hacluster")
    ps = outp.strip().split()[1]
    pass_msg = ""
    if ps not in ("P", "PS"):
        logger_utils.log_only_to_file(': Resetting password of hacluster user')
        rc, outp, errp = ShellUtils().get_stdout_stderr("passwd hacluster", input_s=b"linux\nlinux\n")
        if rc != 0:
            logger.warning("Failed to reset password of hacluster user: %s" % (outp + errp))
        else:
            pass_msg = ", password 'linux'"

    # evil, but necessary
    invoke("rm -f /var/lib/pacemaker/cib/*")

    # only try to start hawk if hawk is installed
    service_manager = ServiceManager()
    if service_manager.service_is_available("hawk.service"):
        service_manager.start_service("hawk.service", enable=True)
        logger.info("Hawk cluster interface is now running. To see cluster status, open:")
        logger.info("  https://{}:7630/".format(_context.default_ip_list[0]))
        logger.info("Log in with username 'hacluster'{}".format(pass_msg))
    else:
        logger.warning("Hawk not installed - not configuring web management interface.")

    if pass_msg:
        logger.warning("You should change the hacluster password to something more secure!")

    if not start_pacemaker(enable_flag=True):
        utils.fatal("Failed to start cluster services")
    wait_for_cluster()


def start_pacemaker(node_list=[], enable_flag=False):
    """
    Start pacemaker service with wait time for sbd
    When node_list set, start pacemaker service in parallel

    Return success node list
    """
    # not _context means not in init or join process
    if not _context:
        sbd.SBDManager.unset_sbd_delay_start(node_list)

    # To avoid possible JOIN flood in corosync
    service_manager = ServiceManager()
    if len(node_list) > 5:
        for node in node_list[:]:
            time.sleep(0.25)
            try:
                service_manager.start_service("corosync.service", remote_addr=node)
            except ValueError as err:
                node_list.remove(node)
                logger.error(err)
    logger.info("Starting and enable %s on %s", constants.PCMK_SERVICE, ', '.join(node_list) or utils.this_node())
    return service_manager.start_service("pacemaker.service", enable=enable_flag, node_list=node_list)


def _parse_user_at_host(s: str, default_user: str) -> typing.Tuple[str, str]:
    user, host = utils.parse_user_at_host(s)
    if user is None:
        user = default_user
    return user, host


def _keys_from_ssh_agent() -> typing.List[ssh_key.Key]:
    try:
        keys = ssh_key.AgentClient().list()
        return keys
    except ssh_key.Error:
        logger.debug("Cannot get a public key from ssh-agent.", exc_info=True)
        return list()


def init_ssh():
    user_host_list = [_parse_user_at_host(x, _context.current_user) for x in _context.user_at_node_list]
    keys = _keys_from_ssh_agent() if _context.use_ssh_agent else list()
    init_ssh_impl(_context.current_user, keys, user_host_list)
    if user_host_list:
        service_manager = ServiceManager()
        for user, node in user_host_list:
            if service_manager.service_is_active("pacemaker.service", remote_addr=node):
                utils.fatal("Cluster is currently active on {} - can't run".format(node))


def init_ssh_impl(local_user: str, ssh_public_keys: typing.List[ssh_key.Key], user_node_list: typing.List[typing.Tuple[str, str]]):
    """ Configure passwordless SSH.

    The local_user on local host will be configured.
    If user_node_list is not empty, those user and host will also be configured.
    If ssh_public_keys is not empty, it will be added to authorized_keys; if not, a new key pair will be generated for each node.
    """
    ServiceManager(sh.ClusterShellAdaptorForLocalShell(sh.LocalShell())).start_service("sshd.service", enable=True)
    if ssh_public_keys:
        local_shell = sh.LocalShell(additional_environ={'SSH_AUTH_SOCK': os.environ.get('SSH_AUTH_SOCK')})
    else:
        local_shell = sh.LocalShell()
    shell = sh.SSHShell(local_shell, local_user)
    authorized_key_manager = ssh_key.AuthorizedKeyManager(shell)
    if ssh_public_keys:
        # Use specified key. Do not generate new ones.
        logger.info("Adding public keys to authorized_keys for user %s...", local_user)
        for key in ssh_public_keys:
            authorized_key_manager.add(None, local_user, key)
            logger.info("Added public key %s.", key.fingerprint())
    else:
        configure_ssh_key(local_user)
    configure_ssh_key('hacluster')
    change_user_shell('hacluster')

    user_by_host = utils.HostUserConfig()
    user_by_host.clear()
    user_by_host.save_local()
    if user_node_list:
        _init_ssh_on_remote_nodes(local_shell, local_user, user_node_list)
        for user, node in user_node_list:
            if user != 'root' and 0 != shell.subprocess_run_without_input(
                    node, user, 'sudo true',
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
            ).returncode:
                raise ValueError(f'Failed to sudo on {user}@{node}')
        for user, node in user_node_list:
            user_by_host.add(user, node)
        user_by_host.add(local_user, utils.this_node())
        user_by_host.save_local()
        # Starting from here, ClusterShell is available
        shell = sh.ClusterShell(local_shell, UserOfHost.instance())
        authorized_key_manager = ssh_key.AuthorizedKeyManager(shell)
        _init_ssh_for_secondary_user_on_remote_nodes(
            shell, authorized_key_manager,
            [node for user, node in user_node_list],
            'hacluster',
        )
        for user, node in user_node_list:
            change_user_shell('hacluster', node)
        user_by_host.save_remote([node for user, node in user_node_list])


def _init_ssh_on_remote_nodes(
        local_shell: sh.LocalShell,
        local_user: str,
        user_node_list: typing.List[typing.Tuple[str, str]],
):
    # Swap public ssh key between remote node and local
    ssh_shell = sh.SSHShell(local_shell, local_user)
    authorized_key_manager = ssh_key.AuthorizedKeyManager(ssh_shell)
    public_key_list = list()
    for user, node in user_node_list:
        logger.info("Adding public keys to authorized_keys on %s@%s", user, node)
        result = ssh_copy_id_no_raise(local_user, user, node, local_shell)
        if result.returncode != 0:
            utils.fatal("Failed to login to remote host {}@{}".format(user, node))
        elif not result.public_keys:
            pass
        elif isinstance(result.public_keys[0], ssh_key.KeyFile):
            public_key = ssh_key.InMemoryPublicKey(
                generate_ssh_key_pair_on_remote(local_shell, local_user, node, user, user),
            )
            public_key_list.append(public_key)
            authorized_key_manager.add(node, user, public_key)
            authorized_key_manager.add(None, local_user, public_key)
    shell_script = _merge_line_into_file(
        '~/.ssh/authorized_keys',
        (key.public_key() for key in public_key_list),
    ).encode('utf-8')
    for i, (remote_user, node) in enumerate(user_node_list):
        result = local_shell.su_subprocess_run(
            local_user,
            'ssh {} {}@{} /bin/sh'.format(constants.SSH_OPTION, remote_user, node),
            input=shell_script,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if result.returncode != 0:
            utils.fatal('Failed to add public keys to {}@{}: {}'.format(remote_user, node, result.stdout))


def _init_ssh_for_secondary_user_on_remote_nodes(
        cluster_shell: sh.ClusterShell,
        authorized_key_manager: ssh_key.AuthorizedKeyManager,
        nodes: typing.Iterable[str],
        user: str,
):
    """Initialize ssh for another user via an already working ClusterShell."""
    key_file_manager = ssh_key.KeyFileManager(cluster_shell)
    local_keys = [ssh_key.KeyFile(path) for path in key_file_manager.list_public_key_for_user(None, user)]
    assert local_keys
    for node in nodes:
        if not sh.SSHShell(cluster_shell.local_shell, user).can_run_as(node, user):
            for key in local_keys:
                authorized_key_manager.add(node, user, key)
            is_generated, remote_keys = key_file_manager.ensure_key_pair_exists_for_user(node, user)
            if is_generated:
                logger.info("A new ssh keypair is generated for user %s@%s.", user, node)
            for key in remote_keys:
                authorized_key_manager.add(None, user, key)


def _merge_line_into_file(path: str, lines: typing.Iterable[str]) -> str:
    shell_script = '''set -e
[ -e "$path" ] || echo '# created by crmsh' > "$path"
for key in "${keys[@]}"; do
    grep -F "$key" "$path" > /dev/null || sed -i "\\$a $key" "$path"
done'''
    keys_definition = ("keys+=('{}')\n".format(key) for key in lines)
    buf = io.StringIO()
    buf.write(f'path={path}\n')
    for item in keys_definition:
        buf.write(item)
    buf.write(shell_script)
    return buf.getvalue()


def _fetch_core_hosts(shell: sh.ClusterShell, remote_host) -> typing.Tuple[typing.List[str], typing.List[str]]:
    cmd = 'crm options show core.hosts'
    text = shell.get_stdout_or_raise_error(cmd, remote_host)
    match = re.match('core\\.hosts\\s*=\\s*(.*)\\s*', text)
    if match is None:
        utils.fatal('Malformed core.hosts from host {}: {}'.format(remote_host, text))
    user_list = list()
    host_list = list()
    for item in re.split(',\\s*', match.group(1)):
        part = item.split('@', 2)
        if len(part) != 2:
            utils.fatal('Malformed core.hosts from host {}: {}'.format(remote_host, text))
        user_list.append(part[0])
        host_list.append(part[1])
    return user_list, host_list


def is_nologin(user, remote=None):
    """
    Check if user's shell is nologin
    """
    rc, error = sh.cluster_shell().get_rc_and_error(
        remote, None,
        "set -e\n"
        f"shell=$(getent passwd '{user}' | awk -F: '{{ print $NF }}')\n"
        '[ -n "${shell}" ] && [ -f "${shell}" ] && [ -x "${shell}" ] || exit 1\n'
        'case $(basename "$shell") in\n'
        '  nologin) exit 1 ;;\n'
        '  false) exit 1 ;;\n'
        'esac\n'
        '"${shell}" < /dev/null &>/dev/null\n'
    )
    return 0 != rc


def change_user_shell(user, remote=None):
    """
    To change user's login shell
    """
    user_msg = f"'{user}' on {remote}" if remote else f"'{user}'"
    message = f"The user {user_msg} will have the login shell configuration changed to /bin/bash"
    if user != "root" and is_nologin(user, remote):
        if _context is not None and not _context.yes_to_all:
            logger.info(message)
            if not confirm("Continue?"):
                return
        cmd = f"usermod -s /bin/bash {user}"
        sh.cluster_shell().get_stdout_or_raise_error(cmd, remote)


def configure_ssh_key(user):
    """
    Configure ssh key for user, generate a new key pair if needed,
    and add the public key to authorized_keys
    """
    change_user_shell(user)
    shell = sh.LocalShell()
    key_file_manager = ssh_key.KeyFileManager(sh.ClusterShellAdaptorForLocalShell(shell))
    authorized_key_manager = ssh_key.AuthorizedKeyManager(sh.SSHShell(shell, None))
    is_generated, keys = key_file_manager.ensure_key_pair_exists_for_user(None, user)
    if is_generated:
        logger.info("A new ssh keypair is generated for user %s.", user)
    authorized_key_manager.add(None, user, keys[0])
    logger.info("A public key is added to authorized_keys for user %s: %s", user, keys[0].fingerprint())


@dataclasses.dataclass(frozen=True)
class SshCopyIdResult:
    returncode: int
    public_keys: list[ssh_key.Key]


def ssh_copy_id_no_raise(local_user, remote_user, remote_node, shell: sh.LocalShell = None) -> SshCopyIdResult:
    if shell is None:
        shell = sh.LocalShell()
    if utils.check_ssh_passwd_need(local_user, remote_user, remote_node, shell):
        configure_ssh_key(local_user)
        public_keys = ssh_key.fetch_public_key_file_list(None, local_user)
        sleep(5)    # bsc#1243141: sshd PerSourcePenalties
        logger.info("Configuring SSH passwordless with {}@{}".format(remote_user, remote_node))
        cmd = f"ssh-copy-id -i {public_keys[0].public_key_file()} '{remote_user}@{remote_node}'"
        if not config.core.debug:
            cmd += ' &> /dev/null'
        result = shell.su_subprocess_run(local_user, cmd, tty=True)
        return SshCopyIdResult(result.returncode, public_keys)
    else:
        return SshCopyIdResult(0, list())


def ssh_copy_id(local_user, remote_user, remote_node):
    if 0 != ssh_copy_id_no_raise(local_user, remote_user, remote_node).returncode:
        utils.fatal("Failed to login to remote host {}@{}".format(remote_user, remote_node))


def generate_ssh_key_pair_on_remote(
        shell: sh.LocalShell,
        local_sudoer: str,
        remote_host: str, remote_sudoer: str,
        remote_user: str,
) -> str:
    """generate a key pair on remote and return the public key"""
    # pass cmd through stdin rather than as arguments. It seems sudo has its own argument parsing mechanics,
    # which breaks shell expansion used in cmd
    generate_key_script = f'''
set -e
key_types=({ ' '.join(ssh_key.KeyFileManager.KNOWN_KEY_TYPES) })
for key_type in "${{key_types[@]}}"; do
    priv_key_file=~/.ssh/id_${{key_type}}
    if [ -f "$priv_key_file" ]; then
        pub_key_file=$priv_key_file.pub
        break
    fi
done

if [ -z "$pub_key_file" ]; then
    key_type={ssh_key.KeyFileManager.DEFAULT_KEY_TYPE}
    priv_key_file=~/.ssh/id_${{key_type}}
    ssh-keygen -q -t $key_type -f $priv_key_file -C "Cluster internal on $(hostname)" -N ''
    pub_key_file=$priv_key_file.pub
fi

[ -f "$pub_key_file" ] || ssh-keygen -y -f $priv_key_file > $pub_key_file
'''
    result = shell.su_subprocess_run(
        local_sudoer,
        'ssh {} {}@{} sudo -H -u {} /bin/sh'.format(constants.SSH_OPTION, remote_sudoer, remote_host, remote_user),
        input=generate_key_script.encode('utf-8'),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.returncode != 0:
        raise ValueError(codecs.decode(result.stdout, 'utf-8', 'replace'))

    fetch_key_script = f'''
key_types=({ ' '.join(ssh_key.KeyFileManager.KNOWN_KEY_TYPES) })
for key_type in "${{key_types[@]}}"; do
    priv_key_file=~/.ssh/id_${{key_type}}
    if [ -f "$priv_key_file" ]; then
        pub_key_file=$priv_key_file.pub
        cat $pub_key_file
        break
    fi
done
'''
    result = shell.su_subprocess_run(
        local_sudoer,
        'ssh {} {}@{} sudo -H -u {} /bin/sh'.format(constants.SSH_OPTION, remote_sudoer, remote_host, remote_user),
        input=fetch_key_script.encode('utf-8'),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise ValueError(codecs.decode(result.stderr, 'utf-8', 'replace'))
    return result.stdout.decode('utf-8').strip()


def export_ssh_key_non_interactive(
        shell: sh.LocalShell,
        local_user_to_export, remote_user_to_swap,
        remote_node, local_sudoer, remote_sudoer,
):
    """Copy ssh key from local to remote's authorized_keys. Require a configured non-interactive ssh authentication."""
    # ssh-copy-id will prompt for the password of the destination user
    # this is unwanted, so we write to the authorised_keys file ourselve
    public_key = ssh_key.fetch_public_key_content_list(None, local_user_to_export)[0]
    # FIXME: prevent duplicated entries in authorized_keys
    cmd = '''mkdir -p ~{user}/.ssh && chown {user} ~{user}/.ssh && chmod 0700 ~{user}/.ssh && cat >> ~{user}/.ssh/authorized_keys << "EOF"
{key}
EOF
'''.format(user=remote_user_to_swap, key=public_key)
    result = shell.su_subprocess_run(
        local_sudoer,
        'ssh {} {}@{} sudo /bin/sh'.format(constants.SSH_OPTION, remote_sudoer, remote_node),
        input=cmd.encode('utf-8'),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.returncode != 0:
        raise ValueError('Failed to export ssh public key of local user {} to {}@{}: {}'.format(
            local_user_to_export, remote_user_to_swap, remote_node, result.stdout,
        ))


def init_csync2():
    host_list = utils.list_cluster_nodes()
    if not host_list:
        utils.fatal("Failed to get node list from cluster")

    logger.info("Configuring csync2")
    if os.path.exists(CSYNC2_KEY):
        if not confirm("csync2 is already configured - overwrite?"):
            return

    invoke("rm", "-f", CSYNC2_KEY)
    logger.debug("Generating csync2 shared key")
    if not invokerc("csync2", "-k", CSYNC2_KEY):
        utils.fatal("Can't create csync2 key {}".format(CSYNC2_KEY))

    csync2_file_list = ""
    for f in get_files_to_sync():
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

    for f in [CSYNC2_CFG, CSYNC2_KEY]:
        sync_path(f)

    service_manager = ServiceManager()
    for host in host_list:
        logger.info("Starting {} service on {}".format(CSYNC2_SERVICE, host))
        service_manager.start_service(CSYNC2_SERVICE, enable=True, remote_addr=host)

    with logger_utils.status_long("csync2 syncing files"):
        csync2_update("/")


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


def init_qnetd_remote():
    """
    Triggered by join_cluster, this function adds the joining node's key to the qnetd's authorized_keys
    """
    local_user, remote_user, join_node = _select_user_pair_for_ssh_for_secondary_components(_context.cluster_node)
    join_node_key_content = ssh_key.fetch_public_key_content_list(join_node, remote_user)[0]
    qnetd_host = corosync.get_value("quorum.device.net.host")
    _, qnetd_user, qnetd_host = _select_user_pair_for_ssh_for_secondary_components(qnetd_host)
    authorized_key_manager = ssh_key.AuthorizedKeyManager(sh.cluster_shell())
    authorized_key_manager.add(qnetd_host, qnetd_user, ssh_key.InMemoryPublicKey(join_node_key_content))


def init_corosync_auth():
    """
    Generate the corosync authkey
    """
    if os.path.exists(COROSYNC_AUTH):
        if not confirm("%s already exists - overwrite?" % (COROSYNC_AUTH)):
            return
        utils.rmfile(COROSYNC_AUTH)
    invoke("corosync-keygen -l -k {}".format(COROSYNC_AUTH))


def generate_pacemaker_remote_auth():
    """
    Generate the pacemaker-remote authkey
    """
    if os.path.exists(PCMK_REMOTE_AUTH):
        if not confirm("%s already exists - overwrite?" % (PCMK_REMOTE_AUTH)):
            return
        utils.rmfile(PCMK_REMOTE_AUTH)

    pcmk_remote_dir = os.path.dirname(PCMK_REMOTE_AUTH)
    utils.mkdirs_owned(pcmk_remote_dir, mode=0o750, gid="haclient")
    if not invokerc("dd if=/dev/urandom of={} bs=4096 count=1".format(PCMK_REMOTE_AUTH)):
        logger.warning("Failed to create pacemaker authkey: {}".format(PCMK_REMOTE_AUTH))
    utils.chown(PCMK_REMOTE_AUTH, _context.current_user, "haclient")
    utils.chmod(PCMK_REMOTE_AUTH, 0o640)


class FirewallManager:

    SERVICE_NAME = "high-availability"

    def __init__(self, peer=None):
        self.shell = None
        self.peer = peer
        self.firewalld_running = False
        self.firewall_cmd = None
        self.firewall_cmd_permanent_option = ""
        self.peer_msg = ""
        self.firewalld_installed = utils.package_is_installed("firewalld", self.peer)

        if self.firewalld_installed:
            self.shell = sh.cluster_shell()
            rc, _, _ = self.shell.get_rc_stdout_stderr_without_input(self.peer, "firewall-cmd --state")
            self.firewalld_running = rc == 0
            self.firewall_cmd = "firewall-cmd" if self.firewalld_running else "firewall-offline-cmd"
            self.firewall_cmd_permanent_option = " --permanent" if self.firewalld_running else ""
            self.peer_msg = f"on {self.peer}" if self.peer else f"on {utils.this_node()}"

    def _service_is_available(self) -> bool:
        cmd = f"{self.firewall_cmd} --info-service={self.SERVICE_NAME}"
        rc, _, _ = self.shell.get_rc_stdout_stderr_without_input(self.peer, cmd)
        if rc != 0:
            logger.warning("Firewalld service %s is not available %s", self.SERVICE_NAME, self.peer_msg)
            return False
        return True

    def add_service(self):
        if not self.firewalld_installed or not self._service_is_available():
            return
        cmd = f"{self.firewall_cmd}{self.firewall_cmd_permanent_option} --add-service={self.SERVICE_NAME}"
        rc, _, err = self.shell.get_rc_stdout_stderr_without_input(self.peer, cmd)
        if rc != 0:
            logger.error("Failed to add firewalld service %s %s: %s", self.SERVICE_NAME, self.peer_msg, err)
            return
        if self.firewalld_running:
            cmd = f"{self.firewall_cmd} --add-service={self.SERVICE_NAME}"
            self.shell.get_rc_stdout_stderr_without_input(self.peer, cmd)
        logger.info("Added firewalld service %s %s", self.SERVICE_NAME, self.peer_msg)

    def remove_service(self):
        if not self.firewalld_installed or not self._service_is_available():
            return
        cmd = f"{self.firewall_cmd}{self.firewall_cmd_permanent_option} --remove-service={self.SERVICE_NAME}"
        rc, _, err = self.shell.get_rc_stdout_stderr_without_input(self.peer, cmd)
        if rc != 0:
            logger.error("Failed to remove firewalld service %s %s: %s", self.SERVICE_NAME, self.peer_msg, err)
            return
        if self.firewalld_running:
            cmd = f"{self.firewall_cmd} --remove-service={self.SERVICE_NAME}"
            self.shell.get_rc_stdout_stderr_without_input(self.peer, cmd)
        logger.info("Removed firewalld service %s %s", self.SERVICE_NAME, self.peer_msg)

    @classmethod
    def firewalld_stage_finished(cls) -> bool:
        inst = cls()
        if not inst.firewalld_installed or not inst._service_is_available():
            return True
        cmd = f"{inst.firewall_cmd} --list-services"
        _, outp, _ = inst.shell.get_rc_stdout_stderr_without_input(None, cmd)
        return inst.SERVICE_NAME in outp.split()


def init_firewalld():
    if _context.cluster_is_running:
        for node in utils.list_cluster_nodes():
            FirewallManager(node).add_service()
    else:
        FirewallManager().add_service()


def join_firewalld(*_):
    FirewallManager().add_service()


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
        cls_inst._is_local_addr(_context.interfaces_inst.ip_list)

    @classmethod
    def valid_mcast_ip(cls, addr, prev_value_list=[]):
        """
        Check whether the address is already in use and whether the address exists on local address and network
        """
        cls_inst = cls(addr, prev_value_list)
        cls_inst._is_local_addr(_context.interfaces_inst.ip_list + _context.interfaces_inst.network_list)

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


def adjust_corosync_parameters_according_to_profiles():
    """
    Adjust corosync's parameters according profiles
    """
    if not _context.profiles_dict:
        return
    for k, v in _context.profiles_dict.items():
        # Format like: corosync.totem.token: 5000
        if k.startswith("corosync."):
            corosync.set_value('.'.join(k.split('.')[1:]), v)


def get_address_list() -> typing.List[str]:
    """
    Get address list, for both interactive and non-interactive ways
    """
    if _context.transport == "udp":
        valid_func = Validation.valid_mcast_ip
    else:
        valid_func = Validation.valid_ucast_ip

    if _context.yes_to_all or _context.nic_addr_list:
        loop_count = len(_context.default_ip_list)
    else:
        # interative mode and without -i option specified
        loop_count = min(corosync.KNET_LINK_NUM_LIMIT, len(_context.interfaces_inst.nic_list))

    ringXaddr_list = []
    for i in range(loop_count):
        addr = prompt_for_string("Address for ring{}".format(i),
                default=pick_default_value(_context.default_ip_list, ringXaddr_list),
                valid_func=valid_func,
                prev_value=ringXaddr_list)
        ringXaddr_list.append(addr)
        # only confirm when not the last loop and without -i option specified
        if not _context.nic_addr_list and \
                i < (loop_count - 1) and \
                not confirm("\nAdd another ring?"):
            break

    return ringXaddr_list


def config_corosync_conf() -> None:
    """
    Configure corosync.conf
    """
    if _context.yes_to_all:
        logger.info(f"Configuring corosync({_context.transport})")
    inst = corosync.ConfParser(config_data=corosync.COROSYNC_CONF_TEMPLATE)

    if _context.ipv6:
        inst.set("totem.ip_version", "ipv6")
    inst.set("totem.cluster_name", _context.cluster_name)
    inst.set("totem.transport", _context.transport)
    ringXaddr_list = get_address_list()
    for i, ip in enumerate(ringXaddr_list):
        inst.set("nodelist.node.ring{}_addr".format(i), ip)
    inst.set("nodelist.node.name", utils.this_node())
    inst.set("nodelist.node.nodeid", "1")

    inst.save(corosync.conf())


def init_corosync() -> None:
    """
    Configure corosync (unicast or multicast, encrypted?)
    """
    init_corosync_auth()

    if os.path.exists(corosync.conf()):
        if not confirm("%s already exists - overwrite?" % (corosync.conf())):
            return

    if _context.transport != 'knet':
        logger.warning(
            'Transport %s does not support encryption and message authentication. Corosync traffic will be in cleartext.',
            _context.transport,
        )
    config_corosync_conf()
    adjust_corosync_parameters_according_to_profiles()


def init_sbd():
    """
    Configure SBD (Storage-based fencing).

    SBD can also run in diskless mode if no device
    is configured.
    """
    import crmsh.sbd
    if _context.stage == "sbd":
        crmsh.sbd.cleanup_existing_sbd_resource()
    _context.sbd_manager.init_and_deploy_sbd()


def init_ocfs2():
    """
    OCFS2 configure process
    """
    if not _context.ocfs2_devices:
        return
    ocfs2_manager = cluster_fs.ClusterFSManager(_context)
    ocfs2_manager.init()


def init_gfs2():
    """
    GFS2 configure process
    """
    if not _context.gfs2_devices:
        return
    gfs2_manager = cluster_fs.ClusterFSManager(_context)
    gfs2_manager.init()


def init_cluster():
    """
    Initial cluster configuration.
    """
    service_manager = ServiceManager()
    if _context.stage == "cluster":
        if service_manager.service_is_enabled(constants.SBD_SERVICE):
            service_manager.disable_service(constants.SBD_SERVICE)

    generate_pacemaker_remote_auth()

    init_cluster_local()

    _rc, nnodes = ShellUtils().get_stdout("crm_node -l")
    nnodes = len(nnodes.splitlines())
    if nnodes < 1:
        utils.fatal("No nodes found in cluster")
    if nnodes > 1:
        utils.fatal("Joined existing cluster - will not reconfigure.")

    logger.info("Loading initial cluster configuration")

    crm_configure_load("update", """property cib-bootstrap-options: fencing-enabled=false
op_defaults op-options: timeout=600
rsc_defaults rsc-options: resource-stickiness=1 migration-threshold=3
""")

    if corosync.is_qdevice_configured():
        logger.info("Starting and enable corosync-qdevice.service on %s", utils.this_node())
        service_manager.start_service("corosync-qdevice.service", enable=True)
    elif service_manager.service_is_enabled("corosync-qdevice.service"):
        service_manager.disable_service("corosync-qdevice.service")

    adjust_properties()


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
    wait_for_resource(
        f"Configuring virtual IP ({adminaddr})",
        "admin-ip",
        timeout_ms=5000,
        fatal_on_timeout=False
    )


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
        if utils.package_is_installed("corosync-qdevice"):
            break
        else:
            logger.error("Package corosync-qdevice is not installed")
            if confirm("Please install the package manually and press 'y' to continue"):
                continue
            else:
                return

    qnetd_addr_input = prompt_for_string("HOST or IP of the QNetd server to be used")
    ssh_user, qnetd_host = utils.parse_user_at_host(qnetd_addr_input)
    qdevice.QDevice.check_qnetd_addr(qnetd_host)
    _context.qnetd_addr_input = qnetd_addr_input
    qdevice_port = prompt_for_string("TCP PORT of QNetd server", default=5403,
            valid_func=qdevice.QDevice.check_qdevice_port)
    qdevice_algo = prompt_for_string("QNetd decision ALGORITHM (ffsplit/lms)", default="ffsplit",
            valid_func=qdevice.QDevice.check_qdevice_algo)
    qdevice_tie_breaker = prompt_for_string("QNetd TIE_BREAKER (lowest/highest/valid node id)", default="lowest",
            valid_func=qdevice.QDevice.check_qdevice_tie_breaker)
    qdevice_tls = prompt_for_string("Whether using TLS on QDevice (on/off/required)", default="on",
            valid_func=qdevice.QDevice.check_qdevice_tls)
    qdevice_heuristics = prompt_for_string("Heuristics COMMAND to run with absolute path; For multiple commands, use \";\" to separate",
            valid_func=qdevice.QDevice.check_qdevice_heuristics,
            allow_empty=True)
    qdevice_heuristics_mode = prompt_for_string("MODE of operation of heuristics (on/sync/off)", default="sync",
            valid_func=qdevice.QDevice.check_qdevice_heuristics_mode) if qdevice_heuristics else None

    _context.qdevice_inst = qdevice.QDevice(
            qnetd_host,
            port=qdevice_port,
            algo=qdevice_algo,
            tie_breaker=qdevice_tie_breaker,
            tls=qdevice_tls,
            ssh_user=ssh_user,
            cmds=qdevice_heuristics,
            mode=qdevice_heuristics_mode,
            is_stage=_context.stage == "qdevice")


def _setup_passwordless_ssh_for_qnetd(cluster_node_list: typing.List[str]):
    local_user, qnetd_user, qnetd_addr = _select_user_pair_for_ssh_for_secondary_components(_context.qnetd_addr_input)
    # Configure ssh passwordless to qnetd if detect password is needed
    if 0 != ssh_copy_id_no_raise(
            local_user, qnetd_user, qnetd_addr,
            sh.LocalShell(additional_environ={'SSH_AUTH_SOCK': os.environ.get('SSH_AUTH_SOCK', '')}),
    ).returncode:
        msg = f"Failed to login to {qnetd_user}@{qnetd_addr}. Please check the credentials."
        sudoer = userdir.get_sudoer()
        if sudoer and qnetd_user != sudoer:
            args = ['sudo crm']
            args += [x for x in sys.argv[1:]]
            for i, arg in enumerate(args):
                if arg == '--qnetd-hostname' and i + 1 < len(args):
                    if '@' not in args[i + 1]:
                        args[i + 1] = f'{sudoer}@{qnetd_addr}'
                        msg += '\nOr, run "{}".'.format(' '.join(args))
        raise ValueError(msg)

    cluster_shell = sh.cluster_shell()
    # Add other nodes' public keys to qnetd's authorized_keys
    for node in cluster_node_list:
        if node == utils.this_node():
            continue
        local_user, remote_user, node = _select_user_pair_for_ssh_for_secondary_components(node)
        try:
            remote_key_content = ssh_key.fetch_public_key_content_list(node, remote_user)[0]
            in_memory_key = ssh_key.InMemoryPublicKey(remote_key_content)
            ssh_key.AuthorizedKeyManager(cluster_shell).add(qnetd_addr, qnetd_user, in_memory_key)
        except ssh_key.Error:
            # crmsh#1850: if ssh-agent was used, there will not be a key pair on the node.
            logger.debug(
                "Skip adding the ssh key of %s:%s to authorized_keys of the qnetd node: keypair does not exist",
                remote_user, node,
            )

    user_by_host = utils.HostUserConfig()
    user_by_host.add(local_user, utils.this_node())
    user_by_host.add(qnetd_user, qnetd_addr)
    user_by_host.save_remote(cluster_node_list)


def init_qdevice():
    """
    Setup qdevice and qnetd service
    """
    if not _context.qdevice_inst:
        configure_qdevice_interactive()
    if not _context.qdevice_inst:
        ServiceManager().disable_service("corosync-qdevice.service")
        return
    is_qdevice_stage = _context.stage == "qdevice"

    logger.info("""Configure Qdevice/Qnetd:""")

    cluster_node_list = qdevice.get_node_list(is_qdevice_stage)
    _setup_passwordless_ssh_for_qnetd(cluster_node_list)

    qdevice_inst = _context.qdevice_inst
    if corosync.is_qdevice_configured() and not confirm("Qdevice is already configured - overwrite?"):
        if is_qdevice_stage:
            qdevice_inst.start_qdevice_service()
        return

    qdevice_inst.set_cluster_name()
    qdevice_inst.validate_and_start_qnetd()
    qdevice_inst.certificate_and_config_qdevice()

    if is_qdevice_stage:
        qdevice_inst.start_qdevice_service()
    adjust_properties()


def init():
    """
    Basic init
    """
    if _context.quiet:
        logger_utils.disable_info_in_console()
    log_start()
    init_network()


def join_ssh(seed_host, seed_user):
    """
    SSH configuration for joining node.
    """
    if not seed_host:
        utils.fatal("No existing IP/hostname specified (use -c option)")
    local_user = _context.current_user
    keys = _keys_from_ssh_agent() if _context.use_ssh_agent else list()
    return join_ssh_impl(local_user, seed_host, seed_user, keys)


def join_ssh_impl(local_user, seed_host, seed_user, ssh_public_keys: typing.List[ssh_key.Key]):
    ServiceManager(sh.ClusterShellAdaptorForLocalShell(sh.LocalShell())).start_service("sshd.service", enable=True)
    if ssh_public_keys:
        local_shell = sh.LocalShell(additional_environ={'SSH_AUTH_SOCK': os.environ.get('SSH_AUTH_SOCK')})
        ssh_shell = sh.SSHShell(local_shell, local_user)
        authorized_key_manager = ssh_key.AuthorizedKeyManager(ssh_shell)
        authorized_key_manager.add(seed_host, seed_user, ssh_public_keys[0])
        logger.info(
            'A public key is added to authorized_keys for user %s@%s: %s',
            local_user, seed_host, ssh_public_keys[0].fingerprint(),
        )
        authorized_key_manager.add(None, seed_user, ssh_public_keys[0])
        logger.info(
            'A public key is added to authorized_keys for user %s: %s',
            local_user, ssh_public_keys[0].fingerprint(),
        )
        # From here, login to remote_node is passwordless
        ssh_shell = sh.SSHShell(local_shell, local_user)
    else:
        local_shell = sh.LocalShell(additional_environ={'SSH_AUTH_SOCK': ''})
        result = ssh_copy_id_no_raise(local_user, seed_user, seed_host, local_shell)
        if 0 != result.returncode:
            msg = f"Failed to login to {seed_user}@{seed_host}. Please check the credentials."
            sudoer = userdir.get_sudoer()
            if sudoer and seed_user != sudoer:
                args = ['sudo crm']
                args += [x for x in sys.argv[1:]]
                for i, arg in enumerate(args):
                    if arg == '-c' or arg == '--cluster-node' and i + 1 < len(args):
                        if '@' not in args[i+1]:
                            args[i + 1] = f'{sudoer}@{seed_host}'
                            msg += '\nOr, run "{}".'.format(' '.join(args))
            raise ValueError(msg)
        # From here, login to remote_node is passwordless
        ssh_shell = sh.SSHShell(local_shell, local_user)
        authorized_key_manager = ssh_key.AuthorizedKeyManager(ssh_shell)
        if not result.public_keys:
            pass
        elif isinstance(result.public_keys[0], ssh_key.KeyFile):
            public_key = ssh_key.InMemoryPublicKey(
                generate_ssh_key_pair_on_remote(local_shell, local_user, seed_host, seed_user, seed_user),
            )
            authorized_key_manager.add( None, local_user, public_key)
            logger.info('A public key is added to authorized_keys for user %s: %s', local_user, public_key.fingerprint())
        elif isinstance(result.public_keys[0], ssh_key.InMemoryPublicKey):
            authorized_key_manager.add(None, local_user, result.public_keys[0])
            logger.info('A public key is added to authorized_keys for user %s: %s', local_user, result.public_keys[0].fingerprint())
        # else is not None do nothing
    if seed_user != 'root' and 0 != ssh_shell.subprocess_run_without_input(
            seed_host, seed_user, 'sudo true',
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
    ).returncode:
        raise ValueError(f'Failed to sudo on {seed_user}@{seed_host}')

    user_by_host = utils.HostUserConfig()
    user_by_host.clear()
    user_by_host.add(seed_user, seed_host)
    user_by_host.add(local_user, utils.this_node())
    user_by_host.save_local()
    detect_cluster_service_on_node(seed_host)
    user_by_host.add(seed_user, get_node_canonical_hostname(seed_host))
    user_by_host.save_local()

    configure_ssh_key('hacluster')
    change_user_shell('hacluster')
    swap_public_ssh_key_for_secondary_user(sh.cluster_shell(), seed_host, 'hacluster')

    if _context.stage:
        setup_passwordless_with_other_nodes(seed_host)


def join_ssh_with_ssh_agent(
        local_shell: sh.LocalShell,
        local_user: str, seed_host: str, seed_user: str,
        ssh_public_keys: typing.List[ssh_key.Key],
):
    # As ssh-agent is used, the local_user does not have any effects
    shell = sh.SSHShell(local_shell, 'root')
    authorized_key_manager = ssh_key.AuthorizedKeyManager(shell)
    if not shell.can_run_as(seed_host, seed_user):
        for key in ssh_public_keys:
            authorized_key_manager.add(seed_host, seed_user, key)
    for key in ssh_public_keys:
        authorized_key_manager.add(None, local_user, key)


def swap_public_ssh_key_for_secondary_user(shell: sh.ClusterShell, host: str, user: str):
    key_file_manager = ssh_key.KeyFileManager(shell)
    local_key = ssh_key.KeyFile(key_file_manager.list_public_key_for_user(None, user)[0])
    is_generated, remote_keys = key_file_manager.ensure_key_pair_exists_for_user(host, user)
    if is_generated:
        logger.info("A new ssh keypair is generated for user %s@%s.", user, host)
    authorized_key_manager = ssh_key.AuthorizedKeyManager(shell)
    authorized_key_manager.add(None, user, remote_keys[0])
    authorized_key_manager.add(host, user, local_key)


def swap_public_ssh_key(
        remote_node,
        local_user_to_swap,
        remote_user_to_swap,
        local_sudoer,
        remote_sudoer,
        local_shell: sh.LocalShell = None,  # FIXME: should not have default value
):
    """
    Swap public ssh key between remote_node and local
    """
    if local_shell is None:
        local_shell = sh.LocalShell()
    # Detect whether need password to login to remote_node
    if utils.check_ssh_passwd_need(local_user_to_swap, remote_user_to_swap, remote_node, local_shell):
        export_ssh_key_non_interactive(
            local_shell,
            local_user_to_swap, remote_user_to_swap,
            remote_node, local_sudoer, remote_sudoer,
        )

    public_key = generate_ssh_key_pair_on_remote(
        local_shell,
        local_sudoer, remote_node, remote_sudoer, remote_user_to_swap,
    )
    ssh_key.AuthorizedKeyManager(sh.SSHShell(sh.LocalShell(), local_user_to_swap)).add(
        None, local_user_to_swap, ssh_key.InMemoryPublicKey(public_key),
    )
    return public_key


def join_ssh_merge(cluster_node, remote_user):
    """
    Ensure known_hosts is the same in all nodes
    """
    logger.info("Merging known_hosts")

    # create local entry in known_hosts
    shell = sh.cluster_shell()
    hostname = shell.local_shell.hostname()
    local_user, remote_user = shell.user_of_host.user_pair_for_ssh(hostname)
    shell.local_shell.su_subprocess_run(
        local_user,
        f'ssh -o BatchMode=yes {constants.SSH_OPTION} {hostname}',
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    hosts = utils.fetch_cluster_node_list_from_node(cluster_node) + [utils.this_node()]
    known_hosts_new: set[str] = set()
    cat_cmd = "[ -e ~/.ssh/known_hosts ] && cat ~/.ssh/known_hosts || true"
    for host in hosts:
        known_hosts_content = shell.get_stdout_or_raise_error(cat_cmd, host)
        if known_hosts_content:
            known_hosts_new.update((utils.to_ascii(known_hosts_content) or "").splitlines())

    if known_hosts_new:
        script = _merge_line_into_file('~/.ssh/known_hosts', known_hosts_new)
        for host in hosts:
            shell.get_stdout_or_raise_error(script, host)


def setup_passwordless_with_other_nodes(init_node):
    """
    Setup passwordless with other cluster nodes

    Should fetch the node list from init node, then swap the key
    """
    # Fetch cluster nodes list
    local_user = _context.current_user
    local_shell = sh.LocalShell(
        additional_environ={'SSH_AUTH_SOCK': os.environ.get('SSH_AUTH_SOCK', '') if _context.use_ssh_agent else ''},
    )
    shell = sh.ClusterShell(local_shell, user_of_host.UserOfHost.instance(), _context.use_ssh_agent, True)
    rc, out, err = shell.get_rc_stdout_stderr_without_input(init_node, constants.CIB_QUERY)
    if rc != 0:
        utils.fatal("Can't fetch cluster nodes list from {}: {}".format(init_node, err))
    cluster_node_list = [x.uname for x in cibquery.get_cluster_nodes(etree.fromstring(out))]
    user_by_host = utils.HostUserConfig()
    user_by_host.add(local_user, utils.this_node())
    try:
        user_list, host_list = _fetch_core_hosts(shell, init_node)
        for user, host in zip(user_list, host_list):
            user_by_host.add(user, host)
    except ValueError:
        # No core.hosts on the seed host, may be a cluster upgraded from previous version
        pass
    user_by_host.save_local()

    # Filter out init node from cluster_nodes_list
    rc, out, err = shell.get_rc_stdout_stderr_without_input(init_node, 'hostname')
    if rc != 0:
        utils.fatal("Can't fetch hostname of {}: {}".format(init_node, err))
    init_node_hostname = out
    # Swap ssh public key between join node and other cluster nodes
    for node in (node for node in cluster_node_list if node != init_node_hostname):
        try:
            remote_privileged_user = utils.user_of(node)
        except UserNotFoundError:
            remote_privileged_user = local_user
        result = ssh_copy_id_no_raise(local_user, remote_privileged_user, node, local_shell)
        if result.returncode != 0:
            utils.fatal("Failed to login to remote host {}@{}".format(remote_privileged_user, node))
        else:
            user_by_host.add(remote_privileged_user, node)
            user_by_host.save_local()
        if utils.this_node() in cluster_node_list:
            nodes_including_self = cluster_node_list
        else:
            nodes_including_self = [utils.this_node()]
            nodes_including_self.extend(cluster_node_list)
        # FIXME: 2 layers of loop is unnecessary?
        _merge_ssh_authorized_keys(shell, user_of_host.UserOfHost.instance(), nodes_including_self)
        if local_user != 'hacluster':
            change_user_shell('hacluster', node)
            swap_public_ssh_key(node, 'hacluster', 'hacluster', local_user, remote_privileged_user, local_shell)
    if local_user != 'hacluster':
        swap_key_for_hacluster(cluster_node_list)

    user_by_host.save_remote(cluster_node_list)


def _merge_ssh_authorized_keys(shell: sh.ClusterShell, user_of_host: user_of_host.UserOfHost, nodes: typing.Sequence[str]):
    keys = set()
    with tempfile.TemporaryDirectory(prefix='crmsh-bootstrap-') as tmpdir:
        # sftp does not accept `~`
        for host, file in parallax.parallax_slurp(nodes, tmpdir, '.ssh/authorized_keys'):
            with open(file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.startswith('ssh-'):
                        keys.add(line.rstrip())
    script = _merge_line_into_file('~/.ssh/authorized_keys', keys)
    for node in nodes:
        rc, error = shell.get_rc_and_error(node, user_of_host.user_of(node), script)
        if rc != 0:
            raise ValueError(error)


def swap_key_for_hacluster(other_node_list):
    """
    In some cases, old cluster may not be configured passwordless for hacluster.
    The new join node should check and swap the public key between the old cluster nodes.
    """
    shell = sh.cluster_shell()
    key_file_manager = ssh_key.KeyFileManager(shell)
    authorized_key_manager = ssh_key.AuthorizedKeyManager(shell)
    keys: typing.List[ssh_key.Key] = [
        key_file_manager.ensure_key_pair_exists_for_user(node, 'hacluster')[1][0]
        for node in other_node_list
    ]
    keys.append(ssh_key.KeyFile(key_file_manager.list_public_key_for_user(None, 'hacluster')[0]))
    for key in keys:
        authorized_key_manager.add(None, 'hacluster', key)
    for node in other_node_list:
        for key in keys:
            authorized_key_manager.add(node, 'hacluster', key)


def sync_files_to_disk():
    """
    Sync file content to disk between cluster nodes
    """
    target_files_str = ""

    for f in get_files_to_sync():
        # check if the file exists on the local node
        if not os.path.isfile(f):
            continue
        try:
            # check if the file exists on the remote node
            utils.cluster_run_cmd(f"test -f {f}")
        except ValueError:
            continue
        else:
            target_files_str += f + " "

    if target_files_str:
        utils.cluster_run_cmd(f"sync {target_files_str.strip()}")


def detect_mountpoint(seed_host: str) -> None:
    # It would be massively useful at this point if new nodes could come
    # up in standby mode, so we could query the CIB locally to see if
    # there was any further local setup that needed doing, e.g.: creating
    # mountpoints for clustered filesystems.  Unfortunately we don't have
    # that yet, so the following crawling horror takes a punt on the seed
    # node being up, then asks it for a list of mountpoints...
    if seed_host:
        _rc, outp, _ = sh.cluster_shell().get_rc_stdout_stderr_without_input(seed_host, "cibadmin -Q --xpath \"//primitive\"")
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


def join_cluster(seed_host, remote_user):
    """
    Cluster configuration for joining node.
    """
    file_list_to_retrieve = [f for f in get_files_to_sync() if f != CSYNC2_KEY and f != CSYNC2_CFG]
    retrieve_files(seed_host, file_list_to_retrieve)

    is_qdevice_configured = corosync.is_qdevice_configured()
    if is_qdevice_configured and not ServiceManager().service_is_available("corosync-qdevice.service"):
        utils.fatal("corosync-qdevice.service is not available")

    shell = sh.cluster_shell()

    if is_qdevice_configured:
        if not _context.use_ssh_agent or not _keys_from_ssh_agent():
            # trigger init_qnetd_remote on init node
            cmd = f"crm cluster init qnetd_remote {utils.this_node()} -y"
            shell.get_stdout_or_raise_error(cmd, seed_host)

    shutil.copy(corosync.conf(), _context.get_corosync_conf_orig())

    # check if use IPv6
    _context.ipv6 = corosync.is_using_ipv6()

    init_network()

    link_number = corosync.get_link_number()
    join_link_number = len(_context.default_ip_list)
    # the join link number can't be greater than the peer's link number
    # or less than the peer's link number if -y is set
    if join_link_number > link_number or (_context.yes_to_all and join_link_number < link_number):
        utils.fatal(f"Node {seed_host} has {link_number} links, but provided {join_link_number}")

    detect_mountpoint(seed_host)

    # If corosync.conf() doesn't exist or is empty, we will fail here. (bsc#943227)
    if not os.path.exists(corosync.conf()):
        utils.fatal("{} is not readable. Please ensure that hostnames are resolvable.".format(corosync.conf()))

    ringXaddr_res = []
    for i in range(link_number):
        while True:
            ringXaddr = prompt_for_string(
                    'Address for ring{}'.format(i),
                    default=pick_default_value(_context.default_ip_list, ringXaddr_res),
                    valid_func=Validation.valid_ucast_ip,
                    prev_value=ringXaddr_res)
            if not ringXaddr:
                error("No value for ring{}".format(i))
            ringXaddr_res.append(ringXaddr)
            break
    print("")
    invoke("rm -f /var/lib/pacemaker/cib/*")
    try:
        corosync.add_node_config(ringXaddr_res)
    except corosync.IPAlreadyConfiguredError as e:
        logger.warning(e)
    sync_path(corosync.conf(), seed_host)
    shell.get_stdout_or_raise_error('corosync-cfgtool -R', seed_host)

    _context.sbd_manager.join_sbd(remote_user, seed_host)

    # Initialize the cluster before adjusting quorum. This is so
    # that we can query the cluster to find out how many nodes
    # there are (so as not to adjust multiple times if a previous
    # attempt to join the cluster failed)
    init_cluster_local()

    adjust_properties()

    # Ditch no-quorum-policy=ignore
    no_quorum_policy = utils.get_property("no-quorum-policy")
    if no_quorum_policy == "ignore":
        logger.info("Ditching no-quorum-policy=ignore")
        if not utils.delete_property("no-quorum-policy"):
            logger.error("Failed to delete no-quorum-policy=ignore")

    corosync.configure_two_node()
    sync_path(corosync.conf(), seed_host)
    sync_files_to_disk()

    with logger_utils.status_long("Reloading cluster configuration"):
        shell.get_stdout_or_raise_error("corosync-cfgtool -R")

    if is_qdevice_configured:
        start_qdevice_on_join_node(seed_host)
    else:
        ServiceManager(sh.ClusterShellAdaptorForLocalShell(sh.LocalShell())).disable_service("corosync-qdevice.service")


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
    pcmk_delay_max_value = utils.get_pcmk_delay_max_configured_value()
    if pcmk_delay_max_value > 0 and is_2node_wo_qdevice:
        utils.set_property("priority-fencing-delay", 2*pcmk_delay_max_value, conditional=True)
    else:
        utils.set_property("priority-fencing-delay", 0)


def start_qdevice_on_join_node(seed_host):
    """
    Doing qdevice certificate process and start qdevice service on join node
    """
    with logger_utils.status_long(f"Starting and enable corosync-qdevice.service on {utils.this_node()}"):
        if corosync.is_qdevice_tls_on():
            qnetd_addr = corosync.get_value("quorum.device.net.host")
            qdevice_inst = qdevice.QDevice(qnetd_addr, cluster_node=seed_host)
            qdevice_inst.certificate_process_on_join()
        ServiceManager(sh.ClusterShellAdaptorForLocalShell(sh.LocalShell())).start_service("corosync-qdevice.service", enable=True)


def get_cluster_node_ip(node: str) -> str:
    """
    ringx_addr might be hostname or IP
    _context.cluster_node by now is always hostname

    If ring0_addr is IP, we should get the configured iplist which belong _context.cluster_node
    Then filter out which one is configured as ring0_addr
    At last assign that ip to _context.cluster_node_ip which will be removed later
    """
    addr_list = corosync.get_values('nodelist.node.ring0_addr')
    if node in addr_list:
        return

    ip_list = utils.get_iplist_from_name(node)
    for ip in ip_list:
        if ip in addr_list:
            return ip


def stop_and_disable_services(remote_addr=None):
    """
    Stop and disable cluster related service
    """
    service_manager = ServiceManager()
    for service in SERVICES_STOP_LIST:
        if service_manager.service_is_active(service, remote_addr=remote_addr):
            logger.info("Stopping and disable %s on node %s", service, remote_addr or utils.this_node())
            service_manager.stop_service(service, disable=True, remote_addr=remote_addr)
    for service in SERVICES_DISABLE_LIST:
        if service_manager.service_is_enabled(service, remote_addr=remote_addr):
            logger.info("Disable %s on node %s", service, remote_addr or utils.this_node())
            service_manager.disable_service(service, remote_addr=remote_addr)


def rm_configuration_files(remote=None):
    """
    Delete configuration files from the node to be removed
    """
    shell = sh.cluster_shell()
    shell.get_stdout_or_raise_error("rm -f {}".format(' '.join(_context.rm_list)), remote)
    if os.path.exists(sbd.SBDManager.SYSCONFIG_SBD):
        sbd.cleanup_sbd_configurations(remote)


def remove_pacemaker_remote_node_from_cluster(node):
    logger.info("Removing pacemaker remote node %s from cluster", node)
    shell = sh.cluster_shell()
    remote_node_res_id = xmlutil.CrmMonXmlParser().get_res_id_of_remote_node(node)
    if not remote_node_res_id:
        logger.error("Cannot find the resource ID of the pacemaker remote node %s", node)
        return
    shell.get_stdout_or_raise_error(f"crm resource stop {remote_node_res_id}")
    shell.get_stdout_or_raise_error(f"crm configure delete {remote_node_res_id}")
    logger.info("Removing node %s from CIB", node)
    if not NodeMgmt.call_delnode(node):
        utils.fatal("Failed to remove {}.".format(node))


def remove_node_from_cluster(node, dead_node=False):
    """
    Remove node from running cluster and the corosync / pacemaker configuration.
    """
    if xmlutil.CrmMonXmlParser().is_node_remote(node):
        remove_pacemaker_remote_node_from_cluster(node)
        return

    node_ip = get_cluster_node_ip(node)
    if not dead_node:
        stop_and_disable_services(remote_addr=node)
        qdevice.QDevice.remove_qdevice_db([node])
        rm_configuration_files(node)

    # execute the command : crm node delete $HOSTNAME
    logger.info("Removing node %s from CIB", node)
    if not NodeMgmt.call_delnode(node):
        utils.fatal("Failed to remove {}.".format(node))

    # Remove node from nodelist
    if corosync.get_values("nodelist.node.ring0_addr"):
        corosync.del_node(node_ip if node_ip is not None else node)

    corosync.configure_two_node(removing=True)
    logger.info("Propagating configuration changes across the remaining nodes")
    sync_path(corosync.conf())
    sh.cluster_shell().get_stdout_or_raise_error("corosync-cfgtool -R")

    adjust_properties()

    if not dead_node:
        FirewallManager(peer=node).remove_service()

    user_by_host = utils.HostUserConfig()
    user_by_host.remove(node)
    user_by_host.save_remote(utils.list_cluster_nodes())


def ssh_stage_finished():
    """
    Dectect if the ssh stage is finished
    """
    feature_check = crmsh.healthcheck.PasswordlessHaclusterAuthenticationFeature()
    return feature_check.check_quick() and feature_check.check_local([utils.this_node()])


def corosync_stage_finished():
    """
    Dectect if the corosync stage is finished
    """
    return corosync.is_valid_corosync_conf()


INIT_STAGE_CHECKER = {
        "ssh": ssh_stage_finished,
        "firewalld": FirewallManager.firewalld_stage_finished,
        "corosync": corosync_stage_finished,
        "cluster": is_online
}


JOIN_STAGE_CHECKER = {
        "ssh": ssh_stage_finished,
        "firewalld": FirewallManager.firewalld_stage_finished,
        "ssh_merge": lambda: True,
        "cluster": is_online
}


def check_stage_dependency(stage):
    stage_checker = INIT_STAGE_CHECKER if _context.type == "init" else JOIN_STAGE_CHECKER
    if stage not in stage_checker:
        return
    for stage_name, check_func in stage_checker.items():
        if stage == stage_name:
            break
        if not check_func():
            utils.fatal(f"Please run '{stage_name}' stage first")


def bootstrap_init(context):
    """
    Init cluster process
    """
    global _context
    _context = context
    stage = _context.stage

    _context.validate()

    init()

    _context.load_profiles()
    _context.init_sbd_manager()

    if stage in ('qnetd_remote', ):
        args = _context.args
        logger_utils.log_only_to_file(f"args: {args}")
        if len(args) != 2:
            utils.fatal(f"Expected NODE argument for '{stage}' stage")
        _context.cluster_node = args[1]
    else:
        check_tty()
        if not check_prereqs():
            return

    if stage != "":
        check_stage_dependency(stage)
        globals()["init_" + stage]()
    else:
        init_ssh()
        init_firewalld()
        init_corosync()
        init_sbd()

        lock_inst = lock.Lock()
        try:
            with lock_inst.lock():
                init_qdevice()
                init_cluster()
                init_admin()
                init_ocfs2()
                init_gfs2()
        except lock.ClaimLockError as err:
            utils.fatal(err)

    bootstrap_finished()


def bootstrap_add(context):
    """
    Adds the given node to the cluster.
    """
    if not context.user_at_node_list:
        return

    global _context
    _context = context

    options = ""
    for nic in _context.interfaces_inst.input_nic_list:
        options += '-i {} '.format(nic)
    options = " {}".format(options.strip()) if options else ""

    if not context.use_ssh_agent:
        options += ' --no-use-ssh-agent'

    shell = sh.ClusterShell(
        sh.LocalShell({'SSH_AUTH_SOCK': os.environ.get('SSH_AUTH_SOCK', '') if _context.use_ssh_agent else ''}),
        UserOfHost.instance(),
        _context.use_ssh_agent,
    )
    for (user, node) in (_parse_user_at_host(x, _context.current_user) for x in _context.user_at_node_list):
        print()
        logger.info("Adding node {} to cluster".format(node))
        cmd = 'crm cluster join -y {} -c {}@{}'.format(options, _context.current_user, utils.this_node())
        logger.info("Running command on {}: {}".format(node, cmd))
        out = shell.get_stdout_or_raise_error(cmd, node)
        print(out)


def detect_cluster_service_on_node(peer_node):
    service_manager = ServiceManager()
    for _ in range(REJOIN_COUNT):
        if service_manager.service_is_active("pacemaker.service", peer_node):
            break
        logger.warning("Cluster is inactive on %s. Retry in %d seconds", peer_node, REJOIN_INTERVAL)
        sleep(REJOIN_INTERVAL)
    else:
        utils.fatal("Cluster is inactive on {}".format(peer_node))


def bootstrap_join(context):
    """
    Join cluster process
    """
    global _context
    _context = context

    _context.validate()

    init()
    _context.init_sbd_manager()

    check_tty()

    if not check_prereqs():
        return

    if _context.stage != "":
        remote_user, cluster_node = _parse_user_at_host(_context.cluster_node, _context.current_user)
        check_stage_dependency(_context.stage)
        globals()["join_" + _context.stage](cluster_node, remote_user)
    else:
        if not _context.yes_to_all and _context.cluster_node is None:
            logger.info("""Join This Node to Cluster:
  You will be asked for the IP address of an existing node, from which
  configuration will be copied.  If you have not already configured
  passwordless ssh between nodes, you will be prompted for the root
  password of the existing node.
""")
            # TODO: prompt for user@host
            cluster_user_at_node = prompt_for_string("IP address or hostname of existing node (e.g.: 192.168.1.1)", ".+")
            _context.cluster_node = cluster_user_at_node
            _context.initialize_user()

        remote_user, cluster_node = _parse_user_at_host(_context.cluster_node, _context.current_user)
        utils.ssh_port_reachable_check(cluster_node)
        join_ssh(cluster_node, remote_user)
        remote_user = utils.user_of(cluster_node)

        lock_inst = lock.RemoteLock(cluster_node)
        try:
            with lock_inst.lock():
                service_manager = ServiceManager()
                utils.check_all_nodes_reachable("joining a node to the cluster", cluster_node, check_passwd=False)
                setup_passwordless_with_other_nodes(cluster_node)
                join_firewalld()
                join_ssh_merge(cluster_node, remote_user)
                probe_partitions()
                join_cluster_fs(cluster_node, remote_user)
                join_cluster(cluster_node, remote_user)
        except (lock.SSHError, lock.ClaimLockError) as err:
            utils.fatal(err)

    bootstrap_finished()


def bootstrap_finished():
    logger.info("Done (log saved to %s on %s)", log.CRMSH_LOG_FILE, utils.this_node())


def join_cluster_fs(peer_host, peer_user):
    """
    If init node configured OCFS2/GFS2 device, verify that device on join node
    """
    inst = cluster_fs.ClusterFSManager(_context)
    inst.join(peer_host)


def remove_qdevice() -> None:
    """
    Remove qdevice service and configuration from cluster
    """
    if not corosync.is_qdevice_configured():
        utils.fatal("No QDevice configuration in this cluster")
    if not confirm("Removing QDevice service and configuration from cluster: Are you sure?"):
        return

    utils.check_all_nodes_reachable("removing QDevice from the cluster")
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
        corosync.configure_two_node(removing=True)
        sync_path(corosync.conf())
    if qdevice_reload_policy == qdevice.QdevicePolicy.QDEVICE_RELOAD:
        sh.cluster_shell().get_stdout_or_raise_error("corosync-cfgtool -R")
    elif qdevice_reload_policy == qdevice.QdevicePolicy.QDEVICE_RESTART:
        restart_cluster()
    else:
        logger.warning("To remove qdevice service, need to restart cluster service manually on each node")

    adjust_properties()


def bootstrap_remove(context):
    """
    Remove node from cluster, or remove qdevice configuration
    """
    global _context
    _context = context
    force_flag = crmsh.options.force or _context.force

    init()

    if _context.qdevice_rm_flag and _context.cluster_node:
        utils.fatal("Either remove node or qdevice")
    if _context.cluster_node:
        logger.info("Removing node %s from cluster", _context.cluster_node)

    service_manager = ServiceManager()
    if not service_manager.service_is_active("corosync.service"):
        utils.fatal("Cluster is not active - can't execute removing action")

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
        _context.initialize_user()

    if not _context.cluster_node:
        utils.fatal("No existing IP/hostname specified (use -c option)")

    remote_user, cluster_node = _parse_user_at_host(_context.cluster_node, _context.current_user)

    try:
        utils.check_all_nodes_reachable("removing a node from the cluster")
    except utils.DeadNodeError as e:
        if force_flag and cluster_node in e.summary.dead_nodes:
            remove_node_from_cluster(cluster_node, dead_node=True)
            bootstrap_finished()
            return
        else:
            raise

    if service_manager.service_is_active("pacemaker.service", cluster_node):
        cluster_node = get_node_canonical_hostname(cluster_node)

    if not force_flag and not confirm("Removing node \"{}\" from the cluster: Are you sure?".format(cluster_node)):
        return

    if cluster_node == utils.this_node():
        if not force_flag:
            utils.fatal("Removing self requires --force")
        remove_self(force_flag)
    else:
        configured_nodes = xmlutil.CrmMonXmlParser().get_node_list()
        if cluster_node in configured_nodes:
            remove_node_from_cluster(cluster_node)
        else:
            utils.fatal(f"Node {cluster_node} is not configured in cluster! (valid nodes: {', '.join(configured_nodes)})")

    bootstrap_finished()


def remove_self(force_flag=False):
    me = utils.this_node()
    yes_to_all = _context.yes_to_all
    nodes = utils.list_cluster_nodes()
    othernode = next((x for x in nodes if x != me), None)
    if othernode is not None:
        logger.info("Removing node %s from cluster on %s", me, othernode)
        cmd = "crm{} cluster remove{} -c {}".format(" -F" if force_flag else "", " -y" if yes_to_all else "", me)
        rc, stdout, stderr = sh.cluster_shell().get_rc_stdout_stderr_without_input(othernode, cmd)
        if rc != 0:
            utils.fatal(f"Failed to remove this node from {othernode}: {stderr}")
        elif stdout:
            print(stdout)
    else:
        # disable and stop cluster
        stop_and_disable_services()
        qdevice.QDevice.remove_certification_files_on_qnetd()
        qdevice.QDevice.remove_qdevice_db([utils.this_node()])
        rm_configuration_files()
        FirewallManager().remove_service()


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
        utils.rmfile(BOOTH_AUTH)
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
        utils.rmfile(BOOTH_CFG)
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
    sync_path(BOOTH_DIR)
    init_csync2_geo()
    geo_cib_config(_context.clusters)


def geo_fetch_config(node):
    cmd = "tar -c -C '{}' .".format(BOOTH_DIR)
    with tempfile.TemporaryDirectory() as tmpdir:
        pipe_outlet, pipe_inlet = os.pipe()
        try:
            child = subprocess.Popen(['tar', '-x', '-C', tmpdir], stdin=pipe_outlet, stderr=subprocess.DEVNULL)
        except Exception:
            os.close(pipe_inlet)
            raise
        finally:
            os.close(pipe_outlet)
        try:
            result = sh.cluster_shell().subprocess_run_without_input(node, None, cmd, stdout=pipe_inlet, stderr=subprocess.PIPE)
        finally:
            os.close(pipe_inlet)
        rc = child.wait()
        if result.returncode != 0:
            utils.fatal("Failed to create ssh connection to {}: {}".format(node, result.stderr))
        if rc != 0:
            raise ValueError("Problem encountered with booth configuration from {}.".format(node))
        try:
            if os.path.isfile("%s/authkey" % (tmpdir)):
                invoke("mv %s/authkey %s" % (tmpdir, BOOTH_AUTH))
                os.chmod(BOOTH_AUTH, 0o600)
            if os.path.isfile("%s/booth.conf" % (tmpdir)):
                invoke("mv %s/booth.conf %s" % (tmpdir, BOOTH_CFG))
                os.chmod(BOOTH_CFG, 0o644)
        except OSError as err:
            raise ValueError("Problem encountered with booth configuration from {}: {}".format(node, err))


def _select_user_pair_for_ssh_for_secondary_components(dest: str):
    """Select a user pair for operating secondary components, e.g. qdevice and geo cluster arbitor"""
    user, node = utils.parse_user_at_host(dest)
    if user is not None:
        try:
            local_user = utils.user_of(utils.this_node())
        except UserNotFoundError:
            local_user = user
        remote_user = user
    else:
        try:
            local_user, remote_user = UserOfHost.instance().user_pair_for_ssh(node)
        except UserNotFoundError:
            try:
                local_user = utils.user_of(utils.this_node())
            except UserNotFoundError:
                local_user = userdir.getuser()
            remote_user = local_user
    return local_user, remote_user, node


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
    user, node = utils.parse_user_at_host(_context.cluster_node)
    if not sh.cluster_shell().can_run_as(node, 'root'):
        local_user, remote_user, node = _select_user_pair_for_ssh_for_secondary_components(_context.cluster_node)
        local_shell = sh.LocalShell(additional_environ={
            'SSH_AUTH_SOCK': os.environ.get('SSH_AUTH_SOCK', '') if _context.use_ssh_agent else '',
        })
        result = ssh_copy_id_no_raise(local_user, remote_user, node, local_shell)
        if 0 != result.returncode:
            raise ValueError(f"Failed to login to {remote_user}@{node}. Please check the credentials.")
        user_by_host = utils.HostUserConfig()
        user_by_host.add(local_user, utils.this_node())
        user_by_host.add(remote_user, node)
        user_by_host.save_local()
    geo_fetch_config(node)
    logger.info("Sync booth configuration across cluster")
    sync_path(BOOTH_DIR)
    geo_cib_config(_context.clusters)


def bootstrap_arbitrator(context):
    """
    Configure this machine as an arbitrator.
    It fetches its booth configuration from a cluster node already in the cluster.
    """
    global _context
    _context = context

    init_common_geo()
    check_tty()
    user, node = utils.parse_user_at_host(_context.cluster_node)
    user_by_host = utils.HostUserConfig()
    user_by_host.clear()
    user_by_host.save_local()
    if not sh.cluster_shell().can_run_as(node, 'root'):
        local_user, remote_user, node = _select_user_pair_for_ssh_for_secondary_components(_context.cluster_node)
        local_shell = sh.LocalShell(additional_environ={
            'SSH_AUTH_SOCK': os.environ.get('SSH_AUTH_SOCK', '') if _context.use_ssh_agent else '',
        })
        result = ssh_copy_id_no_raise(local_user, remote_user, node, local_shell)
        if 0 != result.returncode:
            raise ValueError(f"Failed to login to {remote_user}@{node}. Please check the credentials.")
        user_by_host.add(local_user, utils.this_node())
        user_by_host.add(remote_user, node)
        user_by_host.save_local()
    init_firewalld()
    geo_fetch_config(node)
    if not os.path.isfile(BOOTH_CFG):
        utils.fatal("Failed to copy {} from {}".format(BOOTH_CFG, _context.cluster_node))
    # TODO: verify that the arbitrator IP in the configuration is us?
    logger.info("Enabling and starting the booth arbitrator service")
    ServiceManager(sh.ClusterShellAdaptorForLocalShell(sh.LocalShell())).start_service("booth@booth", enable=True)


def get_fencing_timeout_generally_expected():
    """
    Adjust fencing-timeout for all scenarios, formula is:

    fencing-timeout = FENCING_TIMEOUT_DEFAULT + token + consensus
    """
    fencing_enabled = utils.get_property("fencing-enabled")
    # When fencing disabled, return
    if utils.is_boolean_false(fencing_enabled):
        return None

    return FENCING_TIMEOUT_DEFAULT + corosync.token_and_consensus_timeout()


def adjust_pcmk_delay_max(is_2node_wo_qdevice):
    """
    For each fence agent,
    add parameter pcmk_delay_max when cluster is two-node cluster without qdevice
    else remove pcmk_delay_max
    """
    cib_factory = cibconfig.cib_factory_instance()
    cib_factory.refresh()

    shell = sh.cluster_shell()
    if is_2node_wo_qdevice:
        for res in cib_factory.fence_id_list_without_pcmk_delay():
            cmd = "crm resource param {} set pcmk_delay_max {}s".format(res, PCMK_DELAY_MAX)
            shell.get_stdout_or_raise_error(cmd)
            logger.info("Add parameter 'pcmk_delay_max={}s' for resource '{}'".format(PCMK_DELAY_MAX, res))
    else:
        for res in cib_factory.fence_id_list_with_pcmk_delay():
            cmd = "crm resource param {} delete pcmk_delay_max".format(res)
            shell.get_stdout_or_raise_error(cmd)
            logger.info("Delete parameter 'pcmk_delay_max' for resource '{}'".format(res))


def adjust_fencing_timeout():
    """
    Adjust fencing-timeout for sbd and other scenarios
    """
    if ServiceManager().service_is_active(constants.SBD_SERVICE):
        sbd.SBDConfigChecker(quiet=True, fix=True).check_and_fix()
    else:
        value = get_fencing_timeout_generally_expected()
        if value:
            utils.set_property("fencing-timeout", value, conditional=True)


def adjust_properties():
    """
    Adjust properties for the cluster:
    - pcmk_delay_max
    - fencing-timeout
    - priority in rsc_defaults
    - priority-fencing-delay

    Call it when:
    - node join/remove
    - add qdevice via stage
    - remove qdevice
    - add sbd via stage
    """
    if not ServiceManager().service_is_active("pacemaker.service"):
        return
    is_2node_wo_qdevice = utils.is_2node_cluster_without_qdevice()
    adjust_pcmk_delay_max(is_2node_wo_qdevice)
    adjust_fencing_timeout()
    adjust_priority_in_rsc_defaults(is_2node_wo_qdevice)
    adjust_priority_fencing_delay(is_2node_wo_qdevice)
    sbd.SBDManager.warn_diskless_sbd()


def retrieve_files(from_node: str, file_list: list, msg: str = None):
    find_args = ' '.join(shlex.quote(f) for f in file_list)
    cmd = f'find {find_args} -print | cpio -o'

    if not msg:
        msg = f"Retrieving all configuration files from {from_node}"

    with logger_utils.status_long(msg):
        pipe_outlet, pipe_inlet = os.pipe()
        try:
            child = subprocess.Popen(['cpio', '-iud'], stdin=pipe_outlet, stderr=subprocess.DEVNULL)
        except Exception:
            os.close(pipe_inlet)
            raise
        finally:
            os.close(pipe_outlet)
        try:
            result = sh.cluster_shell().subprocess_run_without_input(
                    from_node, None, cmd, stdout=pipe_inlet, stderr=subprocess.DEVNULL
            )
        finally:
            os.close(pipe_inlet)
        rc = child.wait()
        # Some errors may happen here, since all files in get_files_to_sync() may not exist.
        if result is None or result.returncode == 255:
            utils.fatal(f"Failed to create ssh connect to {from_node}")
        if rc != 0:
            utils.fatal(f"Failed to retrieve files from {from_node}")


def sync_path(path, peer_node=None):
    """
    Sync files between cluster nodes
    """
    node_list = []
    if peer_node:
        node_list = utils.fetch_cluster_node_list_from_node(peer_node)
    utils.cluster_copy_path(path, nodes=node_list)


def restart_cluster():
    logger.info("Restarting cluster service")
    utils.cluster_run_cmd("crm cluster restart")
    wait_for_cluster()


def get_files_to_sync():
    return (
        (
            corosync.conf(),
            watchdog.Watchdog.WATCHDOG_CFG,
            sbd.SBDManager.SYSCONFIG_SBD,
            sbd.SBDManager.SBD_SYSTEMD_DELAY_START_DIR,
            sbd.SBDManager.SBD_SYSTEMD_DELAY_START_DISABLE_DIR
        ) + STATIC_FILES_TO_SYNC
    )
# EOF
