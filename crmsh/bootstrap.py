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
from string import Template
from lxml import etree
from pathlib import Path
from . import config
from . import utils
from . import xmlutil
from .cibconfig import mkset_obj, cib_factory
from . import corosync
from . import tmpfiles
from . import clidisplay
from . import term
from . import lock


LOG_FILE = "/var/log/crmsh/ha-cluster-bootstrap.log"
CSYNC2_KEY = "/etc/csync2/key_hagroup"
CSYNC2_CFG = "/etc/csync2/csync2.cfg"
COROSYNC_AUTH = "/etc/corosync/authkey"
SYSCONFIG_SBD = "/etc/sysconfig/sbd"
SYSCONFIG_FW = "/etc/sysconfig/SuSEfirewall2"
SYSCONFIG_FW_CLUSTER = "/etc/sysconfig/SuSEfirewall2.d/services/cluster"
PCMK_REMOTE_AUTH = "/etc/pacemaker/authkey"
COROSYNC_CONF_ORIG = tmpfiles.create()[1]
RSA_PRIVATE_KEY = "/root/.ssh/id_rsa"
RSA_PUBLIC_KEY = "/root/.ssh/id_rsa.pub"
AUTHORIZED_KEYS_FILE = "/root/.ssh/authorized_keys"
SERVICES_STOP_LIST = ["corosync-qdevice.service", "corosync.service", "hawk.service"]

INIT_STAGES = ("ssh", "ssh_remote", "csync2", "csync2_remote", "corosync", "storage", "sbd", "cluster", "vgfs", "admin", "qdevice")


class Context(object):
    """
    Context object used to avoid having to pass these variables
    to every bootstrap method.
    """
    def __init__(self):
        '''
        Initialize attributes
        '''
        self.type = None # init or join
        self.quiet = None
        self.yes_to_all = None
        self.template = None
        self.cluster_name = None
        self.watchdog = None
        self.no_overwrite_sshkey = None
        self.nic_list = None
        self.unicast = None
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
        self.shared_device = None
        self.ocfs2_device = None
        self.cluster_node = None
        self.cluster_node_ip = None
        self.force = None
        self.arbitrator = None
        self.clusters = None
        self.tickets = None
        self.sbd_manager = None
        self.sbd_devices = None
        self.diskless_sbd = None
        self.stage = None
        self.args = None
        self.ui_context = None
        self.interfaces_inst = None
        self.default_nic_list = []
        self.default_ip_list = []
        self.local_ip_list = []
        self.local_network_list = []
        self.rm_list = [SYSCONFIG_SBD, CSYNC2_CFG, corosync.conf(), CSYNC2_KEY,
                COROSYNC_AUTH, "/var/lib/heartbeat/crm/*", "/var/lib/pacemaker/cib/*"]

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
        self.qdevice_inst = corosync.QDevice(
                self.qnetd_addr,
                port=self.qdevice_port,
                algo=self.qdevice_algo,
                tie_breaker=self.qdevice_tie_breaker,
                tls=self.qdevice_tls,
                cmds=self.qdevice_heuristics,
                mode=self.qdevice_heuristics_mode)

    def validate_option(self):
        """
        Validate options
        """
        if self.admin_ip:
            try:
                Validation.valid_admin_ip(self.admin_ip)
            except ValueError as err:
                error(err)
        if self.qdevice_inst:
            try:
                self.qdevice_inst.valid_attr()
            except ValueError as err:
                error(err)
        if self.nic_list:
            if len(self.nic_list) > 2:
                error("Maximum number of interface is 2")
            if len(self.nic_list) != len(set(self.nic_list)):
                error("Duplicated input")
        if self.no_overwrite_sshkey:
            warn("--no-overwrite-sshkey option is deprecated since crmsh does not overwrite ssh keys by default anymore and will be removed in future versions")
        if self.type == "join" and self.watchdog:
            warn("-w option is deprecated and will be removed in future versions")

    def init_sbd_manager(self):
        self.sbd_manager = SBDManager(self.sbd_devices, self.diskless_sbd)


class Watchdog(object):
    """
    Class to find valid watchdog device name
    """
    QUERY_CMD = "sbd query-watchdog"
    DEVICE_FIND_REGREX = "\[[0-9]+\] (/dev/.*)\n.*\nDriver: (.*)"

    def __init__(self, _input=None, peer_host=None):
        """
        Init function
        """
        self._input = _input
        self._peer_host = peer_host
        self._watchdog_info_dict = {}
        self._watchdog_device_name = None
    
    @property
    def watchdog_device_name(self):
        return self._watchdog_device_name

    @staticmethod
    def _verify_watchdog_device(dev, ignore_error=False):
        """
        Use wdctl to verify watchdog device
        """
        rc, _, err = utils.get_stdout_stderr("wdctl {}".format(dev))
        if rc != 0:
            if ignore_error:
                return False
            else:
                error("Invalid watchdog device {}: {}".format(dev, err))
        return True

    @staticmethod
    def _load_watchdog_driver(driver):
        """
        Load specific watchdog driver
        """
        invoke("echo {} > /etc/modules-load.d/watchdog.conf".format(driver))
        invoke("systemctl restart systemd-modules-load")

    @staticmethod
    def _get_watchdog_device_from_sbd_config():
        """
        Try to get watchdog device name from sbd config file
        """
        conf = utils.parse_sysconfig(SYSCONFIG_SBD)
        return conf.get("SBD_WATCHDOG_DEV")

    @staticmethod
    def _driver_is_loaded(driver):
        """
        Check if driver was already loaded
        """
        _, out, _ = utils.get_stdout_stderr("lsmod")
        return re.search("\n{}\s+".format(driver), out)

    def _set_watchdog_info(self):
        """
        Set watchdog info through sbd query-watchdog command
        Content in self._watchdog_info_dict: {device_name: driver_name}
        """
        rc, out, err = utils.get_stdout_stderr(self.QUERY_CMD)
        if rc == 0 and out:
            # output format might like:
            #   [1] /dev/watchdog\nIdentity: Software Watchdog\nDriver: softdog\n
            self._watchdog_info_dict = dict(re.findall(self.DEVICE_FIND_REGREX, out))
        else:
            error("Failed to run {}: {}".format(self.QUERY_CMD, err))

    def _get_device_through_driver(self, driver_name):
        """
        Get watchdog device name which has driver_name
        """
        for device, driver in self._watchdog_info_dict.items():
            if driver == driver_name and self._verify_watchdog_device(device):
                return device
        return None

    def _get_driver_through_device_remotely(self, dev_name):
        """
        Given watchdog device name, get driver name on remote node
        """
        cmd = "ssh -o StrictHostKeyChecking=no root@{} {}".format(self._peer_host, self.QUERY_CMD)
        rc, out, err = utils.get_stdout_stderr(cmd)
        if rc == 0 and out:
            # output format might like:
            #   [1] /dev/watchdog\nIdentity: Software Watchdog\nDriver: softdog\n
            device_driver_dict = dict(re.findall(self.DEVICE_FIND_REGREX, out))
            if device_driver_dict and dev_name in device_driver_dict:
                return device_driver_dict[dev_name]
            else:
                return None
        else:
            error("Failed to run {} remotely: {}".format(self.QUERY_CMD, err))

    def _get_first_unused_device(self):
        """
        Get first unused watchdog device name
        """
        for dev in self._watchdog_info_dict:
            if self._verify_watchdog_device(dev, ignore_error=True):
                return dev
        return None

    def _set_input(self):
        """
        If self._input was not provided by option:
          1. Try to get it from sbd config file
          2. Try to get the first valid device from result of sbd query-watchdog
          3. Set the self._input as softdog
        """
        if not self._input:
            dev = self._get_watchdog_device_from_sbd_config()
            if dev and self._verify_watchdog_device(dev, ignore_error=True):
                self._input = dev
                return
            first_unused = self._get_first_unused_device()
            self._input = first_unused if first_unused else "softdog"

    def _valid_device(self, dev):
        """
        Is an unused watchdog device
        """
        if dev in self._watchdog_info_dict and self._verify_watchdog_device(dev):
            return True
        return False

    def join_watchdog(self):
        """
        In join proces, get watchdog device from config
        If that device not exist, get driver name from init node, and load that driver
        """
        self._set_watchdog_info()

        res = self._get_watchdog_device_from_sbd_config()
        if not res:
            error("Failed to get watchdog device from {}".format(SYSCONFIG_SBD))
        self._input = res

        if not self._valid_device(self._input):
            driver = self._get_driver_through_device_remotely(self._input)
            self._load_watchdog_driver(driver)

    def init_watchdog(self):
        """
        In init process, find valid watchdog device
        """
        self._set_watchdog_info()
        self._set_input()

        # self._input is a device name
        if self._valid_device(self._input):
            self._watchdog_device_name = self._input
            return

        # self._input is invalid, exit
        if not invokerc("modinfo {}".format(self._input)):
            error("Should provide valid watchdog device or driver name by -w option")

        # self._input is a driver name, load it if it was unloaded
        if not self._driver_is_loaded(self._input):
            self._load_watchdog_driver(self._input)
            self._set_watchdog_info()

        # self._input is a loaded driver name, find corresponding device name
        res = self._get_device_through_driver(self._input)
        if res:
            self._watchdog_device_name = res
            return


class SBDManager(object):
    """
    Class to manage sbd configuration and services
    """
    SYSCONFIG_SBD_TEMPLATE = "/usr/share/fillup-templates/sysconfig.sbd"
    SBD_STATUS_DESCRIPTION = """
Configure SBD:
  If you have shared storage, for example a SAN or iSCSI target,
  you can use it avoid split-brain scenarios by configuring SBD.
  This requires a 1 MB partition, accessible to all nodes in the
  cluster.  The device path must be persistent and consistent
  across all nodes in the cluster, so /dev/disk/by-id/* devices
  are a good choice.  Note that all data on the partition you
  specify here will be destroyed.
"""

    def __init__(self, sbd_devices=None, diskless_sbd=False):
        """
        Init function

        sbd_devices is provided by '-s' option on init process
        diskless_sbd is provided by '-S' option on init process
        """
        self.sbd_devices_input = sbd_devices
        self.diskless_sbd = diskless_sbd
        self._sbd_devices = None
        self._watchdog_inst = None

    def _parse_sbd_device(self):
        """
        Parse sbd devices, possible command line is like:
          -s "/dev/sdb1;/dev/sdb2"
          -s /dev/sdb1 -s /dev/sbd2
        """
        result_list = []
        for dev in self.sbd_devices_input:
            if ';' in dev:
                result_list.extend(dev.strip(';').split(';'))
            else:
                result_list.append(dev)
        return result_list

    @staticmethod
    def _get_device_uuid(dev, node=None):
        """
        Get UUID for specific device and node
        """
        cmd = "sbd -d {} dump".format(dev)
        if node:
            cmd = "ssh -o StrictHostKeyChecking=no root@{} '{}'".format(node, cmd)

        rc, out, err = utils.get_stdout_stderr(cmd)
        if rc != 0 and err:
            raise ValueError("Cannot dump sbd meta-data: {}".format(err))
        if rc == 0 and out:
            res = re.search("UUID\s*:\s*(.*)\n", out)
            if not res:
                raise ValueError("Cannot find sbd device UUID for {}".format(dev))
            return res.group(1)

    def _compare_device_uuid(self, dev, node_list):
        """
        Compare local sbd device UUID with other node's sbd device UUID
        """
        if not node_list:
            return
        local_uuid = self._get_device_uuid(dev)
        for node in node_list:
            remote_uuid = self._get_device_uuid(dev, node)
            if local_uuid != remote_uuid:
                raise ValueError("Device {} doesn't have the same UUID with {}".format(dev, node))

    def _verify_sbd_device(self, dev_list, compare_node_list=[]):
        """
        Verify sbd device
        """
        if len(dev_list) > 3:
            raise ValueError("Maximum number of SBD device is 3")
        for dev in dev_list:
            if not is_block_device(dev):
                raise ValueError("{} doesn't look like a block device".format(dev))
            self._compare_device_uuid(dev, compare_node_list)

    def _get_sbd_device_interactive(self):
        """
        Get sbd device on interactive mode
        """
        if _context.yes_to_all:
            warn("Not configuring SBD ({} left untouched).".format(SYSCONFIG_SBD))
            return

        status(self.SBD_STATUS_DESCRIPTION)

        if not confirm("Do you wish to use SBD?"):
            warn("Not configuring SBD - STONITH will be disabled.")
            return

        configured_dev_list = self._get_sbd_device_from_config()
        if configured_dev_list and not confirm("SBD is already configured to use {} - overwrite?".format(';'.join(configured_dev_list))):
            return configured_dev_list

        dev_list = []
        dev_looks_sane = False
        while not dev_looks_sane:
            dev = prompt_for_string('Path to storage device (e.g. /dev/disk/by-id/...), or "none" for diskless sbd, use ";" as separator for multi path', r'none|\/.*')
            if not dev:
                continue
            if dev == "none":
                self.diskless_sbd = True
                return
            dev_list = dev.strip(';').split(';')
            try:
                self._verify_sbd_device(dev_list)
            except ValueError as err_msg:
                print_error_msg(str(err_msg))
                continue
            for dev_item in dev_list:
                warn("All data on {} will be destroyed!".format(dev_item))
                if confirm('Are you sure you wish to use this device?'):
                    dev_looks_sane = True
                else:
                    dev_looks_sane = False
                    break

        return dev_list

    def _get_sbd_device(self):
        """
        Get sbd device from options or interactive mode
        """
        dev_list = []
        if self.sbd_devices_input:
            dev_list = self._parse_sbd_device()
            self._verify_sbd_device(dev_list)
        elif not self.diskless_sbd:
            dev_list = self._get_sbd_device_interactive()
        self._sbd_devices = dev_list

    def _initialize_sbd(self):
        """
        Initialize SBD device
        """
        if self.diskless_sbd:
            return
        for dev in self._sbd_devices:
            rc, _, err = invoke("sbd -d {} create".format(dev))
            if not rc:
                error("Failed to initialize SBD device {}: {}".format(dev, err))

    def _update_configuration(self):
        """
        Update /etc/sysconfig/sbd
        """
        shutil.copyfile(self.SYSCONFIG_SBD_TEMPLATE, SYSCONFIG_SBD)
        sbd_config_dict = {
                "SBD_PACEMAKER": "yes",
                "SBD_STARTMODE": "always",
                "SBD_DELAY_START": "no",
                "SBD_WATCHDOG_DEV": self._watchdog_inst.watchdog_device_name
                }
        if self._sbd_devices:
            sbd_config_dict["SBD_DEVICE"] = ';'.join(self._sbd_devices)
        utils.sysconfig_set(SYSCONFIG_SBD, **sbd_config_dict)
        csync2_update(SYSCONFIG_SBD)

    @staticmethod
    def _get_sbd_device_from_config():
        """
        Gets currently configured SBD device, i.e. what's in /etc/sysconfig/sbd
        """
        conf = utils.parse_sysconfig(SYSCONFIG_SBD)
        res = conf.get("SBD_DEVICE")
        if res:
            return res.strip(';').split(';')
        else:
            return None

    def sbd_init(self):
        """
        Function sbd_init includes these steps:
        1. Get sbd device from options or interactive mode
        2. Initialize sbd device
        3. Write config file /etc/sysconfig/sbd
        """
        if not utils.package_is_installed("sbd"):
            return
        self._watchdog_inst = Watchdog(_input=_context.watchdog)
        self._watchdog_inst.init_watchdog()
        self._get_sbd_device()
        if not self._sbd_devices and not self.diskless_sbd:
            invoke("systemctl disable sbd.service")
            return
        status_long("Initializing {}SBD...".format("diskless " if self.diskless_sbd else ""))
        self._initialize_sbd()
        self._update_configuration()
        invoke("systemctl enable sbd.service")
        status_done()

    def configure_sbd_resource(self):
        """
        Configure stonith-sbd resource and stonith-enabled property
        """
        if not utils.package_is_installed("sbd"):
            return
        if utils.service_is_enabled("sbd.service"):
            if self._get_sbd_device_from_config():
                if not invokerc("crm configure primitive stonith-sbd stonith:external/sbd pcmk_delay_max=30s"):
                    error("Can't create stonith-sbd primitive")
                if not invokerc("crm configure property stonith-enabled=true"):
                    error("Can't enable STONITH for SBD")
            else:
                if not invokerc("crm configure property stonith-enabled=true stonith-watchdog-timeout=5s"):
                    error("Can't enable STONITH for diskless SBD")

    def join_sbd(self, peer_host):
        """
        Function join_sbd running on join process only
        On joining process, check whether peer node has enabled sbd.service
        If so, check prerequisites of SBD and verify sbd device on join node
        """
        if not utils.package_is_installed("sbd"):
            return
        if not os.path.exists(SYSCONFIG_SBD) or not utils.service_is_enabled("sbd.service", peer_host):
            invoke("systemctl disable sbd.service")
            return
        self._watchdog_inst = Watchdog(peer_host=peer_host)
        self._watchdog_inst.join_watchdog()
        dev_list = self._get_sbd_device_from_config()
        if dev_list:
            self._verify_sbd_device(dev_list, [peer_host])
        status("Got {}SBD configuration".format("" if dev_list else "diskless "))
        invoke("systemctl enable sbd.service")

    @classmethod
    def verify_sbd_device(cls):
        """
        This classmethod is for verifying sbd device on a running cluster
        Raise ValueError for exceptions
        """
        inst = cls()
        dev_list = inst._get_sbd_device_from_config()
        if not dev_list:
            raise ValueError("No sbd device configured")
        inst._verify_sbd_device(dev_list, utils.list_cluster_nodes_except_me())


_context = None


def die(*args):
    """
    Broken out as special case for log() failure.  Ordinarily you
    should just use error() to terminate.
    """
    raise ValueError(" ".join([str(arg) for arg in args]))


def error(*args):
    """
    Log an error message and raise ValueError to bail out of
    bootstrap process.
    """
    log("ERROR: {}".format(" ".join([str(arg) for arg in args])))
    die(*args)


def print_error_msg(msg):
    """
    Just print error message
    """
    print(term.render(clidisplay.error("ERROR:")) + " {}".format(msg))


def warn(*args):
    """
    Log and display a warning message.
    """
    log("WARNING: {}".format(" ".join(str(arg) for arg in args)))
    print(term.render(clidisplay.warn("WARNING: {}".format(" ".join(str(arg) for arg in args)))))


@utils.memoize
def log_file_fallback():
    """
    If the standard log location isn't writable,
    just log to the nearest temp dir.
    """
    return os.path.join(utils.get_tempdir(), "ha-cluster-bootstrap.log")


def log(*args):
    global LOG_FILE
    try:
        Path(os.path.dirname(LOG_FILE)).mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "ab") as logfile:
            text = " ".join([utils.to_ascii(arg) for arg in args]) + "\n"
            logfile.write(text.encode('ascii', 'backslashreplace'))
    except IOError:
        if LOG_FILE != log_file_fallback():
            LOG_FILE = log_file_fallback()
            log(*args)
        else:
            die("Can't append to {} - aborting".format(LOG_FILE))


def drop_last_history():
    hlen = readline.get_current_history_length()
    if hlen > 0:
        readline.remove_history_item(hlen - 1)


def prompt_for_string(msg, match=None, default='', valid_func=None, prev_value=[]):
    if _context.yes_to_all:
        return default

    while True:
        disable_completion()
        val = utils.multi_input('  %s [%s]' % (msg, default))
        enable_completion()
        if not val:
            val = default
        else:
            drop_last_history()

        if not val:
            return None
        if not match and not valid_func:
            return val
        if match and not re.match(match, val):
            print_error_msg("Invalid value entered")
            continue
        if valid_func:
            try:
                valid_func(val, prev_value)
            except ValueError as err:
                print_error_msg(err)
                continue

        return val


def confirm(msg):
    if _context.yes_to_all:
        return True
    disable_completion()
    rc = utils.ask(msg)
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
    log("+ " + " ".join(args))
    rc, stdout, stderr = utils.get_stdout_stderr(" ".join(args))
    if stdout:
        log(stdout)
    if stderr:
        log(stderr)
    return rc == 0, stdout, stderr


def invokerc(*args):
    """
    Calling invoke, return True/False
    """
    rc, _, _ = invoke(*args)
    return rc


def crm_configure_load(action, configuration):
    log(": loading crm config (%s), content is:" % (action))
    log(configuration)
    if not cib_factory.initialize():
        error("Failed to load cluster configuration")
    set_obj = mkset_obj()
    if action == 'replace':
        cib_factory.erase()
    if not set_obj.save(configuration, remove=False, method=action):
        error("Failed to load cluster configuration")
    if not cib_factory.commit():
        error("Failed to commit cluster configuration")


def wait_for_resource(message, resource, needle="running on"):
    status_long(message)
    while True:
        _rc, out, err = utils.get_stdout_stderr("crm_resource --locate --resource " + resource)
        if needle in out:
            break
        if needle in err:
            break
        status_progress()
        sleep(1)
    status_done()


def wait_for_stop(message, resource):
    return wait_for_resource(message, resource, needle="NOT running")


def wait_for_cluster():
    status_long("Waiting for cluster")
    while True:
        _rc, out, _err = utils.get_stdout_stderr("crm_mon -1")
        if is_online(out):
            break
        status_progress()
        sleep(2)
    status_done()


def get_cluster_node_hostname():
    """
    Get the hostname of the cluster node used during the join process if an IP address is used.
    """
    peer_node = None
    if _context.cluster_node:
        if utils.IP.is_valid_ip(_context.cluster_node):
            rc, out, err = utils.get_stdout_stderr("ssh {} crm_node --name".format(_context.cluster_node))
            if rc != 0:
                error(err)
            peer_node = out
        else:
            peer_node = _context.cluster_node
    return peer_node


def is_online(crm_mon_txt):
    """
    Check whether local node is online
    Besides that, in join process, check whether init node is online
    """
    if not re.search("Online: .* {} ".format(utils.this_node()), crm_mon_txt):
        return False

    # if peer_node is None, this is in the init process
    peer_node = get_cluster_node_hostname()
    if peer_node is None:
        return True
    # In join process
    # If the joining node is already online but can't find the init node
    # The communication IP maybe mis-configured
    if not re.search("Online: .* {} ".format(peer_node), crm_mon_txt):
        shutil.copy(COROSYNC_CONF_ORIG, corosync.conf())
        csync2_update(corosync.conf())
        utils.stop_service("corosync")
        print()
        error("Cannot see peer node \"{}\", please check the communication IP".format(peer_node))
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


def status(msg):
    log("# " + msg)
    if not _context.quiet:
        print("  {}".format(msg))


def status_long(msg):
    log("# {}...".format(msg))
    if not _context.quiet:
        sys.stdout.write("  {}...".format(msg))
        sys.stdout.flush()


def status_progress():
    if not _context.quiet:
        sys.stdout.write(".")
        sys.stdout.flush()


def status_done():
    log("# done")
    if not _context.quiet:
        print("done")


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
    status_long("Probing for new partitions")
    partprobe()
    sleep(5)
    status_done()


def check_tty():
    """
    Check for pseudo-tty: Cannot display read prompts without a TTY (bnc#892702)
    """
    if _context.yes_to_all:
        return
    if not sys.stdin.isatty():
        error("No pseudo-tty detected! Use -t option to ssh if calling remotely.")


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
        warn("Hostname '{}' is unresolvable. {}".format(
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
        warn("No NTP service found.")
        warned = True
    elif not utils.service_is_enabled(timekeeper):
        warn("{} is not configured to start at system boot.".format(timekeeper))
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
    # Reload rsyslog to make sure it logs with the correct hostname
    if utils.service_is_active("rsyslog.service"):
        invoke("systemctl reload rsyslog.service")
    datestr = utils.get_stdout("date --rfc-3339=seconds")[1]
    log('================================================================')
    log("%s %s" % (datestr, " ".join(sys.argv)))
    log('----------------------------------------------------------------')


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
        status("Restarting firewall (tcp={}, udp={})".format(" ".join(tcp), " ".join(udp)))
        if not invokerc("rcSuSEfirewall2 restart"):
            error("Failed to restart firewall (SuSEfirewall2)")

    def init_firewall_firewalld(tcp, udp):
        has_firewalld = utils.service_is_active("firewalld")
        cmdbase = 'firewall-cmd --zone=public --permanent ' if has_firewalld else 'firewall-offline-cmd --zone=public '

        def cmd(args):
            if not invokerc(cmdbase + args):
                error("Failed to configure firewall.")

        for p in tcp:
            cmd("--add-port={}/tcp".format(p))

        for p in udp:
            cmd("--add-port={}/udp".format(p))

        if has_firewalld:
            if not invokerc("firewall-cmd --reload"):
                error("Failed to reload firewall configuration.")

    def init_firewall_ufw(tcp, udp):
        """
        try configuring firewall with ufw
        """
        for p in tcp:
            if not invokerc("ufw allow {}/tcp".format(p)):
                error("Failed to configure firewall (ufw)")
        for p in udp:
            if not invokerc("ufw allow {}/udp".format(p)):
                error("Failed to configure firewall (ufw)")

    if utils.package_is_installed("firewalld"):
        init_firewall_firewalld(tcp, udp)
    elif utils.package_is_installed("SuSEfirewall2"):
        init_firewall_suse(tcp, udp)
    elif utils.package_is_installed("ufw"):
        init_firewall_ufw(tcp, udp)
    else:
        warn("Failed to detect firewall: Could not open ports tcp={}, udp={}".format("|".join(tcp), "|".join(udp)))


def firewall_open_basic_ports():
    """
    Open ports for csync2, mgmtd, hawk & dlm respectively
    """
    configure_firewall(tcp=["30865", "5560", "7630", "21064"])


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
        error("corosync service is running!")

    firewall_open_corosync_ports()

    # reset password, but only if it's not already set
    _rc, outp = utils.get_stdout("passwd -S hacluster")
    ps = outp.strip().split()[1]
    pass_msg = ""
    if ps not in ("P", "PS"):
        log(': Resetting password of hacluster user')
        rc, outp, errp = utils.get_stdout_stderr("passwd hacluster", input_s=b"linux\nlinux\n")
        if rc != 0:
            warn("Failed to reset password of hacluster user: %s" % (outp + errp))
        else:
            pass_msg = ", password 'linux'"

    # evil, but necessary
    invoke("rm -f /var/lib/heartbeat/crm/* /var/lib/pacemaker/cib/*")

    # only try to start hawk if hawk is installed
    if utils.service_is_available("hawk.service"):
        utils.start_service("hawk.service", enable=True)
        status("Hawk cluster interface is now running. To see cluster status, open:")
        status("  https://{}:7630/".format(_context.default_ip_list[0]))
        status("Log in with username 'hacluster'{}".format(pass_msg))
    else:
        warn("Hawk not installed - not configuring web management interface.")

    if pass_msg:
        warn("You should change the hacluster password to something more secure!")

    utils.start_service("pacemaker.service", enable=True)
    wait_for_cluster()


def install_tmp(tmpfile, to):
    with open(tmpfile, "r") as src:
        with utils.open_atomic(to, "w") as dst:
            for line in src:
                dst.write(line)


def append(fromfile, tofile):
    log("+ cat %s >> %s" % (fromfile, tofile))
    with open(tofile, "a") as tf:
        with open(fromfile, "r") as ff:
            tf.write(ff.read())


def append_unique(fromfile, tofile):
    """
    Append unique content from fromfile to tofile
    """
    if not utils.check_file_content_included(fromfile, tofile):
        append(fromfile, tofile)


def rmfile(path, ignore_errors=False):
    """
    Try to remove the given file, and
    report an error on failure
    """
    try:
        os.remove(path)
    except os.error as err:
        if not ignore_errors:
            error("Failed to remove {}: {}".format(path, err))


def mkdirs_owned(dirs, mode=0o777, uid=-1, gid=-1):
    """
    Create directory path, setting the mode and
    ownership of the leaf directory to mode/uid/gid.
    """
    if not os.path.exists(dirs):
        try:
            os.makedirs(dirs, mode)
        except OSError as err:
            error("Failed to create {}: {}".format(dirs, err))
        if uid != -1 or gid != -1:
            utils.chown(dirs, uid, gid)


def init_ssh():
    """
    Configure passwordless SSH.
    """
    utils.start_service("sshd.service", enable=True)
    configure_local_ssh_key()


def configure_local_ssh_key():
    """
    Configure ssh rsa key locally

    If /root/.ssh/id_rsa not exist, generate a new one
    Add /root/.ssh/id_rsa.pub to /root/.ssh/authorized_keys anyway, make sure itself authorized
    """
    if not os.path.exists(RSA_PRIVATE_KEY):
        status("Generating SSH key")
        invoke("ssh-keygen -q -f {} -C 'Cluster Internal on {}' -N ''".format(RSA_PRIVATE_KEY, utils.this_node()))
    if not os.path.exists(AUTHORIZED_KEYS_FILE):
        open(AUTHORIZED_KEYS_FILE, 'w').close()
    append_unique(RSA_PUBLIC_KEY, AUTHORIZED_KEYS_FILE)


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


def append_to_remote_file(fromfile, remote_node, tofile):
    """
    Append content of fromfile to tofile on remote_node
    """
    err_details_string = """
    crmsh has no way to help you to setup up passwordless ssh among nodes at this time. 
    As the hint, likely, `PasswordAuthentication` is 'no' in /etc/ssh/sshd_config. 
    Given in this case, users must setup passwordless ssh beforehand, or change it to 'yes' and manage passwords properly
    """
    cmd = "cat {} | ssh -oStrictHostKeyChecking=no root@{} 'cat >> {}'".format(fromfile, remote_node, tofile)
    rc, _, err = invoke(cmd)
    if not rc:
        error("Failed to append contents of {} to {}:\n\"{}\"\n{}".format(fromfile, remote_node, err, err_details_string))


def init_csync2():
    status("Configuring csync2")
    if os.path.exists(CSYNC2_KEY):
        if not confirm("csync2 is already configured - overwrite?"):
            return

    invoke("rm", "-f", CSYNC2_KEY)
    status_long("Generating csync2 shared key (this may take a while)")
    if not invokerc("csync2", "-k", CSYNC2_KEY):
        error("Can't create csync2 key {}".format(CSYNC2_KEY))
    status_done()

    utils.str2file("""group ha_group
{
key /etc/csync2/key_hagroup;
host %s;
include /etc/booth;
include /etc/corosync/corosync.conf;
include /etc/corosync/authkey;
include /etc/csync2/csync2.cfg;
include /etc/csync2/key_hagroup;
include /etc/ctdb/nodes;
include /etc/drbd.conf;
include /etc/drbd.d;
include /etc/ha.d/ldirectord.cf;
include /etc/lvm/lvm.conf;
include /etc/multipath.conf;
include /etc/samba/smb.conf;
include /etc/sysconfig/nfs;
include /etc/sysconfig/pacemaker;
include /etc/sysconfig/sbd;
include /etc/pacemaker/authkey;
include /etc/modules-load.d/watchdog.conf;
}
    """ % (utils.this_node()), CSYNC2_CFG)

    utils.start_service("csync2.socket", enable=True)
    status_long("csync2 checking files")
    invoke("csync2", "-cr", "/")
    status_done()


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
        warn("{} was not synced".format(path))


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
        error("Hostname not specified")

    curr_cfg = open(CSYNC2_CFG).read()

    was_quiet = _context.quiet
    try:
        _context.quiet = True
        # if host doesn't already exist in csync2 config, add it
        if not re.search(r"^\s*host.*\s+%s\s*;" % (newhost), curr_cfg, flags=re.M):
            curr_cfg = re.sub(r"\bhost.*\s+\S+\s*;", r"\g<0>\n\thost %s;" % (utils.doublequote(newhost)), curr_cfg, count=1)
            utils.str2file(curr_cfg, CSYNC2_CFG)
            csync2_update("/")
        else:
            log(": Not updating %s - remote host %s already exists" % (CSYNC2_CFG, newhost))
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
    invoke("corosync-keygen -l")


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
        warn("Failed to create pacemaker authkey: {}".format(PCMK_REMOTE_AUTH))
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
        status("Configuring corosync (unicast)")
    else:
        status("""
Configure Corosync (unicast):
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
            error("No value for ring{}".format(i))
        ringXaddr_res.append(ringXaddr)

        mcastport = prompt_for_string(
                'Port for ring{}'.format(i),
                match='[0-9]+',
                default=pick_default_value(default_ports, mcastport_res),
                valid_func=Validation.valid_port,
                prev_value=mcastport_res)
        if not mcastport:
            error("Expected a multicast port for ring{}".format(i))
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
    csync2_update(corosync.conf())


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
        status("Configuring corosync")
    else:
        status("""
Configure Corosync:
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
            error("No value for bindnetaddr")
        bindnetaddr_res.append(bindnetaddr)

        mcastaddr = prompt_for_string(
                'Multicast address',
                default=gen_mcastaddr(),
                valid_func=Validation.valid_mcast_address,
                prev_value=mcastaddr_res)
        if not mcastaddr:
            error("No value for mcastaddr")
        mcastaddr_res.append(mcastaddr)

        mcastport = prompt_for_string(
                'Multicast port',
                match='[0-9]+',
                default=pick_default_value(default_ports, mcastport_res),
                valid_func=Validation.valid_port,
                prev_value=mcastport_res)
        if not mcastport:
            error("No value for mcastport")
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
    csync2_update(corosync.conf())


def init_corosync():
    """
    Configure corosync (unicast or multicast, encrypted?)
    """
    def requires_unicast():
        host = utils.detect_cloud()
        if host is not None:
            status("Detected cloud platform: {}".format(host))
        return host is not None

    init_corosync_auth()

    if os.path.exists(corosync.conf()):
        if not confirm("%s already exists - overwrite?" % (corosync.conf())):
            return

    if _context.unicast or requires_unicast():
        init_corosync_unicast()
    else:
        init_corosync_multicast()


def is_block_device(dev):
    from stat import S_ISBLK
    try:
        rc = S_ISBLK(os.stat(dev).st_mode)
    except OSError:
        return False
    return rc


def list_partitions(dev):
    rc, outp, errp = utils.get_stdout_stderr("parted -s %s print" % (dev))
    partitions = []
    for line in outp.splitlines():
        m = re.match(r"^\s*([0-9]+)\s*", line)
        if m:
            partitions.append(m.group(1))
    if rc != 0:
        # ignore "Error: /dev/vdb: unrecognised disk label"
        if errp.count('\n') > 1 or "unrecognised disk label" not in errp.strip():
            error("Failed to list partitions in {}: {}".format(dev, errp))
    return partitions


def list_devices(dev):
    "TODO: THIS IS *WRONG* FOR MULTIPATH! (but possibly nothing we can do about it)"
    _rc, outp = utils.get_stdout("fdisk -l %s" % (dev))
    partitions = []
    for line in outp.splitlines():
        m = re.match(r"^(\/dev\S+)", line)
        if m:
            partitions.append(m.group(1))
    return partitions


def init_storage():
    """
    Configure SBD and OCFS2 both on the same storage device.
    """
    dev = _context.shared_device
    partitions = []
    dev_looks_sane = False

    if _context.yes_to_all or not dev:
        status("Configuring shared storage")
    else:
        status("""
Configure Shared Storage:
  You will need to provide the path to a shared storage device,
  for example a SAN volume or iSCSI target.  The device path must
  be persistent and consistent across all nodes in the cluster,
  so /dev/disk/by-id/* devices are a good choice.  This device
  will be automatically paritioned into two pieces, 1MB for SBD
  fencing, and the remainder for an OCFS2 filesystem.
""")

    while not dev_looks_sane:
        dev = prompt_for_string('Path to storage device (e.g. /dev/disk/by-id/...)', r'\/.*', dev)
        if not dev:
            error("No value for shared storage device")

        if not is_block_device(dev):
            if _context.yes_to_all:
                error(dev + " is not a block device")
            else:
                print("    That doesn't look like a block device", file=sys.stderr)
        else:
            #
            # Got something that looks like a block device, there
            # are four possibilities now:
            #
            #  1) It's completely broken/inaccessible
            #  2) No recognizable partition table
            #  3) Empty partition table
            #  4) Non-empty parition table
            #
            partitions = list_partitions(dev)
            if partitions:
                status("WARNING: Partitions exist on %s!" % (dev))
                if confirm("Are you ABSOLUTELY SURE you want to overwrite?"):
                    dev_looks_sane = True
                else:
                    dev = ""
            else:
                # It's either broken, no partition table, or empty partition table
                status("%s appears to be empty" % (dev))
                if confirm("Device appears empty (no partition table). Do you want to use {}?".format(dev)):
                    dev_looks_sane = True
                else:
                    dev = ""

    if partitions:
        if not confirm("Really?"):
            return
        status_long("Erasing existing partitions...")
        for part in partitions:
            if not invokerc("parted -s %s rm %s" % (dev, part)):
                error("Failed to remove partition %s from %s" % (part, dev))
        status_done()

    status_long("Creating partitions...")
    if not invokerc("parted", "-s", dev, "mklabel", "msdos"):
        error("Failed to create partition table")

    # This is a bit rough, and probably won't result in great performance,
    # but it's fine for test/demo purposes to carve off 1MB for SBD.  Note
    # we have to specify the size of the first partition in this in bytes
    # rather than MB, or parted's rounding gives us a ~30Kb partition
    # (see rhbz#623268).
    if not invokerc("parted -s %s mkpart primary 0 1048576B" % (dev)):
        error("Failed to create first partition on %s" % (dev))
    if not invokerc("parted -s %s mkpart primary 1M 100%%" % (dev)):
        error("Failed to create second partition")

    status_done()

    # TODO: May not be strictly necessary, but...
    probe_partitions()

    # TODO: THIS IS *WRONG* FOR MULTIPATH! (but possibly nothing we can do about it)
    devices = list_devices(dev)

    _context.sbd_device = devices[0]
    if not _context.sbd_device:
        error("Unable to determine device path for SBD partition")

    _context.ocfs2_device = devices[1]
    if not _context.ocfs2_device:
        error("Unable to determine device path for OCFS2 partition")

    status("Created %s for SBD partition" % (_context.sbd_device))
    status("Created %s for OCFS2 partition" % (_context.ocfs2_device))


def init_sbd():
    """
    Configure SBD (Storage-based fencing).

    SBD can also run in diskless mode if no device
    is configured.
    """
    _context.sbd_manager.sbd_init()


def init_cluster():
    """
    Initial cluster configuration.
    """
    init_cluster_local()

    _rc, nnodes = utils.get_stdout("crm_node -l")
    nnodes = len(nnodes.splitlines())
    if nnodes < 1:
        error("No nodes found in cluster")
    if nnodes > 1:
        error("Joined existing cluster - will not reconfigure.")

    status("Loading initial cluster configuration")

    crm_configure_load("update", """
property cib-bootstrap-options: stonith-enabled=false
op_defaults op-options: timeout=600 record-pending=true
rsc_defaults rsc-options: resource-stickiness=1 migration-threshold=3
""")

    _context.sbd_manager.configure_sbd_resource()


def init_vgfs():
    """
    Configure cluster OCFS2 device.
    """
    dev = _context.ocfs2_device
    if not dev:
        error("vgfs stage requires -o <dev>")
    mntpoint = "/srv/clusterfs"

    if not is_block_device(dev):
        error("OCFS2 device \"{}\" does not exist".format(dev))

    # TODO: configurable mountpoint and vg name
    crm_configure_load("update", """
primitive dlm ocf:pacemaker:controld op start timeout=90 op stop timeout=100 op monitor interval=60 timeout=60
primitive clusterfs Filesystem directory=%(mntpoint)s fstype=ocfs2 device=%(dev)s \
    op monitor interval=20 timeout=40 op start timeout=60 op stop timeout=60 \
    meta target-role=Stopped
clone base-clone dlm meta interleave=true
clone c-clusterfs clusterfs meta interleave=true clone-max=8
order base-then-clusterfs inf: base-clone c-clusterfs
colocation clusterfs-with-base inf: c-clusterfs base-clone
    """ % {"mntpoint": utils.doublequote(mntpoint), "dev": utils.doublequote(dev)})

    wait_for_resource("Waiting for DLM", "dlm:0")
    wait_for_stop("Making sure filesystem is not active", "clusterfs:0")

    _rc, blkid, _err = utils.get_stdout_stderr("blkid %s" % (dev))
    if "TYPE" in blkid:
        if not confirm("Exiting filesystem found on \"{}\" - destroy?".format(dev)):
            for res in ("base-clone", "c-clusterfs"):
                invoke("crm resource stop %s" % (res))
                wait_for_stop("Waiting for resource %s to stop" % (res), res)
            invoke("crm configure delete dlm clusterfs base-group base-clone c-clusterfs base-then-clusterfs clusterfs-with-base")

    status_long("Creating OCFS2 filesystem")
    # TODO: want "-T vmstore", but this'll only fly on >2GB partition
    # Note: using undocumented '-x' switch to avoid prompting if overwriting
    # existing partition.  For the commit that introduced this, see:
    # http://oss.oracle.com/git/?p=ocfs2-tools.git;a=commit;h=8345a068479196172190f4fa287052800fa2b66f
    # TODO: if make the cluster name configurable, we need to update it here too
    if not invokerc("mkfs.ocfs2 --cluster-stack pcmk --cluster-name %s -N 8 -x %s" % (_context.cluster_name, dev)):
        error("Failed to create OCFS2 filesystem on %s" % (dev))
    status_done()

    # TODO: refactor, maybe
    if not invokerc("mkdir -p %s" % (mntpoint)):
        error("Can't create mountpoint %s" % (mntpoint))
    if not invokerc("crm resource meta clusterfs delete target-role"):
        error("Can't start cluster filesystem clone")
    wait_for_resource("Waiting for %s to be mounted" % (mntpoint), "clusterfs:0")


def init_admin():
    # Skip this section when -y is passed
    # unless $ADMIN_IP is set
    adminaddr = _context.admin_ip
    if _context.yes_to_all and not adminaddr:
        return

    if not adminaddr:
        status("""
Configure Administration IP Address:
  Optionally configure an administration virtual IP
  address. The purpose of this IP address is to
  provide a single IP that can be used to interact
  with the cluster, rather than using the IP address
  of any specific cluster node.
""")
        if not confirm("Do you wish to configure a virtual IP address?"):
            return

        adminaddr = prompt_for_string('Virtual IP', valid_func=Validation.valid_admin_ip)
        if not adminaddr:
            error("Expected an IP address")

    crm_configure_load("update", 'primitive admin-ip IPaddr2 ip=%s op monitor interval=10 timeout=20' % (utils.doublequote(adminaddr)))
    wait_for_resource("Configuring virtual IP ({})".format(adminaddr), "admin-ip")


def init_qdevice():
    """
    Setup qdevice and qnetd service
    """
    # If don't want to config qdevice, return
    if not _context.qdevice_inst:
        utils.disable_service("corosync-qdevice.service")
        return

    status("""
Configure Qdevice/Qnetd:""")
    qdevice_inst = _context.qdevice_inst
    qnetd_addr = qdevice_inst.qnetd_addr
    # Configure ssh passwordless to qnetd if detect password is needed
    if utils.check_ssh_passwd_need(qnetd_addr):
        status("Copy ssh key to qnetd node({})".format(qnetd_addr))
        rc, _, err = invoke("ssh-copy-id -i /root/.ssh/id_rsa.pub root@{}".format(qnetd_addr))
        if not rc:
            error("Failed to copy ssh key: {}".format(err))
    # Start qdevice service if qdevice already configured
    if utils.is_qdevice_configured() and not confirm("Qdevice is already configured - overwrite?"):
        start_qdevice_service()
        return

    # Validate qnetd node
    qdevice_inst.valid_qnetd()
    # Config qdevice
    config_qdevice()
    # Execute certificate process when tls flag is on
    if utils.is_qdevice_tls_on():
        status_long("Qdevice certification process")
        qdevice_inst.certificate_process_on_init()
        status_done()

    start_qdevice_service()


def start_qdevice_service():
    """
    Start qdevice and qnetd service
    """
    qdevice_inst = _context.qdevice_inst
    qnetd_addr = qdevice_inst.qnetd_addr

    status("Enable corosync-qdevice.service in cluster")
    utils.cluster_run_cmd("systemctl enable corosync-qdevice")
    status("Starting corosync-qdevice.service in cluster")
    utils.cluster_run_cmd("systemctl start corosync-qdevice")

    status("Enable corosync-qnetd.service on {}".format(qnetd_addr))
    qdevice_inst.enable_qnetd()
    status("Starting corosync-qnetd.service on {}".format(qnetd_addr))
    qdevice_inst.start_qnetd()


def config_qdevice():
    """
    Process of config qdevice
    """
    qdevice_inst = _context.qdevice_inst

    qdevice_inst.remove_qdevice_db()
    qdevice_inst.write_qdevice_config()
    if not corosync.is_unicast():
        corosync.add_nodelist_from_cmaptool()
    status_long("Update configuration")
    update_expected_votes()
    utils.cluster_run_cmd("crm corosync reload")
    status_done()


def init():
    """
    Basic init
    """
    log_start()
    init_network()


def join_ssh(seed_host):
    """
    SSH configuration for joining node.
    """
    if not seed_host:
        error("No existing IP/hostname specified (use -c option)")

    utils.start_service("sshd.service", enable=True)
    configure_local_ssh_key()
    swap_public_ssh_key(seed_host)

    # This makes sure the seed host has its own SSH keys in its own
    # authorized_keys file (again, to help with the case where the
    # user has done manual initial setup without the assistance of
    # ha-cluster-init).
    rc, _, err = invoke("ssh root@{} crm cluster init -i {} ssh_remote".format(seed_host, _context.default_nic_list[0]))
    if not rc:
        error("Can't invoke crm cluster init -i {} ssh_remote on {}: {}".format(_context.default_nic_list[0], seed_host, err))


def swap_public_ssh_key(remote_node):
    """
    Swap public ssh key between remote_node and local
    """
    # Detect whether need password to login to remote_node
    if utils.check_ssh_passwd_need(remote_node):
        # If no passwordless configured, paste /root/.ssh/id_rsa.pub to remote_node's /root/.ssh/authorized_keys
        status("Configuring SSH passwordless with root@{}".format(remote_node))
        # After this, login to remote_node is passwordless
        append_to_remote_file(RSA_PUBLIC_KEY, remote_node, AUTHORIZED_KEYS_FILE)

    try:
        # Fetch public key file from remote_node
        public_key_file_remote = fetch_public_key_from_remote_node(remote_node)
    except ValueError as err:
        warn(err)
        return
    # Append public key file from remote_node to local's /root/.ssh/authorized_keys
    # After this, login from remote_node is passwordless
    # Should do this step even passwordless is True, to make sure we got two-way passwordless
    append_unique(public_key_file_remote, AUTHORIZED_KEYS_FILE)


def fetch_public_key_from_remote_node(node):
    """
    Fetch public key file from remote node
    Return a temp file contains public key
    Return None if no key exist
    """

    # For dsa, might need to add PubkeyAcceptedKeyTypes=+ssh-dss to config file, see
    # https://superuser.com/questions/1016989/ssh-dsa-keys-no-longer-work-for-password-less-authentication
    for key in ("id_rsa", "id_ecdsa", "id_ed25519", "id_dsa"):
        public_key_file = "/root/.ssh/{}.pub".format(key)
        cmd = "ssh -oStrictHostKeyChecking=no root@{} 'test -f {}'".format(node, public_key_file)
        if not invokerc(cmd):
            continue
        _, temp_public_key_file = tmpfiles.create()
        cmd = "scp -oStrictHostKeyChecking=no root@{}:{} {}".format(node, public_key_file, temp_public_key_file)
        rc, _, err = invoke(cmd)
        if not rc:
            error("Failed to run \"{}\": {}".format(cmd, err))
        return temp_public_key_file
    raise ValueError("No ssh key exist on {}".format(node))


def join_csync2(seed_host):
    """
    Csync2 configuration for joining node.
    """
    if not seed_host:
        error("No existing IP/hostname specified (use -c option)")
    status_long("Configuring csync2")

    # Necessary if re-running join on a node that's been configured before.
    rmfile("/var/lib/csync2/{}.db3".format(utils.this_node()), ignore_errors=True)

    # Not automatically updating /etc/hosts - risky in the general case.
    # etc_hosts_add_me
    # local hosts_line=$(etc_hosts_get_me)
    # [ -n "$hosts_line" ] || error "No valid entry for $(hostname) in /etc/hosts - csync2 can't work"

    # If we *were* updating /etc/hosts, the next line would have "\"$hosts_line\"" as
    # the last arg (but this requires re-enabling this functionality in ha-cluster-init)
    cmd = "crm cluster init -i {} csync2_remote {}".format(_context.default_nic_list[0], utils.this_node())
    rc, _, err = invoke("ssh -o StrictHostKeyChecking=no root@{} {}".format(seed_host, cmd))
    if not rc:
        error("Can't invoke \"{}\" on {}: {}".format(cmd, seed_host, err))

    # This is necessary if syncing /etc/hosts (to ensure everyone's got the
    # same list of hosts)
    # local tmp_conf=/etc/hosts.$$
    # invoke scp root@seed_host:/etc/hosts $tmp_conf \
    #   || error "Can't retrieve /etc/hosts from seed_host"
    # install_tmp $tmp_conf /etc/hosts
    rc, _, err = invoke("scp root@%s:'/etc/csync2/{csync2.cfg,key_hagroup}' /etc/csync2" % (seed_host))
    if not rc:
        error("Can't retrieve csync2 config from {}: {}".format(seed_host, err))

    utils.start_service("csync2.socket", enable=True)

    # Sync new config out.  This goes to all hosts; csync2.cfg definitely
    # needs to go to all hosts (else hosts other than the seed and the
    # joining host won't have the joining host in their config yet).
    # Strictly, the rest of the files need only go to the new host which
    # could theoretically be effected using `csync2 -xv -P $(hostname)`,
    # but this still leaves all the other files in dirty state (becuase
    # they haven't gone to all nodes in the cluster, which means a
    # subseqent join of another node can fail its sync of corosync.conf
    # when it updates expected_votes.  Grrr...
    if not invokerc('ssh -o StrictHostKeyChecking=no root@{} "csync2 -rm /; csync2 -rxv || csync2 -rf / && csync2 -rxv"'.format(seed_host)):
        print("")
        warn("csync2 run failed - some files may not be sync'd")

    status_done()


def join_ssh_merge(_cluster_node):
    status("Merging known_hosts")

    me = utils.this_node()
    hosts = [m.group(1)
             for m in re.finditer(r"^\s*host\s*([^ ;]+)\s*;", open(CSYNC2_CFG).read(), re.M)
             if m.group(1) != me]
    if not hosts:
        hosts = [_cluster_node]
        warn("Unable to extract host list from %s" % (CSYNC2_CFG))

    try:
        import parallax
    except ImportError:
        error("parallax python library is missing")

    opts = parallax.Options()
    opts.ssh_options = ['StrictHostKeyChecking=no']

    # The act of using pssh to connect to every host (without strict host key
    # checking) ensures that at least *this* host has every other host in its
    # known_hosts
    known_hosts_new = set()
    cat_cmd = "[ -e /root/.ssh/known_hosts ] && cat /root/.ssh/known_hosts || true"
    log("parallax.call {} : {}".format(hosts, cat_cmd))
    results = parallax.call(hosts, cat_cmd, opts)
    for host, result in results.items():
        if isinstance(result, parallax.Error):
            warn("Failed to get known_hosts from {}: {}".format(host, str(result)))
        else:
            if result[1]:
                known_hosts_new.update((utils.to_ascii(result[1]) or "").splitlines())
    if known_hosts_new:
        hoststxt = "\n".join(sorted(known_hosts_new))
        tmpf = utils.str2tmp(hoststxt)
        log("parallax.copy {} : {}".format(hosts, hoststxt))
        results = parallax.copy(hosts, tmpf, "/root/.ssh/known_hosts")
        for host, result in results.items():
            if isinstance(result, parallax.Error):
                warn("scp to {} failed ({}), known_hosts update may be incomplete".format(host, str(result)))


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

    csync2_update(corosync.conf())


def setup_passwordless_with_other_nodes(init_node):
    """
    Setup passwordless with other cluster nodes

    Should fetch the node list from init node, then swap the key
    """
    # Fetch cluster nodes list
    cmd = "ssh -o StrictHostKeyChecking=no root@{} crm_node -l".format(init_node)
    rc, out, err = utils.get_stdout_stderr(cmd)
    if rc != 0:
        error("Can't fetch cluster nodes list from {}: {}".format(init_node, err))
    cluster_nodes_list = []
    for line in out.splitlines():
        _, node, stat = line.split()
        if stat == "member":
            cluster_nodes_list.append(node)

    # Filter out init node from cluster_nodes_list
    cmd = "ssh -o StrictHostKeyChecking=no root@{} hostname".format(init_node)
    rc, out, err = utils.get_stdout_stderr(cmd)
    if rc != 0:
        error("Can't fetch hostname of {}: {}".format(init_node, err))
    if out in cluster_nodes_list:
        cluster_nodes_list.remove(out)

    # Swap ssh public key between join node and other cluster nodes
    for node in cluster_nodes_list:
        swap_public_ssh_key(node)


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

    # Need to do this if second (or subsequent) node happens to be up and
    # connected to storage while it's being repartitioned on the first node.
    probe_partitions()

    # It would be massively useful at this point if new nodes could come
    # up in standby mode, so we could query the CIB locally to see if
    # there was any further local setup that needed doing, e.g.: creating
    # mountpoints for clustered filesystems.  Unfortunately we don't have
    # that yet, so the following crawling horror takes a punt on the seed
    # node being up, then asks it for a list of mountpoints...
    if _context.cluster_node:
        _rc, outp, _ = utils.get_stdout_stderr("ssh -o StrictHostKeyChecking=no root@{} 'cibadmin -Q --xpath \"//primitive\"'".format(seed_host))
        if outp:
            xml = etree.fromstring(outp)
            mountpoints = xml.xpath(' and '.join(['//primitive[@class="ocf"',
                                                  '@provider="heartbeat"',
                                                  '@type="Filesystem"]']) +
                                    '/instance_attributes/nvpair[@name="directory"]/@value')
            for m in mountpoints:
                invoke("mkdir -p {}".format(m))
    else:
        status("No existing IP/hostname specified - skipping mountpoint detection/creation")

    # Bump expected_votes in corosync.conf
    # TODO(must): this is rather fragile (see related code in ha-cluster-remove)

    # If corosync.conf() doesn't exist or is empty, we will fail here. (bsc#943227)
    if not os.path.exists(corosync.conf()):
        error("{} is not readable. Please ensure that hostnames are resolvable.".format(corosync.conf()))

    # if unicast, we need to add our node to $corosync.conf()
    is_unicast = corosync.is_unicast()
    if is_unicast:
        ringXaddr_res = []
        for i in 0, 1:
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
            if not rrp_flag:
                break
        print("")
        invoke("rm -f /var/lib/heartbeat/crm/* /var/lib/pacemaker/cib/*")
        try:
            corosync.add_node_ucast(ringXaddr_res)
        except corosync.IPAlreadyConfiguredError as e:
            warn(e)
        csync2_update(corosync.conf())
        invoke("ssh -o StrictHostKeyChecking=no root@{} corosync-cfgtool -R".format(seed_host))

    _context.sbd_manager.join_sbd(seed_host)

    if ipv6_flag and not is_unicast:
        # for ipv6 mcast
        # using ipv6 need nodeid configured
        local_nodeid = get_local_nodeid()
        update_nodeid(local_nodeid)

    is_qdevice_configured = utils.is_qdevice_configured()
    if is_qdevice_configured and not is_unicast:
        # expected_votes here maybe is "0", set to "3" to make sure cluster can start
        corosync.set_value("quorum.expected_votes", "3")

    # Initialize the cluster before adjusting quorum. This is so
    # that we can query the cluster to find out how many nodes
    # there are (so as not to adjust multiple times if a previous
    # attempt to join the cluster failed)
    init_cluster_local()

    status_long("Reloading cluster configuration")

    if ipv6_flag and not is_unicast:
        # for ipv6 mcast
        nodeid_dict = {}
        _rc, outp, _ = utils.get_stdout_stderr("crm_node -l")
        if _rc == 0:
            for line in outp.split('\n'):
                tmp = line.split()
                nodeid_dict[tmp[1]] = tmp[0]

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
    status_done()

    if is_qdevice_configured:
        start_qdevice_on_join_node(seed_host)
    else:
        utils.disable_service("corosync-qdevice.service")


def start_qdevice_on_join_node(seed_host):
    """
    Doing qdevice certificate process and start qdevice service on join node
    """
    status_long("Starting corosync-qdevice.service")
    if not corosync.is_unicast():
        corosync.add_nodelist_from_cmaptool()
        csync2_update(corosync.conf())
        invoke("crm corosync reload")
    if utils.is_qdevice_tls_on():
        qnetd_addr = corosync.get_value("quorum.device.net.host")
        qdevice_inst = corosync.QDevice(qnetd_addr, cluster_node=seed_host)
        qdevice_inst.certificate_process_on_join()
    utils.start_service("corosync-qdevice.service", enable=True)
    status_done()


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
            status("Stopping the {}".format(service))
            utils.stop_service(service, disable=True, remote_addr=remote_addr)


def remove_node_from_cluster():
    """
    Remove node from running cluster and the corosync / pacemaker configuration.
    """
    node = _context.cluster_node
    set_cluster_node_ip()

    stop_services(SERVICES_STOP_LIST, remote_addr=node)

    # delete configuration files from the node to be removed
    rc, _, err = invoke('ssh -o StrictHostKeyChecking=no root@{} "bash -c \\\"rm -f {}\\\""'.format(node, " ".join(_context.rm_list)))
    if not rc:
        error("Deleting the configuration files failed: {}".format(err))

    # execute the command : crm node delete $HOSTNAME
    status("Removing the node {}".format(node))
    if not invokerc("crm node delete {}".format(node)):
        error("Failed to remove {}".format(node))

    if not invokerc("sed -i /{}/d {}".format(node, CSYNC2_CFG)):
        error("Removing the node {} from {} failed".format(node, CSYNC2_CFG))

    # Remove node from nodelist
    if corosync.get_values("nodelist.node.ring0_addr"):
        del_target = _context.cluster_node_ip or node
        corosync.del_node(del_target)

    decrease_expected_votes()

    status("Propagating configuration changes across the remaining nodes")
    csync2_update(CSYNC2_CFG)
    csync2_update(corosync.conf())

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
    _context.initialize_qdevice()
    _context.validate_option()
    _context.init_sbd_manager()

    stage = _context.stage
    if stage is None:
        stage = ""

    # vgfs stage requires running cluster, everything else requires inactive cluster,
    # except ssh and csync2 (which don't care) and csync2_remote (which mustn't care,
    # just in case this breaks ha-cluster-join on another node).
    corosync_active = utils.service_is_active("corosync.service")
    if stage in ("vgfs", "admin", "qdevice"):
        if not corosync_active:
            error("Cluster is inactive - can't run %s stage" % (stage))
    elif stage == "":
        if corosync_active:
            error("Cluster is currently active - can't run")
    elif stage not in ("ssh", "ssh_remote", "csync2", "csync2_remote"):
        if corosync_active:
            error("Cluster is currently active - can't run %s stage" % (stage))

    # Need hostname resolution to work, want NTP (but don't block ssh_remote or csync2_remote)
    if stage not in ('ssh_remote', 'csync2_remote'):
        check_tty()
        if not check_prereqs(stage):
            return
    elif stage == 'csync2_remote':
        args = _context.args
        log("args: {}".format(args))
        if len(args) != 2:
            error("Expected NODE argument to csync2_remote")
        _context.cluster_node = args[1]

    if stage != "":
        globals()["init_" + stage]()
    else:
        init_ssh()
        init_csync2()
        init_corosync()
        init_remote_auth()
        if _context.template == 'ocfs2':
            if _context.sbd_device is None or _context.ocfs2_device is None:
                init_storage()
        init_sbd()

        lock_inst = lock.Lock()
        try:
            with lock_inst.lock():
                init_cluster()
                if _context.template == 'ocfs2':
                    init_vgfs()
                init_admin()
                init_qdevice()
        except lock.ClaimLockError as err:
            error(err)

    status("Done (log saved to %s)" % (LOG_FILE))


def bootstrap_join(context):
    """
    Join cluster process
    """
    global _context
    _context = context

    init()
    _context.init_sbd_manager()
    _context.validate_option()

    check_tty()

    corosync_active = utils.service_is_active("corosync.service")
    if corosync_active:
        error("Abort: Cluster is currently active. Run this command on a node joining the cluster.")

    if not check_prereqs("join"):
        return

    cluster_node = _context.cluster_node
    if _context.stage != "":
        globals()["join_" + _context.stage](cluster_node)
    else:
        if not _context.yes_to_all and cluster_node is None:
            status("""Join This Node to Cluster:
  You will be asked for the IP address of an existing node, from which
  configuration will be copied.  If you have not already configured
  passwordless ssh between nodes, you will be prompted for the root
  password of the existing node.
""")
            cluster_node = prompt_for_string("IP address or hostname of existing node (e.g.: 192.168.1.1)", ".+")
            _context.cluster_node = cluster_node

        utils.ping_node(cluster_node)

        join_ssh(cluster_node)

        if not utils.service_is_active("pacemaker.service", cluster_node):
            error("Cluster is inactive on {}".format(cluster_node))

        lock_inst = lock.RemoteLock(cluster_node)
        try:
            with lock_inst.lock():
                setup_passwordless_with_other_nodes(cluster_node)
                join_remote_auth(cluster_node)
                join_csync2(cluster_node)
                join_ssh_merge(cluster_node)
                join_cluster(cluster_node)
        except (lock.SSHError, lock.ClaimLockError) as err:
            error(err)

    status("Done (log saved to %s)" % (LOG_FILE))


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
        error("No QDevice configuration in this cluster")
    if not confirm("Removing QDevice service and configuration from cluster: Are you sure?"):
        return

    status("Disable corosync-qdevice.service")
    invoke("crm cluster run 'systemctl disable corosync-qdevice'")
    status("Stopping corosync-qdevice.service")
    invoke("crm cluster run 'systemctl stop corosync-qdevice'")

    status_long("Removing QDevice configuration from cluster")
    qnetd_host = corosync.get_value('quorum.device.net.host')
    qdevice_inst = corosync.QDevice(qnetd_host)
    qdevice_inst.remove_qdevice_config()
    qdevice_inst.remove_qdevice_db()
    update_expected_votes()
    invoke("crm cluster run 'crm corosync reload'")
    status_done()


def bootstrap_remove(context):
    """
    Remove node from cluster, or remove qdevice configuration
    """
    global _context
    _context = context
    force_flag = config.core.force or _context.force

    init()

    if not utils.service_is_active("corosync.service"):
        error("Cluster is not active - can't execute removing action")

    if _context.qdevice_rm_flag and _context.cluster_node:
        error("Either remove node or qdevice")

    if _context.qdevice_rm_flag:
        remove_qdevice()
        return

    if not _context.yes_to_all and _context.cluster_node is None:
        status("""Remove This Node from Cluster:
  You will be asked for the IP address or name of an existing node,
  which will be removed from the cluster. This command must be
  executed from a different node in the cluster.
""")
        _context.cluster_node = prompt_for_string("IP address or hostname of cluster node (e.g.: 192.168.1.1)", ".+")

    if not _context.cluster_node:
        error("No existing IP/hostname specified (use -c option)")

    _context.cluster_node = get_cluster_node_hostname()

    if not force_flag and not confirm("Removing node \"{}\" from the cluster: Are you sure?".format(_context.cluster_node)):
        return

    if _context.cluster_node == utils.this_node():
        if not force_flag:
            error("Removing self requires --force")
        remove_self()
        return

    if _context.cluster_node in xmlutil.listnodes():
        remove_node_from_cluster()
    else:
        error("Specified node {} is not configured in cluster! Unable to remove.".format(_context.cluster_node))


def remove_self():
    me = _context.cluster_node
    yes_to_all = _context.yes_to_all
    nodes = xmlutil.listnodes(include_remote_nodes=False)
    othernode = next((x for x in nodes if x != me), None)
    if othernode is not None:
        # remove from other node
        cmd = "crm cluster remove{} -c {}".format(" -y" if yes_to_all else "", me)
        rc = utils.ext_cmd_nosudo("ssh{} -o StrictHostKeyChecking=no {} '{}'".format("" if yes_to_all else " -t", othernode, cmd))
        if rc != 0:
            error("Failed to remove this node from {}".format(othernode))
    else:
        # disable and stop cluster
        stop_services(SERVICES_STOP_LIST)
        # remove all trace of cluster from this node
        # delete configuration files from the node to be removed
        if not invokerc('bash -c "rm -f {}"'.format(" ".join(_context.rm_list))):
            error("Deleting the configuration files failed")


def init_common_geo():
    """
    Tasks to do both on first and other geo nodes.
    """
    if not utils.package_is_installed("booth"):
        error("Booth not installed - Not configurable as a geo cluster node.")


BOOTH_CFG = "/etc/booth/booth.conf"
BOOTH_AUTH = "/etc/booth/authkey"


def init_csync2_geo():
    """
    TODO: Configure csync2 for geo cluster
    That is, create a second sync group which
    syncs the geo configuration across the whole
    geo cluster.
    """


def create_booth_authkey():
    status("Create authentication key for booth")
    if os.path.exists(BOOTH_AUTH):
        rmfile(BOOTH_AUTH)
    rc, _, err = invoke("booth-keygen {}".format(BOOTH_AUTH))
    if not rc:
        error("Failed to generate booth authkey: {}".format(err))


def create_booth_config(arbitrator, clusters, tickets):
    status("Configure booth")

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
    status("Sync booth configuration across cluster")
    csync2_update("/etc/booth")
    init_csync2_geo()
    geo_cib_config(_context.clusters)


def geo_fetch_config(node):
    # TODO: clean this up
    status("Retrieving configuration - This may prompt for root@%s:" % (node))
    tmpdir = tmpfiles.create_dir()
    rc, _, err = invoke("scp -oStrictHostKeyChecking=no root@%s:'/etc/booth/*' %s/" % (node, tmpdir))
    if not rc:
        error("Failed to retrieve configuration: {}".format(err))
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
        error("Local cluster name is {}, expected {}".format(cluster_name, "|".join(list(clusters.keys()))))

    status("Configure cluster resources for booth")
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
    status("Sync booth configuration across cluster")
    csync2_update("/etc/booth")
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
        error("Failed to copy {} from {}".format(BOOTH_CFG, node))
    # TODO: verify that the arbitrator IP in the configuration is us?
    status("Enabling and starting the booth arbitrator service")
    utils.start_service("booth@booth", enable=True)

# EOF
