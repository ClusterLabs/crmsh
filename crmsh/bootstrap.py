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
# TODO: Firewall handling for non-SUSE platforms
# TODO: Make csync2 usage optional
# TODO: Configuration file for bootstrap?

import os
import sys
import random
import re
import time
from string import Template
from lxml import etree
from . import config
from . import utils
from . import xmlutil
from .cibconfig import mkset_obj, cib_factory
from . import corosync
from . import tmpfiles
from . import clidisplay
from . import term


LOG_FILE = "/var/log/ha-cluster-bootstrap.log"
CSYNC2_KEY = "/etc/csync2/key_hagroup"
CSYNC2_CFG = "/etc/csync2/csync2.cfg"
COROSYNC_AUTH = "/etc/corosync/authkey"
SYSCONFIG_SBD = "/etc/sysconfig/sbd"
SYSCONFIG_FW = "/etc/sysconfig/SuSEfirewall2"
SYSCONFIG_FW_CLUSTER = "/etc/sysconfig/SuSEfirewall2.d/services/cluster"

INIT_STAGES = ("ssh", "ssh_remote", "csync2", "csync2_remote", "corosync", "storage", "sbd", "cluster", "vgfs", "admin")


class Context(object):
    def __init__(self, quiet, yes_to_all, nic=None, ip_address=None, ip_network=None):
        self.quiet = quiet
        self.yes_to_all = yes_to_all
        self.nic = nic
        self.ip_address = ip_address
        self.ip_network = ip_network
        self.cluster_name = None
        self.cluster_node = None
        self.ocfs2_device = None
        self.shared_device = None
        self.sbd_device = None
        self.unicast = None
        self.admin_ip = None
        self.watchdog = None
        self.host_status = None
        self.connect_name = None

_context = None


def die(*args):
    """
    Broken out as special case for log() failure.  Ordinarily you
    should just use error() to terminate.
    """
    raise ValueError(" ".join([str(arg) for arg in args]))


def error(*args):
    log("ERROR: {}".format(" ".join([str(arg) for arg in args])))
    die(*args)


def warn(*args):
    log("WARNING: {}".format(" ".join(str(arg) for arg in args)))
    if not _context.quiet:
        print term.render(clidisplay.warn("! {}".format(" ".join(str(arg) for arg in args))))


def log(*args):
    try:
        with open(LOG_FILE, "a") as logfile:
            logfile.write(" ".join([str(arg) for arg in args]) + "\n")
    except IOError:
        die("Can't append to {} - aborting".format(LOG_FILE))


def prompt_for_string(msg, match=None, default=''):
    if _context.yes_to_all:
        return default
    while True:
        val = utils.multi_input('  %s [%s]' % (msg, default))
        if val is None or len(val) == 0:
            val = default
        if match is None:
            return val
        if re.match(match, val) is not None:
            return val
        print >>sys.stderr, "    Invalid value entered"


def confirm(msg):
    return _context.yes_to_all or utils.ask(msg)


def invoke(*args):
    """
    Log command execution to log file.
    Log output from command to log file.
    Return returncode == 0
    """
    log("+ " + " ".join(args))
    rc, stdout, stderr = utils.get_stdout_stderr(" ".join(args))
    if stdout:
        log(stdout)
    if stderr:
        log(stderr)
    return rc == 0


def invokerc(*args):
    "Like invoke, but returns the returncode, not True/False"
    log("+ " + " ".join(args))
    rc, stdout, stderr = utils.get_stdout_stderr(" ".join(args))
    if stdout:
        log(stdout)
    if stderr:
        log(stderr)
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
        rc, out, err = utils.get_stdout_stderr("crm_mon -1")
        if "online" in out.lower():
            break
        status_progress()
        sleep(5)
    status_done()


def start_service(service):
    """
    Start and enable systemd service
    """
    invoke("systemctl enable " + service)
    rc, _out, _err = utils.get_stdout_stderr('systemctl -q is-active ' + service)
    if rc != 0:
        if not invoke("systemctl start " + service):
            error("Failed to start " + service)


def stop_service(service):
    """
    Stops the systemd service
    """
    return invoke("systemctl stop " + service)


def service_is_enabled(service):
    """
    Check if service is enabled
    """
    rc, _out, _err = utils.get_stdout_stderr('systemctl is-enabled %s' % (service))
    return rc == 0


def service_is_active(service):
    """
    Check if service is active
    """
    rc, _out, _err = utils.get_stdout_stderr('systemctl -q is-active %s' % (service))
    return rc == 0


def package_is_installed(pkg):
    """
    Check if package is installed
    """
    return invoke("rpm -q --quiet {}".format(pkg))


def sleep(t):
    """
    Sleep for t seconds.
    """
    t = float(t)
    time.sleep(t)


def status(msg):
    log("# " + msg)
    if not _context.quiet:
        print "  {}".format(msg)


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
        print "done"


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


def configured_sbd_device():
    """
    Gets currently configured SBD device, i.e. what's in /etc/sysconfig/sbd
    """
    conf = utils.parse_sysconfig(SYSCONFIG_SBD)
    return conf.get("SBD_DEVICE")


def check_tty():
    """
    Check for pseudo-tty: Cannot display read prompts without a TTY (bnc#892702)
    """
    if _context.yes_to_all:
        return
    if not sys.stdin.isatty():
        error("No pseudo-tty detected! Use -t option to ssh if calling remotely.")


def grep_output(cmd, txt):
    _rc, outp, _err = utils.get_stdout_stderr(cmd)
    return txt in outp


def grep_file(fn, txt):
    return os.path.exists(fn) and txt in open(fn).read()


def service_is_available(svcname):
    return grep_output("systemctl list-unit-files {}".format(svcname), svcname)


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

    ntpd = "ntp.service"
    if service_is_available("ntpd.service"):
        ntpd = "ntpd.service"

    if not service_is_enabled(ntpd):
        warn("NTP is not configured to start at system boot.")
        warned = True

    if stage in ("", "join", "sbd"):
        if not check_watchdog():
            warn("No watchdog device found. If SBD is used, the cluster will be unable to start without a watchdog.")
            warned = True

    if warned:
        if not confirm("Do you want to continue anyway?"):
            return False

    firewall_open_basic_ports()
    return True


def init_watchdog():
    """
    If a watchdog device was provided on the command line, configure it
    """
    if _context.watchdog:
        _, outp = utils.get_stdout("lsmod")
        if not any(re.match(r"^{}\b", d) is not None for d in outp.splitlines()):
            invoke("modprobe {}".format(_context.watchdog))
            with open("/etc/modules-load.d/watchdog.conf", "w") as f:
                f.write("{}\n".format(_context.watchdog))
            invoke("systemctl restart systemd-modules-load")


def log_start():
    """
    Convenient side-effect: this will die immediately if the log file
    is not writable (e.g. if not running as root)
    """
    # Reload rsyslog to make sure it logs with the correct hostname
    if service_is_active("rsyslog.service"):
        invoke("systemctl reload rsyslog.service")
    datestr = utils.get_stdout("date --rfc-3339=seconds")[1]
    log('================================================================')
    log("%s %s" % (datestr, " ".join(sys.argv)))
    log('----------------------------------------------------------------')


def init_network():
    """
    Auto-detection of IP address and netmask only works if $NET_IF is
    up. If $IP_ADDRESS is overridden, network detect shouldn't work,
    because "ip route" won't be able to help us.
    """
    nic, ipaddr, ipnetwork, _prefix = utils.network_defaults(_context.nic)
    if _context.nic is None:
        _context.nic = nic
    if _context.ip_address is None:
        _context.ip_address = ipaddr
    if _context.ip_network is None:
        _context.ip_network = ipnetwork
    if _context.ip_address is None:
        warn("Could not detect IP address for {}".format(nic))
    if _context.ip_network is None:
        warn("Could not detect network address for {}".format(nic))


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
        if not service_is_active("SuSEfirewall2"):
            return

        # Firewall is active, either restart or complain if we couldn't tweak it
        status("Restarting firewall (tcp={}, udp={})".format(" ".join(tcp), " ".join(udp)))
        if not invoke("rcSuSEfirewall2 restart"):
            error("Failed to restart firewall")

    def init_firewall_rhel7(tcp, udp):
        for p in tcp:
            if not invoke("firewall-cmd --zone=public --add-port={}/tcp --permanent".format(p)):
                error("Failed to configure firewall")

        for p in udp:
            if not invoke("firewall-cmd --zone=public --add-port={}/udp --permanent".format(p)):
                error("Failed to configure firewall")

        if not service_is_active("firewalld"):
            return

        if not invoke("firewall-cmd --reload"):
            warn("Failed to reload firewall configuration")

    def init_firewall_ufw(tcp, udp):
        """
        try configuring firewall with ufw
        """
        for p in tcp:
            if not invoke("ufw allow {}/tcp".format(p)):
                error("Failed to configure firewall using ufw")
        for p in udp:
            if not invoke("ufw allow {}/udp".format(p)):
                error("Failed to configure firewall using ufw")

    version = open("/proc/version").read()
    if "SUSE" in version:
        init_firewall_suse(tcp, udp)
    elif "Red Hat 7" in version:
        init_firewall_rhel7(tcp, udp)
    elif utils.is_program("ufw"):
        init_firewall_ufw(tcp, udp)
    else:
        warn("Firewall: Could not open ports tcp={}, udp={}".format("|".join(tcp), "|".join(udp)))


def firewall_open_basic_ports():
    # ports for csync2, mgmtd, hawk & dlm respectively
    configure_firewall(tcp=["30865", "5560", "7630", "21064"])


def firewall_open_corosync_ports():
    """
    Have to do this separately, as we need general firewall config early
    so csync2 works, but need corosync config *after* corosync.conf has
    been created/updated.

    Please note corosync uses two UDP ports mcastport (for mcast
    receives) and mcastport - 1 (for mcast sends).
    """
    # all mcastports defined in corosync config
    udp = corosync.get_values("totem.interface.mcastport")
    udp.extend([str(int(p) - 1) for p in udp])

    configure_firewall(udp=udp)


def init_cluster_local():
    # Caller should check this, but I'm paranoid...
    if service_is_active("corosync.service"):
        error("corosync service is running!")

    firewall_open_corosync_ports()

    # reset password, but only if it's not already set
    _rc, outp = utils.get_stdout("passwd -S hacluster")
    ps = outp.strip().split()[1]
    pass_msg = ""
    if ps not in ("P", "PS"):
        log(': Resetting password of hacluster user')
        rc, outp, errp = utils.get_stdout_stderr("passwd hacluster", input_s="linux\nlinux\n")
        if rc != 0:
            warn("Failed to reset password of hacluster user: %s" % (outp + errp))
        else:
            pass_msg = ", password 'linux'"

    # evil, but necessary
    invoke("rm -f /var/lib/heartbeat/crm/* /var/lib/pacemaker/cib/*")

    # only try to start hawk if hawk is installed
    if service_is_available("hawk.service"):
        start_service("hawk.service")
        status("  Hawk cluster interface is now running. To see cluster status, open:")
        status("    https://%s:7630/" % (_context.ip_address))
        status("  Log in with username 'hacluster'%s" % (pass_msg))
    else:
        warn("Hawk not installed - not configuring web management interface.")

    if pass_msg:
        warn("You should change the hacluster password to something more secure!")

    if configured_sbd_device():
        invoke("systemctl enable sbd.service")
    else:
        invoke("systemctl disable sbd.service")

    start_service("pacemaker.service")
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


def init_ssh():
    """
    Configure passwordless SSH.
    """
    start_service("sshd.service")
    invoke("mkdir -m 700 -p /root/.ssh")
    if os.path.exists("/root/.ssh/id_rsa"):
        if not confirm("/root/.ssh/id_rsa already exists - overwrite?"):
            return
        try:
            os.remove("/root/.ssh/id_rsa")
        except os.error:
            error("Failed to remove /root/.ssh/id_rsa")
    status("Generating SSH key")
    invoke("ssh-keygen -q -f /root/.ssh/id_rsa -C 'Cluster Internal' -N ''")
    append("/root/.ssh/id_rsa.pub", "/root/.ssh/authorized_keys")


def init_ssh_remote():
    """
    Called by ha-cluster-join
    """
    authkeys = open("/root/.ssh/authorized_keys", "r+")
    authkeys_data = authkeys.read()
    for key in ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"):
        fn = os.path.join("/root/.ssh", key)
        if not os.path.exists(fn):
            continue
        keydata = open(fn + ".pub").read()
        if keydata not in authkeys_data:
            append(fn + ".pub", "/root/.ssh/authorized_keys")


def init_csync2():
    status("Configuring csync2")
    if os.path.exists(CSYNC2_KEY):
        if not confirm("csync2 is already configured - overwrite?"):
            return

    invoke("rm", "-f", CSYNC2_KEY)
    status_long("Generating csync2 shared key (this may take a while)")
    if not invoke("csync2", "-k", CSYNC2_KEY):
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
include /etc/sysconfig/pacemaker;
include /etc/sysconfig/sbd;
}
    """ % (utils.this_node()), CSYNC2_CFG)

    start_service("csync2.socket")
    status_long("csync2 checking files")
    invoke("csync2", "-cr", "/")
    status_done()


def csync2_update(path):
    invoke("csync2 -rm %s" % (path))
    invoke("csync2 -rf %s" % (path))
    invoke("csync2 -rxv %s" % (path))


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
            invoke("csync2", "-c", CSYNC2_CFG)
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
        try:
            os.remove(COROSYNC_AUTH)
        except os.error:
            error("Failed to remove %s" % (COROSYNC_AUTH))
    invoke("corosync-keygen -l")


def init_corosync_unicast():
    if _context.yes_to_all:
        status("Configuring corosync (unicast)")
    else:
        status("""
Configure Corosync (unicast):
  This will configure the cluster messaging layer.  You will need
  to specify a network address over which to communicate (default
  is %s's network, but you can use the network address of any
  active interface).
""" % (_context.nic))

    if os.path.exists(corosync.conf()):
        if not confirm("%s already exists - overwrite?" % (corosync.conf())):
            return

    mcastport = prompt_for_string('Port', '[0-9]+', "5405")
    if not mcastport:
        error("No value for mcastport")

    corosync.create_configuration(
        clustername=_context.cluster_name,
        bindnetaddr=None,
        mcastport=mcastport,
        transport="udpu")
    csync2_update(corosync.conf())


def init_corosync_multicast():
    def gen_mcastaddr():
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
  is %s's network, but you can use the network address of any
  active interface).
""" % (_context.nic))

    if os.path.exists(corosync.conf()):
        if not confirm("%s already exists - overwrite?" % (corosync.conf())):
            return

    bindnetaddr = prompt_for_string('Network address to bind to (e.g.: 192.168.1.0)', r'([0-9]+\.){3}[0-9]+', _context.ip_network)
    if not bindnetaddr:
        error("No value for bindnetaddr")

    mcastaddr = prompt_for_string('Multicast address (e.g.: 239.x.x.x)', r'([0-9]+\.){3}[0-9]+', gen_mcastaddr())
    if not mcastaddr:
        error("No value for mcastaddr")

    mcastport = prompt_for_string('Multicast port', '[0-9]+', "5405")
    if not mcastport:
        error("No value for mcastport")

    corosync.create_configuration(
        clustername=_context.cluster_name,
        bindnetaddr=bindnetaddr,
        mcastaddr=mcastaddr,
        mcastport=mcastport)
    csync2_update(corosync.conf())


def init_corosync():
    """
    Configure corosync (unicast or multicast, encrypted?)
    """
    def check_amazon():
        _rc, outp = utils.get_stdout("dmidecode -s system-version")
        return re.search(r"\<.*\.amazon\>", outp) is not None

    init_corosync_auth()
    if _context.unicast or check_amazon():
        init_corosync_unicast()
    else:
        init_corosync_multicast()


def is_block_device(dev):
    from stat import S_ISBLK
    return S_ISBLK(os.stat(dev).st_mode)


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
                print >>sys.stderr, "    That doesn't look like a block device"
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
            if len(partitions) > 0:
                status("WARNING: Partitions exist on %s!" % (dev))
                if confirm("Are you ABSOLUTELY SURE you want to overwrite?"):
                    dev_looks_sane = True
                else:
                    dev = ""
            else:
                # It's either broken, no partition table, or empty partition table
                status("%s appears to be empty" % (dev))
                if confirm("Are you sure you wish to use this device?"):
                    dev_looks_sane = True
                else:
                    dev = ""

    if len(partitions):
        if not confirm("Really?"):
            return
        status_long("Erasing existing partitions...")
        for part in partitions:
            if not invoke("parted -s %s rm %s" % (dev, part)):
                error("Failed to remove partition %s from %s" % (part, dev))
        status_done()

    status_long("Creating partitions...")
    if not invoke("parted", "-s", dev, "mklabel", "msdos"):
        error("Failed to create partition table")

    # This is a bit rough, and probably won't result in great performance,
    # but it's fine for test/demo purposes to carve off 1MB for SBD.  Note
    # we have to specify the size of the first partition in this in bytes
    # rather than MB, or parted's rounding gives us a ~30Kb partition
    # (see rhbz#623268).
    if not invoke("parted -s %s mkpart primary 0 1048576B" % (dev)):
        error("Failed to create first partition on %s" % (dev))
    if not invoke("parted -s %s mkpart primary 1M 100%%" % (dev)):
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


def check_watchdog():
    """
    Verify watchdog device. Fall back to /dev/watchdog.
    """
    wdconf = "/etc/modules-load.d/watchdog.conf"
    watchdog_dev = "/dev/watchdog"
    if os.path.exists(wdconf):
        txt = open(wdconf, "r").read()
        for line in txt.splitlines():
            m = re.match(r'^\s*watchdog-device\s*=\s*(.*)$', line)
            if m:
                watchdog_dev = m.group(1)
    rc, _out, _err = utils.get_stdout_stderr("wdctl %s" % (watchdog_dev))
    return rc == 0


def init_sbd():
    """
    Configure SBD (Storage-based fencing).
    """
    if not _context.sbd_device:
        # SBD device not set up by init_storage (ocfs2 template) and
        # also not passed in as command line argument - prompt user
        if _context.yes_to_all:
            warn("Not configuring SBD (%s left untouched)." % (SYSCONFIG_SBD))
            return
        status("""
Configure SBD:
  If you have shared storage, for example a SAN or iSCSI target,
  you can use it avoid split-brain scenarios by configuring SBD.
  This requires a 1 MB partition, accessible to all nodes in the
  cluster.  The device path must be persistent and consistent
  across all nodes in the cluster, so /dev/disk/by-id/* devices
  are a good choice.  Note that all data on the partition you
  specify here will be destroyed.
""")

        configured_dev = configured_sbd_device()
        if configured_dev:
            if not confirm("SBD is already configured to use %s - overwrite?" % (configured_dev)):
                return

        if not confirm("Do you wish to use SBD?"):
            warn("Not configuring SBD - STONITH will be disabled.")
            # Comment out SBD devices if present
            scfg = open(SYSCONFIG_SBD).read()
            scfg, nmatches = re.subn(r'^\([^#].*\)$', r'#\1', scfg)
            if nmatches > 0:
                utils.str2file(scfg, SYSCONFIG_SBD)
                csync2_update(SYSCONFIG_SBD)
            return

        dev = ""
        dev_looks_sane = False
        while not dev_looks_sane:
            dev = prompt_for_string('Path to storage device (e.g. /dev/disk/by-id/...)', r'\/.*', dev)
            if not is_block_device(dev):
                print >>sys.stderr, "    That doesn't look like a block device"
            else:
                warn("All data on {} will be destroyed!".format(dev))
                if confirm('Are you sure you wish to use this device'):
                    dev_looks_sane = True
                else:
                    dev = ""
        _context.sbd_device = dev

    if not is_block_device(_context.sbd_device):
        error("SBD device %s doesn't seem to exist" % (_context.sbd_device))

    # TODO: need to ensure watchdog is available
    # (actually, should work if watchdog unavailable, it'll just whine in the logs...)
    # TODO: what about timeouts for multipath devices?
    status_long('Initializing SBD...')
    if not invoke("sbd -d %s create" % (_context.sbd_device)):
        error("Failed to initialize SBD device %s" % (_context.sbd_device))
    status_done()

    utils.sysconfig_set(SYSCONFIG_SBD, SBD_DEVICE=_context.sbd_device, SBD_WATCHDOG="yes")
    csync2_update(SYSCONFIG_SBD)


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
property cib-bootstrap-options: stonith-enabled=false placement-strategy=balanced
op_defaults op-options: timeout=600 record-pending=true
rsc_defaults rsc-options: resource-stickiness=1 migration-threshold=3
""")

    if utils.parse_sysconfig(SYSCONFIG_SBD).get("SBD_DEVICE"):
        if not invoke("crm configure primitive stonith-sbd stonith:external/sbd pcmk_delay_max=30s"):
            error("Can't create stonith-sbd primitive")
        if not invoke("crm configure property stonith-enabled=true"):
            error("Can't enable STONITH")


def init_vgfs():
    """
    Configure cluster OCFS2 device.
    """
    dev = _context.ocfs2_device
    mntpoint = "/srv/clusterfs"

    if not is_block_device(dev):
        error("OCFS2 device $OCFS2_DEVICE does not exist")

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
        if not confirm("Exiting filesystem found on $OCFS2_DEVICE - destroy?"):
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
    if not invoke("mkfs.ocfs2 --cluster-stack pcmk --cluster-name %s -N 8 -x %s" % (_context.cluster_name, dev)):
        error("Failed to create OCFS2 filesystem on %s" % (dev))
    status_done()

    # TODO: refactor, maybe
    if not invoke("mkdir -p %s" % (mntpoint)):
        error("Can't create mountpoint %s" % (mntpoint))
    if not invoke("crm resource meta clusterfs delete target-role"):
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
        if not confirm("Do you wish to configure an administration IP?"):
            return

        adminaddr = prompt_for_string('Administration Virtual IP', r'([0-9]+\.){3}[0-9]+', "")
        if not adminaddr:
            error("No value for admin address")

    crm_configure_load("update", 'primitive admin-ip IPaddr2 ip=%s op monitor interval=10 timeout=20' % (utils.doublequote(adminaddr)))
    wait_for_resource("Waiting for Admin Address", "admin-ip")


def init():
    """
    Basic init
    """
    log_start()
    init_network()


def join_ssh(seed_host):
    """
    """
    if not seed_host:
        error("No existing IP/hostname specified (use -c option)")

    start_service("sshd.service")
    invoke("mkdir -m 700 -p /root/.ssh")

    tmpdir = tmpfiles.create_dir()
    status("Retrieving SSH keys - This may prompt for root@%s:" % (seed_host))
    invoke("scp -oStrictHostKeyChecking=no  root@%s:'/root/.ssh/id_*' %s/" % (seed_host, tmpdir))

    # This supports all SSH key types, for the case where ha-cluster-init
    # wasn't used to set up the seed node, and the user has manually
    # created, for example, DSA keys (bnc#878080)
    got_keys = 0
    for key in ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"):
        if not os.path.exists(os.path.join(tmpdir, key)):
            continue

        if os.path.exists(os.path.join("/root/.ssh", key)):
            if not confirm("/root/.ssh/%s already exists - overwrite?" % (key)):
                continue
        invoke("mv %s* /root/.ssh/" % (os.path.join(tmpdir, key)))
        if not grep_file("/root/.ssh/authorized_keys", open("/root/.ssh/%s.pub" % (key)).read()):
            append("/root/.ssh/%s.pub" % (key), "/root/.ssh/authorized_keys")
        got_keys += 1

    if got_keys == 0:
        status("No new SSH keys installed")
    elif got_keys == 1:
        status("One new SSH key installed")
    else:
        status("%s new SSH keys installed" % (got_keys))

    # This makes sure the seed host has its own SSH keys in its own
    # authorized_keys file (again, to help with the case where the
    # user has done manual initial setup without the assistance of
    # ha-cluster-init).
    if not invoke("ssh root@%s ha-cluster-init ssh_remote" % (seed_host)):
        error("Can't invoke ha-cluster-init ssh_remote on %s" % (seed_host))


def join_csync2(seed_host):
    """
    """
    if not seed_host:
        error("No existing IP/hostname specified (use -c option)")
    status("Configuring csync2")

    # Necessary if re-running join on a node that's been configured before.
    invoke("rm -f /var/lib/csync2/{}.db3".format(utils.this_node()))

    # Not automatically updating /etc/hosts - risky in the general case.
    # etc_hosts_add_me
    # local hosts_line=$(etc_hosts_get_me)
    # [ -n "$hosts_line" ] || error "No valid entry for $(hostname) in /etc/hosts - csync2 can't work"

    # If we *were* updating /etc/hosts, the next line would have "\"$hosts_line\"" as
    # the last arg (but this requires re-enabling this functionality in ha-cluster-init)
    if not invoke("ssh root@{} ha-cluster-init csync2_remote {}".format(seed_host, utils.this_node())):
        error("Can't invoke ha-cluster-init csync2_remote on {}".format(seed_host))

    # This is necessary if syncing /etc/hosts (to ensure everyone's got the
    # same list of hosts)
    # local tmp_conf=/etc/hosts.$$
    # invoke scp root@seed_host:/etc/hosts $tmp_conf \
    #   || error "Can't retrieve /etc/hosts from seed_host"
    # install_tmp $tmp_conf /etc/hosts

    if not invoke("scp root@%s:'/etc/csync2/{csync2.cfg,key_hagroup}' /etc/csync2" % (seed_host)):
        error("Can't retrieve csync2 config from %s" % (seed_host))

    start_service("csync2.socket")

    # Sync new config out.  This goes to all hosts; csync2.cfg definitely
    # needs to go to all hosts (else hosts other than the seed and the
    # joining host won't have the joining host in their config yet).
    # Strictly, the rest of the files need only go to the new host which
    # could theoretically be effected using `csync2 -xv -P $(hostname)`,
    # but this still leaves all the other files in dirty state (becuase
    # they haven't gone to all nodes in the cluster, which means a
    # subseqent join of another node can fail its sync of corosync.conf
    # when it updates expected_votes.  Grrr...
    if not invoke('ssh root@%s "csync2 -mr / ; csync2 -fr / ; csync2 -xv"' % (seed_host)):
        warn("csync2 run failed - some files may not be sync'd")


def join_ssh_merge(_cluster_node):
    status("Merging known_hosts")

    hosts = [m.group(1) for m in re.finditer(r"^\s*host\s*([^ ;]+)\s*;", open(CSYNC2_CFG).read(), re.M)]
    if len(hosts) == 0:
        error("Unable to extract host list from %s" % (CSYNC2_CFG))

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
    for host, result in results.iteritems():
        if isinstance(result, parallax.Error):
            warn("Failed to get known_hosts from {}: {}".format(host, str(result)))
        else:
            known_hosts_new.update((result[1] or "").splitlines())
    if known_hosts_new:
        hoststxt = "\n".join(sorted(known_hosts_new))
        tmpf = utils.str2tmp(hoststxt)
        log("parallax.copy {} : {}".format(hosts, hoststxt))
        results = parallax.copy(hosts, tmpf, "/root/.ssh/known_hosts")
        for host, result in results.iteritems():
            if isinstance(result, parallax.Error):
                warn("scp to {} failed ({}), known_hosts update may be incomplete".format(host, str(result)))


def join_cluster(seed_host):
    """
    """
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
        rc, outp = utils.get_stdout("ssh -o StrictHostKeyChecking=no root@{} 'cibadmin -Q --xpath \"//primitive\"'".format(seed_host))
        if len(outp):
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
    is_unicast = "nodelist" in open(corosync.conf()).read()
    if is_unicast:
        corosync.add_node(utils.this_node())

    # Increase expected_votes
    new_quorum = 0
    for v in corosync.get_values("quorum.expected_votes"):
        new_quorum = int(v) + 1
        corosync.set_value("quorum.expected_votes", str(new_quorum))
    corosync.set_value("quorum.two_node", 1 if new_quorum == 2 else 0)
    csync2_update(corosync.conf())

    # ...now that that's out of the way, let's initialize the cluster.
    init_cluster_local()

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


def remove_ssh():
    seed_host = _context.cluster_node
    if not seed_host:
        error("No existing IP/hostname specified (use -c option)")

    # check whether corosync has been started on local node
    if not service_is_active("corosync.service"):
        error("Cluster is not active - can't execute removing action")

    remove_get_hostname(seed_host)


def remove_get_hostname(seed_host):
    """
    Get the nodename

    Sets _context.host_status to
    0 = Disconnected
    1 = Connected
    2 = Connected through IP address
    """
    _context.connect_name = seed_host
    _context.host_status = 0
    _rc, outp, _errp = utils.get_stdout_stderr("ssh root@{} \"hostname\"".format(seed_host))
    if outp:
        _context.connect_name = seed_host
        _context.cluster_node = outp.strip()
        _context.host_status = 1
    elif re.match(r'^[\[0-9].*', seed_host):
        # IP address
        warn("Could not connect to {}".format(seed_host))
        nodename = prompt_for_string('Please enter the hostname of the node to be removed', '.+' "")
        if not nodename:
            error("Not a valid hostname")

        if nodename not in xmlutil.listnodes():
            error("Specified node {} is not configured in cluster, can not remove".format(nodename))

        _rc, outp, _errp = utils.get_stdout_stderr("ssh root@{} \"hostname\"".format(nodename))
        if outp:
            _context.connect_name = seed_host
            _context.cluster_node = nodename
            _context.host_status = 1
        else:
            _context.host_status = 2
    else:
        if seed_host not in xmlutil.listnodes():
            error("Specified node {} is not configured in cluster, can not remove".format(nodename))

        warn("Could not resolve hostname {}".format(seed_host))
        nodename = prompt_for_string('Please enter the IP address of the node to be removed (e.g: 192.168.0.1)', r'([0-9]+\.){3}[0-9]+', "")
        if not nodename:
            error("Invalid IP address")

        # try to use the IP address to connect
        _rc, outp, _errp = utils.get_stdout_stderr("ssh root@{} \"hostname\"".format(nodename))
        if outp:
            ipaddr = nodename
            nodename = outp.strip()
            if nodename != seed_host:
                warn("Specified IP address {ipaddr} is node {nodename}, not configured in cluster.".format(ipaddr=ipaddr, nodename=nodename))
                warn("Trying to remove node {}".format(seed_host))
                _context.host_status = 0
                _context.cluster_node = nodename
            else:
                _context.host_status = 2
                _context.connect_name = ipaddr
        else:
            _context.host_status = 0


def remove_cluster():
    """
    """
    node = _context.cluster_node

    if _context.host_status != 0:
        status("Stopping the corosync service")
        if not invoke('ssh root@{} "systemctl stop corosync"'.format(_context.connect_name)):
            error("Stopping corosync on {} failed".format(_context.connect_name))

        # delete configuration files from the node to be removed
        toremove = [SYSCONFIG_SBD, CSYNC2_CFG, corosync.conf(), CSYNC2_KEY, COROSYNC_AUTH]
        if not invoke('ssh root@{} "bash -c \\\"rm -f {} && rm -f /var/lib/heartbeat/crm/* /var/lib/pacemaker/cib/*\\\""'.format(node, " ".join(toremove))):
            error("Deleting the configuration files failed")
    else:
        # Check node status
        _, outp = utils.get_stdout("crm_node --list")
        if any("lost" in l for l in [l for l in outp.splitlines() if node in l.split()]):
            if not confirm("The node has not been cleaned up... - remove it?"):
                return

    # execute the command : crm node delete $HOSTNAME
    status("Removing the node {}".format(node))
    if not invoke("crm node delete {}".format(node)):
        error("Failed to remove {}".format(node))

    if not invoke("sed -i /{}/d {}".format(node, CSYNC2_CFG)):
        error("Removing the node {} from {} failed".format(node, CSYNC2_CFG))

    # Remove node from nodelist if this is a unicast configuration
    if "nodelist" in open(corosync.conf()).read():
        corosync.del_node(node)

    # Decrement expected_votes in corosync.conf
    votes = corosync.get_values("quorum.expected_votes")
    for vote in votes:
        new_quorum = int(vote) - 1
        corosync.set_value("quorum.expected_votes", str(new_quorum))
        corosync.set_value("quorum.two_node", 1 if new_quorum == 2 else 0)

    status("Propagating configuration changes across the remaining nodes")
    csync2_update(CSYNC2_CFG)

    # Trigger corosync config reload to ensure expected_votes is propagated
    invoke("corosync-cfgtool -R")


def remove_localhost_check():
    """
    Check whether the specified node is a cluster member
    or the local node.
    """
    nodename = _context.cluster_node
    nodes = xmlutil.listnodes()
    if nodename not in nodes:
        error("Specified node {} is not configured in cluster! Unable to remove.".format(nodename))

    return nodename == utils.this_node()


def bootstrap_init(cluster_name="hacluster", nic=None, ocfs2_device=None,
                   shared_device=None, sbd_device=None, quiet=False,
                   template=None, admin_ip=None, yes_to_all=False,
                   unicast=False, watchdog=None, stage=None, args=None):
    """
    -i <nic>
    -o <ocfs2-device>
    -p <shared-device>
    -s <sbd-device>
    -t <template>
    -A [<admin-ip>]
    -q - quiet
    -y - yes to all
    -u - unicast
    <stage>

    stages:
    ssh
    ssh_remote
    csync2
    csync2_remote
    corosync
    storage
    sbd
    cluster
    vgfs
    admin
    """
    global _context
    _context = Context(quiet=quiet, yes_to_all=yes_to_all, nic=nic)
    _context.cluster_name = cluster_name
    _context.ocfs2_device = ocfs2_device
    _context.shared_device = shared_device
    _context.sbd_device = sbd_device
    _context.unicast = unicast
    _context.admin_ip = admin_ip
    _context.watchdog = watchdog

    if stage is None:
        stage = ""

    # vgfs stage requires running cluster, everything else requires inactive cluster,
    # except ssh and csync2 (which don't care) and csync2_remote (which mustn't care,
    # just in case this breaks ha-cluster-join on another node).
    corosync_active = service_is_active("corosync.service")
    if stage in ("vgfs", "admin"):
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
        log("args: {}".format(args))
        if len(args) != 2:
            error("Expected NODE argument to csync2_remote")
        _context.cluster_node = args[1]

    init()

    if stage != "":
        globals()["init_" + stage]()
    else:
        if watchdog is not None:
            init_watchdog()
        init_ssh()
        init_csync2()
        init_corosync()
        if template == 'ocfs2':
            if sbd_device is None or ocfs2_device is None:
                init_storage()
        init_sbd()
        init_cluster()
        if template == 'ocfs2':
            init_vgfs()
        init_admin()

    status("Done (log saved to %s)" % (LOG_FILE))


def bootstrap_join(cluster_node=None, nic=None, quiet=False, yes_to_all=False, watchdog=None, stage=None):
    """
    -c <cluster-node>
    -i <nic>
    -q - quiet
    -y - yes to all
    <stage>
    # stages:
    ssh
    csync2
    ssh_merge
    cluster
    """
    global _context
    _context = Context(quiet=quiet, yes_to_all=yes_to_all, nic=nic)
    _context.cluster_node = cluster_node
    _context.watchdog = watchdog

    check_tty()

    corosync_active = service_is_active("corosync.service")
    if corosync_active:
        error("Abort: Cluster is currently active. Run this command on a node joining the cluster.")

    if not check_prereqs("join"):
        return

    init()

    if stage != "":
        globals()["join_" + stage](cluster_node)
    else:
        if not yes_to_all and cluster_node is None:
            status("""Join This Node to Cluster:
  You will be asked for the IP address of an existing node, from which
  configuration will be copied.  If you have not already configured
  passwordless ssh between nodes, you will be prompted for the root
  password of the existing node.
""")
            cluster_node = prompt_for_string("IP address or hostname of existing node (e.g.: 192.168.1.1)", ".+")
            _context.cluster_node = cluster_node

        join_ssh(cluster_node)
        join_csync2(cluster_node)
        join_ssh_merge(cluster_node)
        join_cluster(cluster_node)

    status("Done (log saved to %s)" % (LOG_FILE))


def bootstrap_remove(cluster_node=None, quiet=False, yes_to_all=False):
    """
    -c <cluster-node> - node to remove from cluster
    -q - quiet
    -y - yes to all
    """
    global _context
    _context = Context(quiet=quiet, yes_to_all=yes_to_all)
    _context.cluster_node = cluster_node

    if not yes_to_all and cluster_node is None:
        status("""Remove This Node from Cluster:
  You will be asked for the IP address or name of an existing node,
  which will be removed from the cluster. This command must be
  executed from a different node in the cluster.
""")
        cluster_node = prompt_for_string("IP address or hostname of cluster node (e.g.: 192.168.1.1)", ".+")
        _context.cluster_node = cluster_node

    init()
    remove_ssh()
    if remove_localhost_check():
        if not config.core.force:
            error("Removing self requires --force")
        # get list of cluster nodes
        me = utils.this_node()
        nodes = xmlutil.listnodes()
        othernode = next((x for x in nodes if x != me), None)
        if othernode is not None:
            # remove from other node
            cmd = "crm cluster remove{} -c {}".format(" -y" if yes_to_all else "", me)
            rc = utils.ext_cmd_nosudo("ssh{} -o StrictHostKeyChecking=no {} '{}'".format("" if yes_to_all else " -t", othernode, cmd))
            if rc != 0:
                error("Failed to remove this node from {}".format(othernode))
        else:
            # stop cluster
            if not stop_service("corosync"):
                error("Stopping corosync on failed")

            # remove all trace of cluster from this node
            # delete configuration files from the node to be removed
            toremove = [SYSCONFIG_SBD, CSYNC2_CFG, corosync.conf(), CSYNC2_KEY, COROSYNC_AUTH]
            if not invoke('bash -c "rm -f {} && rm -f /var/lib/heartbeat/crm/* /var/lib/pacemaker/cib/*"'.format(" ".join(toremove))):
                error("Deleting the configuration files failed")
    else:
        remove_cluster()


def init_common_geo():
    """
    Tasks to do both on first and other geo nodes.
    """
    if not package_is_installed("booth"):
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
        invoke("rm -f {}".format(BOOTH_AUTH))
    if not invoke("booth-keygen {}".format(BOOTH_AUTH)):
        error("Failed to generate booth authkey")


def create_booth_config(arbitrator, clusters, tickets):
    status("Configure booth")

    config_template = Template("""# The booth configuration file is "/etc/booth/booth.conf". You need to
# prepare the same booth configuration file on each arbitrator and
# each node in the cluster sites where the booth daemon can be launched.

# "transport" means which transport layer booth daemon will use.
# Currently only "UDP" is supported.
transport="UDP"
port="9929"
arbitrator="$arbitrator"
$sites
authfile="$authkey"
$tickets
""")
    ticket_template = Template("""ticket="$name"
     expire="600"
""")
    site_template = Template('site="$site"\n')

    cfg = config_template.substitute(
        arbitrator=arbitrator,
        sites="".join(site_template.substitute(site=s) for s in clusters.itervalues()),
        authkey=BOOTH_AUTH,
        tickets="".join(ticket_template.substitute(name=t) for t in tickets))

    if os.path.exists(BOOTH_CFG):
        invoke("rm -f {}".format(BOOTH_CFG))
    utils.str2file(cfg, BOOTH_CFG)
    utils.chown(BOOTH_CFG, "hacluster", "haclient")
    os.chmod(BOOTH_CFG, 0o644)


def bootstrap_init_geo(quiet, yes_to_all, arbitrator, clusters, tickets):
    """
    Configure as a geo cluster member.
    """
    global _context
    _context = Context(quiet=quiet, yes_to_all=yes_to_all)

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
    create_booth_config(arbitrator, clusters, tickets)
    status("Sync booth configuration across cluster")
    csync2_update("/etc/booth")
    init_csync2_geo()
    geo_cib_config(clusters)


def geo_fetch_config(node):
    # TODO: clean this up
    status("Retrieving configuration - This may prompt for root@%s:" % (node))
    tmpdir = tmpfiles.create_dir()
    invoke("scp root@%s:'/etc/booth/*' %s/" % (node, tmpdir))
    if os.path.isfile("%s/authkey" % (tmpdir)):
        invoke("mv %s/authkey %s" % (tmpdir, BOOTH_AUTH))
    if os.path.isfile("%s/booth.conf" % (tmpdir)):
        invoke("mv %s/booth.conf %s" % (tmpdir, BOOTH_CFG))
    os.chmod(BOOTH_AUTH, 0o600)
    os.chmod(BOOTH_CFG, 0o644)


def geo_cib_config(clusters):
    cluster_name = corosync.get_values('totem.cluster_name')[0]
    if cluster_name not in clusters.keys():
        error("Local cluster name is {}, expected {}".format(cluster_name, "|".join(clusters.keys())))

    status("Configure cluster resources for booth")
    crm_template = Template("""
primitive booth-ip ocf:heartbeat:IPaddr2 $iprules
primitive booth-site ocf:pacemaker:booth-site \
  meta resource-stickiness="INFINITY" \
  params config=booth op monitor interval="10s"
group g-booth booth-ip booth-site meta target-role=Stopped
""")
    iprule = 'params rule #cluster-name eq {} ip="{}"'

    crm_configure_load("update", crm_template.substitute(iprules=" ".join(iprule.format(k, v) for k, v in clusters.iteritems())))


def bootstrap_join_geo(quiet, yes_to_all, node, clusters):
    """
    Run on second cluster to add to a geo configuration.
    It fetches its booth configuration from the other node (cluster node or arbitrator).
    """
    global _context
    _context = Context(quiet=quiet, yes_to_all=yes_to_all)
    init_common_geo()
    check_tty()
    geo_fetch_config(node)
    status("Sync booth configuration across cluster")
    csync2_update("/etc/booth")
    geo_cib_config(clusters)


def bootstrap_arbitrator(quiet, yes_to_all, node):
    """
    Configure this machine as an arbitrator.
    It fetches its booth configuration from a cluster node already in the cluster.
    """
    global _context
    _context = Context(quiet=quiet, yes_to_all=yes_to_all)
    init_common_geo()
    check_tty()
    geo_fetch_config(node)
    if not os.path.isfile(BOOTH_CFG):
        error("Failed to copy {} from {}".format(BOOTH_CFG, node))
    # TODO: verify that the arbitrator IP in the configuration is us?
    status("Enabling and starting the booth arbitrator service")
    start_service("booth@booth")

# EOF
