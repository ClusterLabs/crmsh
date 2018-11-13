# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.
'''
Session-only options (not saved).
'''

interactive = False
batch = False
ask_no = False
regression_tests = False
profile = ""
history = "live"
input_file = ""
shadow = ""
scriptdir = ""
# set to true when completing non-interactively
shell_completion = False


arg_parameter_key = ["action", "dest", "metavar", "default", "type", "help"]

cluster_init_base_options_value = [
    ("-h", "--help", "store_true", "help", "", None, None, "Show this help message"),

    ("-q", "--quiet", "store_true", "quiet", "", None, None,
     "Be quiet (don't describe what's happening, just do it)"),

    ("-y", "--yes", "store_true", "yes_to_all", "", None, None,
     'Answer "yes" to all prompts (use with caution, this is destructive, especially during the "storage" stage)'),

    ("-t", "--template", "store", "template", "", None, None,
     'Optionally configure cluster with template "name" (currently only "ocfs2" is valid here)'),

    ("-n", "--name", "store", "name", "NAME", "hacluster", None,
     'Set the name of the configured cluster.'),

    ("-N", "--nodes", "store", "nodes", "NODES", None, None,
     'Additional nodes to add to the created cluster. ' +
     'May include the current node, which will always be the initial cluster node.'),

    ("-S", "--enable-sbd", "store_true", "diskless_sbd", "", None, None,
     "Enable SBD even if no SBD device is configured (diskless mode)"),

    ("-w", "--watchdog", "store", "watchdog", "WATCHDOG", None, None, "Use the given watchdog device")
]

cluster_init_net_options_value = [
    ("-i", "--interface", "store", "nic", "IF", None, str, "Bind to IP address on interface IF"),

    ("-u", "--unicast", "store_true", "unicast", "", None, None,
     "Configure corosync to communicate over unicast (UDP), and not multicast. " +
     "Default is multicast unless an environment where multicast cannot be used is detected."),

    ("-A", "--admin-ip", "store", "admin_ip", "IP", None, str,
     "Configure IP address as an administration virtual IP"),

    ("-M", "--multi-heartbeats", "store_true", "second_hb", "", None, None,
     "Configure corosync with second heartbeat line"),

    ("-I", "--ipv6", "store_true", "ipv6", "", None, None, "Configure corosync use IPv6"),

    ("--qdevice", "store", "qdevice", "QDEVICE", None, str, "QDevice IP"),

    ("--qdevice-port", "store", "qdevice_port", "QDEVICE_PORT", 5403, int, "QDevice port"),

    ("--qdevice-algo", "store", "qdevice_algo", "QDEVICE_ALGO", "ffsplit", str, "QDevice algorithm"),

    ("--qdevice-tie-breaker", "store", "qdevice_tie_breaker", "QDEVICE_TIE_BREAKER", "lowest", str,
     "QDevice tie breaker")
]

cluster_init_storage_options_value = [
    ("-p", "--partition-device", "store", "shared_device", "DEVICE", None, str,
     'Partition this shared storage device (only used in "storage" stage)'),

    ("-s", "--sbd-device", "store", "sbd_device", "DEVICE", None, str,
     "Block device to use for SBD fencing"),

    ("-o", "--ocfs2-device", "store", "ocfs2_device", "DEVICE", None, str,
     'Block device to use for OCFS2 (only used in "vgfs" stage)')
]

CLUSTER_INIT_BASE_OPTIONS = []
CLUSTER_INIT_NET_OPTIONS = []
CLUSTER_INIT_STORAGE_OPTIONS = []
for value_tuple in cluster_init_base_options_value:
    CLUSTER_INIT_BASE_OPTIONS.append((value_tuple[:-6], dict(zip(arg_parameter_key, value_tuple[-6:]))))
for value_tuple in cluster_init_net_options_value:
    CLUSTER_INIT_NET_OPTIONS.append((value_tuple[:-6], dict(zip(arg_parameter_key, value_tuple[-6:]))))
for value_tuple in cluster_init_storage_options_value:
    CLUSTER_INIT_STORAGE_OPTIONS.append((value_tuple[:-6], dict(zip(arg_parameter_key, value_tuple[-6:]))))
