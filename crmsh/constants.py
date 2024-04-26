# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# See COPYING for license information.

from .ordereddict import odict


# A list of all keywords introduced in the
# CIB language.
keywords = {
    "node": "element",
    "primitive": "element",
    "resource": "element",
    "group": "element",
    "bundle": "element",
    "clone": "element",
    "ms": "element",
    "master": "element",
    "location": "element",
    "colocation": "element",
    "collocation": "element",
    "order": "element",
    "rsc_ticket": "element",
    "rsc_template": "element",
    "property": "element",
    "rsc_defaults": "element",
    "op_defaults": "element",
    "acl_target": "element",
    "acl_group": "element",
    "user": "element",
    "role": "element",
    "fencing_topology": "element",
    "fencing-topology": "element",
    "tag": "element",
    "alert": "element",
    "monitor": "element",
    "params": "subelement",
    "meta": "subelement",
    "attributes": "subelement",
    "utilization": "subelement",
    "operations": "subelement",
    "op": "subelement",
    "rule": "subelement",
    "to": "subelement",
    "inf": "value",
    "INFINITY": "value",
    "and": "op",
    "or": "op",
    "lt": "op",
    "gt": "op",
    "lte": "op",
    "gte": "op",
    "eq": "op",
    "ne": "op",
    "defined": "op",
    "not_defined": "op",
    "in_range": "op",
    "in": "op",
    "date_spec": "op",
    "spec": "op",
    "date": "value",
    "yes": "value",
    "no": "value",
    "true": "value",
    "false": "value",
    "on": "value",
    "off": "value",
    "normal": "value",
    "member": "value",
    "ping": "value",
    "remote": "value",
    "start": "value",
    "stop": "value",
    "Mandatory": "value",
    "Optional": "value",
    "Serialize": "value",
    "ref": "value",
    "xpath": "value",
    "xml": "element",
}

cib_cli_map = {
    "node": "node",
    "primitive": "primitive",
    "group": "group",
    "clone": "clone",
    "master": "ms",
    "bundle": "bundle",
    "rsc_location": "location",
    "rsc_colocation": "colocation",
    "rsc_order": "order",
    "rsc_ticket": "rsc_ticket",
    "template": "rsc_template",
    "cluster_property_set": "property",
    "rsc_defaults": "rsc_defaults",
    "op_defaults": "op_defaults",
    "acl_target": "acl_target",
    "acl_group": "acl_group",
    "acl_user": "user",
    "acl_role": "role",
    "fencing-topology": "fencing_topology",
    "tag": "tag",
    "alert": "alert",
}
container_tags = ("group", "clone", "ms", "master", "bundle")
clonems_tags = ("clone", "ms", "master")
resource_tags = ("primitive", "group", "clone", "ms", "master", "template", "bundle")
constraint_tags = ("rsc_location", "rsc_colocation", "rsc_order", "rsc_ticket")
constraint_rsc_refs = ("rsc", "with-rsc", "first", "then")
children_tags = ("group", "primitive")
nvpairs_tags = ("meta_attributes", "instance_attributes", "utilization")
defaults_tags = ("rsc_defaults", "op_defaults")
resource_cli_names = ("primitive", "group", "clone", "ms", "master", "rsc_template", "bundle")
constraint_cli_names = ("location", "colocation", "collocation", "order", "rsc_ticket")
nvset_cli_names = ("property", "rsc_defaults", "op_defaults")
op_cli_names = ("monitor",
                "start",
                "stop",
                "migrate_to",
                "migrate_from",
                "promote",
                "demote",
                "notify",
                "reload")
ra_operations = tuple(["probe"] + list(op_cli_names))

subpfx_list = {
    "instance_attributes": "instance_attributes",
    "meta_attributes": "meta_attributes",
    "utilization": "utilization",
    "operations": "ops",
    "rule": "rule",
    "expression": "expression",
    "date_expression": "expression",
    "duration": "duration",
    "date_spec": "date_spec",
    "read": "read",
    "write": "write",
    "deny": "deny",
}
acl_rule_names = ("read", "write", "deny")
acl_spec_map = odict({
    "xpath": "xpath",
    "ref": "ref",
    "tag": "tag",
    "attribute": "attribute",
})
# ACLs were rewritten in pacemaker 1.1.12
# this is the new acl syntax
acl_spec_map_2 = odict({
    "xpath": "xpath",
    "ref": "reference",
    "reference": "reference",
    "tag": "object-type",
    "type": "object-type",
    "attr": "attribute",
    "attribute": "attribute"
})

acl_spec_map_2_rev = (('xpath', 'xpath'),
                      ('reference', 'ref'),
                      ('attribute', 'attr'),
                      ('object-type', 'type'))

acl_shortcuts = {
    "meta":
    (r"//primitive\[@id='@@'\]/meta_attributes", r"/nvpair\[@name='@@'\]"),
    "params":
    (r"//primitive\[@id='@@'\]/instance_attributes", r"/nvpair\[@name='@@'\]"),
    "utilization":
    (r"//primitive\[@id='@@'\]/utilization",),
    "location":
    (r"//rsc_location\[@id='cli-prefer-@@' and @rsc='@@'\]",),
    "property":
    (r"//crm_config/cluster_property_set", r"/nvpair\[@name='@@'\]"),
    "nodeattr":
    (r"//nodes/node/instance_attributes", r"/nvpair\[@name='@@'\]"),
    "nodeutil":
    (r"//nodes/node/utilization", r"\[@uname='@@'\]"),
    "node":
    (r"//nodes/node", r"\[@uname='@@'\]"),
    "status":
    (r"/cib/status",),
    "cib":
    (r"/cib",),
}
lrm_exit_codes = {
    "success": "0",
    "unknown": "1",
    "args": "2",
    "unimplemented": "3",
    "perm": "4",
    "installed": "5",
    "configured": "6",
    "not_running": "7",
    "master": "8",
    "failed_master": "9",
}
lrm_status_codes = {
    "pending": "-1",
    "done": "0",
    "cancelled": "1",
    "timeout": "2",
    "notsupported": "3",
    "error": "4",
}
cib_user_attrs = ("validate-with",)
node_states = ("online", "offline", "unclean")
precious_attrs = ("id-ref",)
op_extra_attrs = ("interval",)
rsc_meta_attributes = (
    "allow-migrate", "maintenance", "is-managed", "interval-origin",
    "migration-threshold", "priority", "multiple-active",
    "failure-timeout", "resource-stickiness", "target-role",
    "restart-type", "description", "remote-node", "requires",
    "provides", "remote-port", "remote-addr", "remote-connect-timeout",
    "critical", "allow-unhealthy-nodes", "container-attribute-target"
)
common_meta_attributes = ("priority", "target-role", "is-managed")
group_meta_attributes = common_meta_attributes + ("container", )
clone_meta_attributes = common_meta_attributes + (
    "ordered", "notify", "interleave", "globally-unique",
    "clone-max", "clone-node-max", "clone-state", "description",
    "clone-min", "promotable", "promoted-max", "promoted-node-max",
)
ms_meta_attributes = common_meta_attributes + (
    "clone-max", "clone-node-max", "notify", "globally-unique", "ordered", 
    "interleave", "master-max", "master-node-max", "description",
)
bundle_meta_attributes = common_meta_attributes
alert_meta_attributes = (
    "timeout", "timestamp-format"
)
trace_ra_attr = "trace_ra"
trace_dir_attr = "trace_dir"
score_types = {'advisory': '0', 'mandatory': 'INFINITY'}
boolean_ops = ('or', 'and')
binary_ops = ('lt', 'gt', 'lte', 'gte', 'eq', 'ne')
binary_types = ('string', 'version', 'number')
unary_ops = ('defined', 'not_defined')
simple_date_ops = ('lt', 'gt')
date_ops = ('lt', 'gt', 'in_range', 'date_spec')
date_spec_names = '''hours monthdays weekdays yearsdays months \
weeks years weekyears moon'''.split()
in_range_attrs = ('start', 'end')
node_default_type = "normal"
node_attributes_keyw = ("attributes", "utilization")
shadow_envvar = "CIB_shadow"
attr_defaults = {
    "node": {"type": "normal"},
    "resource_set": {"sequential": "true", "require-all": "true"},
    "rule": {"boolean-op": "and"},
}
cib_no_section_rc = 6
# Graphviz attributes for various CIB elements.
# Shared for edge and node and graph attributes.
# Keys are graphviz attributes, values are dicts where keys
# are CIB element names and values graphviz values.
# - element "." refers to the whole graph
# - element "class:<ra_class>" refers to primitives of a
#   specific RA class
# - optional_set is a resource_set with require-all set to
#   false
# - group and optional_set are subgraphs (boxes)
graph = {
    ".": {
        "compound": "true",
    },
    "*": {
        "fontname": "Helvetica",
        "fontsize": "11",
    },
    "node": {
        "style": "bold",
        "shape": "box",
        "color": "#7ac142",
    },
    "primitive": {
        "fillcolor": "#e4e5e6",
        "color": "#b9b9b9",
        "shape": "box",
        "style": "rounded,filled",
    },
    "rsc_template": {
        "fillcolor": "#ffd457",
        "color": "#b9b9b9",
        "shape": "box",
        "style": "rounded,filled,dashed",
    },
    "class:stonith": {
        "shape": "box",
        "style": "dashed",
    },
    "location": {
        "style": "dashed",
        "dir": "none",
    },
    "clone": {
        "color": "#ec008c",
    },
    "ms": {
        "color": "#f8981d",
    },
    "bundle": {
        "color": "#00aeef",
        "style": "rounded",
    },
    "group": {
        "color": "#00aeef",
        "group": "#00aeef",
        "labelloc": "b",
        "labeljust": "r",
        "labelfontsize": "12",
    },
    "optional_set": {
        "style": "dotted",
    },
    "template:edge": {
        "color": "#b9b9b9",
        "style": "dotted",
        "arrowtail": "open",
        "dir": "back",
    },
}

need_reset = False
prompt = ''
tmp_cib = False
tmp_cib_prompt = "@tmp@"
live_cib_prompt = "live"

simulate_programs = {
    "ptest": "ptest",
    "simulate": "crm_simulate",
}

meta_progs_20 = ("pacemaker-controld", "pacemaker-schedulerd", "pacemaker-fenced", "pacemaker-based")

# elide these properties from tab completion
controld_metadata_do_not_complete = ("dc-version",
                                 "cluster-infrastructure",
                                 "crmd-integration-timeout",
                                 "crmd-finalization-timeout",
                                 "expected-quorum-votes")
extra_cluster_properties = ("dc-version",
                            "cluster-infrastructure",
                            "last-lrm-refresh",
                            "cluster-name")
pcmk_version = ""  # set later

container_type = ("docker", "podman", "rkt")
container_helptxt = {
    "container": {
        "image": """image:(string)
    Container image tag(required)""",

        "replicas": """replicas:(integer)
    Default:Value of promoted-max if that is positive, else 1
    A positive integer specifying the number of container instances to launch""",

        "replicas-per-host": """replicas-per-host:(integer)
    Default:1
    A positive integer specifying the number of container instances allowed to
    run on a single node""",

        "promoted-max": """promoted-max:(integer)
    Default:0
    A non-negative integer that, if positive, indicates that the containerized
    service should be treated as a promotable service, with this many replicas
    allowed to run the service in the promoted role""",

        "run-command": """run-command:(string)
    Default:/usr/sbin/pacemaker_remoted if bundle contains a primitive, otherwise none
    This command will be run inside the container when launching it ("PID 1").
    If the bundle contains a primitive, this command must start pacemaker_remoted
    (but could, for example, be a script that does other stuff, too).""",

        "options": """options:(string)
    Extra command-line options to pass to the 'docker run', 'podman run' or 'rkt run' command"""
    },

    "network": {
        "add-host": """add-host:(string)
    Default:True
    If True, and ip-range-start is specified, Pacemake will automatically ensure that
    /etc/hosts inside the containers has entries for each replica name and its assigned IP.""",

        "ip-range-start": """ip-range-start:(IPv4 address)
    If specified, Pacemaker will create an implicit ocf:heartbeat:IPaddr2 resource
    for each container instance, starting with this IP address, using up to replicas
    sequential addresses. These addresses can be used from the host’s network to
    reach the service inside the container, though it is not visible within the
    container itself. Only IPv4 addresses are currently supported.""",

        "host-netmask": """host-netmask:(integer)
    Default:32
    If ip-range-start is specified, the IP addresses are created with this CIDR
    netmask (as a number of bits).""",

        "host-interface": """host-interface:(string)
    If ip-range-start is specified, the IP addresses are created on this host
    interface (by default, it will be determined from the IP address).""",

        "control-port": """control-port:(integer)
    Default: 3121
    If the bundle contains a primitive, the cluster will use this integer TCP port
    for communication with Pacemaker Remote inside the container. Changing this is
    useful when the container is unable to listen on the default port, for example,
    when the container uses the host’s network rather than ip-range-start (in which
    case replicas-per-host must be 1), or when the bundle may run on a Pacemaker
    Remote node that is already listening on the default port. Any PCMK_remote_port
    environment variable set on the host or in the container is ignored for bundle
    connections.""",

        "port-mapping": {
            "id": """id:(string)
    A unique name for the port mapping (required)""",

            "port": """port:(integer)
    If this is specified, connections to this TCP port number on the host network
    (on the container’s assigned IP address, if ip-range-start is specified) will
    be forwarded to the container network. Exactly one of port or range must be
    specified in a port-mapping.""",

            "internal-port": """internal-port:(integer)
    Default: value of port
    If port and this are specified, connections to port on the host’s network will
    be forwarded to this port on the container network.""",

                "range": """range:(first_port-last_port)
    If this is specified, connections to these TCP port numbers (expressed as
    first_port-last_port) on the host network (on the container’s assigned IP address,
    if ip-range-start is specified) will be forwarded to the same ports in the container
    network. Exactly one of port or range must be specified in a port-mapping."""
        }
    },

    "storage": {
        "id": """id:(string)
    A unique name for the storage mapping (required)""",

        "source-dir": """source-dir:(string)
    The absolute path on the host’s filesystem that will be mapped into the container.
    Exactly one of source-dir and source-dir-root must be specified in a storage-mapping.""",

        "source-dir-root": """source-dir-root:(string)
    The start of a path on the host’s filesystem that will be mapped into the container,
    using a different subdirectory on the host for each container instance. The subdirectory
    will be named the same as the replica name. Exactly one of source-dir and source-dir-root
    must be specified in a storage-mapping.""",

           "target-dir": """target-dir:(string)
    The path name within the container where the host storage will be mapped (required)""",

            "options": """options:(string)
    A comma-separated list of file system mount options to use when mapping the storage"""
    },
}


QDEVICE_HELP_INFO = """  QDevice participates in quorum decisions. With the assistance of 
  a third-party arbitrator Qnetd, it provides votes so that a cluster 
  is able to sustain more node failures than standard quorum rules 
  allow. It is recommended for clusters with an even number of nodes 
  and highly recommended for 2 node clusters."""


SSH_OPTION_ARGS = ["-o", "StrictHostKeyChecking=no"]
SSH_OPTION = ' '.join(SSH_OPTION_ARGS)


CLOUD_AWS = "amazon-web-services"
CLOUD_AZURE = "microsoft-azure"
CLOUD_GCP = "google-cloud-platform"


RED = '\033[31m'
YELLOW = '\033[33m'
GREEN = '\033[32m'
END = '\033[0m'


CIB_QUERY = "cibadmin -Q"
CIB_UPGRADE = "crm configure upgrade force"
CIB_RAW_FILE = "/var/lib/pacemaker/cib/cib.xml"
XML_NODE_PATH = "/cib/configuration/nodes/node"
XML_STATUS_PATH = "/cib/status/node_state"
XML_NODE_QUERY_STANDBY_PATH = "//nodes/node[@id='{node_id}']/instance_attributes/nvpair[@name='standby']"
XML_STATUS_QUERY_STANDBY_PATH = "//status/node_state[@id='{node_id}']/transient_attributes/instance_attributes/nvpair[@name='standby']"
CRM_MON_ONE_SHOT = "crm_mon -1"
CRM_MON_XML_OUTPUT= "crm_mon --output-as=xml"
STONITH_TIMEOUT_DEFAULT = 60
PCMK_DELAY_MAX = 30
DLM_CONTROLD_RA = "ocf::pacemaker:controld"
LVMLOCKD_RA = "ocf::heartbeat:lvmlockd"
HA_USER = "hacluster"
HA_GROUP = "haclient"
SCHEMA_MIN_VER_SUPPORT_OCF_1_1 = "pacemaker-3.7"
REJOIN_COUNT = 60
REJOIN_INTERVAL = 10
DC_DEADTIME_DEFAULT = 20

ADVISED_ACTION_LIST = ['monitor', 'start', 'stop', 'promote', 'demote']
ADVISED_KEY_LIST = ['timeout', 'interval', 'role']
DEFAULT_INTERVAL_IN_ACTION = "20s"
WAIT_TIMEOUT_MS_DEFAULT = 120000
CSYNC2_SERVICE = "csync2.socket"

RSC_ROLE_PROMOTED = "Promoted"
RSC_ROLE_UNPROMOTED = "Unpromoted"
RSC_ROLE_PROMOTED_LEGACY = "Master"
RSC_ROLE_UNPROMOTED_LEGACY = "Slave"
PCMK_VERSION_DEFAULT = "2.0.0"

INTERFACE_HELP = """Bind to IP address on interface IF. 
Allowed value is nic name or IP address. 
If a nic name is provided, the first IP of that nic will be used. 
Use multiple -i for more links. Note: Only one link is allowed for the non knet transport type
"""

NON_FUNCTIONAL_COMMANDS = {'help', 'cd', 'ls', 'quit', 'up'}
NON_FUNCTIONAL_OPTIONS = {'--help', '--help-without-redirect'}
COROSYNC_STATUS_TYPES = ("ring", "quorum", "qdevice", "qnetd", "cpg")

COROSYNC_PORT = 5405
CSYNC2_PORT = 30865
HAWK_PORT = 7630
DLM_PORT = 21064
# vim:ts=4:sw=4:et:
