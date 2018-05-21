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
op_attr_names = ("interval", "start-delay", "interval-origin", "timeout", "enabled",
                "record-pending", "role", "on-fail")
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
    "provides", "remote-port", "remote-addr", "remote-connect-timeout"
)
common_meta_attributes = ("priority", "target-role", "is-managed")
group_meta_attributes = common_meta_attributes + ("container", )
clone_meta_attributes = common_meta_attributes + (
    "ordered", "notify", "interleave", "globally-unique",
    "clone-max", "clone-node-max", "clone-state", "description",
    "clone-min",
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
roles_names = ('Stopped', 'Started', 'Master', 'Slave')
actions_names = ('start', 'promote', 'demote', 'stop')
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

meta_progs = ("crmd", "pengine", "stonithd", "cib")
# elide these properties from tab completion
crmd_metadata_do_not_complete = ("dc-version",
                                 "cluster-infrastructure",
                                 "crmd-integration-timeout",
                                 "crmd-finalization-timeout",
                                 "expected-quorum-votes")
extra_cluster_properties = ("dc-version",
                            "cluster-infrastructure",
                            "last-lrm-refresh",
                            "cluster-name")
pcmk_version = ""  # set later

container_type = ["docker", "rkt"]
container_helptxt = {
    "docker": {
        "image": """image:(string)
    Docker image tag(required)""",

        "replicas": """replicas:(integer)
    Default:Value of masters if that is positive, else 1
    A positive integer specifying the number of container instances to launch""",

        "replicas-per-host": """replicas-per-host:(integer)
    Default:1
    A positive integer specifying the number of container instances allowed to
    run on a single node""",

        "masters": """masters:(integer)
    Default:0
    A non-negative integer that, if positive, indicates that the containerized
    service should be treated as a multistate service, with this many replicas
    allowed to run the service in the master role""",

        "run-command": """run-command:(string)
    Default:/usr/sbin/pacemaker_remoted if bundle contains a primitive, otherwise none
    This command will be run inside the container when launching it ("PID 1").
    If the bundle contains a primitive, this command must start pacemaker_remoted
    (but could, for example, be a script that does other stuff, too).""",

        "options": """options:(string)
    Extra command-line options to pass to docker run"""
    },

    "network": {
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
    will be named the same as the bundle host name, as described in the note for ip-range-start.
    Exactly one of source-dir and source-dir-root must be specified in a storage-mapping.""",

           "target-dir": """target-dir:(string)
    The path name within the container where the host storage will be mapped (required)""",

            "options": """options:(string)
    File system mount options to use when mapping the storage"""
    },

    "rkt": {
        "image": """image:(string)
    Container image tag (required)""",

        "replicas": """replicas:(integer)
    Default:Value of masters if that is positive, else 1
    A positive integer specifying the number of container instances to launch""",

        "replicas-per-host": """replicas-per-host:(interval)
    Default:1
    A positive integer specifying the number of container instances allowed to
    run on a single node""",

        "masters": """masters:(integer)
    Default:0
    A non-negative integer that, if positive, indicates that the containerized
    service should be treated as a multistate service, with this many replicas
    allowed to run the service in the master role""",

        "run-command": """run-command:(string)
    Default:/usr/sbin/pacemaker_remoted if bundle contains a primitive, otherwise none
    This command will be run inside the container when launching it ("PID 1").
    If the bundle contains a primitive, this command must start pacemaker_remoted
    (but could, for example, be a script that does other stuff, too).""",

        "options": """options:(string)
    Extra command-line options to pass to rkt run"""
    }
}


location_helptxt = {
    "rsc-pattern": """rsc-pattern(string)
A regular expression matching the names of resources to which this constraint applies,
if rsc is not specified.""",

    "score": """score:(string)    "+INFINITY"|"+inf"|"-INFINITY"|"-inf"|"score number"
Positive values indicate a preference for running the affected resource(s) on this
node — the higher the value, the stronger the preference. Negative values indicate the
resource(s) should avoid this node (a value of -INFINITY changes "should" to "must").""",

    "resource-discovery": """resource-discovery:(string)    "always"|"never"|"exclusive"
Default: "always"
Whether Pacemaker should perform resource discovery (that is, check whether the resource
is already running) for this resource on this node. This should normally be left as the
default, so that rogue instances of a service can be stopped when they are running where
they are not supposed to be. However, there are two situations where disabling resource
discovery is a good idea: when a service is not installed on a node, discovery might return
an error (properly written OCF agents will not, so this is usually only seen with other agent
types); and when Pacemaker Remote is used to scale a cluster to hundreds of nodes, limiting
resource discovery to allowed nodes can significantly boost performance. (since 1.1.13)

• always: Always perform resource discovery for the specified resource on this node.
• never: Never perform resource discovery for the specified resource on this node. This option
should generally be used with a -INFINITY score, although that is not strictly required.
• exclusive: Perform resource discovery for the specified resource only on this node (and other
nodes similarly marked as exclusive). Multiple location constraints using exclusive discovery
for the same resource across different nodes creates a subset of nodes resource-discovery is
exclusive to. If a resource is marked for exclusive discovery on one or more nodes, that resource
is only allowed to be placed within that subset of nodes."""
}


order_helptxt = {
    "first-action": """first-action(string)    "start"|"stop"|"promote"|"demote"
Default: "start"
The action that the first resource must complete before then-action can be initiated for
the then resource. Allowed values: start, stop, promote, demote.""",

    "then-action": """then-action(string)    "start"|"stop"|"promote"|"demote"
Default: value of first-action
The action that the then resource can execute only after the first-action on the first
resource has completed. Allowed values: start, stop, promote, demote.""",

    "kind": """kind(string)    "Optional"|"Mandatory"|"Serialize"
How to enforce the constraint. Allowed values:

• Optional: Just a suggestion. Only applies if both resources are executing the specified
actions. Any change in state by the first resource will have no effect on the then resource.
• Mandatory: Always. If first does not perform first-action, then will not be allowed to
performed then-action. If first is restarted, then (if running) will be stopped beforehand
and started afterward.
• Serialize: Ensure that no two stop/start actions occur concurrently for the resources.
First and then can start in either order, but one must complete starting before the other
can be started. A typical use case is when resource start-up puts a high load on the host.""",

    "symmetrical": """symmetrical(string)    "True"|"False"
Default: "True"
If true, the reverse of the constraint applies for the opposite action (for example, if B
starts after A starts, then B stops before A stops).""",

    "score": """score:(string)    "+INFINITY"|"+inf"|"-INFINITY"|"-inf"|"score number" """,

    "require-all": """require-all:(string)    "true"|"false"
Default: "true" """
}


colocation_helptxt = {
    "score": """score:(string)    "+INFINITY"|"+inf"|"-INFINITY"|"-inf"|"score number"
Positive values indicate the resources should run on the same node. Negative values indicate
the resources should run on different nodes. Values of +/- INFINITY change "should" to "must".""",

    "role": """role:(string)    "Started"|"Slave"|"Master"
An additional attribute of colocation constraints that specifies the role that rsc must be in.
Allowed values: Started, Master, Slave.""",

    "with_role": """with_role:(string)    "Started"|"Slave"|"Master"
An additional attribute of colocation constraints that specifies the role that with-rsc must be in.
Allowed values: Started, Master, Slave.""",

    "node-attribute": """node-attribute:(string)
Default: "#uname"
The node attribute that must be the same on the node running rsc and the node running with-rsc for
the constraint to be satisfied."""
}


rscset_helptxt = {
    "sequential": """sequential:(string)    "true"|"false"
Default: "true"
Whether the members of the set must be acted on in order.""",

    "require-all": """require-all:(string)    "true"|"false"
Default: "true"
Whether all members of the set must be active before continuing. With the current
implementation, the cluster may continue even if only one member of the set is started,
but if more than one member of the set is starting at the same time, the cluster will
still wait until all of those have started before continuing (this may change in future
versions).""",

    "role": """role:(string)
Limit the effect of the constraint to the specified role.""",

    "action": """action:(string)
Limit the effect of the constraint to the specified action.""",

    "score": """score:(string)
Advanced use only. Use a specific score for this set within the constraint."""
}


rules_helptxt = {
    "role": """role:(string)    "Started"|"Slave"|"Master"
Limits the rule to apply only when the resource is in the specified role.
Allowed values are "Started", "Slave", and "Master". A rule with role="Master"
cannot determine the initial location of a clone instance and will only affect
which of the active instances will be promoted.""",

    "score": """score:(string)    "+INFINITY"|"+inf"|"-INFINITY"|"-inf"|"score number"
The score to apply if the rule evaluates to true. Limited to use in rules that
are part of location constraints.""",

    "score-attribute": """score-attribute:(string)
The node attribute to look up and use as a score if the rule evaluates to true.
Limited to use in rules that are part of location constraints.""",

    "boolean-op": """boolean-op:(string)    "and"|"or"
How to combine the result of multiple expression objects.""",

    "date": {
        "operation": """operation:(string)    "gt"|"lt"|"in_range"|"date_spec"
    Compares the current date/time with the start and/or end date, depending on
    the context. Allowed values:
    • gt: True if the current date/time is after start
    • lt: True if the current date/time is before end
    • in_range: True if the current date/time is after start and before end
    • date_spec: True if the current date/time matches a date_spec object""",

        "start": """start:(string)
    A date/time conforming to the ISO8601 specification.""",

        "end": """end:(string)
    A date/time conforming to the ISO8601 specification. Can be inferred by
    supplying a value for start and a duration."""
    },

    "expression": {
        "attribute": """attribute:(string)
    The node attribute to test (required)
    Built-in node attributes:
    #uname: Node name
    #id: Node ID
    #kind: Node type. Possible values are cluster, remote, and container.
           Kind is remote for Pacemaker Remote nodes created with the
           ocf:pacemaker:remote resource, and container for Pacemaker Remote
           guest nodes and bundle nodes
    #is_dc: "true" if this node is a Designated Controller (DC), "false" otherwise
    #cluster-name: The value of the cluster-name cluster property, if set
    #site-name: The value of the site-name cluster property, if set, otherwise
                identical to #cluster-name
    #role: The role the relevant multistate resource has on this node. Valid only
           within a rule for a location constraint for a multistate resource.""",

        "type": """type:(string)
    Determines how the value(s) should be tested. Allowed values are string, integer,
    and version.""",

        "operation": """operation:(string)
    The comparison to perform (required). Allowed values:
    • lt: True if the value of the node’s attribute is less than value
    • gt: True if the value of the node’s attribute is greater than value
    • lte: True if the value of the node’s attribute is less than or equal to value
    • gte: True if the value of the node’s attribute is greater than or equal to value
    • eq: True if the value of the node’s attribute is equal to value
    • ne: True if the value of the node’s attribute is not equal to value
    • defined: True if the node has the named attribute
    • not_defined: True if the node does not have the named attribute""",

        "value": """value:(string)
    User-supplied value for comparison (required)""",

        "value-source": """value-source(string)
    How the value is derived (since 1.1.17). Allowed values:
    • literal: value is a literal string to compare against
    • param: value is the name of a resource parameter to compare against
      (only valid in location constraints)
    • meta: value is the name of a resource meta-attribute to compare against
      (only valid in location constraints)"""
    },

    "date-common": {
        "hours": """hours:
    Allowed values: 0-23""",

        "monthdays": """monthdays:
    Allowed values: 1-31 (depending on month and year)""",

        "weekdays": """weekdays:
    Allowed values: 1-7 (1=Monday, 7=Sunday)""",

        "yeardays": """yearsdays:
    Allowed values: 1-366 (depending on the year)""",

        "months": """months:
    Allowed values: 1-12""",

        "weeks": """weeks:
    Allowed values: 1-53 (depending on weekyear)""",

        "years": """years:
    Year according to the Gregorian calendar""",

        "weekyears": """weekyears:
    Year in which the week started; e.g. 1 January 2005 can be specified as
    2005-001 Ordinal, 2005-01-01 Gregorian or 2004-W53-6 Weekly and thus would
    match years="2005" or weekyears="2004" """,

        "moon": """moon:
    Allowed values are 0-7 (0 is new, 4 is full moon). Seriously, you can use
    this. This was implemented to demonstrate the ease with which new comparisons
    could be added."""
    }
}

# vim:ts=4:sw=4:et:
