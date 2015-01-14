# Copyright (C) 2012 Dejan Muhamedagic <dmuhamedagic@suse.de>
#
# log pattern specification (for pacemaker v1.1.8)
#
# patterns are grouped one of several classes:
#  - resource: pertaining to a resource
#  - node: pertaining to a node
#  - quorum: quorum changes
#  - events: other interesting events (core dumps, etc)
#
# paterns are grouped based on a detail level
# detail level 0 is the lowest, i.e. should match the least
# number of relevant messages

# NB:
# %% stands for whatever user input we get, for instance a
# resource name or node name or just some regular expression
# in optimal case, it should be surrounded by literals
#
# [Note that resources may contain clone numbers!]

log_patterns = {
	"resource": (
		( # detail 0
			"crmd.*Initiating.*%%_(?:start|stop|promote|demote|migrate)_",
			"lrmd.*operation_finished: %%_",
			"crmd.*process_lrm_event: LRM operation %%_(?:start|stop|promote|demote|migrate)_.*confirmed=true",
			"crmd.*process_lrm_event: LRM operation %%_.*Timed Out",
			"[(]%%[)][[]",
		),
		( # detail 1
			"crmd.*Initiating%%_(?:monitor_0|notify)",
		),
	),
	"node": (
		( # detail 0
			" %% .*Corosync.Cluster.Engine",
			" %% .*Executive.Service.RELEASE",
			" %% .*crm_shutdown:.Requesting.shutdown",
			" %% .*pcmk_shutdown:.Shutdown.complete",
			" %% .*Configuration.validated..Starting.heartbeat",
			"pengine.*Scheduling Node %% for STONITH",
			"pengine.*pe_fence_node: Node %% will be fenced",
			"crmd.* tengine_stonith_callback: .* for %% failed",
			"stonith-ng.*log_operation:.*host '%%'",
			"te_fence_node: Exec.*on %% ",
			"pe_fence_node: Node %% will be fenced",
			"stonith-ng.*remote_op_timeout.*on %% for.*timed out",
			"stonith-ng.*can_fence_host_with_device:.*can not fence %%:",
			"stonithd.*Succeeded.*node %%:",
			"pcmk_peer_update.*(?:lost|memb): %% ",
			"crmd.*ccm_event.*(?:NEW|LOST):.* %% ",
			"Node return implies stonith of %% ",
		),
		( # detail 1
		),
	),
	"quorum": (
		( # detail 0
			"crmd.*crm_update_quorum:.Updating.quorum.status",
			"crmd.*ais.disp.*quorum.(?:lost|ac?quir)",
		),
		( # detail 1
		),
	),
	"events": (
		( # detail 0
			"(?:CRIT|crit):",
			"(?:ERROR|error):",
		),
		( # detail 1
			"(?:WARN|warning):",
		),
	),
}
