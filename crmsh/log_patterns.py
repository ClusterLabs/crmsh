# Copyright (C) 2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# See COPYING for license information.
#
# log pattern specification
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

from . import constants
from . import utils

__all__ = ('patterns',)

_patterns_old = {
    "resource": (
        (  # detail 0
            "lrmd.*%% (?:start|stop|promote|demote|migrate)",
            "lrmd.*RA output: .%%:.*:stderr",
            "lrmd.*WARN: Managed %%:.*exited",
            "lrmd.*WARN: .* %% .*timed out$",
            "crmd.*LRM operation %%_(?:start|stop|promote|demote|migrate)_.*confirmed=true",
            "crmd.*LRM operation %%_.*Timed Out",
            "[(]%%[)]\\[",
        ),
        (  # detail 1
            "lrmd.*%% (?:probe|notify)",
            "lrmd.*Managed %%:.*exited",
        ),
    ),
    "node": (
        (  # detail 0
            " %% .*Corosync.Cluster.Engine",
            " %% .*Executive.Service.RELEASE",
            " %% .*Requesting.shutdown",
            " %% .*Shutdown.complete",
            " %% .*Configuration.validated..Starting.heartbeat",
            "pengine.*Scheduling Node %% for STONITH",
            "crmd.* of %% failed",
            "stonith-ng.*host '%%'",
            "Exec.*on %% ",
            "Node %% will be fenced",
            "stonith-ng.*for %% timed",
            "stonith-ng.*can not fence %%:",
            "stonithd.*Succeeded.*node %%:",
            "(?:lost|memb): %% ",
            "crmd.*(?:NEW|LOST):.* %% ",
            "Node return implies stonith of %% ",
        ),
        (  # detail 1
        ),
    ),
    "quorum": (
        (  # detail 0
            "crmd.*Updating.quorum.status",
            "crmd.*quorum.(?:lost|ac?quir)",
        ),
        (  # detail 1
        ),
    ),
    "events": (
        (  # detail 0
            "CRIT:",
            "ERROR:",
        ),
        (  # detail 1
            "WARN:",
        ),
    ),
}

_patterns_118 = {
    "resource": (
        (  # detail 0
            "crmd.*Initiating.*%%_(?:start|stop|promote|demote|migrate)_",
            "lrmd.*operation_finished: %%_",
            "lrmd.*executing - rsc:%% action:(?:start|stop|promote|demote|migrate)",
            "lrmd.*finished - rsc:%% action:(?:start|stop|promote|demote|migrate)",

            "crmd.*LRM operation %%_(?:start|stop|promote|demote|migrate)_.*confirmed=true",
            "crmd.*LRM operation %%_.*Timed Out",
            "[(]%%[)]\\[",
        ),
        (  # detail 1
            "crmd.*Initiating.*%%_(?:monitor_0|notify)",
            "lrmd.*executing - rsc:%% action:(?:monitor_0|notify)",
            "lrmd.*finished - rsc:%% action:(?:monitor_0|notify)",
        ),
    ),
    "node": (
        (  # detail 0
            " %% .*Corosync.Cluster.Engine",
            " %% .*Executive.Service.RELEASE",
            " %% .*crm_shutdown:.Requesting.shutdown",
            " %% .*pcmk_shutdown:.Shutdown.complete",
            " %% .*Configuration.validated..Starting.heartbeat",
            "pengine.*Scheduling Node %% for STONITH",
            "pengine.*Node %% will be fenced",
            "crmd.*for %% failed",
            "stonith-ng.*host '%%'",
            "Exec.*on %% ",
            "Node %% will be fenced",
            "stonith-ng.*on %% for.*timed out",
            "stonith-ng.*can not fence %%:",
            "stonithd.*Succeeded.*node %%:",
            "(?:lost|memb): %% ",
            "crmd.*(?:NEW|LOST|new|lost):.* %% ",
            "Node return implies stonith of %% ",
        ),
        (  # detail 1
        ),
    ),
    "quorum": (
        (  # detail 0
            "crmd.*Updating.(quorum).status",
            r"crmd.*quorum.(?:lost|ac?quir[^\s]*)",
        ),
        (  # detail 1
        ),
    ),
    "events": (
        (  # detail 0
            "(CRIT|crit|ERROR|error|UNCLEAN|unclean):",
        ),
        (  # detail 1
            "(WARN|warning):",
        ),
    ),
}

_patterns_200 = {
    "resource": (
        (  # detail 0
            "pacemaker-controld.*Initiating.*%%_(?:start|stop|promote|demote|migrate)_",
            "pacemaker-execd.*operation_finished: %%_",
            "pacemaker-execd.*executing - rsc:%% action:(?:start|stop|promote|demote|migrate)",
            "pacemaker-execd.*finished - rsc:%% action:(?:start|stop|promote|demote|migrate)",

            "pacemaker-controld.*Result of .* operation for .* on .*: .*confirmed=true",
            "pacemaker-controld.*Result of .* operation for .* on .*: Timed Out",
            "[(]%%[)]\\[",
        ),
        (  # detail 1
            "pacemaker-controld.*Initiating.*%%_(?:monitor_0|notify)",
            "pacemaker-execd.*executing - rsc:%% action:(?:monitor_0|notify)",
            "pacemaker-execd.*finished - rsc:%% action:(?:monitor_0|notify)",
        ),
    ),
    "node": (
        (  # detail 0
            " %% .*Corosync.Cluster.Engine",
            " %% .*Executive.Service.RELEASE",
            " %% .*crm_shutdown:.Requesting.shutdown",
            " %% .*pcmk_shutdown:.Shutdown.complete",
            " %% .*Configuration.validated..Starting.heartbeat",
            "schedulerd.*Scheduling Node %% for STONITH",
            "schedulerd.*will be fenced",
            "pacemaker-controld.*for %% failed",
            "stonith-ng.*host '%%'",
            "Exec.*on %% ",
            " %% will be fenced",
            "stonith-ng.*on %% for.*timed out",
            "stonith-ng.*can not fence %%:",
            "pacemaker-fenced.*Succeeded.*node %%:",
            "fenced.*(requests|(Succeeded|Failed).to.|result=)",
            "(?:lost|memb): %% ",
            "pacemaker-controld.*(?:NEW|LOST|new|lost):.* %% ",
            r"error:.*Connection to (fencer|stonith-ng).* (closed|failed|lost)",
            r"Fencing daemon connection failed",
            r"pacemaker-controld.*Fencer successfully connected",
            "State transition .* S_RECOVERY",
            r"pacemakerd.* Respawning pacemaker-controld subdaemon after unexpected exit",
            r"pacemaker-controld\[[0-9]+\] exited with status 1 \(",
            r"Connection to the scheduler failed",
            "pacemaker-controld.*I_ERROR.*save_cib_contents",
            r"pacemaker-controld.*: Input I_TERMINATE .*from do_recover",
            "pacemaker-controld.*Could not recover from internal error",
            r"pacemaker-controld.*Connection to executor failed",
            r"pacemaker-controld.*I_ERROR.*lrm_connection_destroy",
            r"pacemaker-controld.*State transition .* S_RECOVERY",
            r"pacemaker-controld.*: Input I_TERMINATE .*from do_recover",
            r"pacemaker-controld.*Could not recover from internal error",
            r"pacemakerd.*pacemaker-controld\[[0-9]+\] exited with status 1",
            r"pacemakerd.* Respawning pacemaker-execd subdaemon after unexpected exit",
            r"pacemakerd.* Respawning pacemaker-controld subdaemon after unexpected exit",
            r"pacemakerd.* pacemaker-attrd\[[0-9]+\] exited with status 102",
            r"pacemakerd.* pacemaker-controld\[[0-9]+\] exited with status 1",
            r"pacemakerd.* Respawning pacemaker-attrd subdaemon after unexpected exit",
            r"pacemakerd.* Respawning pacemaker-based subdaemon after unexpected exit",
            r"pacemakerd.* Respawning pacemaker-controld subdaemon after unexpected exit",
            r"pacemakerd.* Respawning pacemaker-fenced subdaemon after unexpected exit",
            r"pacemaker-.* Connection to cib_.* (failed|closed)",
            r"pacemaker-attrd.*:.*Lost connection to the CIB manager",
            r"pacemaker-controld.*:.*Lost connection to the CIB manager",
            r"pacemaker-controld.*I_ERROR.*crmd_cib_connection_destroy",
            r"pacemaker-controld.* State transition .* S_RECOVERY",
            r"pacemaker-controld.*: Input I_TERMINATE .*from do_recover",
            r"pacemaker-controld.*Could not recover from internal error",
	),
        (  # detail 1
        ),
    ),
    "quorum": (
        (  # detail 0
            "pacemaker-controld.*Updating.(quorum).status",
            r"pacemaker-controld.*quorum.(?:lost|ac?quir[^\s]*)",
            r"pacemakerd.*:\s*warning:.*Lost connection to cluster layer",
            r"pacemaker-attrd.*:\s*(crit|error):.*Lost connection to (cluster layer|the CIB manager)",
            r"pacemaker-based.*:\s*(crit|error):.*Lost connection to cluster layer",
            r"pacemaker-controld.*:\s*(crit|error):.*Lost connection to (cluster layer|the CIB manager)",
            r"pacemaker-fenced.*:\s*(crit|error):.*Lost connection to (cluster layer|the CIB manager)",
            r"schedulerd.*Scheduling node .* for fencing",
            r"pacemaker-controld.*:\s*Peer .* was terminated \(.*\) by .* on behalf of .*:\s*OK",
        ),
        (  # detail 1
        ),
    ),
    "events": (
        (  # detail 0
            "(CRIT|crit|ERROR|error|UNCLEAN|unclean):",
            r"Shutting down...NOW",
            r"Timer I_TERMINATE just popped",
            r"input=I_ERROR",
            r"input=I_FAIL",
            r"input=I_INTEGRATED cause=C_TIMER_POPPED",
            r"input=I_FINALIZED cause=C_TIMER_POPPED",
            r"input=I_ERROR",
            r"(pacemakerd|pacemaker-execd|pacemaker-controld):.*, exiting",
            r"schedulerd.*Attempting recovery of resource",
            r"is taking more than 2x its timeout",
            r"Confirm not received from",
            r"Welcome reply not received from",
            r"Attempting to schedule .* after a stop",
            r"Resource .* was active at shutdown",
            r"duplicate entries for call_id",
            r"Search terminated:",
            r":global_timer_callback",
            r"Faking parameter digest creation",
            r"Parameters to .* action changed:",
            r"Parameters to .* changed",
            r"pacemakerd.*\[[0-9]+\] terminated( with signal| as IPC server|$)",
            r"pacemaker-schedulerd.*Recover\s+.*\(.* -\> .*\)",
            r"rsyslogd.* imuxsock lost .* messages from pid .* due to rate-limiting",
            r"Peer is not part of our cluster",
            r"We appear to be in an election loop",
            r"Unknown node -> we will not deliver message",
            r"(Blackbox dump requested|Problem detected)",
            r"pacemakerd.*Could not connect to Cluster Configuration Database API",
            r"Receiving messages from a node we think is dead",
            r"share the same cluster nodeid",
            r"share the same name",
            r"pacemaker-controld:.*Transition failed: terminated",
            r"Local CIB .* differs from .*:",
            r"warn.*:\s*Continuing but .* will NOT be used",
            r"warn.*:\s*Cluster configuration file .* is corrupt",
            #r"Executing .* fencing operation",
            r"Election storm",
            r"stalled the FSA with pending inputs",
        ),
        (  # detail 1
            "(WARN|warning):",
        ),
    ),
}


def patterns(cib_f=None):
    if utils.is_min_pcmk_ver(constants.PCMK_VERSION_DEFAULT, cib_f=cib_f):
        return _patterns_200
    is118 = utils.is_larger_than_pcmk_118(cib_f=cib_f)
    if is118:
        return _patterns_118
    else:
        return _patterns_old
