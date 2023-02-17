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
            "[(]%%[)]\[",
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
            "[(]%%[)]\[",
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


def patterns(cib_f=None):
    is118 = utils.is_larger_than_pcmk_118(cib_f=cib_f)
    if is118:
        return _patterns_118
    else:
        return _patterns_old
