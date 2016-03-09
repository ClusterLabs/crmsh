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

log_patterns = {
    "resource": (
        (  # detail 0
            "lrmd.*%% (?:start|stop|promote|demote|migrate)",
            "lrmd.*RA output: .%%:.*:stderr",
            "lrmd.*WARN: Managed %%:.*exited",
            "lrmd.*WARN: .* %% .*timed out$",
            "crmd.*LRM operation %%_(?:start|stop|promote|demote|migrate)_.*confirmed=true",
            "crmd.*LRM operation %%_.*Timed Out",
            "[(]%%[)][[]",
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
