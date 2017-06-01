
import socket

# HA_NOARCHBIN = "/usr/share/crmsh/hb_report"

ARGOPTS_VALUE = "f:t:l:u:X:p:L:e:E:n:MSDZVsvhdQ"
B_CONF = None
CIB_DIR = None
COMPRESS = 1
COMPRESS_PROG = ""
COMPRESS_EXT = ""
CORES_DIRS = None
CONF = None
CRM_DAEMON_DIR = None
CTS = ""
DEST = ""
DESTDIR = ""
DO_SANITIZE = 0
EXTRA_LOGS = "/var/log/messages /var/log/pacemaker.log"
FORCE_REMOVE_DEST = ""
FROM_TIME = ""
GET_STAMP_FUNC = None
HA_DEBUGFILE = None
HA_LOG = ""
HA_LOGFACILITY = "daemon"
HA_LOGFILE = None
HA_LOGLEVEL = "info"
HA_BIN = None
HA_VARLIB = None
LOCAL_SUDO = ""
LOG_PATTERNS = "CRIT: ERROR:"
NO_DESCRIPTION = 1
NO_SSH = ""
NODES = ""
OCF_DIR = None
PACKAGES = None
PCMK_LIB = None
PCMK_LOG = "/var/log/pacemaker.log"
PE_STATE_DIR = None
PTEST = "crm_simulate"
SANITIZE = "passw.*"
SKIP_LVL = 0
SLAVE = 0
SLAVEPIDS = None
SSH_OPTS = "-o StrictHostKeyChecking=no -o EscapeChar=none -o ConnectTimeout=15"
SSH_PASSWORD_NODES = ""
SSH_USER = ""
SUDO = ""
THIS_IS_NODE = 0
TMP = None
TMPFLIST = None
TO_TIME = 0
TRY_SSH = "root hacluster"
# UNIQUE_MSG = "Mark:HB_REPORT:%d" % now_second
USER_CLUSTER_TYPE = "Corosync/Pacemaker"
USER_NODES = ""
VERBOSITY = 0
WE = socket.gethostname()
WORKDIR = None


# Important events
#
# Patterns format:
#  title extended_regexp
# NB: don't use spaces in titles or regular expressions!
EVENT_PATTERNS = """
membership crmd.*(NEW|LOST)|pcmk.*(lost|memb|LOST|MEMB):
quorum crmd.*Updating.quorum.status|crmd.*quorum.(lost|ac?quir)
pause Process.pause.detected
resources lrmd.*(start|stop)
stonith crmd.*Exec|stonith-ng.*log_oper.*reboot|stonithd.*(requests|(Succeeded|Failed).to.STONITH|result=)
start_stop Configuration.validated..Starting.heartbeat|Corosync.Cluster.Engine|Executive.Service.RELEASE|Requesting.shutdown|Shutdown.complete
"""

PACKAGES = """pacemaker libpacemaker3
pacemaker-pygui pacemaker-pymgmt pymgmt-client
openais libopenais2 libopenais3 corosync libcorosync4
resource-agents cluster-glue libglue2 ldirectord libqb0
heartbeat heartbeat-common heartbeat-resources libheartbeat2
booth
ocfs2-tools ocfs2-tools-o2cb ocfs2console
ocfs2-kmp-default ocfs2-kmp-pae ocfs2-kmp-xen ocfs2-kmp-debug ocfs2-kmp-trace
drbd drbd-kmp-xen drbd-kmp-pae drbd-kmp-default drbd-kmp-debug drbd-kmp-trace
drbd-heartbeat drbd-pacemaker drbd-utils drbd-bash-completion drbd-xen
lvm2 lvm2-clvm cmirrord
libdlm libdlm2 libdlm3
hawk ruby lighttpd
kernel-default kernel-pae kernel-xen
glibc
"""

EMAIL_TMPLATE = """
Please edit this template and describe the issue/problem you
encountered. Then, post to
    http://clusterlabs.org/mailman/listinfo/users
or file a bug at
    https://github.com/ClusterLabs/crmsh/issues

Thank you.

Date: {0}
By: report {1}
Subject: [short problem description]
Severity: [choose one] enhancement minor normal major critical blocking
Component: [choose one] CRM LRM CCM RA fencing openais comm GUI tools other
--------------------------------------------------------

Detailed description:

"""


ANALYSIS_F = "analysis.txt"
BT_F = "backtraces.txt"
CIB_F = "cib.xml"
CIB_TXT_F = "cib.txt"
CONFIGURATIONS = ["/etc/drbd.conf",
                  "/etc/drbd.d",
                  "/etc/booth/booth.conf"]
COROSYNC_RECORDER_F = "fdata.txt"
CRM_MON_F = "crm_mon.txt"
CRM_VERIFY_F = "crm_verify.txt"
DESCRIPTION_F = "description.txt"
DLM_DUMP_F = "dlm_dump.txt"
HALOG_F = "ha-log.txt"
HB_UUID_F = "hb_uuid.txt"
HOSTCACHE = "hostcache"
JOURNAL_F = "journal.log"
MEMBERSHIP_F = "members.txt"
PERMISSIONS_F = "permissions.txt"
SYSINFO_F = "sysinfo.txt"
SYSSTATS_F = "sysstats.txt"
TIME_F = "time.txt"
