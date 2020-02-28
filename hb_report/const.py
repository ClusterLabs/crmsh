CIB_F = "cib.xml"
HALOG_F = "ha-log.txt"
JOURNAL_F = "journal.log"
TRY_SSH = "root hacluster"
SSH_OPTS = "StrictHostKeyChecking=no EscapeChar=none ConnectTimeout=15"
CIB_F = "cib.xml"
CIB_TXT_F = "cib.txt"
SYSINFO_F = "sysinfo.txt"
SYSSTATS_F = "sysstats.txt"
SBDCONF = "/etc/sysconfig/sbd"
SBD_F = "sbd.txt"
CONF = "/etc/corosync/corosync.conf"
B_CONF = "corosync.conf"
COROSYNC_LIB = "/var/lib/corosync"
CRM_MON_F = "crm_mon.txt"
MEMBERSHIP_F = "members.txt"
CRM_VERIFY_F = "crm_verify.txt"
PERMISSIONS_F = "permissions.txt"
DLM_DUMP_F = "dlm_dump.txt"
COROSYNC_RECORDER_F = "fdata.txt"
TIME_F = "time.txt"
CTX_F = "context.txt"
ANALYSIS_F = "analysis.txt"
OCFS2_F = "ocfs2.txt"
EVENTS_F = "events.txt"
PCMK_LOG_F = "pacemaker.log"
OSRELEASE = "/etc/os-release"
PTEST = "crm_simulate"
COMPRESS_DATA_FLAG = "COMPRESS HB_REPORT DATA:::"
OTHER_CONFS = ("/etc/drbd.conf", "/etc/drbd.d", "/etc/booth/booth.conf")
COLLECT_FUNCTIONS = ("sys_info", "sys_stats", "sbd_info", "get_config", "get_pe_inputs",
        "touch_dc", "get_core_files", "get_other_confs", "check_perms", "dlm_dump",
        "time_status", "corosync_blackbox", "get_ratraces", "dump_ocfs2", "get_extra_logs",
        "dump_corosync_log", "dump_context", "events", "dump_pcmk_log")
EVENT_PATTERNS = """pacemaker-controld.*(now lost|Quorum lost|is now member|Updating quorum status)
pacemaker-controld.*Result of
pacemaker-controld.*Stonith operation
pacemakerd.*Shutdown complete
pacemaker-fenced.*Requesting.*fencing
corosync.* started and ready
corosync.*membership .* was formed
corosync.* new configuration
corosync.* (FAULTY|recovered ring)
lack of quorum
healthy
unclean"""
# packages from network:/ha-clustering:/Factory x86_64+noarch
# filtered out 32bit|-test-|-tests-|-devel-|pcs
PACKAGES = "booth cluster-glue cluster-md-kmp-default cluster-network-kmp-default corosync corosync-qdevice corosync-qnetd corosync-testagents crmsh crmsh-scripts csync2 dlm-kmp-default drbd drbd-formula drbd-kmp-default drbd-utils drbdmanage fence-agents fence-agents-amt_ws gfs2-kmp-default gfs2-utils golang-drbdtop gradle gradle-kit ha-cluster-bootstrap habootstrap-formula hawk-apiserver hawk2 iscsi-formula iscsi-formula-suma ldirectord libcfg6 libcmap4 libcorosync_common4 libcpg4 libdlm libdlm3 libglue2 libknet1 libknet1-compress-bzip2-plugin libknet1-compress-lz4-plugin libknet1-compress-lzma-plugin libknet1-compress-lzo2-plugin libknet1-compress-plugins-all libknet1-compress-zlib-plugin libknet1-compress-zstd-plugin libknet1-crypto-nss-plugin libknet1-crypto-openssl-plugin libknet1-crypto-plugins-all libknet1-plugins-all libnozzle1 libpacemaker3 libqb-tools libqb20 libquorum5 libsam4 libtotem_pg5 libvotequorum8 linstor-client linstor-common linstor-controller linstor-satellite monitoring-plugins-metadata nfs-formula o2locktop ocfs2-kmp-default ocfs2-tools ocfs2-tools-o2cb omping pacemaker pacemaker-cli pacemaker-cts pacemaker-mgmt pacemaker-mgmt-client pacemaker-remote pcs pcsd pssh python-linstor python-pssh python2-PyHDB python2-cluster-preflight-check python2-parallax python2-prometheus_client python2-shaptools python3-PyHDB python3-cluster-preflight-check python3-parallax python3-prometheus_client python3-shaptools resource-agents ruby2.6-rubygem-sass-listen ruby2.6-rubygem-sass-listen-doc salt-shaptools saphanabootstrap-formula sapnwbootstrap-formula sbd yast2-cluster yast2-drbd yast2-geo-cluster yast2-iplb yast2-multipath"

EXTRA_HELP = '''
Examples
  # collect from 2pm, today
  hb_report -f 2pm report_1

  # collect from "2007/9/5 12:30" to "2007/9/5 14:00"
  hb_report -f "2007/9/5 12:30" -t "2007/9/5 14:00" report_2

  # collect from 1:00 to 3:00, today; include /var/log/cluster/ha-debug as extra log
  hb_report -f 1:00 -t 3:00 -E /var/log/cluster/ha-debug report_3

  # collect from "09sep07 2:00" and use 'hacluster' as ssh user
  hb_report -f "09sep07 2:00" -u hacluster report_4

  # collect from 18:00, today; replace sensitive message like "usern.*" or "admin.*"
  hb_report -f 18:00 -s -p "usern.*" -p "admin.*" report_5

  # collect from 1 mounth ago
  hb_report -b 1m

  # collect from 12 days ago
  hb_report -b 12d

  # collect from 75 hours ago
  hb_report -b 75H

  # collect from 10 minutes ago
  hb_report -b 10M

. WARNING . WARNING . WARNING . WARNING . WARNING . WARNING .

We won't sanitize the CIB and the peinputs files, because that
would make them useless when trying to reproduce the PE behaviour.
You may still choose to obliterate sensitive information if you
use the -s and -p options, but in that case the support may be
lacking as well.

Additional system logs are collected in order to have a more
complete report. If you don't want that specify -M.

IT IS YOUR RESPONSIBILITY TO PROTECT THE DATA FROM EXPOSURE!

SEE ALSO
  crmsh_hb_report(8)'''
