# Copyright (C) 2017 Xin Liang <XLiang@suse.com>
# See COPYING for license information.
BIN_CRM = "/usr/sbin/crm"
BIN_COLLECTOR = f"{BIN_CRM} report __collector"
COMPRESS_DATA_FLAG = "COMPRESS CRM_REPORT DATA:::"
LOG_PATTERNS = ["CRIT:", "ERROR:", "WARNING:", "crit:", "error:", "warning:"]
PTEST = "crm_simulate"
SSH_OPTS = "-o StrictHostKeyChecking=no -o EscapeChar=none -o ConnectTimeout=15"
CHECK_LOG_LINES = 10
STAMP_TYPE = ""

DECRIPTION_TMPLATE = """
Please edit this template and describe the issue/problem you
encountered. Then, post to
    http://clusterlabs.org/mailman/listinfo/users
or file a bug at
    https://github.com/ClusterLabs/crmsh/issues

Thank you.

Date: {0}
By: crm report {1}
Subject: [short problem description]
Severity: [choose one] enhancement minor normal major critical blocking
--------------------------------------------------------

Detailed description:

"""

# Fetched by command
# zypper packages --repo SLE-Product-HA-16.0 | grep -v Name|awk -F'|' 'NR>2 {name=$3; gsub(/^ +| +$/, "", name); if (name != "" && name != "Name") print "\""name"\","}'
PACKAGE_LIST = [
        "cluster-md-kmp-default",
        "corosync",
        "corosync-devel",
        "corosync-libs",
        "corosync-qdevice",
        "corosync-qnetd",
        "crmsh",
        "crmsh-scripts",
        "csync2",
        "dlm-kmp-default",
        "drbd",
        "drbd-kmp-default",
        "drbd-selinux",
        "drbd-utils",
        "fence-agents-aliyun",
        "fence-agents-all",
        "fence-agents-alom",
        "fence-agents-apc",
        "fence-agents-apc-snmp",
        "fence-agents-aws",
        "fence-agents-azure-arm",
        "fence-agents-bladecenter",
        "fence-agents-brocade",
        "fence-agents-cisco-mds",
        "fence-agents-cisco-ucs",
        "fence-agents-common",
        "fence-agents-devel",
        "fence-agents-drac5",
        "fence-agents-eaton-snmp",
        "fence-agents-eaton-ssh",
        "fence-agents-emerson",
        "fence-agents-eps",
        "fence-agents-gce",
        "fence-agents-hds-cb",
        "fence-agents-hpblade",
        "fence-agents-ibm-powervs",
        "fence-agents-ibm-vpc",
        "fence-agents-ibmblade",
        "fence-agents-ibmz",
        "fence-agents-ifmib",
        "fence-agents-ilo-moonshot",
        "fence-agents-ilo-mp",
        "fence-agents-ilo-ssh",
        "fence-agents-ilo2",
        "fence-agents-intelmodular",
        "fence-agents-ipdu",
        "fence-agents-ipmilan",
        "fence-agents-ironic",
        "fence-agents-kdump",
        "fence-agents-lpar",
        "fence-agents-mpath",
        "fence-agents-netio",
        "fence-agents-nutanix-ahv",
        "fence-agents-pve",
        "fence-agents-raritan",
        "fence-agents-rcd-serial",
        "fence-agents-redfish",
        "fence-agents-rsa",
        "fence-agents-rsb",
        "fence-agents-sanbox2",
        "fence-agents-sbd",
        "fence-agents-scsi",
        "fence-agents-vbox",
        "fence-agents-virsh",
        "fence-agents-vmware",
        "fence-agents-vmware-rest",
        "fence-agents-wti",
        "fence-agents-zvm",
        "gfs2-kmp-default",
        "gfs2-utils",
        "graphviz",
        "graphviz-gd",
        "graphviz-plugins-core",
        "haproxy",
        "hawk-apiserver",
        "hawk2",
        "keepalived",
        "libdlm",
        "libdlm-devel",
        "libdlm3",
        "libknet-devel",
        "libknet1",
        "libknet1-compress-bzip2-plugin",
        "libknet1-compress-lz4-plugin",
        "libknet1-compress-lzma-plugin",
        "libknet1-compress-lzo2-plugin",
        "libknet1-compress-plugins-all",
        "libknet1-compress-zlib-plugin",
        "libknet1-compress-zstd-plugin",
        "libknet1-crypto-nss-plugin",
        "libknet1-crypto-openssl-plugin",
        "libknet1-crypto-plugins-all",
        "libknet1-plugins-all",
        "liblab_gamut1",
        "libnozzle-devel",
        "libnozzle1",
        "librsync-devel",
        "librsync2",
        "lvm2-lockd",
        "pacemaker",
        "pacemaker-cli",
        "pacemaker-cts",
        "pacemaker-devel",
        "pacemaker-libs",
        "pacemaker-remote",
        "pacemaker-schemas",
        "patterns-ha-ha_sles",
        "python3-pacemaker",
        "python313-azure-common",
        "python313-azure-core",
        "python313-azure-identity",
        "python313-azure-mgmt-compute",
        "python313-azure-mgmt-core",
        "python313-azure-mgmt-network",
        "python313-azure-mgmt-nspkg",
        "python313-azure-nspkg",
        "python313-boto3",
        "python313-botocore",
        "python313-google-api-core",
        "python313-google-api-python-client",
        "python313-google-auth",
        "python313-google-auth-httplib2",
        "python313-googleapis-common-protos",
        "python313-grpcio",
        "python313-grpcio-status",
        "python313-s3transfer",
        "rear29a",
        "resource-agents",
        "sbd",
        "sbd-devel",
        "sle-ha-release",
        "suse-lifecycle-data-sle_ha",
]

ANALYSIS_F = "analysis.txt"
COREDUMP_F = "coredump_info.txt"
CIB_F = "cib.xml"
CONFIGURE_SHOW_F = "configure_show.txt"
CONFIGURATIONS = [
    "/etc/drbd.conf",
    "/etc/drbd.d",
    "/etc/booth/booth.conf"
]
COROSYNC_RECORDER_F = "fdata.txt"
COROSYNC_F = "corosync.conf"
COROSYNC_STATUS_F = "corosync_status.txt"
CRM_MON_F = "crm_mon.txt"
CRM_VERIFY_F = "crm_verify.txt"
DESCRIPTION_F = "description.txt"
DLM_DUMP_F = "dlm_dump.txt"
JOURNAL_F = "journal.log"
JOURNAL_PCMK_F = "journal_pacemaker.log"
JOURNAL_COROSYNC_F = "journal_corosync.log"
JOURNAL_SBD_F = "journal_sbd.log"
MEMBERSHIP_F = "members.txt"
PERMISSIONS_F = "permissions.txt"
SBDCONF = "/etc/sysconfig/sbd"
PCMKCONF = "/etc/sysconfig/pacemaker"
SYSINFO_F = "sysinfo.txt"
SYSSTATS_F = "sysstats.txt"
OCFS2_F = "ocfs2.txt"
GFS2_F = "gfs2.txt"
SBD_F = "sbd.txt"
QDEVICE_F = "quorum_qdevice_qnetd.txt"
OSRELEASE = "/etc/os-release"
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
RESULT_TIME_SUFFIX = "%a-%d-%b-%Y"
NAME = "crm report"
COROSYNC_LIB = "/var/lib/corosync"

DESCRIPTION_HELP = '''Description:
crm report is a utility to collect all information (logs,
configuration files, system information, etc) relevant to
Pacemaker (CRM) over the given period of time.
'''

EXTRA_HELP = '''
Examples
  # collect from 2pm, today
  {name} -f 2pm report_1

  # collect from "2007/9/5 12:30" to "2007/9/5 14:00"
  {name} -f "2007/9/5 12:30" -t "2007/9/5 14:00" report_2

  # collect from 1:00 to 3:00, today; include /var/log/cluster/ha-debug as extra log
  {name} -f 1:00 -t 3:00 -E /var/log/cluster/ha-debug report_3

  # collect from "09sep07 2:00" and use 'hacluster' as ssh user
  {name} -f "09sep07 2:00" -u hacluster report_4

  # collect from 18:00, today; replace sensitive message like "usern.*" or "admin.*"
  {name} -f 18:00 -s -p "usern.*" -p "admin.*" report_5

  # collect from 1 mounth ago
  {name} -f 1m

  # collect from 75 hours ago
  {name} -f 75H

  # collect from 10 minutes ago
  {name} -f 10M

  # collect from 2 days ago to 1 day ago
  {name} -f 2d -t 1d
'''.format(name=NAME)
# vim:ts=4:sw=4:et:
