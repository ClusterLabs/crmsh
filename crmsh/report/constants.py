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
# zypper packages --repo SLE-Product-HA15-SP7-Pool | grep -v Name|awk -F'|' 'NR>2 {name=$3; gsub(/^ +| +$/, "", name); if (name != "" && name != "Name") print "\""name"\","}'
PACKAGE_LIST = [
        "booth",
        "cluster-glue",
        "cluster-glue-devel",
        "cluster-glue-libs",
        "cluster-md-kmp-default",
        "corosync",
        "corosync-qdevice",
        "corosync-qnetd",
        "corosync-testagents",
        "crmsh",
        "crmsh-scripts",
        "csync2",
        "ctdb",
        "dlm-kmp-default",
        "doxygen2man",
        "dracut-mkinitrd-deprecated",
        "drbd",
        "drbd-kmp-default",
        "drbd-utils",
        "ebiso",
        "fence-agents",
        "fence-agents-azure-arm",
        "fence-agents-devel",
        "gfs2-kmp-default",
        "gfs2-utils",
        "ha-cluster-bootstrap",
        "haproxy",
        "hawk-apiserver",
        "hawk2",
        "keepalived",
        "ldirectord",
        "libcfg6",
        "libcmap4",
        "libcorosync-devel",
        "libcorosync_common4",
        "libcpg4",
        "libdlm",
        "libdlm3",
        "libqb-tests",
        "libqb-tools",
        "libquorum5",
        "libsam4",
        "libtotem_pg5",
        "libvotequorum8",
        "lvm2-lockd",
        "monitoring-plugins-fping",
        "monitoring-plugins-http",
        "monitoring-plugins-ldap",
        "monitoring-plugins-metadata",
        "monitoring-plugins-mysql",
        "monitoring-plugins-pgsql",
        "monitoring-plugins-tcp",
        "ocfs2-kmp-default",
        "ocfs2-tools",
        "ocfs2-tools-o2cb",
        "omping",
        "pacemaker",
        "pacemaker-cli",
        "pacemaker-cts",
        "pacemaker-devel",
        "pacemaker-libs",
        "pacemaker-remote",
        "pacemaker-schemas",
        "patterns-ha-geo-ha_geo",
        "patterns-ha-ha_sles",
        "perl-Net-INET6Glue",
        "perl-Net-Telnet",
        "prometheus-ha_cluster_exporter",
        "python3-gv",
        "python3-pacemaker",
        "python3-parallax",
        "rear23a",
        "rear27a",
        "release-notes-ha",
        "resource-agents",
        "ruby2.5-rubygem-actioncable-5_1",
        "ruby2.5-rubygem-actionmailer-5_1",
        "ruby2.5-rubygem-actionpack-5_1",
        "ruby2.5-rubygem-actionview-5_1",
        "ruby2.5-rubygem-activejob-5_1",
        "ruby2.5-rubygem-activemodel-5_1",
        "ruby2.5-rubygem-activerecord-5_1",
        "ruby2.5-rubygem-activesupport-5_1",
        "ruby2.5-rubygem-arel",
        "ruby2.5-rubygem-axiom-types",
        "ruby2.5-rubygem-coercible",
        "ruby2.5-rubygem-concurrent-ruby",
        "ruby2.5-rubygem-crass",
        "ruby2.5-rubygem-descendants_tracker",
        "ruby2.5-rubygem-equalizer",
        "ruby2.5-rubygem-erubi",
        "ruby2.5-rubygem-gettext",
        "ruby2.5-rubygem-gettext_i18n_rails",
        "ruby2.5-rubygem-gettext_i18n_rails_js",
        "ruby2.5-rubygem-globalid",
        "ruby2.5-rubygem-i18n",
        "ruby2.5-rubygem-ice_nine",
        "ruby2.5-rubygem-js-routes",
        "ruby2.5-rubygem-kramdown",
        "ruby2.5-rubygem-locale",
        "ruby2.5-rubygem-loofah",
        "ruby2.5-rubygem-mail",
        "ruby2.5-rubygem-method_source",
        "ruby2.5-rubygem-mini_mime",
        "ruby2.5-rubygem-nio4r",
        "ruby2.5-rubygem-po_to_json",
        "ruby2.5-rubygem-puma",
        "ruby2.5-rubygem-rack",
        "ruby2.5-rubygem-rack-test-0_6",
        "ruby2.5-rubygem-rails-5_1",
        "ruby2.5-rubygem-rails-dom-testing",
        "ruby2.5-rubygem-rails-html-sanitizer",
        "ruby2.5-rubygem-railties-5_1",
        "ruby2.5-rubygem-rb-fsevent",
        "ruby2.5-rubygem-rb-inotify",
        "ruby2.5-rubygem-sass",
        "ruby2.5-rubygem-sass-listen",
        "ruby2.5-rubygem-sass-rails",
        "ruby2.5-rubygem-sprockets",
        "ruby2.5-rubygem-sprockets-rails",
        "ruby2.5-rubygem-text",
        "ruby2.5-rubygem-thor",
        "ruby2.5-rubygem-thread_safe",
        "ruby2.5-rubygem-tilt",
        "ruby2.5-rubygem-tzinfo",
        "ruby2.5-rubygem-virtus",
        "ruby2.5-rubygem-websocket-driver-0_6",
        "ruby2.5-rubygem-websocket-extensions",
        "sbd",
        "scsires",
        "sle-ha-release",
        "system-role-ha",
        "yast2-cluster",
        "yast2-drbd",
        "yast2-geo-cluster",
        "yast2-iplb",
        "yast2-rear",
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
TIME_F = "time.txt"
OCFS2_F = "ocfs2.txt"
GFS2_F = "gfs2.txt"
SBD_F = "sbd.txt"
PRE_MIGRATION_F = "pre_migration.txt"
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
