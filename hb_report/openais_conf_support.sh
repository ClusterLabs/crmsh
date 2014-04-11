 # Copyright (C) 2007 Dejan Muhamedagic <dmuhamedagic@suse.de>
 # 
 # This program is free software; you can redistribute it and/or
 # modify it under the terms of the GNU General Public
 # License as published by the Free Software Foundation; either
 # version 2.1 of the License, or (at your option) any later version.
 # 
 # This software is distributed in the hope that it will be useful,
 # but WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 # General Public License for more details.
 # 
 # You should have received a copy of the GNU General Public
 # License along with this library; if not, write to the Free Software
 # Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 #

#
# Stack specific part (openais)
# openais.conf/logd.cf parsing
#
# cut out a stanza
getstanza() {
	awk -v name="$1" '
	!in_stanza && NF==2 && /^[a-z][a-z]*[[:space:]]*{/ { # stanza start
		if ($1 == name)
			in_stanza = 1
	}
	in_stanza { print }
	in_stanza && NF==1 && $1 == "}" { exit }
	'
}
# supply stanza in $1 and variable name in $2
# (stanza is optional)
getcfvar() {
	[ -f "$CONF" ] || return
	sed 's/#.*//' < $CONF |
		if [ $# -eq 2 ]; then
			getstanza "$1"
			shift 1
		else
			cat
		fi |
		awk -v varname="$1" '
		NF==2 && match($1,varname":$")==1 { print $2; exit; }
		'
}
iscfvarset() {
	test "`getcfvar $1`"
}
iscfvartrue() {
	getcfvar $1 $2 |
		egrep -qsi "^(true|y|yes|on|1)"
}
uselogd() {
	iscfvartrue use_logd
}
get_ais_logvars() {
	if iscfvartrue to_file; then
		HA_LOGFILE=`getcfvar logfile`
		HA_LOGFILE=${HA_LOGFILE:-"syslog"}
		HA_DEBUGFILE=$HA_LOGFILE
	elif iscfvartrue to_syslog; then
		HA_LOGFACILITY=`getcfvar syslog_facility`
		HA_LOGFACILITY=${HA_LOGFACILITY:-"daemon"}
	fi
}
getlogvars() {
	HA_LOGFACILITY=${HA_LOGFACILITY:-$DEFAULT_HA_LOGFACILITY}
	HA_LOGLEVEL="info"
	iscfvartrue debug && # prefer debug level if set
		HA_LOGLEVEL="debug"
	if uselogd; then
		[ -f "$LOGD_CF" ] || {
			debug "logd used but logd.cf not found: using defaults"
			return  # no configuration: use defaults
		}
		debug "reading log settings from $LOGD_CF"
		get_logd_logvars
	else
		debug "reading log settings from $CONF"
		get_ais_logvars
	fi
}
cluster_info() {
	: echo "openais version: how?"
	if [ "$CONF" = /etc/corosync/corosync.conf ]; then
		/usr/sbin/corosync -v
	fi
}
essential_files() {
	cat<<EOF
d $PCMK_LIB 0750 hacluster haclient
d $PE_STATE_DIR 0750 hacluster haclient
d $CIB_DIR 0750 hacluster haclient
EOF
}
