# Copyright (C) 2007 Dejan Muhamedagic <dmuhamedagic@suse.de>
# See COPYING for license information.

#
# Stack specific part (heartbeat)
# ha.cf/logd.cf parsing
#
getcfvar() {
	[ -f "$CONF" ] || return
	sed 's/#.*//' < $CONF |
		grep -w "^$1" |
		sed 's/^[^[:space:]]*[[:space:]]*//'
}
iscfvarset() {
	test "`getcfvar $1`"
}
iscfvartrue() {
	getcfvar "$1" |
		egrep -qsi "^(true|y|yes|on|1)"
}
uselogd() {
	iscfvartrue use_logd &&
		return 0  # if use_logd true
	iscfvarset logfacility ||
	iscfvarset logfile ||
	iscfvarset debugfile ||
		return 0  # or none of the log options set
	false
}
get_hb_logvars() {
	# unless logfacility is set to none, heartbeat/ha_logd are
	# going to log through syslog
	HA_LOGFACILITY=`getcfvar logfacility`
	[ "" = "$HA_LOGFACILITY" ] && HA_LOGFACILITY=$DEFAULT_HA_LOGFACILITY
	[ none = "$HA_LOGFACILITY" ] && HA_LOGFACILITY=""
	HA_LOGFILE=`getcfvar logfile`
	HA_DEBUGFILE=`getcfvar debugfile`
}
getlogvars() {
	HA_LOGFACILITY=${HA_LOGFACILITY:-$DEFAULT_HA_LOGFACILITY}
	HA_LOGLEVEL="info"
	cfdebug=`getcfvar debug` # prefer debug level if set
	isnumber $cfdebug || cfdebug=""
	[ "$cfdebug" ] && [ $cfdebug -gt 0 ] &&
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
		get_hb_logvars
	fi
}
cluster_info() {
	echo "heartbeat version: `$HA_BIN/heartbeat -V`"
}
essential_files() {
	cat<<EOF
d $HA_VARLIB 0755 root root
d $HA_VARLIB/ccm 0750 hacluster haclient
d $PCMK_LIB 0750 hacluster haclient
d $PE_STATE_DIR 0750 hacluster haclient
d $CIB_DIR 0750 hacluster haclient
EOF
}
