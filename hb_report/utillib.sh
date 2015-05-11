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
# figure out the cluster type, depending on the process list
# and existence of configuration files
#
get_cluster_type() {
	if ps -ef | egrep -qs '[a]isexec|[c]orosync' ||
			[ -f /etc/ais/openais.conf -a ! -f "$HA_CF" ] ||
			[ -f /etc/corosync/corosync.conf -a ! -f "$HA_CF" ]
	then
		debug "this is OpenAIS cluster stack"
		echo "openais"
	else
		debug "this is Heartbeat cluster stack"
		echo "heartbeat"
	fi
}
#
# find out which membership tool is installed
#
echo_membership_tool() {
	local f membership_tools
	membership_tools="ccm_tool crm_node"
	for f in $membership_tools; do
		which $f 2>/dev/null && break
	done
}
# find out if ptest or crm_simulate
#
echo_ptest_tool() {
	local f ptest_progs
	ptest_progs="crm_simulate ptest"
	for f in $ptest_progs; do
		which $f 2>/dev/null && break
	done
}
#
# find nodes for this cluster
#
getnodes() {
	# 1. set by user?
	if [ "$USER_NODES" ]; then
		echo $USER_NODES
	# 2. running crm
	elif iscrmrunning; then
		debug "querying CRM for nodes"
		get_crm_nodes
	# 3. hostcache
	elif [ -f $HA_VARLIB/hostcache ]; then
		debug "reading nodes from $HA_VARLIB/hostcache"
		awk '{print $1}' $HA_VARLIB/hostcache
	# 4. ha.cf
	elif [ "$CLUSTER_TYPE" = heartbeat ]; then
		debug "reading nodes from ha.cf"
		getcfvar node
	# 5. if the cluster's stopped, try the CIB
	elif [ -f $CIB_DIR/$CIB_F ]; then
		debug "reading nodes from the archived $CIB_DIR/$CIB_F"
		(CIB_file=$CIB_DIR/$CIB_F get_crm_nodes)
	fi
}

logd_getcfvar() {
	sed 's/#.*//' < $LOGD_CF |
		grep -w "^$1" |
		sed 's/^[^[:space:]]*[[:space:]]*//'
}
get_logd_logvars() {
	# unless logfacility is set to none, heartbeat/ha_logd are
	# going to log through syslog
	HA_LOGFACILITY=`logd_getcfvar logfacility`
	[ "" = "$HA_LOGFACILITY" ] && HA_LOGFACILITY=$DEFAULT_HA_LOGFACILITY
	[ none = "$HA_LOGFACILITY" ] && HA_LOGFACILITY=""
	HA_LOGFILE=`logd_getcfvar logfile`
	HA_DEBUGFILE=`logd_getcfvar debugfile`
}
findlogdcf() {
	local f
	for f in \
		`test -x $HA_BIN/ha_logd &&
			which strings > /dev/null 2>&1 &&
			strings $HA_BIN/ha_logd | grep 'logd\.cf'` \
		`for d; do echo $d/logd.cf $d/ha_logd.cf; done`
	do
		if [ -f "$f" ]; then
			echo $f
			debug "found logd.cf at $f"
			return 0
		fi
	done
	debug "no logd.cf"
	return 1
}
#
# logging
#
syslogmsg() {
	local severity logtag
	severity=$1
	shift 1
	logtag=""
	[ "$HA_LOGTAG" ] && logtag="-t $HA_LOGTAG"
	logger -p ${HA_LOGFACILITY:-$DEFAULT_HA_LOGFACILITY}.$severity $logtag $*
}

#
# find log destination
#
findmsg() {
	local d syslogdirs favourites mark log
	# this is tricky, we try a few directories
	syslogdirs="/var/log /var/logs /var/syslog /var/adm
	/var/log/ha /var/log/cluster /var/log/pacemaker
	/var/log/heartbeat /var/log/crm /var/log/corosync /var/log/openais"
	favourites="ha-*"
	mark=$1
	log=""
	for d in $syslogdirs; do
		[ -d $d ] || continue
		log=`grep -l -e "$mark" $d/$favourites` && break
		test "$log" && break
		log=`grep -l -e "$mark" $d/*` && break
		test "$log" && break
	done 2>/dev/null
	[ "$log" ] &&
		ls -t $log | tr '\n' ' '
	[ "$log" ] &&
		debug "found HA log at `ls -t $log | tr '\n' ' '`" ||
		debug "no HA log found in $syslogdirs"
}

#
# print a segment of a log file
#
str2time() {
	perl -e "\$time='$*';" -e '
	$unix_tm = 0;
	eval "use Date::Parse";
	if (!$@) {
		$unix_tm = str2time($time);
	} else {
		eval "use Date::Manip";
		if (!$@) {
			$unit_tm = UnixDate(ParseDateString($time), "%s");
		}
	}
	if ($unix_tm != "") {
		$unix_tm = int($unix_tm);
	}
	print $unix_tm;
	'
}
getstamp_syslog() {
	awk '{print $1,$2,$3}'
}
getstamp_legacy() {
	awk '{print $2}' | sed 's/_/ /'
}
getstamp_rfc5424() {
	awk '{print $1}'
}
get_ts() {
	local l="$1" ts
	ts=$(str2time `echo "$l" | $getstampproc`)
	if [ -z "$ts" ]; then
		local fmt
		for fmt in rfc5424 syslog legacy; do
			[ "getstamp_$fmt" = "$getstampproc" ] && continue
			ts=$(str2time `echo "$l" | getstamp_$fmt`)
			[ -n "$ts" ] && break
		done
	fi
	echo $ts
}
linetime() {
	get_ts "`tail -n +$2 $1 | head -1`"
}
find_getstampproc() {
	local t l func trycnt
	t=0 l="" func=""
	trycnt=10
	while [ $trycnt -gt 0 ] && read l; do
		t=$(str2time `echo $l | getstamp_syslog`)
		if [ "$t" ]; then
			func="getstamp_syslog"
			debug "the log file is in the syslog format"
			break
		fi
		t=$(str2time `echo $l | getstamp_rfc5424`)
		if [ "$t" ]; then
			func="getstamp_rfc5424"
			debug "the log file is in the rfc5424 format"
			break
		fi
		t=$(str2time `echo $l | getstamp_legacy`)
		if [ "$t" ]; then
			func="getstamp_legacy"
			debug "the log file is in the legacy format (please consider switching to syslog format)"
			break
		fi
		trycnt=$(($trycnt-1))
	done
	echo $func
}
find_first_ts() {
	local l ts
	while read l; do
		ts=`get_ts "$l"`
		[ "$ts" ] && break
		warning "cannot extract time: |$l|; will try the next one"
	done
	echo $ts
}
findln_by_time() {
	local logf=$1
	local tm=$2
	local first=1
	local last=`wc -l < $logf`
	local tmid mid trycnt
	while [ $first -le $last ]; do
		mid=$((($last+$first)/2))
		trycnt=10
		while [ $trycnt -gt 0 ]; do
			tmid=`linetime $logf $mid`
			[ "$tmid" ] && break
			warning "cannot extract time: $logf:$mid; will try the next one"
			trycnt=$(($trycnt-1))
			# shift the whole first-last segment
			first=$(($first-1))
			last=$(($last-1))
			mid=$((($last+$first)/2))
		done
		if [ -z "$tmid" ]; then
			warning "giving up on log..."
			return
		fi
		if [ $tmid -gt $tm ]; then
			last=$(($mid-1))
		elif [ $tmid -lt $tm ]; then
			first=$(($mid+1))
		else
			break
		fi
	done
	echo $mid
}

dumplog() {
	local logf=$1
	local from_line=$2
	local to_line=$3
	[ "$from_line" ] ||
		return
	tail -n +$from_line $logf |
		if [ "$to_line" ]; then
			head -$(($to_line-$from_line+1))
		else
			cat
		fi
}

#
# find files newer than a and older than b
#
isnumber() {
	echo "$*" | grep -qs '^[0-9][0-9]*$'
}
touchfile() {
	local t
	t=`mktemp` &&
	perl -e "\$file=\"$t\"; \$tm=$1;" -e 'utime $tm, $tm, $file;' &&
	echo $t
}
find_files() {
	local dirs from_time to_time
	local from_stamp to_stamp findexp
	dirs=$1
	from_time=$2
	to_time=$3
	isnumber "$from_time" && [ "$from_time" -gt 0 ] || {
		warning "sorry, can't find files based on time if you don't supply time"
		return
	}
	if ! from_stamp=`touchfile $from_time`; then
		warning "can't create temporary files"
		return
	fi
	add_tmpfiles $from_stamp
	findexp="-newer $from_stamp"
	if isnumber "$to_time" && [ "$to_time" -gt 0 ]; then
		if ! to_stamp=`touchfile $to_time`; then
			warning "can't create temporary files"
			return
		fi
		add_tmpfiles $to_stamp
		findexp="$findexp ! -newer $to_stamp"
	fi
	find $dirs -type f $findexp
}

#
# check permissions of files/dirs
#
pl_checkperms() {
perl -e '
# check permissions and ownership
# uid and gid are numeric
# everything must match exactly
# no error checking! (file should exist, etc)
($filename, $perms, $in_uid, $in_gid) = @ARGV;
($mode,$uid,$gid) = (stat($filename))[2,4,5];
$p=sprintf("%04o", $mode & 07777);
$p ne $perms and exit(1);
$uid ne $in_uid and exit(1);
$gid ne $in_gid and exit(1);
' $*
}
num_id() {
	getent $1 $2 | awk -F: '{print $3}'
}
chk_id() {
	[ "$2" ] && return 0
	echo "$1: id not found"
	return 1
}
check_perms() {
	local f p uid gid n_uid n_gid
	essential_files |
	while read type f p uid gid; do
		[ -$type $f ] || {
			echo "$f wrong type or doesn't exist"
			continue
		}
		n_uid=`num_id passwd $uid`
		chk_id "$uid" "$n_uid" || continue
		n_gid=`num_id group $gid`
		chk_id "$gid" "$n_gid" || continue
		pl_checkperms $f $p $n_uid $n_gid || {
			echo "wrong permissions or ownership for $f:"
			ls -ld $f
		}
	done
}

#
# coredumps
#
pkg_mgr_list() {
# list of:
# regex pkg_mgr
# no spaces allowed in regex
	cat<<EOF
zypper.install zypper
EOF
}
listpkg_zypper() {
	local bins
	local binary=$1 core=$2
	gdb $binary $core </dev/null 2>&1 |
	awk '
	# this zypper version dumps all packages on a single line
	/Missing separate debuginfos.*zypper.install/ {
		sub(".*zypper.install ",""); print
		exit}
	n>0 && /^Try: zypper install/ {gsub("\"",""); print $NF}
	n>0 {n=0}
	/Missing separate debuginfo/ {n=1}
	' | sort -u
}
fetchpkg_zypper() {
	local pkg
	debug "get debuginfo packages using zypper: $@"
	zypper -qn ref > /dev/null
	# use --ignore-unknown if available, much faster
	# (2 is zypper exit code for syntax/usage)
	zypper -qn --ignore-unknown install -C $@ >/dev/null
	[ $? -ne 2 ] && return
	for pkg in $@; do
		zypper -qn install -C $pkg >/dev/null
	done
}
find_pkgmgr() {
	local binary=$1 core=$2
	local regex pkg_mgr
	pkg_mgr_list |
	while read regex pkg_mgr; do
		if gdb $binary $core </dev/null 2>&1 |
				grep "$regex" > /dev/null; then
			echo $pkg_mgr
			break
		fi
	done
}
get_debuginfo() {
	local binary=$1 core=$2
	local pkg_mgr pkgs
	gdb $binary $core </dev/null 2>/dev/null |
		egrep 'Missing.*debuginfo|no debugging symbols found' > /dev/null ||
		return  # no missing debuginfo
	pkg_mgr=`find_pkgmgr $binary $core`
	if [ -z "$pkg_mgr" ]; then
		warning "found core for $binary but there is no debuginfo and we don't know how to get it on this platform"
		return
	fi
	pkgs=`listpkg_$pkg_mgr $binary $core`
	[ -n "$pkgs" ] &&
		fetchpkg_$pkg_mgr $pkgs
}
findbinary() {
	local random_binary binary fullpath
	random_binary=`which cat 2>/dev/null` # suppose we are lucky
	binary=`gdb $random_binary $1 < /dev/null 2>/dev/null |
		grep 'Core was generated' | awk '{print $5}' |
		sed "s/^.//;s/[.':]*$//"`
	if [ x = x"$binary" ]; then
		debug "could not detect the program name for core $1 from the gdb output; will try with file(1)"
		binary=$(file $1 | awk '/from/{
			for( i=1; i<=NF; i++ )
				if( $i == "from" ) {
					print $(i+1)
					break
				}
			}')
		binary=`echo $binary | tr -d "'"`
		binary=$(echo $binary | tr -d '`')
		if [ "$binary" ]; then
			binary=`which $binary 2>/dev/null`
		fi
	fi
	if [ x = x"$binary" ]; then
		warning "could not find the program path for core $1"
		return
	fi
	fullpath=`which $binary 2>/dev/null`
	if [ x = x"$fullpath" ]; then
		for d in $HA_BIN $CRM_DAEMON_DIR; do
			if [ -x $d/$binary ]; then
				echo $d/$binary
				debug "found the program at $d/$binary for core $1"
			else
				warning "could not find the program path for core $1"
			fi
		done
	else
		echo $fullpath
		debug "found the program at $fullpath for core $1"
	fi
}
getbt() {
	local corefile absbinpath
	which gdb > /dev/null 2>&1 || {
		warning "please install gdb to get backtraces"
		return
	}
	for corefile; do
		absbinpath=`findbinary $corefile`
		[ x = x"$absbinpath" ] && continue
		get_debuginfo $absbinpath $corefile
		echo "====================== start backtrace ======================"
		ls -l $corefile
		gdb -batch -n -quiet -ex ${BT_OPTS:-"thread apply all bt full"} -ex quit \
			$absbinpath $corefile 2>/dev/null
		echo "======================= end backtrace ======================="
	done
}

#
# heartbeat configuration/status
#
iscrmrunning() {
	local pid maxwait
	ps -ef | grep -qs [c]rmd || return 1
	crmadmin -D >/dev/null 2>&1 &
	pid=$!
	maxwait=100
	while kill -0 $pid 2>/dev/null && [ $maxwait -gt 0 ]; do
		sleep 0.1
		maxwait=$(($maxwait-1))
	done
	if kill -0 $pid 2>/dev/null; then
		kill $pid
		false
	else
		wait $pid
	fi
}
dumpstate() {
	crm_mon -1 | grep -v '^Last upd' > $1/$CRM_MON_F
	cibadmin -Ql > $1/$CIB_F
	`echo_membership_tool` $MEMBERSHIP_TOOL_OPTS -p > $1/$MEMBERSHIP_F 2>&1
}
getconfig() {
	[ -f "$CONF" ] &&
		cp -p $CONF $1/
	[ -f "$LOGD_CF" ] &&
		cp -p $LOGD_CF $1/
	if iscrmrunning; then
		dumpstate $1
		touch $1/RUNNING
	else
		cp -p $CIB_DIR/$CIB_F $1/ 2>/dev/null
		touch $1/STOPPED
	fi
	[ "$HOSTCACHE" ] &&
		cp -p $HA_VARLIB/hostcache $1/$HOSTCACHE 2>/dev/null
	[ "$HB_UUID_F" ] &&
		crm_uuid -r > $1/$HB_UUID_F 2>&1
	[ -f "$1/$CIB_F" ] &&
		crm_verify -V -x $1/$CIB_F >$1/$CRM_VERIFY_F 2>&1
}
crmconfig() {
	[ -f "$1/$CIB_F" ] && which crm >/dev/null 2>&1 &&
		CIB_file=$1/$CIB_F crm configure show >$1/$CIB_TXT_F 2>&1
}
get_crm_nodes() {
	cibadmin -Ql -o nodes |
	awk '
	/<node / {
		for( i=1; i<=NF; i++ )
			if( $i~/^uname=/ ) {
				sub("uname=.","",$i);
				sub("\".*","",$i);
				print $i;
				next;
			}
	}
	'
}
get_live_nodes() {
	if [ `id -u` = 0 ] && which fping >/dev/null 2>&1; then
		fping -a $@ 2>/dev/null
	else
		local h
		for h; do ping -c 2 -q $h >/dev/null 2>&1 && echo $h; done
	fi
}

#
# remove values of sensitive attributes
#
# this is not proper xml parsing, but it will work under the
# circumstances
is_sensitive_xml() {
	local patt epatt
	epatt=""
	for patt in $SANITIZE; do
		epatt="$epatt|$patt"
	done
	epatt="`echo $epatt|sed 's/.//'`"
	egrep -qs "name=\"$epatt\""
}
test_sensitive_one() {
	local file compress decompress
	file=$1
	compress=""
	echo $file | grep -qs 'gz$' && compress=gzip
	echo $file | grep -qs 'bz2$' && compress=bzip2
	if [ "$compress" ]; then
		decompress="$compress -dc"
	else
		compress=cat
		decompress=cat
	fi
	$decompress < $file | is_sensitive_xml
}
sanitize_xml_attrs() {
	local patt
	sed $(
	for patt in $SANITIZE; do
		echo "-e /name=\"$patt\"/s/value=\"[^\"]*\"/value=\"****\"/"
	done
	)
}
sanitize_hacf() {
	awk '
	$1=="stonith_host"{ for( i=5; i<=NF; i++ ) $i="****"; }
	{print}
	'
}
sanitize_one() {
	local file compress decompress tmp ref
	file=$1
	compress=""
	echo $file | grep -qs 'gz$' && compress=gzip
	echo $file | grep -qs 'bz2$' && compress=bzip2
	if [ "$compress" ]; then
		decompress="$compress -dc"
	else
		compress=cat
		decompress=cat
	fi
	tmp=`mktemp`
	ref=`mktemp`
	add_tmpfiles $tmp $ref
	if [ -z "$tmp" -o -z "$ref" ]; then
		fatal "cannot create temporary files"
	fi
	touch -r $file $ref  # save the mtime
	if [ "`basename $file`" = ha.cf ]; then
		sanitize_hacf
	else
		$decompress | sanitize_xml_attrs | $compress
	fi < $file > $tmp
	mv $tmp $file
	touch -r $ref $file
}

#
# keep the user posted
#
fatal() {
	echo "`uname -n`: ERROR: $*" >&2
	exit 1
}
warning() {
	echo "`uname -n`: WARN: $*" >&2
}
info() {
	echo "`uname -n`: INFO: $*" >&2
}
debug() {
	[ "$VERBOSITY" ] && [ $VERBOSITY -gt 0 ] &&
	echo "`uname -n`: DEBUG: $*" >&2
	return 0
}
pickfirst() {
	for x; do
		which $x >/dev/null 2>&1 && {
			echo $x
			return 0
		}
	done
	return 1
}

# tmp files business
drop_tmpfiles() {
	trap 'rm -rf `cat $__TMPFLIST`; rm $__TMPFLIST' EXIT
}
init_tmpfiles() {
	if __TMPFLIST=`mktemp`; then
		drop_tmpfiles
	else
		# this is really bad, let's just leave
		fatal "eek, mktemp cannot create temporary files"
	fi
}
add_tmpfiles() {
	test -f "$__TMPFLIST" || return
	echo $* >> $__TMPFLIST
}

#
# get some system info
#
distro() {
	local relf f
	which lsb_release >/dev/null 2>&1 && {
		lsb_release -d
		debug "using lsb_release for distribution info"
		return
	}
	relf=`ls /etc/debian_version 2>/dev/null` ||
	relf=`ls /etc/slackware-version 2>/dev/null` ||
	relf=`ls -d /etc/*-release 2>/dev/null` && {
		for f in $relf; do
			test -f $f && {
				echo "`ls $f` `cat $f`"
				debug "found $relf distribution release file"
				return
			}
		done
	}
	warning "no lsb_release, no /etc/*-release, no /etc/debian_version: no distro information"
}

pkg_ver_deb() {
	dpkg-query -f '${Name} ${Version}' -W $* 2>/dev/null
}
pkg_ver_rpm() {
	rpm -q --qf '%{name} %{version}-%{release} - %{distribution} %{arch}\n' $* 2>&1 |
		grep -v 'not installed'
}
pkg_ver_pkg_info() {
	for pkg; do
		pkg_info | grep $pkg
	done
}
pkg_ver_pkginfo() {
	for pkg; do
		pkginfo $pkg | awk '{print $3}'  # format?
	done
}
verify_deb() {
	debsums -s $* 2>/dev/null
}
verify_rpm() {
	rpm --verify $* 2>&1 | grep -v 'not installed'
}
verify_pkg_info() {
	:
}
verify_pkginfo() {
	:
}

get_pkg_mgr() {
	local pkg_mgr
	if which dpkg >/dev/null 2>&1 ; then
		pkg_mgr="deb"
	elif which rpm >/dev/null 2>&1 ; then
		pkg_mgr="rpm"
	elif which pkg_info >/dev/null 2>&1 ; then 
		pkg_mgr="pkg_info"
	elif which pkginfo >/dev/null 2>&1 ; then 
		pkg_mgr="pkginfo"
	else
		warning "Unknown package manager!"
		return
	fi
	echo $pkg_mgr
}

pkg_versions() {
	local pkg_mgr=`get_pkg_mgr`
	[ -z "$pkg_mgr" ] &&
		return
	debug "the package manager is $pkg_mgr"
	pkg_ver_$pkg_mgr $*
}
verify_packages() {
	local pkg_mgr=`get_pkg_mgr`
	[ -z "$pkg_mgr" ] &&
		return
	verify_$pkg_mgr $*
}

crm_info() {
	$CRM_DAEMON_DIR/crmd version 2>&1
}
