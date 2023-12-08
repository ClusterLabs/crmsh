#!/bin/bash
# Copyright (C) 2007 Dejan Muhamedagic <dejan@suse.de>
# See COPYING for license information.

: ${TESTDIR:=testcases}
: ${CRM:=crm}
CRM_NO_REG="$CRM"
CRM="$CRM -R"
export PYTHONUNBUFFERED=1
export CRMSH_REGRESSION_TEST=1

if [ "$1" = prof ]; then
	CRM="$CRM -X regtest.profile"
fi

. ./defaults
. ./crm-interface
. ./descriptions

resetvars() {
	unset args
	unset extcheck
}

#
# special operations squad
#
specopt_setenv() {
	eval $rest
}
specopt_ext() {
	eval $rest
}
specopt_extcheck() {
	extcheck="$rest"
	set $extcheck
	which "$1" >/dev/null 2>&1 ||  # a program in the PATH
		extcheck="$TESTDIR/$extcheck"  # or our script
}
specopt_repeat() {
	repeat_limit=$rest
}
specopt() {
	cmd=$(echo $cmd | sed 's/%//')  # strip leading '%'
	echo ".$(echo "$cmd" | tr "[:lower:]" "[:upper:]") $rest"  # show what we got
	"specopt_$cmd"  # do what they asked for
}

#
# substitute variables in the test line
#
substvars() {
	sed "
	s/%t/$test_cnt/g
	s/%l/$line/g
	s/%i/$repeat_cnt/g
	"
}

dotest_session() {
	echo -n "." >&3
	test_cnt=$(($test_cnt+1))
	"describe_$cmd" "$*"  # show what we are about to do
	"crm_$cmd" |  # and execute the command
		{ [ "$extcheck" ] && $extcheck || cat;}
}
dotest_single() {
	echo -n "." >&3
	test_cnt=$(($test_cnt+1))
	describe_single "$*" # show what we are about to do
	crm_single "$*" |  # and execute the command
		{ [ "$extcheck" ] && $extcheck || cat;}
	if [ "$showobj" ]; then
		crm_showobj $showobj
	fi
}
runtest_session() {
	while read line; do
		if [ "$line" = . ]; then
			break
		fi
		echo "$line"
	done | dotest_session $*
}
runtest_single() {
	while [ $repeat_cnt -le $repeat_limit ]; do
		dotest_single "$*"
		resetvars  # unset all variables
		repeat_cnt=$(($repeat_cnt+1))
	done
	repeat_limit=1 repeat_cnt=1
}

#
# run the tests
#
repeat_limit=1 repeat_cnt=1
line=1
test_cnt=1

crm_setup
crm_mksample
while read cmd rest; do
	case "$cmd" in
		"") : empty ;;
		"#"*) : a comment ;;
		"%stop") break ;;
		"%"*) specopt ;;
		show|showxml|session|filesession) runtest_session $rest ;;
		*) runtest_single $cmd $rest ;;
	esac
	line=$(($line+1))
done
