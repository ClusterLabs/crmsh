#!/bin/bash
# Copyright (C) 2009 Lars Marowsky-Bree <lmb@suse.de>
# See COPYING for license information.

BASE=${1:-`pwd`}/cibtests
AUTOCREATE=1

logt() {
	local msg="$1"
	echo $(date) "$msg" >>$LOGF
	echo "$msg"
}

difft() {
	crm_diff -V -u -o $1 -n $2
}

run() {
	local cmd="$1"
	local erc="$2"
	local msg="$3"
	local rc
	local out

	echo $(date) "$1" >>$LOGF
	CIB_file=$CIB_file $1 >>$LOGF 2>&1 ; rc=$?
	echo $(date) "Returned: $rc (expected $erc)" >>$LOGF
	if [ $erc != "I" ]; then
		if [ $rc -ne $erc ]; then
			logt "$msg: FAILED ($erc != $rc)"
			cat $LOGF
			return 1
		fi
	fi
	echo "$msg: ok"
	return 0
}

runt() {
	local T="$1"
	local CIBE="$BASE/$(basename $T .input).exp.xml"
	cp $BASE/shadow.base $CIB_file
	run "crm" 0 "Running testcase: $T" <$T

	# strip <cib> attributes from CIB_file
	echo "<cib>" > $CIB_file.$$
	tail -n +2 $CIB_file >> $CIB_file.$$
	mv $CIB_file.$$ $CIB_file

	local rc
	if [ ! -e $CIBE ]; then
		if [ "$AUTOCREATE" = "1" ]; then
			logt "Creating new expected output for $T."
			cp $CIB_file $CIBE
			return 0
		else
			logt "$T: No expected output."
			return 0
		fi
	fi

	if ! crm_diff -u -o $CIBE -n $CIB_file >/dev/null 2>&1 ; then
		logt "$T: XML: $CIBE does not match $CIB_file"
		difft $CIBE $CIB_file
		return 1
	fi
	return 0
}

LOGF=$(mktemp)
export PATH=/usr/sbin:$PATH

export CIB_file=$BASE/shadow.test

failed=0
for T in $(ls $BASE/*.input) ; do
	runt $T
	failed=$(($? + $failed))
done

if [ $failed -gt 0 ]; then
	logt "$failed tests failed!"
	echo "Log:" $LOGF "CIB:" $CIB_file
	exit 1
fi

logt "All tests passed!"
#rm $LOGF $CIB_file
exit 0

