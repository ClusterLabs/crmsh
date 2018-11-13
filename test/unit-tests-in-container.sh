#!/bin/sh

oname=$1
ogroup=$2
ouid=$3
ogid=$4

cat /etc/group | awk '{ FS = ":" } { print $3 }' | grep -q "$ogid" || groupadd -g "$ogid"
id -u $oname >/dev/null 2>&1 || useradd -u $ouid -g $ogid $oname

preamble() {
	systemctl start dbus
}

unit_tests() {
	echo "** Unit tests"
	su $oname -c "./test/run -v"
}

preamble
unit_tests

