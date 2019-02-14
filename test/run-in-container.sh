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
	su $oname -c "./test/run"
}

configure() {
	echo "** Autogen / Configure"
	su $oname -c "./autogen.sh"
	su $oname -c "./configure --prefix /usr"
}

make_install() {
	echo "** Make / Install"
	make install
}

regression_tests() {
	echo "** Regression tests"
	sh /usr/share/crmsh/tests/regression.sh
}

preamble
unit_tests
configure
make_install
regression_tests

chown $oname:$ogroup /app/crmtestout/*

