#!/bin/sh

oname=$1
ouid=$2
ogid=$3

cat /etc/group | awk '{ FS = ":" } { print $3 }' | grep -q $ogid || groupadd -g $ogid
id -u $oname >/dev/null 2>&1 || useradd -u $ouid -g $ogid $oname

echo "** Unit tests"
su $oname -c "./test/run"
echo "** Autogen / Configure"
su $oname -c "./autogen.sh"
su $oname -c "./configure --prefix /usr"
echo "** Make / Install"
make install
echo "** Regression tests"
sh /usr/share/crmsh/tests/regression.sh
