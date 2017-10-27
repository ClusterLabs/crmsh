#!/bin/sh
echo "** Unit tests"
./test/run
echo "** Autogen / Configure"
./autogen.sh
./configure --prefix /usr
echo "** Make / Install"
make install
echo "** Regression tests"
sh /usr/share/crmsh/tests/regression.sh
