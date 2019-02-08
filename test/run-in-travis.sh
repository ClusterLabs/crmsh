#!/bin/sh

unit_tests() {
	echo "** Unit tests"
	./test/run --with-coverage --cover-package=crmsh
	coverage xml
}

configure() {
	echo "** Autogen / Configure"
	./autogen.sh
	./configure --prefix /usr
}

make_install() {
	echo "** Make / Install"
	make install
}

regression_tests() {
	echo "** Regression tests"
	sh /usr/share/crmsh/tests/regression.sh
}

unit_tests
rc_unittest=$?
configure
make_install
regression_tests && exit $rc_unittest
