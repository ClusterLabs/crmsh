#!/bin/sh

unit_tests() {
	echo "** Unit tests"
	./test/run
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

bootstrap_tests() {
	echo "** Bootstrap process tests using python-behave"
        behave --no-logcapture --tags "@bootstrap" --tags "~@wip" /usr/share/crmsh/tests/features/bootstrap_$1.feature
}

case "$1" in
	build)
		configure
		make_install
		exit $?;;
	bootstrap)
		configure
		make_install
		bootstrap_tests "$2"
		exit $?;;
	*)
		unit_tests
		rc_unittest=$?
		configure
		make_install
		regression_tests && exit $rc_unittest;;
esac
