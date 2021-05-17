#!/bin/sh
configure() {
	echo "** Autogen / Configure"
	./autogen.sh
	./configure --prefix /usr
}

make_install() {
	echo "** Make / Install"
	make install
	make install-crmconfDATA prefix=
}

regression_tests() {
	echo "** Regression tests"
	sh /usr/share/crmsh/tests/regression.sh
}

functional_tests() {
	echo "**  $1 process tests using python-behave"
        SUFFIX="${2:-*}"
        behave --no-logcapture --tags "@$1" --tags "~@wip" /usr/share/crmsh/tests/features/$1_$SUFFIX.feature
}

case "$1" in
	build)
		configure
		make_install
		exit $?;;
	bootstrap|qdevice|hb_report|resource|geo|configure|constraints|ocfs2)
		functional_tests $1 $2
		exit $?;;
	*|original)
		configure
		make_install
		regression_tests;;
esac
