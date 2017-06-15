#!/bin/sh
set -ev
./autogen.sh
./configure --prefix=/usr
sudo make install
sudo cp -f /usr/bin/crm /usr/sbin/crm
if [  "$TRAVIS_PYTHON_VERSION" = "2.7_with_system_site_packages" ]; then
	pip -v --isolated install parallax prompt_toolkit
	sudo /usr/share/crmsh/tests/regression.sh
	cd /usr/share/crmsh/tests
	sudo ./cib-tests.sh
fi
