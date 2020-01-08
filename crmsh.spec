#
# spec file for package crmsh
#
# Copyright (c) 2019 SUSE LINUX GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via https://bugs.opensuse.org/
#


%bcond_with regression_tests

%global gname haclient
%global uname hacluster
%global crmsh_docdir %{_defaultdocdir}/%{name}

%global upstream_version tip
%global upstream_prefix crmsh
%global crmsh_release 1

%if 0%{?fedora_version} || 0%{?centos_version} || 0%{?rhel_version} || 0%{?rhel} || 0%{?fedora}
%define pkg_group System Environment/Daemons
%else
%define pkg_group Productivity/Clustering/HA
%endif

%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}

Name:           crmsh
Summary:        High Availability cluster command-line interface
License:        GPL-2.0-or-later
Group:          %{pkg_group}
Version:        3.0.4
Release:        0
Url:            http://crmsh.github.io
Source0:        %{name}-%{version}.tar.bz2

BuildRoot:      %{_tmppath}/%{name}-%{version}-build
%if 0%{?suse_version}
# Requiring pacemaker makes crmsh harder to build on other distributions,
# and is mostly a convenience feature. So only do it for SUSE.
Requires(pre):  pacemaker
%endif
Requires:       %{name}-scripts >= %{version}-%{release}
Requires:       /usr/bin/which
Requires:       python >= 2.6
Requires:       python-dateutil
Requires:       python-lxml
Requires:       python-parallax
BuildRequires:  python-lxml
BuildRequires:  python-setuptools

%if 0%{?suse_version}
# only require csync2 on SUSE since bootstrap
# only works for SUSE at the moment anyway
Requires:       csync2
%endif

%if 0%{?suse_version}
Requires:       python-PyYAML
# Suse splits this off into a separate package
Requires:       python-curses
BuildRequires:  fdupes
BuildRequires:  python-curses
%endif

%if 0%{?fedora_version}
Requires:       PyYAML
%endif

# Required for core functionality
BuildRequires:  asciidoc
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  pkgconfig
BuildRequires:  python

%if 0%{?suse_version} > 1210
# xsltproc is necessary for manpage generation; this is split out into
# libxslt-tools as of openSUSE 12.2.  Possibly strictly should be
# required by asciidoc
BuildRequires:  libxslt-tools
%endif

%if 0%{?suse_version} > 1110 || 0%{?fedora_version} || 0%{?centos_version} || 0%{?rhel_version} || 0%{?rhel} || 0%{?fedora}
BuildArch:      noarch
%endif

%description
The crm shell is a command-line interface for High-Availability
cluster management on GNU/Linux systems. It simplifies the
configuration, management and troubleshooting of Pacemaker-based
clusters, by providing a powerful and intuitive set of features.

%package test
Summary:        Test package for crmsh
Group:          %{pkg_group}
Requires:       crmsh
%if %{with regression_tests}
Requires(post):  mailx
Requires(post):  procps
Requires(post):  python-dateutil
Requires(post):  python-nose
Requires(post):  python-parallax
Requires(post):  pacemaker
%if 0%{?suse_version} > 1110
BuildArch:      noarch
%endif
%if 0%{?suse_version}
Requires(post):  libglue-devel
%else
Requires(post):  cluster-glue-libs-devel
%endif
%if 0%{?fedora_version}
Requires(post):  PyYAML
%else
Requires(post):  python-PyYAML
%endif
%endif

%description test
The crm shell is a command-line interface for High-Availability
cluster management on GNU/Linux systems. It simplifies the
configuration, management and troubleshooting of Pacemaker-based
clusters, by providing a powerful and intuitive set of features.
This package contains the regression test suite for crmsh.

%package scripts
Summary:        Crm Shell Cluster Scripts
Group:          Productivity/Clustering/HA

%description scripts
Cluster scripts for crmsh. The cluster scripts can be run
directly from the crm command line, or used by user interfaces
like hawk to implement configuration wizards.

%prep
%setup -q

# Force the local time
#
# 'hg archive' sets the file date to the date of the last commit.
# This can result in files having been created in the future
# when building on machines in timezones 'behind' the one the
# commit occurred in - which seriously confuses 'make'
find . -mtime -0 -exec touch \{\} \;

%build
./autogen.sh

%{configure}            \
    --sysconfdir=%{_sysconfdir} \
    --localstatedir=%{_var}             \
    --with-version=%{version}    \
    --docdir=%{crmsh_docdir}

make %{_smp_mflags} VERSION="%{version}" sysconfdir=%{_sysconfdir} localstatedir=%{_var}

%if %{with regression_tests}
./test/run --quiet
if [ ! $? ]; then
    echo "Unit tests failed."
    exit 1
fi
%endif

%install
make DESTDIR=%{buildroot} docdir=%{crmsh_docdir} install
install -Dm0644 contrib/bash_completion.sh %{buildroot}%{_sysconfdir}/bash_completion.d/crm.sh
if [ -f %{buildroot}%{_bindir}/crm ]; then
	install -Dm0755 %{buildroot}%{_bindir}/crm %{buildroot}%{_sbindir}/crm
	rm %{buildroot}%{_bindir}/crm
fi
%if 0%{?suse_version}
%fdupes %{buildroot}
%endif

%if %{with regression_tests}
# Run regression tests after installing the package
# NB: this is called twice by OBS, that's why we touch the file
%post test
testfile=/tmp/.crmsh_regression_tests_ran
# check if time in file is less than 2 minutes ago
if [ -e $testfile ] && [ "$(( $(date +%s) - $(cat $testfile) ))" -lt 120 ]; then
	echo "Skipping regression tests..."
	exit 0
fi
# write current time to file
rm -f "$testfile"
echo "$(date +%s)" > "$testfile"
%{_datadir}/%{name}/tests/regression.sh
result1=$?
cd %{_datadir}/%{name}/tests
./cib-tests.sh
result2=$?
[ $result1 -ne 0 ] && (echo "Regression tests failed."; cat ${buildroot}/crmtestout/regression.out)
[ $result2 -ne 0 ] && echo "CIB tests failed."
[ $result1 -eq 0 -a $result2 -eq 0 ]
%endif

%files
###########################################################
%defattr(-,root,root)

%{_sbindir}/crm
%{python_sitelib}/crmsh*

%{_datadir}/%{name}
%exclude %{_datadir}/%{name}/tests
%exclude %{_datadir}/%{name}/scripts

%doc %{_mandir}/man8/*
%{crmsh_docdir}/COPYING
%{crmsh_docdir}/AUTHORS
%{crmsh_docdir}/crm.8.html
%{crmsh_docdir}/crmsh_hb_report.8.html
%{crmsh_docdir}/ChangeLog
%{crmsh_docdir}/README.md
%{crmsh_docdir}/contrib/*

%config %{_sysconfdir}/crm

%dir %{crmsh_docdir}
%dir %{crmsh_docdir}/contrib
%dir %attr (770, %{uname}, %{gname}) %{_var}/cache/crm
%config %{_sysconfdir}/bash_completion.d/crm.sh

%files scripts
%defattr(-,root,root)
%{_datadir}/%{name}/scripts

%files test
%defattr(-,root,root)
%{_datadir}/%{name}/tests

%changelog
