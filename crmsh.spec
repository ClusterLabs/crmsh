#
# spec file for package crmsh
#
# Copyright (c) 2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#


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

# Compatibility macros for distros (fedora) that don't provide Python macros by default
# Do this instead of trying to conditionally include {_rpmconfigdir}/macros.python
%{!?py_ver:     %{expand: %%global py_ver      %%(echo `python -c "import sys; print sys.version[:3]"`)}}
%{!?py_prefix:  %{expand: %%global py_prefix   %%(echo `python -c "import sys; print sys.prefix"`)}}
%{!?py_libdir:  %{expand: %%global py_libdir   %%{expand:%%%%{py_prefix}/%%%%{_lib}/python%%%%{py_ver}}}}
%{!?py_sitedir: %{expand: %%global py_sitedir  %%{expand:%%%%{py_libdir}/site-packages}}}

Name:           crmsh
Summary:        Pacemaker command line interface
License:        GPL-2.0+
Group:          %{pkg_group}
Version:        2.0
Release:        %{?crmsh_release}%{?dist}
Url:            http://savannah.nongnu.org/projects/crmsh
Source0:        crmsh.tar.bz2
# PATCH-FEATURE-OPENSUSE crmsh-cibadmin_can_patch.patch
# dejan@suse.de -- enable atomic CIB updates here, because our
# pacemaker version has been fixed in the meantime
Patch11:        crmsh-cibadmin_can_patch.patch
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
Requires(pre):  pacemaker
Requires:       pssh
Requires:       python >= 2.4
Requires:       python-PyYAML
Requires:       python-dateutil
Requires:       python-lxml
Requires:       which
BuildRequires:  python-PyYAML
BuildRequires:  python-lxml

%if 0%{?suse_version}
# Suse splits this off into a separate package
Requires:       python-curses
BuildRequires:  fdupes
BuildRequires:  libglue-devel
BuildRequires:  libpacemaker-devel
BuildRequires:  python-curses
%else
BuildRequires:  cluster-glue-libs-devel
BuildRequires:  pacemaker-libs-devel
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

%if 0%{?with_regression_tests}
BuildRequires:  corosync
BuildRequires:  procps
BuildRequires:  python-dateutil
BuildRequires:  vim
Requires:       pacemaker
Requires:       pssh
%endif

%description
crm shell, a Pacemaker command line interface.

Pacemaker is an advanced, scalable High-Availability cluster resource
manager for Heartbeat and/or Corosync.

Authors: Dejan Muhamedagic <dejan@suse.de> and many others

%prep
%setup -q -n %{upstream_prefix}
%patch11 -p1

# Force the local time
#
# 'hg archive' sets the file date to the date of the last commit.
# This can result in files having been created in the future
# when building on machines in timezones 'behind' the one the
# commit occurred in - which seriously confuses 'make'
find . -exec touch \{\} \;

%build
./autogen.sh

# RHEL <= 5 does not support --docdir
# SLES <= 10 does not support ./configure --docdir=,
# hence, use this ugly hack
%if 0%{?suse_version} < 1020
export docdir=%{crmsh_docdir}
%{configure}            \
    --sysconfdir=%{_sysconfdir} \
    --localstatedir=%{_var}             \
    --with-pkg-name=%{name} \
    --with-version=%{version}-%{release}
%else
%{configure}            \
    --sysconfdir=%{_sysconfdir} \
    --localstatedir=%{_var}             \
    --with-pkg-name=%{name}     \
    --with-version=%{version}-%{release}    \
    --docdir=%{crmsh_docdir}
%endif

make %{_smp_mflags} docdir=%{crmsh_docdir}

%if 0%{?with_regression_tests}
    if ! test/unittests/testrunner.py ; then
        echo "Shell unit tests failed."
        exit 1
    fi
%endif

%install
make DESTDIR=%{buildroot} docdir=%{crmsh_docdir} install
install -Dm0644 contrib/bash_completion.sh %{buildroot}%{_sysconfdir}/bash_completion.d/crm.sh
%if 0%{?suse_version}
%fdupes %{buildroot}
%endif

%clean
rm -rf %{buildroot}

# Run regression tests after installing the package
# NB: this is called twice by OBS, that's why we touch the file
%if 0%{?with_regression_tests}
%post
if [ ! -e /tmp/.crmsh_regression_tests_ran ]; then
    touch /tmp/.crmsh_regression_tests_ran
    if ! %{_datadir}/%{name}/tests/regression.sh ; then
        echo "Shell tests failed."
        cat crmtestout/regression.out
        exit 1
    fi
fi
%endif

%files
###########################################################
%defattr(-,root,root)

%{_sbindir}/crm
%{py_sitedir}/crmsh

%{_datadir}/%{name}

%doc %{_mandir}/man8/*
%{crmsh_docdir}/COPYING
%{crmsh_docdir}/AUTHORS
%{crmsh_docdir}/crm.8.html
%{crmsh_docdir}/crmsh_hb_report.8.html
%{crmsh_docdir}/ChangeLog
%{crmsh_docdir}/README
%{crmsh_docdir}/contrib/*

%config %{_sysconfdir}/crm

%dir %{crmsh_docdir}
%dir %{crmsh_docdir}/contrib
%dir %attr (770, %{uname}, %{gname}) %{_var}/cache/crm
%config %{_sysconfdir}/bash_completion.d/crm.sh

%changelog
