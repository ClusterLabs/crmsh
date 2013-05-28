%global gname haclient
%global uname hacluster
%global crmsh_docdir %{_defaultdocdir}/%{name}

%global specversion 0
%global upstream_version tip
%global upstream_prefix crmsh

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

%global crmsh_release %{specversion}

Name:		crmsh
Summary:	Pacemaker command line interface
Version:	1.2.5
Release:	%{crmsh_release}%{?dist}
License:	GPL-2.0+
Url:		http://savannah.nongnu.org/projects/crmsh
Group:		%{pkg_group}
Source0:	crmsh.tar.bz2
BuildRoot:	%{_tmppath}/%{name}-%{version}-build
AutoReqProv:	on
Requires(pre):	pacemaker
Requires:	python >= 2.4
Requires:	python-dateutil
Requires:       pssh

%if 0%{?suse_version}
# Suse splits this off into a separate package
Requires:       python-curses python-xml
BuildRequires:  python-curses python-xml
BuildRequires:	libpacemaker-devel libglue-devel
%else
BuildRequires:	pacemaker-libs-devel cluster-glue-libs-devel
%endif

# Required for core functionality
BuildRequires:  automake autoconf pkgconfig python
BuildRequires:	asciidoc
BuildRequires:	libtool

%if 0%{?suse_version} > 1210
# xsltproc is necessary for manpage generation; this is split out into
# libxslt-tools as of openSUSE 12.2.  Possibly strictly should be
# required by asciidoc
BuildRequires:  libxslt-tools
%endif


%if 0%{?with_regression_tests}
BuildRequires:  corosync procps vim-base python-dateutil
Requires:       pacemaker
%endif

%description
crm shell, a Pacemaker command line interface.

Pacemaker is an advanced, scalable High-Availability cluster resource
manager for Heartbeat and/or Corosync.

Authors: Dejan Muhamedagic <dejan@suse.de> and many others

%prep
%setup -q -n %{upstream_prefix}

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
%{configure}			\
	--localstatedir=%{_var}				\
	--with-package-name=%{name} \
	--with-version=%{version}-%{release}
%else
%{configure}			\
	--localstatedir=%{_var}				\
	--with-package-name=%{name}		\
	--with-version=%{version}-%{release}	\
	--docdir=%{crmsh_docdir}
%endif

make %{_smp_mflags} docdir=%{crmsh_docdir}

%install
rm -rf %{buildroot}
make DESTDIR=%{buildroot} docdir=%{crmsh_docdir} install

%clean
rm -rf %{buildroot}

%if 0%{?with_regression_tests}

%post
# Needed so that the shell doesn't get stuck on escape
# sequences
if ! /usr/share/crmsh/tests/regression.sh ; then
	echo "Shell tests failed."
	cat crmtestout/regression.out
	exit 1
fi
%endif

%files
###########################################################
%defattr(-,root,root)

%{_datadir}/crmsh

%{_sbindir}/crm
%{py_sitedir}/crmsh

%doc %{_mandir}/man8/crm.8*
%{crmsh_docdir}/COPYING
%{crmsh_docdir}/AUTHORS
%{crmsh_docdir}/crm.8.html
%{crmsh_docdir}/ChangeLog
%{crmsh_docdir}/README
%{crmsh_docdir}/contrib/*

%dir %{crmsh_docdir}
%dir %{crmsh_docdir}/contrib
%dir %attr (770, %{uname}, %{gname}) %{_var}/cache/crm

%changelog
