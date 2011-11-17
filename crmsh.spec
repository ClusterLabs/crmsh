%global gname haclient
%global uname hacluster
%global crmsh_docdir %{_defaultdocdir}/%{name}

%global specversion 0
%global upstream_version tip
%global upstream_prefix crmsh

# Compatibility macros for distros (fedora) that don't provide Python macros by default
# Do this instead of trying to conditionally include {_rpmconfigdir}/macros.python
%{!?py_ver:     %{expand: %%global py_ver      %%(echo `python -c "import sys; print sys.version[:3]"`)}}
%{!?py_prefix:  %{expand: %%global py_prefix   %%(echo `python -c "import sys; print sys.prefix"`)}}
%{!?py_libdir:  %{expand: %%global py_libdir   %%{expand:%%%%{py_prefix}/%%%%{_lib}/python%%%%{py_ver}}}}
%{!?py_sitedir: %{expand: %%global py_sitedir  %%{expand:%%%%{py_libdir}/site-packages}}}

%global crmsh_release %{specversion}

Name:		crmsh
Summary:	Pacemaker command line interface
Version:	1.1.0
Release:	%{crmsh_release}%{?dist}
License:	GPLv2+ and LGPLv2+
Url:		http://www.clusterlabs.org
Group:		Productivity/Clustering/HA
Source0:	crmsh.tar.bz2
BuildRoot:	%{_tmppath}/%{name}-%{version}-build
AutoReqProv:	on
Requires(pre):	pacemaker
Requires:	python >= 2.4

%if 0%{?suse_version}
# Suse splits this off into a separate package
Requires:       python-curses python-xml
BuildRequires:  python-curses python-xml
%endif

# Required for core functionality
BuildRequires:  automake autoconf pkgconfig python
BuildRequires:	libpacemaker-devel libglue-devel
BuildRequires:	asciidoc

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

%files
###########################################################
%defattr(-,root,root)

%{_datadir}/crmsh

%{_sbindir}/crm
%{py_sitedir}/crm

%doc %{_mandir}/man8/crm.8*
%doc COPYING
%doc AUTHORS
%doc ChangeLog
%doc README

%dir %attr (770, %{uname}, %{gname}) %{_var}/cache/crm

%changelog
