dnl
dnl autoconf for crmsh
dnl
dnl Copyright (C) 2015 Kristoffer Gronlund
dnl Copyright (C) 2008 Andrew Beekhof
dnl
dnl License: GNU General Public License (GPL)

AC_PREREQ([2.53])

AC_INIT([crmsh],[5.0.0],[users@clusterlabs.org])

AC_ARG_WITH(version,
    [  --with-version=version   Override package version (if you're a packager needing to pretend) ],
    [ PACKAGE_VERSION="$withval" ])

AC_ARG_WITH(pkg-name,
    [  --with-pkg-name=name     Override package name (if you're a packager needing to pretend) ],
    [ PACKAGE_NAME="$withval" ])

OCF_ROOT_DIR="/usr/lib/ocf"
AC_ARG_WITH(ocf-root,
    [  --with-ocf-root=DIR      directory for OCF scripts [${OCF_ROOT_DIR}]],
    [ if test x"$withval" = xprefix; then OCF_ROOT_DIR=${prefix}; else
	 OCF_ROOT_DIR="$withval"; fi ])

AC_ARG_WITH(daemon-user,
    [  --with-daemon-user=USER_NAME
                                User to run privileged non-root things as. [default=hacluster]  ],
    [ CRM_DAEMON_USER="$withval" ],
    [ CRM_DAEMON_USER="hacluster" ])

AM_INIT_AUTOMAKE([no-define foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES])
AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE_NAME")
AC_DEFINE_UNQUOTED(VERSION, "$PACKAGE_VERSION")

dnl automake >= 1.11 offers --enable-silent-rules for suppressing the output from
dnl normal compilation.  When a failure occurs, it will then display the full 
dnl command line
dnl Wrap in m4_ifdef to avoid breaking on older platforms
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES])

AC_SUBST(OCF_ROOT_DIR)
AC_SUBST(CRM_DAEMON_USER)

CRM_CACHE_DIR=${localstatedir}/cache/crm
AC_DEFINE_UNQUOTED(CRM_CACHE_DIR,"$CRM_CACHE_DIR", Where crm shell keeps the cache)
AC_SUBST(CRM_CACHE_DIR)

AM_PATH_PYTHON([3])
AC_PATH_PROGS(ASCIIDOC, asciidoc)

AM_CONDITIONAL(BUILD_ASCIIDOC, test x"${ASCIIDOC}" != x"")

AC_CONFIG_FILES(Makefile \
etc/crm.conf             \
version                  \
crmsh.spec               \
)

AC_OUTPUT
