dnl
dnl autoconf for CRM shell
dnl
dnl Copyright (C) 2008 Andrew Beekhof
dnl
dnl License: GNU General Public License (GPL)

dnl ===============================================
dnl Bootstrap 
dnl ===============================================
AC_PREREQ([2.69])

dnl Suggested structure:
dnl     information on the package
dnl     checks for programs
dnl     checks for libraries
dnl     checks for header files
dnl     checks for types
dnl     checks for structures
dnl     checks for compiler characteristics
dnl     checks for library functions
dnl     checks for system services

AC_INIT([crmsh],[2.2.0-rc2],[linux-ha@lists.linux-ha.org])

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

AC_ARG_WITH(
  daemon-user,
    [  --with-daemon-user=USER_NAME
                          User to run privileged non-root things as. [default=hacluster]  ],
    [ CRM_DAEMON_USER="$withval" ],
    [ CRM_DAEMON_USER="hacluster" ],
  )

AM_INIT_AUTOMAKE([1.11 no-define silent-rules])
AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE_NAME")
AC_DEFINE_UNQUOTED(VERSION, "$PACKAGE_VERSION")

dnl automake >= 1.11 offers --enable-silent-rules for suppressing the output from
dnl normal compilation.  When a failure occurs, it will then display the full 
dnl command line
dnl Wrap in m4_ifdef to avoid breaking on older platforms
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES])

dnl ===============================================
dnl General Processing
dnl ===============================================

INIT_EXT=""
echo Our Host OS: $host_os/$host


AC_MSG_NOTICE(Sanitizing prefix: ${prefix})
case $prefix in
  NONE)	prefix=/usr;;
esac

AC_MSG_NOTICE(Sanitizing exec_prefix: ${exec_prefix})
case $exec_prefix in
  dnl For consistency with Heartbeat, map NONE->$prefix
  NONE)	  exec_prefix=$prefix;;
  prefix) exec_prefix=$prefix;;
esac

AC_MSG_NOTICE(Sanitizing libdir: ${libdir})
case $libdir in
  dnl For consistency with Heartbeat, map NONE->$prefix
  *prefix*|NONE)
    AC_MSG_CHECKING(which lib directory to use)
    for aDir in lib64 lib
    do
      trydir="${exec_prefix}/${aDir}"
      if
        test -d ${trydir}
      then
        libdir=${trydir}
        break
      fi
    done
    AC_MSG_RESULT($libdir);
    ;;
esac

dnl Expand autoconf variables so that we dont end up with '${prefix}' 
dnl in #defines and python scripts
dnl NOTE: Autoconf deliberately leaves them unexpanded to allow
dnl    make exec_prefix=/foo install
dnl No longer being able to do this seems like no great loss to me...

eval prefix="`eval echo ${prefix}`"
eval exec_prefix="`eval echo ${exec_prefix}`"
eval bindir="`eval echo ${bindir}`"
eval sbindir="`eval echo ${sbindir}`"
eval libexecdir="`eval echo ${libexecdir}`"
eval datadir="`eval echo ${datadir}`"
eval sysconfdir="`eval echo ${sysconfdir}`"
eval sharedstatedir="`eval echo ${sharedstatedir}`"
eval localstatedir="`eval echo ${localstatedir}`"
eval libdir="`eval echo ${libdir}`"
eval infodir="`eval echo ${infodir}`"
eval mandir="`eval echo ${mandir}`"

dnl Home-grown variables
eval docdir="`eval echo ${docdir}`"
if test x"${docdir}" = x""; then
   docdir=${datadir}/doc/${PACKAGE}-${VERSION}
   #docdir=${datadir}/doc/packages/${PACKAGE}
fi
AC_SUBST(docdir)

CFLAGS="$CFLAGS -I${prefix}/include/heartbeat -I${prefix}/include/pacemaker"

for j in prefix exec_prefix bindir sbindir libexecdir datadir sysconfdir \
    sharedstatedir localstatedir libdir infodir \
    mandir docdir
do 
  dirname=`eval echo '${'${j}'}'`
  if
    test ! -d "$dirname"
  then
    AC_MSG_WARN([$j directory ($dirname) does not exist!])
  fi
done

dnl Variables needed for substitution

AC_SUBST(OCF_ROOT_DIR)
AC_SUBST(CRM_DAEMON_USER)

AC_PATH_PROGS(PKGCONFIG, pkg-config)
if test x"${PKGCONFIG}" = x""; then
   AC_MSG_ERROR(You need pkgconfig installed in order to build ${PACKAGE})
fi

CRM_CACHE_DIR=${localstatedir}/cache/crm
AC_DEFINE_UNQUOTED(CRM_CACHE_DIR,"$CRM_CACHE_DIR", Where crm shell keeps the cache)
AC_SUBST(CRM_CACHE_DIR)

AC_PATH_PROGS(HG, hg false)
AC_PATH_PROGS(GIT, git false)
AC_MSG_CHECKING(build version)
BUILD_VERSION=unknown
if test -f $srcdir/.hg_archival.txt; then
   BUILD_VERSION=`cat $srcdir/.hg_archival.txt | awk '/node:/ { print $2 }'`
elif test -x $HG -a -d .hg; then
   BUILD_VERSION=`$HG id -i`
   if test $? != 0; then
       BUILD_VERSION=unknown
   fi
elif test -x $GIT -a -d .git; then
   BUILD_VERSION=`$GIT describe`
   if test $? != 0; then
       BUILD_VERSION=unknown
   fi
fi

AC_DEFINE_UNQUOTED(BUILD_VERSION, "$BUILD_VERSION", Build version)
AC_MSG_RESULT($BUILD_VERSION)
AC_SUBST(BUILD_VERSION)

dnl ===============================================
dnl Program Paths
dnl ===============================================

PATH="$PATH:/sbin:/usr/sbin:/usr/local/sbin:/usr/local/bin"
export PATH

dnl Replacing AC_PROG_LIBTOOL with AC_CHECK_PROG because LIBTOOL
dnl was NOT being expanded all the time thus causing things to fail.
AM_PATH_PYTHON
AC_PATH_PROGS(ASCIIDOC, asciidoc)
AC_PATH_PROGS(SSH, ssh, /usr/bin/ssh)
AC_PATH_PROGS(SCP, scp, /usr/bin/scp)
AC_PATH_PROGS(HG, hg, /bin/false)
AC_PATH_PROGS(TAR, tar)
AC_PATH_PROGS(MD5, md5)
AC_PATH_PROGS(TEST, test)

AM_CONDITIONAL(BUILD_ASCIIDOC, test x"${ASCIIDOC}" != x"")
if test x"${ASCIIDOC}" != x""; then
   PKG_FEATURES="$PKG_FEATURES ascii-docs"
fi

dnl The Makefiles and shell scripts we output
AC_CONFIG_FILES(Makefile \
hb_report/hb_report      \
crm.conf                 \
version                  \
)

dnl Now process the entire list of files added by previous 
dnl  calls to AC_CONFIG_FILES()
AC_OUTPUT

dnl *****************
dnl Configure summary
dnl *****************

AC_MSG_RESULT([])
AC_MSG_RESULT([$PACKAGE configuration:])
AC_MSG_RESULT([  Version                  = ${VERSION} (Build: $BUILD_VERSION)])
AC_MSG_RESULT([  Features                 =${PKG_FEATURES}])
AC_MSG_RESULT([])
AC_MSG_RESULT([  Prefix                   = ${prefix}])
AC_MSG_RESULT([  Executables              = ${sbindir}])
AC_MSG_RESULT([  Man pages                = ${mandir}])
AC_MSG_RESULT([  Libraries                = ${libdir}])
AC_MSG_RESULT([  Header files             = ${includedir}])
AC_MSG_RESULT([  Arch-independent files   = ${datadir}])
AC_MSG_RESULT([  State information        = ${localstatedir}])
AC_MSG_RESULT([  System configuration     = ${sysconfdir}])
AC_MSG_RESULT([  Cache dir                = ${CRM_CACHE_DIR}]) 
AC_MSG_RESULT([  OCF root dir             = ${OCF_ROOT_DIR}]) 
AC_MSG_RESULT([  CRM daemon user          = ${CRM_DAEMON_USER}]) 
