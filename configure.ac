dnl
dnl autoconf for CRM shell
dnl
dnl Copyright (C) 2008 Andrew Beekhof
dnl
dnl License: GNU General Public License (GPL)

dnl ===============================================
dnl Bootstrap 
dnl ===============================================
AC_PREREQ(2.53)

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

AC_INIT(crmsh, 1.0.0, pacemaker@oss.clusterlabs.org)

AC_ARG_WITH(version,
    [  --with-version=version   Override package version (if you're a packager needing to pretend) ],
    [ PACKAGE_VERSION="$withval" ])

AC_ARG_WITH(pkg-name,
    [  --with-pkg-name=name     Override package name (if you're a packager needing to pretend) ],
    [ PACKAGE_NAME="$withval" ])

AM_INIT_AUTOMAKE($PACKAGE_NAME, $PACKAGE_VERSION)
AC_DEFINE_UNQUOTED(PACEMAKER_VERSION, "$PACKAGE_VERSION", Current crmsh version)

PACKAGE_SERIES=`echo $PACKAGE_VERSION | awk -F. '{ print $1"."$2 }'`
AC_SUBST(PACKAGE_SERIES)

dnl automake >= 1.11 offers --enable-silent-rules for suppressing the output from
dnl normal compilation.  When a failure occurs, it will then display the full 
dnl command line
dnl Wrap in m4_ifdef to avoid breaking on older platforms
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES])

dnl ===============================================
dnl Helpers 
dnl ===============================================
extract_header_define() {
	  AC_MSG_CHECKING(for $2 in $1)
	  Cfile=$srcdir/extract_define.$2.${$}
	  printf "#include <stdio.h>\n" > ${Cfile}.c
	  printf "#include <%s>\n" $1 >> ${Cfile}.c
	  printf "int main(int argc, char **argv) { printf(\"%%s\", %s); return 0; }\n" $2 >> ${Cfile}.c
	  $CC $CFLAGS ${Cfile}.c -o ${Cfile}
	  value=`${Cfile}`
	  AC_MSG_RESULT($value)
	  printf $value
	  rm -f ${Cfile}.c ${Cfile}
	}

dnl ===============================================
dnl Configure Options
dnl ===============================================

dnl Some systems, like Solaris require a custom package name
AC_ARG_WITH(pkgname,
    [  --with-pkgname=name     name for pkg (typically for Solaris) ],
    [ PKGNAME="$withval" ],
    [ PKGNAME="LXHAhb" ],
  )
AC_SUBST(PKGNAME)

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

AC_CHECK_HEADERS(crm_config.h)
AC_CHECK_HEADERS(glue_config.h)
GLUE_HEADER=none
if test "$ac_cv_header_glue_config_h" = "yes";  then
   GLUE_HEADER=glue_config.h

elif test "$ac_cv_header_hb_config_h" = "yes"; then
   GLUE_HEADER=hb_config.h

else
   AC_MSG_FAILURE(Core development headers were not found)
fi

dnl Variables needed for substitution
CRM_DAEMON_USER=`extract_header_define crm_config.h CRM_DAEMON_USER`
AC_DEFINE_UNQUOTED(CRM_DAEMON_USER,"$CRM_DAEMON_USER", User to run Pacemaker daemons as)
AC_SUBST(CRM_DAEMON_USER)

CRM_DAEMON_GROUP=`extract_header_define crm_config.h CRM_DAEMON_GROUP`
AC_DEFINE_UNQUOTED(CRM_DAEMON_GROUP,"$CRM_DAEMON_GROUP", Group to run Pacemaker daemons as)
AC_SUBST(CRM_DAEMON_GROUP)

CRM_STATE_DIR=`extract_header_define crm_config.h CRM_STATE_DIR`
AC_DEFINE_UNQUOTED(CRM_STATE_DIR,"$CRM_STATE_DIR", Where to keep state files and sockets)
AC_SUBST(CRM_STATE_DIR)

PE_STATE_DIR=`extract_header_define crm_config.h PE_STATE_DIR`
AC_DEFINE_UNQUOTED(PE_STATE_DIR,"$PE_STATE_DIR", Where to keep PEngine outputs)
AC_SUBST(PE_STATE_DIR)

dnl Eventually move out of the heartbeat dir tree and create compatability code
CRM_CONFIG_DIR=`extract_header_define crm_config.h CRM_CONFIG_DIR`
AC_DEFINE_UNQUOTED(CRM_CONFIG_DIR,"$CRM_CONFIG_DIR", Where to keep CIB configuration files)
AC_SUBST(CRM_CONFIG_DIR)

CRM_DTD_DIRECTORY=`extract_header_define crm_config.h CRM_DTD_DIRECTORY`
AC_DEFINE_UNQUOTED(CRM_DTD_DIRECTORY,"$CRM_DTD_DIRECTORY", Where to keep CIB configuration files)
AC_SUBST(CRM_DTD_DIRECTORY)

dnl Eventually move out of the heartbeat dir tree and create compatability code
dnl CRM_DAEMON_DIR=$libdir/pacemaker
GLUE_DAEMON_DIR=`extract_header_define $GLUE_HEADER GLUE_DAEMON_DIR`
AC_DEFINE_UNQUOTED(GLUE_DAEMON_DIR,"$GLUE_DAEMON_DIR", Location for Pacemaker daemons)
AC_SUBST(GLUE_DAEMON_DIR)

CRM_CACHE_DIR=${localstatedir}/cache/crm
AC_DEFINE_UNQUOTED(CRM_CACHE_DIR,"$CRM_CACHE_DIR", Where crm shell keeps the cache)
AC_SUBST(CRM_CACHE_DIR)

dnl Needed so that the Corosync plugin can clear out the directory as Heartbeat does
HA_STATE_DIR=`extract_header_define $GLUE_HEADER HA_VARRUNDIR`
AC_DEFINE_UNQUOTED(HA_STATE_DIR,"$HA_STATE_DIR", Where Heartbeat keeps state files and sockets)
AC_SUBST(HA_STATE_DIR)

dnl Needed for the location of hostcache in CTS.py
HA_VARLIBHBDIR=`extract_header_define $GLUE_HEADER HA_VARLIBHBDIR`
AC_SUBST(HA_VARLIBHBDIR)

AC_DEFINE_UNQUOTED(UUID_FILE,"$localstatedir/lib/heartbeat/hb_uuid", Location of Heartbeat's UUID file)

OCF_ROOT_DIR=`extract_header_define $GLUE_HEADER OCF_ROOT_DIR`
if test "X$OCF_ROOT_DIR" = X; then
  AC_MSG_ERROR(Could not locate OCF directory)
fi
AC_SUBST(OCF_ROOT_DIR)

dnl Extract this value from glue_config.h once we no longer support anything else
STONITH_PLUGIN_DIR="$libdir/stonith/plugins/stonith/"
AC_DEFINE_UNQUOTED(STONITH_PLUGIN_DIR,"$STONITH_PLUGIN_DIR", Location for Stonith plugins)
AC_SUBST(STONITH_PLUGIN_DIR)

AC_PATH_PROGS(HG, hg false)
AC_MSG_CHECKING(build version)
BUILD_VERSION=unknown
if test -f $srcdir/.hg_archival.txt; then
   BUILD_VERSION=`cat $srcdir/.hg_archival.txt | awk '/node:/ { print $2 }'`
elif test -x $HG -a -d .hg; then
   BUILD_VERSION=`$HG id -i`
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
AC_PATH_PROGS(PKGCONFIG, pkg-config)

AM_CONDITIONAL(BUILD_ASCIIDOC, test x"${ASCIIDOC}" != x"")
if test x"${ASCIIDOC}" != x""; then
   PKG_FEATURES="$PKG_FEATURES ascii-docs"
fi

dnl The Makefiles and shell scripts we output
AC_CONFIG_FILES(Makefile				        \
doc/Makefile							\
templates/Makefile				\
test/Makefile				\
	test/testcases/Makefile			\
modules/Makefile					\
	modules/ui.py					\
	modules/vars.py					\
	modules/help.py					\
	)

dnl Now process the entire list of files added by previous 
dnl  calls to AC_CONFIG_FILES()
AC_OUTPUT()

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
