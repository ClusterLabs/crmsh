#!/bin/sh
#
#	License: GNU General Public License (GPL)
#	Copyright 2001 horms <horms@vergenet.net>
#		(heavily mangled by alanr)
#
#	bootstrap: set up the project and get it ready to make
#
#	Basically, we run autoconf and automake in the
#	right way to get things set up for this environment.
#
#	We also look and see if those tools are installed, and
#	tell you where to get them if they're not.
#
#	Our goal is to not require dragging along anything
#	more than we need.  If this doesn't work on your system,
#	(i.e., your /bin/sh is broken) send us a patch.
#
#	This code loosely based on the corresponding named script in
#	enlightenment, and also on the sort-of-standard autoconf
#	bootstrap script.

# Run this to generate all the initial makefiles, etc.

testProgram()
{
  cmd=$1

  if [ -z "$cmd" ]; then
    return 1;
  fi

  arch=`uname -s`

  # Make sure the which is in an if-block... on some platforms it throws exceptions
  #
  # The ERR trap is not executed if the failed command is part
  #   of an until or while loop, part of an if statement, part of a &&
  #   or  ||  list.
  if
     which $cmd  </dev/null >/dev/null 2>&1
  then
      :
  else
      return 1
  fi

  # The GNU standard is --version
  if
      $cmd --version </dev/null >/dev/null 2>&1
  then
      return 0
  fi

  # Maybe it suppports -V instead
  if
      $cmd -V </dev/null >/dev/null 2>&1
  then
      return 0
  fi

  # Nope, the program seems broken
  return 1
}

gnu="ftp://ftp.gnu.org/pub/gnu"

for command in autoconf213 autoconf253 autoconf259 autoconf
do
  if
      testProgram $command == 1
  then
    autoconf=$command
    autoheader=`echo  "$autoconf" | sed -e 's/autoconf/autoheader/'`
    autom4te=`echo  "$autoconf" | sed -e 's/autoconf/autmo4te/'`
    autoreconf=`echo  "$autoconf" | sed -e 's/autoconf/autoreconf/'`
    autoscan=`echo  "$autoconf" | sed -e 's/autoconf/autoscan/'`
    autoupdate=`echo  "$autoconf" | sed -e 's/autoconf/autoupdate/'`
    ifnames=`echo  "$autoconf" | sed -e 's/autoconf/ifnames/'`
  fi
done

if [ -z $autoconf ]; then
    echo You must have autoconf installed to compile the crmsh package.
    echo Download the appropriate package for your system,
    echo or get the source tarball at: $gnu/autoconf/
    exit 1
fi

# Create local copies so that the incremental updates will work.
rm -f ./autoconf ./autoheader
ln -s `which $autoconf` ./autoconf
ln -s `which $autoheader` ./autoheader

printf "$autoconf:\t"
$autoconf --version | head -n 1

arch=`uname -s`
# Disable the errors on FreeBSD until a fix can be found.
if [ ! "$arch" = "FreeBSD" ]; then
set -e
#
#	All errors are fatal from here on out...
#	The shell will complain and exit on any "uncaught" error code.
#
#
#	And the trap will ensure sure some kind of error message comes out.
#
trap 'echo ""; echo "$0 exiting due to error (sorry!)." >&2' 0
fi

echo $aclocal $ACLOCAL_FLAGS
$aclocal $ACLOCAL_FLAGS

echo $autoconf
$autoconf

echo Now run ./configure
trap '' 0
