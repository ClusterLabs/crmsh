#!/bin/sh
# Copyright (C) 2015 Kristoffer Gronlund
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
# Generate the data-manifest file which lists
# all files which should be installed to /usr/share/crmsh
target=data-manifest
[ -f $target ] && (printf "Removing $target..."; rm $target)
printf "Generating $target..."
cat <<EOF | sort -df > $target
version
$(git ls-files scripts templates utils test)
EOF
[ ! -f $target ] && printf "FAILED\n"
[ -f $target ] && printf "OK\n"
