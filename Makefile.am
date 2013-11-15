#
# shell: Pacemaker code
#
# Copyright (C) 2008 Andrew Beekhof
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
MAINTAINERCLEANFILES    = Makefile.in aclocal.m4 configure

sbin_SCRIPTS		= crm

EXTRA_DIST		= crm

SUBDIRS = doc modules templates test contrib hb_report

doc_DATA = AUTHORS COPYING README ChangeLog version

# in .spec, set --sysconfdir=/etc
crmconfdir=$(sysconfdir)/$(PACKAGE)
crmconf_DATA = crm.conf

install-exec-local:
	$(INSTALL) -d -m 770 $(DESTDIR)/$(CRM_CACHE_DIR)
	-chown $(CRM_DAEMON_USER):$(CRM_DAEMON_GROUP) $(DESTDIR)/$(CRM_CACHE_DIR)

clean-generic:
	rm -f $(TARFILE) *.tar.bz2 *.sed

dist-clean-local:
	rm -f autoconf automake autoheader

.PHONY: rpm pkg handy handy-copy
