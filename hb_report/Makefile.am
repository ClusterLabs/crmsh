#
# heartbeat: Linux-HA heartbeat code
#
# Copyright (C) 2001 Michael Moerz
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
MAINTAINERCLEANFILES    = Makefile.in

hanoarchdir		= $(datadir)/heartbeat

hanoarch_SCRIPTS	= utillib.sh ha_cf_support.sh \
				openais_conf_support.sh combine-logs.pl
sbin_SCRIPTS		= hb_report
man_MANS		= hb_report.8

STYLESHEET_PREFIX 	?= http://docbook.sourceforge.net/release/xsl/current
MANPAGES_STYLESHEET 	?= $(STYLESHEET_PREFIX)/manpages/docbook.xsl
HTML_STYLESHEET 	?= $(STYLESHEET_PREFIX)/xhtml/docbook.xsl
FO_STYLESHEET 		?= $(STYLESHEET_PREFIX)/fo/docbook.xsl

XSLTPROC_OPTIONS 	?= --xinclude
XSLTPROC_MANPAGES_OPTIONS ?= $(XSLTPROC_OPTIONS)
XSLTPROC_HTML_OPTIONS 	?= $(XSLTPROC_OPTIONS)
XSLTPROC_FO_OPTIONS 	?= $(XSLTPROC_OPTIONS)

%.5 %.8 %.1: %.xml
	$(XSLTPROC) \
	$(XSLTPROC_MANPAGES_OPTIONS) \
	$(MANPAGES_STYLESHEET) $<
