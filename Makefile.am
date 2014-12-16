#
# crmsh
#
# Copyright (C) 2014 Kristoffer Gronlund
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

doc_DATA = AUTHORS COPYING README ChangeLog $(generated_docs)

crmversiondir=$(datadir)/@PACKAGE@
crmversion_DATA = version

# in .spec, set --sysconfdir=/etc
crmconfdir=$(sysconfdir)/crm
crmconf_DATA = crm.conf

templatedir 		= $(datadir)/@PACKAGE@/templates
template_DATA	= templates/apache templates/virtual-ip templates/filesystem templates/ocfs2 templates/clvm templates/gfs2-base templates/gfs2 templates/sbd

contribdir      = $(docdir)/contrib
contrib_DATA	= contrib/pacemaker-crm.vim  contrib/pcmk.vim  contrib/README.vimsyntax

utilsdir 	= $(datadir)/@PACKAGE@/utils
utils_DATA	= utils/crm_script.py utils/crm_init.py
utils_SCRIPTS	= utils/crm_clean.py utils/crm_rpmcheck.py utils/crm_pkg.py

# cluster scripts
healthdir 		= $(datadir)/@PACKAGE@/scripts/health
health_DATA	= scripts/health/main.yml
health_SCRIPTS	= scripts/health/collect.py scripts/health/report.py scripts/health/hahealth.py

uptimedir 		= $(datadir)/@PACKAGE@/scripts/check-uptime
uptime_DATA	= scripts/check-uptime/main.yml
uptime_SCRIPTS	= scripts/check-uptime/fetch.py scripts/check-uptime/report.py

scriptinitdir 		= $(datadir)/@PACKAGE@/scripts/init
scriptinit_DATA	= scripts/init/main.yml scripts/init/corosync.conf.template scripts/init/basic.cib.template
scriptinit_SCRIPTS	= scripts/init/collect.py scripts/init/verify.py scripts/init/configure.py scripts/init/authkey.py scripts/init/init.py


scriptadddir 		= $(datadir)/@PACKAGE@/scripts/add
scriptadd_DATA	= scripts/add/main.yml
scriptadd_SCRIPTS	= scripts/add/add.py

scriptremovedir 		= $(datadir)/@PACKAGE@/scripts/remove
scriptremove_DATA	= scripts/remove/main.yml
scriptremove_SCRIPTS	= scripts/remove/remove.py


testdir		= 	$(datadir)/$(PACKAGE)/tests
test_SCRIPTS	=	test/regression.sh test/evaltest.sh test/cib-tests.sh
test_DATA	=	test/README.regression test/defaults test/descriptions \
			test/crm-interface test/history-test.tar.bz2

testcasesdir		= 	$(datadir)/$(PACKAGE)/tests/testcases
testcases_SCRIPTS	=	test/testcases/ra.filter test/testcases/common.filter test/testcases/xmlonly.sh test/testcases/history.pre test/testcases/history.post
testcases_DATA		=	test/testcases/basicset test/testcases/common.excl \
	test/testcases/confbasic test/testcases/confbasic-xml test/testcases/delete test/testcases/file \
	test/testcases/node test/testcases/ra test/testcases/resource test/testcases/shadow test/testcases/acl test/testcases/options \
	test/testcases/edit test/testcases/edit.excl test/testcases/rset test/testcases/rset-xml test/testcases/history \
	test/testcases/confbasic-xml.exp test/testcases/confbasic.exp test/testcases/delete.exp test/testcases/file.exp \
	test/testcases/node.exp test/testcases/ra.exp test/testcases/resource.exp test/testcases/shadow.exp test/testcases/acl.exp test/testcases/options.exp \
	test/testcases/edit.exp test/testcases/rset.exp test/testcases/rset-xml.exp test/testcases/history.exp test/testcases/history.excl \
	test/testcases/newfeatures test/testcases/newfeatures.exp test/testcases/acl.excl test/testcases/commit test/testcases/commit.exp

test/testcases/confbasic-xml.filter:
	ln test/testcases/xmlonly.sh $@


cibtestsdir		= 	$(datadir)/$(PACKAGE)/tests/cibtests
cibtests_DATA	= test/cibtests/shadow.base \
	test/cibtests/001.exp.xml test/cibtests/001.input \
	test/cibtests/002.exp.xml test/cibtests/002.input \
	test/cibtests/003.exp.xml test/cibtests/003.input \
	test/cibtests/004.exp.xml test/cibtests/004.input

hanoarchdir           = $(datadir)/@PACKAGE@
hanoarch_DATA         = hb_report/utillib.sh hb_report/ha_cf_support.sh hb_report/openais_conf_support.sh
hanoarch_SCRIPTS          = hb_report/hb_report


EXTRA_DIST = crm $(template_DATA) $(contrib_DATA) $(utils_DATA) $(utils_SCRIPTS) $(health_DATA) $(health_SCRIPTS) $(test_DATA) $(testcases_SCRIPTS) $(testcases_DATA) $(cibtests_DATA) $(hanoarch_DATA) $(uptime_DATA) $(uptime_SCRIPTS) $(scriptinit_DATA) $(scriptinit_SCRIPTS) $(scriptadd_DATA) $(scriptadd_SCRIPTS) $(scriptremove_DATA) $(scriptremove_SCRIPTS)

shelllibdir	= $(pyexecdir)/crmsh
shelllib_PYTHON = modules/__init__.py \
			modules/cache.py \
			modules/cibconfig.py \
			modules/cibstatus.py \
			modules/cibverify.py \
			modules/clidisplay.py \
			modules/cliformat.py \
			modules/cmd_status.py \
			modules/command.py \
			modules/completers.py \
			modules/config.py \
			modules/corosync.py \
			modules/crm_gv.py \
			modules/crm_pssh.py \
			modules/help.py \
			modules/idmgmt.py \
			modules/log_patterns_118.py \
			modules/log_patterns.py \
			modules/main.py \
			modules/msg.py \
			modules/options.py \
			modules/ordereddict.py \
			modules/pacemaker.py \
			modules/parse.py \
			modules/ra.py \
			modules/report.py \
			modules/rsctest.py \
			modules/schema.py \
			modules/scripts.py \
			modules/template.py \
			modules/term.py \
			modules/tmpfiles.py \
			modules/ui_assist.py \
			modules/ui_cib.py \
			modules/ui_cibstatus.py \
			modules/ui_cluster.py \
			modules/ui_configure.py \
			modules/ui_context.py \
			modules/ui_corosync.py \
			modules/ui_history.py \
			modules/ui_maintenance.py \
			modules/ui_node.py \
			modules/ui_options.py \
			modules/ui_ra.py \
			modules/ui_report.py \
			modules/ui_resource.py \
			modules/ui_root.py \
			modules/ui_script.py \
			modules/ui_site.py \
			modules/ui_template.py \
			modules/ui_utils.py \
			modules/userdir.py \
			modules/utils.py \
			modules/constants.py \
			modules/xmlbuilder.py \
			modules/xmlutil.py


helpdir     = $(datadir)/$(PACKAGE)

asciiman	= doc/crm.8.adoc doc/crmsh_hb_report.8.adoc
help_DATA	= doc/crm.8.adoc

generated_docs	=
generated_mans	=

if BUILD_ASCIIDOC
generated_docs	+= $(ascii:%.adoc=%.html) $(asciiman:%.adoc=%.html)
generated_mans	+= $(asciiman:%.8.adoc=%.8)
$(generated_mans): $(asciiman)
man8_MANS	= $(generated_mans)
endif

%.html: %.adoc
	$(ASCIIDOC) --unsafe --backend=xhtml11 $<
%.8: %.8.adoc
	a2x -f manpage $<

install-exec-local:
	$(INSTALL) -d -m 770 $(DESTDIR)/$(CRM_CACHE_DIR)
	-chown $(CRM_DAEMON_USER):$(CRM_DAEMON_GROUP) $(DESTDIR)/$(CRM_CACHE_DIR)
	-rm -rf $(generated_docs) $(generated_mans)

clean-generic:
	rm -f $(TARFILE) *.tar.bz2 *.sed

dist-clean-local:
	rm -f autoconf automake autoheader

.PHONY: rpm pkg handy handy-copy
