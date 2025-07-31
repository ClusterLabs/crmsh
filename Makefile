DESTDIR ?= /
datadir ?= /usr/share
confdir ?= /etc
localstatedir ?= /var
tmpfilesdir ?= /lib/tmpfiles.d
mandir ?= /$(datadir)/man

.PHONY: all install uninstall

all: non-python

install: install-non-python

uninstall: uninstall-non-python

.PHONY: non-python manpages html-docs install-non-python uninstall-non-python

non-python: manpages html-docs

manpages: doc/crm.8 doc/crmsh_crm_report.8

html-docs: doc/crm.8.html doc/crmsh_crm_report.8.html doc/profiles.html

%.8: %.8.adoc
	a2x -f manpage $<

%.html: %.adoc
	asciidoc --unsafe --backend=xhtml11 $<

.PHONY: install-non-python uninstall-non-python

install-non-python:
	# additional directories
	install -d -m0770 $(DESTDIR)$(localstatedir)/cache/crm
	install -d -m0770 $(DESTDIR)$(localstatedir)/log/crmsh
	install -d -m0755 $(DESTDIR)${tmpfilesdir}
	# install configuration
	install -Dm0644 -t $(DESTDIR)$(confdir)/crm etc/{crm.conf,profiles.yml}
	install -m0644 crmsh.tmpfiles.d.conf $(DESTDIR)$(tmpfilesdir)/crmsh.conf
	# install manpages
	install -Dpm0644 -t $(DESTDIR)$(mandir)/man8 doc/*.8
	install -Dpm0644 -t $(DESTDIR)$(datadir)/crmsh/ doc/crm.8.adoc
	# install data
	for d in $$(cat data-manifest); do \
		if [ -x "$$d" ] ; then mode="0755" ; else mode="0644" ; fi; \
		install -D -m "$${mode}" "$$d" $(DESTDIR)$(datadir)/crmsh/"$$d"; \
	done
	mv $(DESTDIR)$(datadir)/crmsh/test $(DESTDIR)$(datadir)/crmsh/tests
	install -p test/testcases/xmlonly.sh $(DESTDIR)$(datadir)/crmsh/tests/testcases/configbasic-xml.filter
	install -Dm0644 contrib/bash_completion.sh $(DESTDIR)$(datadir)/bash-completion/completions/crm
	if [ -n "$(fwdefdir)" ]; then \
		install -Dm0644 high-availability.xml $(DESTDIR)$(fwdefdir)/high-availability.xml; \
	fi

uninstall-non-python:
	$(RM) -r $(DESTDIR)$(confdir)/crm
	$(RM) -r $(DESTDIR)$(localstatedir)/cache/crm
	$(RM) -r $(DESTDIR)$(localstatedir)/log/crm
	$(RM) -r $(DESTDIR)$(datadir)/crmsh
	$(RM) -r $(DESTDIR)$(datadir)/bash-completion/completions/crm
	$(RM) $(DESTDIR)$(fwdefdir)/high-availability.xml
	$(RM) $(DESTDIR)$(tmpfilesdir)/crmsh.conf
