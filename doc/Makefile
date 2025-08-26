export PATH := $(PATH):$(CURDIR)/toolchain/bin

.PHONY: all clean subdirs website website-clean

all: crm.8

generated-sources:
	mkdir -p $@

generated-sources/Makefile: crm.8.adoc generated-sources
	adocxt gen-makefile < $< > $@

subdirs: generated-sources/Makefile
	$(MAKE) -C generated-sources all

generated-sources/crm.8.adoc: crm.8.adoc subdirs
	adocxt gen-include < $< > $@

generated-sources/crm.8.aio.adoc: generated-sources/crm.8.adoc generated-sources/profiles.adoc
	adocaio $< > $@

generated-sources/profiles.adoc: profiles.adoc generated-sources
	cp $< $@

crm.8.html: generated-sources/crm.8.aio.adoc
	asciidoc $<

crm.8: generated-sources/crm.8.aio.adoc
	a2x -f manpage $<

website: generated-sources/crm.8.adoc
	$(MAKE) -C website-v1 all

website-clean:
	$(MAKE) -C website-v1 clean

clean:	website-clean
	$(RM) -r generated-sources crm.8.html crm.8
