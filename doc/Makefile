.PHONY: all clean subdirs

all: subdirs crm.8.html

generated-sources:
	mkdir -p $@

generated-sources/Makefile: crm.8.adoc generated-sources
	adocxt gen-makefile < $< > $@

subdirs: generated-sources/Makefile
	$(MAKE) -C generated-sources all

generated-sources/crm.8.adoc: crm.8.adoc generated-sources
	adocxt gen-include < $< > $@

generated-sources/profiles.adoc: profiles.adoc generated-sources
	cp $< $@

crm.8.html: generated-sources/crm.8.adoc generated-sources/profiles.adoc subdirs
	asciidoctor $<

clean:
	$(RM) -r generated-sources crm.8.html
