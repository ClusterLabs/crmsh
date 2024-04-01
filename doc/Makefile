.PHONY: all clean subdirs

all: subdirs generated-sources/crm.8.adoc

generated-sources:
	mkdir -p $@

generated-sources/Makefile: crm.8.adoc generated-sources
	adocxt gen-makefile < $< > $@

subdirs: generated-sources/Makefile
	$(MAKE) -C generated-sources all

generated-sources/crm.8.adoc: crm.8.adoc generated-sources
	adocxt gen-include < $< > $@

clean:
	$(RM) -r generated-sources
