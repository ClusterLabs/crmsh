ASCIIDOC := asciidoc
CRMCONF := crm.conf
SRC := faq.adoc documentation.adoc development.adoc installation.adoc \
	configuration.adoc about.adoc rsctest-guide.adoc \
	history-guide.adoc start-guide.adoc man-1.2.adoc scripts.adoc man-2.0.adoc
TGT := $(patsubst %.adoc,gen/%/index.html,$(SRC))
CSS := css/crm.css css/font-awesome.min.css
CSS := $(patsubst %,gen/%,$(CSS))
IMG := img/loader.gif img/laptop.png img/servers.gif
IMG  := $(patsubst %,gen/%,$(IMG))
FONTS := fonts/FontAwesome.otf fonts/fontawesome-webfont.eot \
	fonts/fontawesome-webfont.svg fonts/fontawesome-webfont.ttf \
	fonts/fontawesome-webfont.woff
FONTS := $(patsubst %,gen/%,$(FONTS))
WATCHDIR := watchdir
XDGOPEN := xdg-open
NEWS := $(wildcard news/*.adoc)
NEWSDOC := $(patsubst %.adoc,gen/%/index.html,$(NEWS))

.PHONY: all clean deploy open

all: site

gen/index.html: index.adoc $(CRMCONF)
	@mkdir -p $(dir $@)
	@$(ASCIIDOC) --unsafe -b html5 -f $(CRMCONF) -o $@ $<
	@python ./postprocess.py -o $@ $<

gen/%/index.html: %.adoc $(CRMCONF)
	@mkdir -p $(dir $@)
	@$(ASCIIDOC) --unsafe -b html5 -f $(CRMCONF) -o $@ $<
	@python ./postprocess.py -o $@ $<

gen/man/index.html: ../crm.8.adoc $(CRMCONF)
	@mkdir -p $(dir $@)
	@$(ASCIIDOC) --unsafe -b html5 -f $(CRMCONF) -o $@ $<
	@python ./postprocess.py -o $@ $<

gen/404.html: 404.adoc $(CRMCONF)
	@mkdir -p $(dir $@)
	@$(ASCIIDOC) --unsafe -b html5 -f $(CRMCONF) -o $@ $<
	@python ./postprocess.py -o $@ $<

news.adoc: $(NEWS) $(CRMCONF)
	@echo "news:" $(NEWS)
	python ./make-news.py $@ $(NEWS)

gen/news/index.html: news.adoc
	@mkdir -p $(dir $@)
	$(ASCIIDOC) --unsafe -b html5 -f $(CRMCONF) -o $@ $<
	@python ./postprocess.py -o $@ $<

gen/css/%.css: css/%.css
	@mkdir -p gen/css
	@cp -r $< $@
	@echo "+ $@"

gen/js/%.js: js/%.js
	@mkdir -p gen/js
	@cp -r $< $@
	@echo "+ $@"

gen/img/%: img/%
	@mkdir -p gen/img
	@cp -r $< $@
	@echo "+ $@"

gen/fonts/%: fonts/%
	@mkdir -p gen/fonts
	@cp -r $< $@
	@echo "+ $@"

gen/atom.xml: $(NEWSDOC)
	@echo "atom:" $(NEWSDOC)
	python ./make-news.py gen/atom.xml $(NEWS)

site: gen/atom.xml gen/index.html gen/404.html gen/news/index.html gen/man/index.html $(TGT) $(CSS) $(IMG) $(FONTS) $(NEWSDOC)

deploy: site
	@echo "TODO: CVS upload"

open: site
	@$(XDGOPEN) gen/index.html

watch:
	@$(WATCHDIR) --verbose --cmd "make" . css img fonts

clean:
	-@$(RM) -rf gen/* news.adoc
