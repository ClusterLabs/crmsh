ASCIIDOC := asciidoc
CRMCONF := crm.conf
SRC := faq.adoc documentation.adoc development.adoc installation.adoc \
	configuration.adoc about.adoc rsctest-guide.adoc download.adoc \
	history-guide.adoc start-guide.adoc man-1.2.adoc scripts.adoc man-2.0.adoc man-3.adoc man-4.3.adoc man-4.6.adoc
HISTORY_LISTINGS = include/history-guide/nfs-probe-err.typescript \
	include/history-guide/sample-cluster.conf.crm \
	include/history-guide/status-probe-fail.typescript \
	include/history-guide/resource-trace.typescript \
	include/history-guide/stonith-corosync-stopped.typescript \
	include/history-guide/basic-transition.typescript \
	include/history-guide/diff.typescript \
	include/history-guide/info.typescript \
	include/history-guide/resource.typescript \
	include/history-guide/transition-log.typescript
TGT := $(patsubst %.adoc,gen/%/index.html,$(SRC))
CSS := css/crm.css css/font-awesome.min.css
CSS := $(patsubst %,gen/%,$(CSS))
ICONS := \
	img/icons/caution.png \
	img/icons/example.png \
	img/icons/home.png \
	img/icons/important.png \
	img/icons/next.png \
	img/icons/note.png \
	img/icons/prev.png \
	img/icons/tip.png \
	img/icons/up.png \
	img/icons/warning.png \
	img/icons/callouts/10.png \
	img/icons/callouts/11.png \
	img/icons/callouts/12.png \
	img/icons/callouts/13.png \
	img/icons/callouts/14.png \
	img/icons/callouts/15.png \
	img/icons/callouts/1.png \
	img/icons/callouts/2.png \
	img/icons/callouts/3.png \
	img/icons/callouts/4.png \
	img/icons/callouts/5.png \
	img/icons/callouts/6.png \
	img/icons/callouts/7.png \
	img/icons/callouts/8.png \
	img/icons/callouts/9.png
IMG := $(ICONS) img/loader.gif img/laptop.png img/servers.gif \
	img/history-guide/sample-cluster.conf.png \
	img/history-guide/smallapache-start.png
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
	@$(ASCIIDOC) --unsafe -b html5 -a icons -a iconsdir=/img/icons -f $(CRMCONF) -o $@ $<
	@python ./postprocess.py -o $@ $<

gen/%/index.html: %.adoc $(CRMCONF)
	@mkdir -p $(dir $@)
	@$(ASCIIDOC) --unsafe -b html5 -a icons -a iconsdir=/img/icons -f $(CRMCONF) -o $@ $<
	@python ./postprocess.py -o $@ $<

gen/history-guide/index.html: $(HISTORY_LISTINGS)

gen/man/index.html: ../generated-sources/crm.8.adoc $(CRMCONF)
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

gen/img/icons/callouts/%: img/icons/callouts/%
	@mkdir -p gen/img/icons/callouts
	@cp -r $< $@
	@echo "+ $@"

gen/img/icons/%: img/icons/%
	@mkdir -p gen/img/icons
	@cp -r $< $@
	@echo "+ $@"

gen/img/history-guide/%: img/history-guide/%
	@mkdir -p gen/img/history-guide
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
	@which dos2unix >/dev/null && find gen -name "*.html" -type f -exec dos2unix {} \;

deploy: site
	@echo "TODO: CVS upload"

open: site
	@$(XDGOPEN) gen/index.html

watch:
	@$(WATCHDIR) --verbose --cmd "make" . css img fonts

clean:
	-@$(RM) -rf gen/* news.adoc
