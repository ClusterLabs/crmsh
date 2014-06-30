ASCIIDOC := asciidoc
SRC := faq.txt documentation.txt development.txt installation.txt \
	configuration.txt about.txt rsctest-guide.txt \
	history-guide.txt start-guide.txt man-1.2.txt scripts.txt man-2.0.txt
TGT := $(patsubst %.txt,gen/%/index.html,$(SRC))
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
NEWS := $(wildcard news/*.txt)
NEWSDOC := $(patsubst %.txt,gen/%/index.html,$(NEWS))

.PHONY: all clean deploy open

all: site

gen/index.html: index.txt crm.conf
	@mkdir -p $(dir $@)
	@$(ASCIIDOC) --unsafe -b html5 -f crm.conf -o $@ $<
	@python ./postprocess.py -o $@ $<

gen/%/index.html: %.txt crm.conf
	@mkdir -p $(dir $@)
	@$(ASCIIDOC) --unsafe -b html5 -f crm.conf -o $@ $<
	@python ./postprocess.py -o $@ $<

gen/man/index.html: ../crm.8.txt crm.conf
	@mkdir -p $(dir $@)
	@$(ASCIIDOC) --unsafe -b html5 -f crm.conf -o $@ $<
	@python ./postprocess.py -o $@ $<

gen/404.html: 404.txt crm.conf
	@mkdir -p $(dir $@)
	@$(ASCIIDOC) --unsafe -b html5 -f crm.conf -o $@ $<
	@python ./postprocess.py -o $@ $<

news.txt: $(NEWS) crm.conf
	@echo "news:" $(NEWS)
	python ./make-news.py $@ $(NEWS)

gen/news/index.html: news.txt
	@mkdir -p $(dir $@)
	$(ASCIIDOC) --unsafe -b html5 -f crm.conf -o $@ $<
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
	-@$(RM) -rf gen/* news.txt
