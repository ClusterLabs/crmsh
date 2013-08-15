#!/usr/bin/env python
# create a table of contents for pages that need it

import sys
import re

TOC_PAGES = ['crm.8.html',
             'quickstart.html',
             'manual.html',
             'faq.html',
             'documentation.html',
             'development.html']
INSERT_AFTER = '<!--TOC-->'


def generate_toc(page):
    toc_data = []
    section = re.compile(r"<h(?P<depth>[0-9])( id=\"(?P<id>[^\"]+)\")?>(?P<text>.*)</h[0-9]>")
    fil = open(page)
    f = fil.readlines()
    fil.close()
    for line in f:
        m = section.match(line)
        if m:
            toc_data.append((m.group('depth'), m.group('text'), m.group('id')))

    toc = ''
    if len(toc_data) > 0:
        toc = '<div id="toc">\n'
        for depth, text, link in toc_data:
            if depth >= 2 and link is not None:
                toc += '<div class="toclevel%s"><a href="#%s">%s</a></div>\n' % (
                    int(depth) - 1, link, text)
        toc += '</div>\n'

    f2 = open(page, 'w')
    for line in f:
        f2.write(line)
        if line.startswith(INSERT_AFTER):
            f2.write(toc)
    f2.close()


def main():
    page = sys.argv[1]
    print "+ " + page
    for tocpage in TOC_PAGES:
        if page.endswith(tocpage):
            generate_toc(page)

if __name__ == "__main__":
    main()
