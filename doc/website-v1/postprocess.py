#!/usr/bin/env python
# create a table of contents for pages that need it

import sys
import re
import argparse

TOC_PAGES = ['man/index.html',
             'man-4.3/index.html',
             'man-3/index.html',
             'man-2.0/index.html',
             'man-1.2/index.html']
V2_PAGES = ['index.html']
INSERT_AFTER = '<!--TOC-->'

def read_toc_data(infile, debug):
    topics_data = []
    commands_data = []
    f = open(infile)
    for line in f:
        if line.startswith('[['):
            line = line[2:-3]  # strip [[ and ]]\n
            info, short_help = line.split(',', 1)
            short_help = short_help.strip()
            info_split = info.split('_')
            if info_split[0] == 'topics':
                if len(info_split) == 2:
                    topics_data.append((1, short_help, info))
                elif len(info_split) >= 3:
                    topics_data.append((2, short_help, info))
            elif info_split[0] == 'cmdhelp':
                if len(info_split) == 2:
                    commands_data.append((2, info_split[1], info))
                elif len(info_split) >= 3:
                    commands_data.append((3, '_'.join(info_split[2:]), info))
    toc = ''
    if len(topics_data) > 0 or len(commands_data) > 0:
        toc = '<div id="toc">\n'
        for depth, text, link in topics_data:
            toc += '<div class="toclevel%s"><a href="#%s">%s</a></div>\n' % (
                depth, link, text)
        for depth, text, link in commands_data:
            toc += '<div class="toclevel%s"><a href="#%s">%s</a></div>\n' % (
                depth, link, text)
        toc += '</div>\n'
    return toc

def generate_toc(infile, outfile, debug):

    if debug:
        print "Infile:", infile
    toc = read_toc_data(infile, debug)
    '''
    toc_data = []
    section = re.compile(r"<h(?P<depth>[0-9])( id=\"(?P<id>[^\"]+)\")?>(?P<text>.*)</h[0-9]>")
    for line in f:
        m = section.match(line)
        if m:
            if debug:
                print "toc_data: %s" % str(((m.group('depth'), m.group('text'), m.group('id'))))
            toc_data.append((m.group('depth'), m.group('text'), m.group('id')))

    toc = ''
    if len(toc_data) > 0:
        toc = '<div id="toc">\n'
        for depth, text, link in toc_data:
            if depth >= 2 and link is not None:
                toc += '<div class="toclevel%s"><a href="#%s">%s</a></div>\n' % (
                    int(depth) - 1, link, text)
        toc += '</div>\n'
'''

    # Write TOC to outfile
    if outfile:
        if debug:
            print "Writing TOC:"
            print "----"
            print toc
            print "----"
            print "Outfile:", outfile
        fil = open(outfile)
        f = fil.readlines()
        fil.close()
        f2 = open(outfile, 'w')
        for line in f:
            f2.write(line)
            if toc and line.startswith(INSERT_AFTER):
                f2.write(toc)
        f2.close()

def generate_v2(page, debug):
    f = open(page).readlines()
    toc_data = []
    section = re.compile(r"<h(?P<depth>[0-9])( id=\"(?P<id>[^\"]+)\")?>(?P<text>.*)</h[0-9]>")
    for line in f:
        m = section.match(line)
        if m:
            if debug:
                print "toc_data: %s" % str(((m.group('depth'), m.group('text'), m.group('id'))))
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
        if toc and line.startswith(INSERT_AFTER):
            f2.write(toc)
    f2.close()

def main():
    parser = argparse.ArgumentParser(description="Generate table of contents")
    parser.add_argument('-d', '--debug', dest='debug', action='store_true',
                        help="Enable debug output")
    parser.add_argument('-o', '--output', metavar='output', type=str,
                        help="File to inject TOC into")
    parser.add_argument('input', metavar='input', type=str,
                        help="File to read TOC metadata from")
    args = parser.parse_args()
    debug = args.debug
    outfile = args.output
    infile = args.input
    print "+ %s -> %s" % (infile, outfile)
    gen = False
    for tocpage in TOC_PAGES:
        if not gen and outfile.endswith(tocpage):
            generate_toc(infile, outfile, debug)
            gen = True
    for tocpage in V2_PAGES:
        if not gen and outfile.endswith(tocpage):
            generate_v2(outfile, debug)
            gen = True

if __name__ == "__main__":
    main()
