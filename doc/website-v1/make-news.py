#!/usr/bin/env python3
"""
Output a combined news.adoc document
Also write an Atom feed document
"""

import os
import sys
import hashlib
import datetime
import time

OUTPUT_HEADER = """= News

"""
OUTPUT_FOOTER = """
link:https://savannah.nongnu.org/news/?group_id=10890[Old News Archive]
"""

ATOM_TEMPLATE = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
<title>crmsh</title>
<subtitle>Cluster manager shell news</subtitle>
<link href="http://crmsh.github.io/atom.xml" rel="self" />
<link href="http://crmsh.github.io/" />
<id>%(id)s</id>
<updated>%(updated)s</updated>
%(entries)s
</feed>
"""

ATOM_NAME = "gen/atom.xml"

root_id = "tag:crmsh.github.io,2014:/atom"

def escape(s):
    s = s.replace('&', '&amp;')
    s = s.replace('<', '&lt;')
    s = s.replace('>', '&gt;')
    s = s.replace('"', "&quot;")
    return s

class Entry(object):
    def __init__(self, fname):
        self.filename = fname
        self.name = os.path.splitext(os.path.basename(fname))[0]
        with open(fname) as f:
            self.title = f.readline().strip()
            f.readline()
            l = f.readline()
            while l.startswith(':'):
                k, v = l[1:].split(':', 1)
                k = k.lower()
                v = v.strip()
                setattr(self, k, v)
                l = f.readline()
            self.content = l + f.read()
        if not hasattr(self, 'author'):
            raise ValueError("Missing author")
        if not hasattr(self, 'email'):
            raise ValueError("Missing email")
        if not hasattr(self, 'date'):
            raise ValueError("Missing date")

    def atom_id(self):
        return root_id + '::' + hashlib.sha1(self.filename.encode('utf-8')).hexdigest()

    def atom_date(self):
        return self.date.replace(' ', 'T') + ':00' + time.tzname[0]

    def date_obj(self):
        from dateutil import parser
        return (parser.parse(self.date))

    def atom_content(self):
        return escape('<pre>\n' + self.content + '\n</pre>\n')

    def atom(self):
        data = {'title': self.title,
                'id': self.atom_id(),
                'updated': self.atom_date(),
                'name': self.name,
                'content': self.atom_content(),
                'author': self.author,
                'email': self.email}
        return """<entry>
<title>%(title)s</title>
<id>%(id)s</id>
<updated>%(updated)s</updated>
<link>http://crmsh.github.io/news/%(name)s</link>
<content type="html">
%(content)s
</content>
<author>
<name>%(author)s</name>
<email>%(email)s</email>
</author>
</entry>
""" % data


def sort_entries(entries):
    return list(reversed(sorted(entries, key=lambda e: e.date_obj())))


def make_atom():
    inputs = sort_entries([Entry(f) for f in sys.argv[2:]])
    with open(ATOM_NAME, 'w') as output:
        output.write(ATOM_TEMPLATE % {
            'id': root_id,
            'updated': inputs[0].atom_date(),
            'entries': '\n'.join(f.atom() for f in inputs)
        })


def main():
    # TODO: sort by date
    inputs = sort_entries([Entry(f) for f in sys.argv[2:]])
    with open(sys.argv[1], 'w') as output:
        output.write(OUTPUT_HEADER)
        e = inputs[0]
        output.write("link:/news/%s[%s]\n\n" % (e.name, e.date))
        output.write(":leveloffset: 1\n\n")
        output.write("include::%s[]\n\n" % (e.filename))
        output.write(":leveloffset: 0\n\n")

        output.write("''''\n")
        for e in inputs[1:]:
            output.write("* link:/news/%s[%s %s]\n" % (e.name, e.date, e.title))
        output.write(OUTPUT_FOOTER)

if __name__ == "__main__":
    if sys.argv[1] == ATOM_NAME:
        make_atom()
    else:
        main()
