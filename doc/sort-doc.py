# Tool to sort the documentation alphabetically
# Makes a lot of assumptions about the structure of the document it edits
# Looks for special markers that indicate structure

# prints output to stdout

# print lines until in a cmdhelp_<section>
# collect all cmdhelp_<section>_<subsection> subsections
# sort and print

import sys
import re


class Sorter(object):
    def __init__(self):
        self.current_section = None
        self.current_subsection = None
        self.subsections = []
        self.re_section = re.compile(r'^\[\[cmdhelp_([^_,]+),')
        self.re_subsection = re.compile(r'^\[\[cmdhelp_([^_]+)_([^,]+),')

    def beginsection(self, line):
        m = self.re_section.match(line)
        name = m.group(1)
        self.current_section = [name, line]
        self.current_subsection = None
        self.subsections = []
        return self.insection

    def insection(self, line):
        if line.startswith('[[cmdhelp_%s_' % (self.current_section[0])):
            return self.beginsubsection(line)
        elif line.startswith('[['):
            self.finishsection()
            return self.preprint(line)
        else:
            self.current_section[1] += line
        return self.insection

    def beginsubsection(self, line):
        m = self.re_subsection.match(line)
        name = m.group(2)
        self.current_subsection = [name, line]
        return self.insubsection

    def insubsection(self, line):
        if line.startswith('[['):
            self.subsections.append(self.current_subsection)
            self.current_subsection = None
            return self.insection(line)
        self.current_subsection[1] += line
        return self.insubsection

    def finishsection(self):
        if self.current_section:
            print self.current_section[1],
            for name, text in sorted(self.subsections, key=lambda x: x[0]):
                print text,
        self.current_section = None
        self.subsections = []

    def preprint(self, line):
        if self.re_section.match(line):
            return self.beginsection(line)
        print line,
        return self.preprint

    def run(self, lines):
        action = self.preprint
        for line in lines:
            prevaction = action
            action = action(line)
            if action is None:
                print prevaction
                print self.current_section
                print self.current_subsection
                sys.exit(1)
        if self.current_section:
            self.finishsection()

Sorter().run(open(sys.argv[1]).readlines())
