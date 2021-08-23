# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# See COPYING for license information.

import os
import re
from . import config
from . import userdir
from . import log


logger = log.setup_logger(__name__)


def get_var(l, key):
    for s in l:
        a = s.split()
        if len(a) == 2 and a[0] == key:
            return a[1]
    return ''


def chk_var(l, key):
    for s in l:
        a = s.split()
        if len(a) == 2 and a[0] == key and a[1]:
            return True
    return False


def chk_key(l, key):
    for s in l:
        a = s.split()
        if len(a) >= 1 and a[0] == key:
            return True
    return False


def validate_template(l):
    'Test for required stuff in a template.'
    if not chk_var(l, '%name'):
        logger.error("invalid template: missing '%name'")
        return False
    if not chk_key(l, '%generate'):
        logger.error("invalid template: missing '%generate'")
        return False
    g = l.index('%generate')
    if not (chk_key(l[0:g], '%required') or chk_key(l[0:g], '%optional')):
        logger.error("invalid template: missing '%required' or '%optional'")
        return False
    return True


def fix_tmpl_refs(l, ident, pfx):
    for i, tmpl in enumerate(l):
        l[i] = tmpl.replace(ident, pfx)


def fix_tmpl_refs_re(l, regex, repl):
    for i, tmpl in enumerate(l):
        l[i] = re.sub(regex, repl, tmpl)


class LoadTemplate(object):
    '''
    Load a template and its dependencies, generate a
    configuration file which should be relatively easy and
    straightforward to parse.
    '''
    edit_instructions = '''# Edit instructions:
#
# Add content only at the end of lines starting with '%%'.
# Only add content, don't remove or replace anything.
# The parameters following '%required' are not optional,
# unlike those following '%optional'.
# You may also add comments for future reference.'''
    no_more_edit = '''# Don't edit anything below this line.'''

    def __init__(self, name):
        self.name = name
        self.all_pre_gen = []
        self.all_post_gen = []
        self.all_pfx = []

    def new_pfx(self, name):
        i = 1
        pfx = name
        while pfx in self.all_pfx:
            pfx = "%s_%d" % (name, i)
            i += 1
        self.all_pfx.append(pfx)
        return pfx

    def generate(self):
        return '\n'.join(
            ["# Configuration: %s" % self.name,
             '',
             self.edit_instructions,
             '',
             '\n'.join(self.all_pre_gen),
             self.no_more_edit,
             '',
             '%generate',
             '\n'.join(self.all_post_gen)])

    def write_config(self, name):
        try:
            f = open("%s/%s" % (userdir.CRMCONF_DIR, name), "w")
        except IOError as msg:
            logger.error("open: %s", msg)
            return False
        print(self.generate(), file=f)
        f.close()
        return True

    def load_template(self, tmpl):
        try:
            l = open(os.path.join(config.path.sharedir, 'templates', tmpl)).read().split('\n')
        except IOError as msg:
            logger.error("open: %s", msg)
            return ''
        if not validate_template(l):
            return ''
        logger.info("pulling in template %s", tmpl)
        g = l.index('%generate')
        pre_gen = l[0:g]
        post_gen = l[g+1:]
        name = get_var(pre_gen, '%name')
        for s in l[0:g]:
            if s.startswith('%depends_on'):
                a = s.split()
                if len(a) != 2:
                    logger.warning("%s: wrong usage", s)
                    continue
                tmpl_id = a[1]
                tmpl_pfx = self.load_template(a[1])
                if tmpl_pfx:
                    fix_tmpl_refs(post_gen, '%'+tmpl_id, '%'+tmpl_pfx)
        pfx = self.new_pfx(name)
        fix_tmpl_refs(post_gen, '%_:', '%'+pfx+':')
        # replace remaining %_, it may be useful at times
        fix_tmpl_refs(post_gen, '%_', pfx)
        v_idx = pre_gen.index('%required') or pre_gen.index('%optional')
        pre_gen.insert(v_idx, '%pfx ' + pfx)
        self.all_pre_gen += pre_gen
        self.all_post_gen += post_gen
        return pfx

    def post_process(self, params):
        pfx_re = '(%s)' % '|'.join(self.all_pfx)
        for n in params:
            fix_tmpl_refs(self.all_pre_gen, '%% '+n, "%% "+n+"  "+params[n])
        fix_tmpl_refs_re(self.all_post_gen,
                         '%' + pfx_re + '([^:]|$)', r'\1\2')
        # process %if ... [%else] ... %fi
        rmidx_l = []
        if_seq = False
        outcome = False  # unnecessary, but to appease lints
        for i in range(len(self.all_post_gen)):
            s = self.all_post_gen[i]
            if if_seq:
                a = s.split()
                if len(a) >= 1 and a[0] == '%fi':
                    if_seq = False
                    rmidx_l.append(i)
                elif len(a) >= 1 and a[0] == '%else':
                    outcome = not outcome
                    rmidx_l.append(i)
                else:
                    if not outcome:
                        rmidx_l.append(i)
                continue
            if not s:
                continue
            a = s.split()
            if len(a) == 2 and a[0] == '%if':
                outcome = not a[1].startswith('%')  # not replaced -> false
                if_seq = True
                rmidx_l.append(i)
        rmidx_l.reverse()
        for i in rmidx_l:
            del self.all_post_gen[i]

# vim:ts=4:sw=4:et:
