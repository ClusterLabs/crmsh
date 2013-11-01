# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

import command
import completers as compl
import utils
import ra
from msg import Options


def complete_class_provider_type(args):
    sp = args[0].split(':')
    if len(sp) < 2:
        return [c+':' for c in ra.ra_classes()]
    elif len(sp) < 3:
        ret = []
        for c in ra.ra_classes():
            if sp[0] == c:
                ret += ['%s:%s:' % (c, p) for p in ra.ra_providers_all(c)]
        return ret
    else:
        providers = []
        for c in ra.ra_classes():
            if sp[0] == c:
                providers += [(c, p) for p in ra.ra_providers_all(c) if p == sp[1]]
        ret = []
        for c, p in providers:
            ret += ['%s:%s:%s' % (c, p, t) for t in ra.ra_types(c, p)]
        return ret


class RA(command.UI):
    '''
    CIB shadow management class
    '''
    name = "ra"
    provider_classes = ["ocf"]

    def do_classes(self, context):
        "usage: classes"
        for c in ra.ra_classes():
            if c in self.provider_classes:
                print "%s / %s" % (c, ' '.join(ra.ra_providers_all(c)))
            else:
                print "%s" % c

    @command.skill_level('administrator')
    def do_providers(self, context, ra_type, ra_class="ocf"):
        "usage: providers <ra> [<class>]"
        print ' '.join(ra.ra_providers(ra_type, ra_class))

    @command.skill_level('administrator')
    @command.completers(compl.call(ra.ra_classes), lambda args: ra.ra_providers_all(args[0]))
    def do_list(self, context, c, p=None):
        "usage: list <class> [<provider>]"
        options = Options.getInstance()
        if not c in ra.ra_classes():
            context.fatal_error("class %s does not exist" % c)
        if p and not p in ra.ra_providers_all(c):
            context.fatal_error("there is no provider %s for class %s" % (p, c))
        if options.regression_tests:
            for t in ra.ra_types(c, p):
                print t
        else:
            utils.multicolumn(ra.ra_types(c, p))

    @command.skill_level('administrator')
    @command.alias('info')
    @command.completers(complete_class_provider_type)
    def do_meta(self, context, *args):
        "usage: meta [<class>:[<provider>:]]<type>"
        if len(args) > 1:  # obsolete syntax
            ra_type = args[0]
            ra_class = args[1]
            if len(args) < 3:
                ra_provider = "heartbeat"
            else:
                ra_provider = args[2]
        else:
            if args[0] in vars.meta_progs:
                ra_class = args[0]
                ra_provider = ra_type = None
            else:
                ra_class, ra_provider, ra_type = ra.disambiguate_ra_type(args[0])
        agent = ra.RAInfo(ra_class, ra_type, ra_provider)
        if agent.mk_ra_node() is None:
            return False
        try:
            utils.page_string(agent.meta_pretty())
        except Exception, msg:
            context.fatal_error(msg)
