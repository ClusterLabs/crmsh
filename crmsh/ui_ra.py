# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import re
from . import command
from . import completers as compl
from . import utils
from . import ra
from . import constants
from . import options


def complete_class_provider_type(args):
    '''
    When need to show the agent supported by cluster,
    grouped by different classes or providers, Tab by Tab,
    instead of completing all the agents at one time.

    First completion:  agent classes
    Second completion: providers of ocf or types of other classes
    Last completion:   types of ocf agents
    '''
    c = args[-1]
    classes = ra.ra_classes()
    if not c:
        # First completion:  agent classes
        return [l+":" for l in classes]

    ret = set([])
    providers = ra.ra_providers_all('ocf')
    if c == 'ocf:' or re.search(r'ocf:[^:]+$', c):
        # Second completion: providers of ocf
        for p in providers:
            if p == '.isolation':
                continue
            ret.add('%s:%s:' % ('ocf', p))
        return list(ret)

    if re.search(r'ocf:.+:', c):
        # Last completion:   types of ocf agents
        for p in providers:
            if p == '.isolation':
                continue
            types = ra.ra_types('ocf', p)
            for t in types:
                ret.add('%s:%s:%s' % ('ocf', p, t))
        return list(ret)

    if c.endswith(':') and c.strip(':') in classes:
        # Second completion: types of other classes
        types = ra.ra_types(c)
        for t in types:
            ret.add('%s:%s' % (c.strip(':'), t))
        return list(ret)

    if re.search(r'.+:.+', c):
        # Second completion: types of other classes
        types = ra.ra_types(c.split(':')[0])
        for t in types:
            ret.add('%s:%s' % (c.split(':')[0], t))
        return list(ret)

    # First completion:  agent classes
    return [l+":" for l in classes]

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
                providers = ra.ra_providers_all(c)
                if providers:
                    print("%s / %s" % (c, ' '.join(providers)))
            else:
                print("%s" % c)

    @command.skill_level('administrator')
    def do_providers(self, context, ra_type, ra_class="ocf"):
        "usage: providers <ra> [<class>]"
        print(' '.join(ra.ra_providers(ra_type, ra_class)))

    @command.skill_level('administrator')
    @command.completers(compl.call(ra.ra_classes), lambda args: ra.ra_providers_all(args[1]))
    def do_list(self, context, class_, provider_=None):
        "usage: list <class> [<provider>]"
        if class_ not in ra.ra_classes():
            context.fatal_error("class %s does not exist" % class_)
        if provider_ and provider_ not in ra.ra_providers_all(class_):
            context.fatal_error("there is no provider %s for class %s" % (provider_, class_))
        types = ra.ra_types(class_, provider_)
        if options.regression_tests:
            for t in types:
                print(t)
        else:
            utils.multicolumn(types)

    @command.skill_level('administrator')
    @command.alias('meta')
    @command.completers(complete_class_provider_type)
    def do_info(self, context, *args):
        "usage: info [<class>:[<provider>:]]<type>"
        if len(args) == 0:
            context.fatal_error("Expected [<class>:[<provider>:]]<type>")
        if args[0] == "cluster":
            meta_string = utils.get_cluster_option_metadata(show_xml=False)
            if not meta_string:
                context.fatal_error("No metadata found for cluster option (supports since pacemaker 2.1.8)")
            utils.page_string(meta_string)
            return True
        if len(args) > 1:  # obsolete syntax
            if len(args) < 3:
                ra_type, ra_class, ra_provider = args[0], args[1], "heartbeat"
            else:
                ra_type, ra_class, ra_provider = args[0], args[1], args[2]
        elif args[0] in constants.meta_progs_20:
            ra_class, ra_provider, ra_type = args[0], None, None
        else:
            ra_class, ra_provider, ra_type = ra.disambiguate_ra_type(args[0])
        agent = ra.RAInfo(ra_class, ra_type, ra_provider)
        if agent.mk_ra_node() is None:
            return False
        try:
            utils.page_string(agent.meta_pretty())
        except Exception as msg:
            context.fatal_error(msg)

    @command.skill_level('administrator')
    def do_validate(self, context, agentname, *params):
        "usage: validate [<class>:[<provider>:]]<type> [<key>=<value> ...]"
        rc, _ = ra.validate_agent(agentname, dict([param.split('=', 1) for param in params]), log=True)
        return rc == 0
