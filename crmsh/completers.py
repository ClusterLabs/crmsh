# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

# Helper completers

from . import xmlutil


def choice(lst):
    '''
    Static completion from a list
    '''
    def completer(args):
        return lst
    return completer


null = choice([])
attr_id = choice(["id="])

def call(fn, *fnargs):
    '''
    Call the given function with the given arguments.
    The function has to return a list of completions.
    '''
    def completer(args):
        return fn(*fnargs)
    return completer


def join(*fns):
    '''
    Combine the output of several completers
    into a single completer.
    '''
    def completer(args):
        ret = []
        for fn in fns:
            ret += list(fn(args))
        return ret
    return completer


booleans = choice(['yes', 'no', 'true', 'false', 'on', 'off'])


def resources(args=None):
    cib_el = xmlutil.resources_xml()
    if cib_el is None:
        return []
    nodes = xmlutil.get_interesting_nodes(cib_el, [])
    rsc_id_list = [x.get("id") for x in nodes if xmlutil.is_resource(x)]
    if args and args[0] in ['promote', 'demote']:
        return [item for item in rsc_id_list if xmlutil.RscState().is_ms_or_promotable_clone(item)]
    if args and args[0] == "started":
        return [item for item in rsc_id_list if xmlutil.RscState().is_running(item)]
    if args and args[0] == "stopped":
        return [item for item in rsc_id_list if not xmlutil.RscState().is_running(item)]
    return rsc_id_list


def resources_started(args=None):
    return resources(["started"])


def resources_stopped(args=None):
    return resources(["stopped"])


def primitives(args):
    cib_el = xmlutil.resources_xml()
    if cib_el is None:
        return []
    nodes = xmlutil.get_interesting_nodes(cib_el, [])
    return [x.get("id") for x in nodes if xmlutil.is_primitive(x)]


nodes = call(xmlutil.listnodes)
online_nodes = call(xmlutil.CrmMonXmlParser().get_node_list, "online")
standby_nodes = call(xmlutil.CrmMonXmlParser().get_node_list, "standby")

shadows = call(xmlutil.listshadows)

status_option = """full bynode inactive ops timing failcounts
                   verbose quiet xml simple tickets noheaders
                   detail brief""".split()
