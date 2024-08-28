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
    if args:
        if args[0] in ('promote', 'demote'):
            rsc_id_list = [item for item in rsc_id_list if xmlutil.RscState().is_ms_or_promotable_clone(item)]
        elif args[0] == "start":
            rsc_id_list = [item for item in rsc_id_list if not xmlutil.RscState().is_running(item)]
        elif args[0] == "stop":
            rsc_id_list = [item for item in rsc_id_list if xmlutil.RscState().is_running(item)]
        rsc_id_list = [item for item in rsc_id_list if item not in args]
    return rsc_id_list


def online_nodes(completed_args):
    xml_parser = xmlutil.CrmMonXmlParser()
    online_nodes = xml_parser.get_node_list("online")
    if completed_args:
        online_nodes = [node for node in online_nodes if node not in completed_args]
    return online_nodes


def standby_nodes(completed_args):
    xml_parser = xmlutil.CrmMonXmlParser()
    standby_nodes = xml_parser.get_node_list("standby")
    if completed_args:
        standby_nodes = [node for node in standby_nodes if node not in completed_args]
    return standby_nodes


def primitives(args):
    cib_el = xmlutil.resources_xml()
    if cib_el is None:
        return []
    nodes = xmlutil.get_interesting_nodes(cib_el, [])
    return [x.get("id") for x in nodes if xmlutil.is_primitive(x)]


nodes = call(xmlutil.listnodes)
shadows = call(xmlutil.listshadows)

status_option = """full bynode inactive ops timing failcounts
                   verbose quiet xml simple tickets noheaders
                   detail brief""".split()
