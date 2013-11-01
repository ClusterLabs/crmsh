# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#

# Helper completers

import xmlutil


def choice(lst):
    '''
    Static completion from a list
    '''
    def completer(args):
        return lst
    return completer


null = choice([])


def call(fn, *args):
    '''
    Call the given function with the given arguments.
    The function has to return a list of completions.
    '''
    def completer(args):
        return fn(*args)
    return completer


def join(*fns):
    '''
    Combine the output of several completers
    into a single completer.
    '''
    def completer(args):
        ret = []
        for fn in fns:
            ret += fn(args)
        return ret
    return completer


booleans = choice(['yes', 'no', 'true', 'false', 'on', 'off'])


def resources(args):
    cib_el = xmlutil.resources_xml()
    if cib_el is None:
        return []
    nodes = xmlutil.get_interesting_nodes(cib_el, [])
    return [x.get("id") for x in nodes if xmlutil.is_resource(x)]


def primitives(args):
    cib_el = xmlutil.resources_xml()
    if cib_el is None:
        return []
    nodes = xmlutil.get_interesting_nodes(cib_el, [])
    return [x.get("id") for x in nodes if xmlutil.is_primitive(x)]

nodes = call(xmlutil.listnodes)

shadows = call(xmlutil.listshadows)
