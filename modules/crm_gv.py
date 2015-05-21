# Copyright (C) 2013 Dejan Muhamedagic <dmuhamedagic@suse.de>
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

import re
import config
import tmpfiles
import utils
from msg import common_err
from ordereddict import odict

# graphviz stuff


def _attr_str(attr_d):
    return ','.join(['%s="%s"' % (k, v)
                     for k, v in attr_d.iteritems()])


class Gv(object):
    '''
    graph.
    '''
    EDGEOP = ''  # actually defined in subclasses

    def __init__(self, id=None):
        if id:
            self.id = self.gv_id(id)
        else:
            self.id = ""
        self.nodes = {}
        self.edges = []
        self.subgraphs = []
        self.node_attrs = odict()
        self.attrs = odict()
        self.graph_attrs = odict()
        self.edge_attrs = []
        self.top_nodes = []
        self.norank_nodes = []

    def gv_id(self, n):
        n = n.replace('-', '_').replace('.', '_')
        if re.match('^[0-9_]', n):
            return '"%s"' % (n)
        return n

    def new_graph_attr(self, attr, v):
        self.graph_attrs[attr] = v

    def new_attr(self, n, attr_n, attr_v):
        id = self.gv_id(n)
        if id not in self.attrs:
            self.attrs[id] = odict()
        self.attrs[id][attr_n] = attr_v

    def new_node(self, n, top_node=False, norank=False):
        '''
        Register every node.
        '''
        id = self.gv_id(n)
        if top_node:
            self.top_nodes.append(id)
        elif id not in self.nodes:
            self.nodes[id] = 0
        if norank:
            self.norank_nodes.append(id)

    def my_edge(self, e):
        return [self.gv_id(x) for x in e]

    def new_edge(self, e):
        ne = self.my_edge(e)
        for i, node in enumerate(ne):
            if i == 0:
                continue
            if node in self.top_nodes:
                continue
            self.nodes[node] = i
        self.edges.append(ne)
        self.edge_attrs.append(odict())
        return len(self.edges)-1

    def new_edge_attr(self, e_id, attr_n, attr_v):
        if e_id >= len(self.edge_attrs):
            return  # if the caller didn't create an edge beforehand
        self.edge_attrs[e_id][attr_n] = attr_v

    def edge_str(self, e_id):
        e_s = self.EDGEOP.join(self.edges[e_id])
        if e_id < len(self.edge_attrs):
            return('%s [%s]' % (e_s, _attr_str(self.edge_attrs[e_id])))
        else:
            return e_s

    def invis_edge_str(self, tn, node):
        attrs = 'style="invis"'
        if node in self.norank_nodes:
            attrs = '%s,constraint="false"' % attrs
        return '%s [%s];' % (self.EDGEOP.join([tn, node]), attrs)

    def invisible_edges(self):
        '''
        Dump invisible edges from top_nodes to every node which
        is at the top of the edge or not in any other edge. This
        seems to be the only way to keep the nodes (as in cluster
        nodes) above resources.
        NB: This is O(n^2) (nodes times resources).
        '''
        l = []
        for tn in self.top_nodes:
            for node, rank in self.nodes.iteritems():
                if rank > 0:
                    continue
                l.append('\t%s' % self.invis_edge_str(tn, node))
        return l

    def header(self):
        return ''

    def footer(self):
        return ''

    def repr(self):
        '''
        Dump gv graph to a string.
        '''
        l = []
        l.append(self.header())
        if self.node_attrs:
            l.append('\tnode [%s];' % _attr_str(self.node_attrs))
        for attr, v in self.graph_attrs.iteritems():
            l.append('\t%s="%s";' % (attr, v))
        for sg in self.subgraphs:
            l.append('\t%s' % '\n\t'.join(sg.repr()))
        for e_id in range(len(self.edges)):
            l.append('\t%s;' % self.edge_str(e_id))
        for n, attr_d in self.attrs.iteritems():
            attr_s = _attr_str(attr_d)
            l.append('\t%s [%s];' % (n, attr_s))
        l += self.invisible_edges()
        l.append(self.footer())
        return l

    def totmpf(self):
        return utils.str2tmp('\n'.join(self.repr()))

    def save(self, outf):
        f = utils.safe_open_w(outf)
        if not f:
            return False
        f.write('\n'.join(self.repr()))
        f.write('\n')
        utils.safe_close_w(f)
        return True


class GvDot(Gv):
    '''
    graphviz dot directed graph.
    '''
    EDGEOP = ' -> '

    def __init__(self, id=None):
        Gv.__init__(self, id)

    def header(self):
        name = self.id and self.id or "G"
        return 'digraph %s {\n' % (name)

    def footer(self):
        return '}'

    def group(self, members, id=None):
        '''
        Groups are subgraphs.
        '''
        sg_obj = SubgraphDot(id)
        sg_obj.new_edge(members)
        self.subgraphs.append(sg_obj)
        self.new_node(members[0])
        return sg_obj

    def optional_set(self, members, id=None):
        '''
        Optional resource sets.
        '''
        sg_obj = SubgraphDot(id)
        e_id = sg_obj.new_edge(members)
        sg_obj.new_edge_attr(e_id, 'style', 'invis')
        sg_obj.new_edge_attr(e_id, 'constraint', 'false')
        self.subgraphs.append(sg_obj)
        return sg_obj

    def display(self):
        if not config.core.dotty:
            common_err("dotty not found")
            return False
        dotf = self.totmpf()
        if not dotf:
            return False
        utils.show_dot_graph(dotf, desc="configuration graph")
        return True

    def image(self, img_type, outf):
        if not config.core.dot:
            common_err("dot not found")
            return False
        dotf = self.totmpf()
        if not dotf:
            return False
        tmpfiles.add(dotf)
        return (utils.ext_cmd_nosudo("%s -T%s -o%s %s" %
                                     (config.core.dot, img_type, outf, dotf)) == 0)


class SubgraphDot(GvDot):
    '''
    graphviz subgraph.
    '''
    def __init__(self, id=None):
        Gv.__init__(self, id)

    def header(self):
        if self.id:
            return 'subgraph %s {' % self.id
        else:
            return '{'

gv_types = {
    "dot": GvDot,
}

# vim:ts=4:sw=4:et:
