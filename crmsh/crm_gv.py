# Copyright (C) 2013 Dejan Muhamedagic <dmuhamedagic@suse.de>
# See COPYING for license information.

import re
from . import config
from . import tmpfiles
from . import utils
from .ordereddict import odict
from . import log


logger = log.setup_logger(__name__)
# graphviz stuff


def _attr_str(attr_d):
    return ','.join(['%s="%s"' % (k, v)
                     for k, v in attr_d.items()])


def _quoted(name):
    if re.match('^[0-9_]', name):
        return '"%s"' % (name)
    return name


class Gv(object):
    '''
    graph.
    '''
    EDGEOP = ''  # actually defined in subclasses

    def __init__(self, ident=None):
        if ident:
            self.ident = self.gv_id(ident)
        else:
            self.ident = ""
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
        return n.replace('-', '_').replace('.', '_')

    def new_graph_attr(self, attr, v):
        self.graph_attrs[attr] = v

    def new_attr(self, n, attr_n, attr_v):
        ident = self.gv_id(n)
        if ident not in self.attrs:
            self.attrs[ident] = odict()
        self.attrs[ident][attr_n] = attr_v

    def new_node(self, n, top_node=False, norank=False):
        '''
        Register every node.
        '''
        ident = self.gv_id(n)
        if top_node:
            self.top_nodes.append(ident)
        elif ident not in self.nodes:
            self.nodes[ident] = 0
        if norank:
            self.norank_nodes.append(ident)

    def my_edge(self, e):
        return [self.gv_id(x) for x in e if x is not None]

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
        e_s = self.EDGEOP.join(_quoted(x) for x in self.edges[e_id])
        if e_id < len(self.edge_attrs):
            return '%s [%s]' % (e_s, _attr_str(self.edge_attrs[e_id]))
        else:
            return e_s

    def invis_edge_str(self, tn, node):
        attrs = 'style="invis"'
        if node in self.norank_nodes:
            attrs = '%s,constraint="false"' % attrs
        return '%s [%s];' % (self.EDGEOP.join([_quoted(tn), _quoted(node)]), attrs)

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
            for node, rank in self.nodes.items():
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
        for attr, v in self.graph_attrs.items():
            l.append('\t%s="%s";' % (attr, v))
        for sg in self.subgraphs:
            l.append('\t%s' % '\n\t'.join(sg.repr()))
        for e_id in range(len(self.edges)):
            l.append('\t%s;' % self.edge_str(e_id))
        for n, attr_d in self.attrs.items():
            attr_s = _attr_str(attr_d)
            l.append('\t%s [%s];' % (_quoted(n), attr_s))
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

    def __init__(self, ident=None):
        Gv.__init__(self, ident)

    def header(self):
        name = self.ident and self.ident or "G"
        return 'digraph %s {\n' % (name)

    def footer(self):
        return '}'

    def group(self, members, ident=None):
        '''
        Groups are subgraphs.
        '''
        sg_obj = SubgraphDot(ident)
        sg_obj.new_edge(members)
        self.subgraphs.append(sg_obj)
        self.new_node(members[0])
        return sg_obj

    def optional_set(self, members, ident=None):
        '''
        Optional resource sets.
        '''
        sg_obj = SubgraphDot(ident)
        e_id = sg_obj.new_edge(members)
        sg_obj.new_edge_attr(e_id, 'style', 'invis')
        sg_obj.new_edge_attr(e_id, 'constraint', 'false')
        self.subgraphs.append(sg_obj)
        return sg_obj

    def display(self):
        if not config.core.dotty:
            logger.error("dotty not found")
            return False
        dotf = self.totmpf()
        if not dotf:
            return False
        utils.show_dot_graph(dotf, desc="configuration graph")
        return True

    def image(self, img_type, outf):
        if not config.core.dot:
            logger.error("dot not found")
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
    def __init__(self, ident=None):
        GvDot.__init__(self, ident)

    def header(self):
        if self.ident:
            return 'subgraph %s {' % self.ident
        else:
            return '{'


gv_types = {
    "dot": GvDot,
}

# vim:ts=4:sw=4:et:
