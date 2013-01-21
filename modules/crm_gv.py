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

import subprocess
from userprefs import UserPrefs
from vars import Vars
from utils import *
from msg import *

# graphviz stuff

def _attr_str(attr_d):
    return ','.join(['%s="%s"' % (k, v) \
        for k, v in attr_d.iteritems()])

class Gv(object):
    '''
    graph.
    '''
    EDGEOP = '' # actually defined in subclasses
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
        self.edge_attrs = odict()
        self.top_nodes = []
        self.norank_nodes = []
    def gv_id(self, n):
        return n.replace('-','_')
    def node_attr(self, attr_n, attr_v):
        self.node_attrs[attr_n] = attr_v
    def new_graph_attr(self, attr, v):
        self.graph_attrs[attr] = v
    def graph_label(self, lbl):
        self.new_graph_attr('label', lbl)
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
    def edge_idx(self, e):
        return ';'.join([self.gv_id(x) for x in e])
    def my_edge(self, e):
        return [self.gv_id(x) for x in e]
    def new_edge(self, e):
        ne = self.my_edge(e)
        for i,node in enumerate(ne):
            if i == 0:
                continue
            if node in self.top_nodes:
                continue
            self.nodes[node] = i
        self.edges.append(ne)
    def new_edge_attr(self, e, attr_n, attr_v):
        e_idx = self.edge_idx(e)
        if e_idx not in self.edge_attrs:
            self.edge_attrs[e_idx] = odict()
        self.edge_attrs[e_idx][attr_n] = attr_v
    def edge_str(self, e):
        e_s = self.EDGEOP.join(e)
        e_idx = self.edge_idx(e)
        if e_idx in self.edge_attrs:
            return('%s [%s]' % (e_s, _attr_str(self.edge_attrs[e_idx])))
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
            for node,rank in self.nodes.iteritems():
                if rank > 0:
                    continue
                l.append('\t%s' % self.invis_edge_str(tn, node))
        return l
    def repr(self):
        '''
        Dump gv graph to a string.
        '''
        l = []
        l.append(self.header())
        if self.node_attrs:
            l.append('\tnode [%s]' % _attr_str(self.node_attrs))
        for attr,v in self.graph_attrs.iteritems():
            l.append('\t%s="%s"' % (attr,v))
        for sg in self.subgraphs:
            l.append('\t%s' % '\n\t'.join(sg.repr()))
        for e in self.edges:
            l.append('\t%s;' % self.edge_str(e))
        for n,attr_d in self.attrs.iteritems():
            attr_s = _attr_str(attr_d)
            l.append('\t%s [%s];' % (n, attr_s))
        l += self.invisible_edges()
        l.append(self.footer())
        return l
    def totmpf(self):
        tmpf = str2tmp('\n'.join(self.repr()))
        if not tmpf:
            return None
        vars.tmpfiles.append(tmpf)
        return tmpf
    def save(self, outf):
        f = safe_open_w(outf)
        if not f:
            return False
        f.write('\n'.join(self.repr()))
        f.write('\n')
        safe_close_w(f)
        return True

class GvDot(Gv):
    '''
    graphviz dot directed graph.
    '''
    EDGEOP = ' -> '
    def __init__(self, id=None):
        Gv.__init__(self, id)
    def header(self):
        return 'digraph %s {' % (self.id and self.id or "G")
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
    def display(self):
        if not user_prefs.dotty:
            common_err("dotty not found")
            return False
        dotf = self.totmpf()
        if not dotf:
            return False
        subprocess.Popen("%s %s" % (user_prefs.dotty, dotf), \
            shell=True, bufsize=0, stdin=None, stdout=None, stderr=None, close_fds=True)
        return True
    def image(self, img_type, outf):
        if not user_prefs.dot:
            common_err("dot not found")
            return False
        dotf = self.totmpf()
        if not dotf:
            return False
        return (ext_cmd_nosudo("%s -T%s -o%s %s" % \
            (user_prefs.dot, img_type, outf, dotf)) == 0)

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

user_prefs = UserPrefs.getInstance()
vars = Vars.getInstance()

# vim:ts=4:sw=4:et:
