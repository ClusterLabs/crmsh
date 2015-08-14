# Copyright (C) 2015 Kristoffer Gronlund <kgronlund@suse.com>
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


import crm_gv
import cibconfig
from nose.tools import eq_


def test_digits_ident():
    g = crm_gv.gv_types["dot"]()
    cibconfig.set_graph_attrs(g, ".")

    g.new_node("1a", top_node=True)
    g.new_attr("1a", 'label', "1a")
    g.new_node("a", top_node=True)
    g.new_attr("a", 'label', "a")

    eq_("""digraph G {

fontname="Helvetica";
fontsize="11";
compound="true";
"1a" [label="1a"];
a [label="a"];
}""", '\n'.join(g.repr()).replace('\t', ''))
