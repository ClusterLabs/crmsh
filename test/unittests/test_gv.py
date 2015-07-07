# Copyright (C) 2015 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.


from crmsh import crm_gv
from crmsh import cibconfig
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
