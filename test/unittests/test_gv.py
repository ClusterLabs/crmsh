# Copyright (C) 2015 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.


import re

from crmsh import crm_gv
from crmsh import cibconfig


def test_digits_ident():
    g = crm_gv.gv_types["dot"]()
    cibconfig.set_graph_attrs(g, ".")

    g.new_node("1a", top_node=True)
    g.new_attr("1a", 'label', "1a")
    g.new_node("a", top_node=True)
    g.new_attr("a", 'label', "a")

    expected = [
        'fontname="Helvetica";',
        'fontsize="11";',
        'compound="true";',
        '"1a" [label="1a"];',
        'a [label="a"];',
    ]
    out = '\n'.join(g.repr()).replace('\t', '')

    for line in re.match(
            r'^digraph G {\n\n(?P<expected>.*)\n}$', out, re.M | re.S
    ).group('expected').split('\n'):
        assert line in expected
        expected.remove(line)

    assert len(expected) == 0
