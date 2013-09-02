# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
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

import vars
from clidisplay import CliDisplay
from msg import common_err, node_debug
import utils
import xmlutil


#
# CLI format generation utilities (from XML)
#
def cli_format(pl, format):
    if format > 0:
        return ' \\\n\t'.join(pl)
    else:
        return ' '.join(pl)


def cli_format_xml(pl, format):
    if format > 0:
        return ' \\\n'.join(pl)
    else:
        return ''.join(pl)


def cli_operations(node, format=1):
    l = []
    node_id = node.get("id")
    s = ''
    if node_id:
        s = '$id="%s"' % node_id
    idref = node.get("id-ref")
    if idref:
        s = '%s $id-ref="%s"' % (s, idref)
    if s:
        l.append("%s %s" % (cli_display.keyword("operations"), s))
    for c in node.iterchildren():
        if c.tag == "op":
            l.append(cli_op(c))
    return cli_format(l, format)


def nvpair_format(n, v):
    if v is None:
        return cli_display.attr_name(n)
    return '%s="%s"' % (cli_display.attr_name(n), cli_display.attr_value(v))


def cli_pairs(pl):
    'Return a string of name="value" pairs (passed in a list of pairs).'
    l = []
    for n, v in pl:
        l.append(nvpair_format(n, v))
    return ' '.join(l)


def nvpairs2list(node, add_id=False):
    '''
    Convert nvpairs to a list of pairs.
    The id attribute is normally skipped, since they tend to be
    long and therefore obscure the relevant content. For some
    elements, however, they are included (e.g. properties).
    '''
    pl = []
    # if there's id-ref, there can be then _only_ id-ref
    value = node.get("id-ref")
    if value:
        pl.append(["$id-ref", value])
        return pl
    if add_id or \
            (not len(node) and len(node.attrib) == 1):
        value = node.get("id")
        if value:
            pl.append(["$id", value])
    for c in node.iterchildren():
        if c.tag == "attributes":
            pl = nvpairs2list(c)
        elif c.tag != "nvpair":
            node_debug("expected nvpair got", c)
            continue
        name = c.get("name")
        if "value" in c.keys():
            value = c.get("value")
        else:
            value = None
        pl.append([name, value])
    return pl


def op_instattr(node):
    pl = []
    for c in node.iterchildren():
        if c.tag != "instance_attributes":
            common_err("only instance_attributes are supported in operations")
        else:
            pl += nvpairs2list(c)
    return pl


def cli_op(node):
    action, pl = xmlutil.op2list(node)
    if not action:
        return ""
    pl += op_instattr(node)
    return "%s %s %s" % (cli_display.keyword("op"), action, cli_pairs(pl))


def date_exp2cli(node):
    l = []
    operation = node.get("operation")
    l.append(cli_display.keyword("date"))
    l.append(cli_display.keyword(operation))
    if operation in utils.olist(vars.simple_date_ops):
        value = node.get(utils.keyword_cmp(operation, 'lt') and "end" or "start")
        l.append('"%s"' % cli_display.attr_value(value))
    else:
        if operation == 'in_range':
            for name in vars.in_range_attrs:
                v = node.get(name)
                if v:
                    l.append(nvpair_format(name, v))
        for c in node.iterchildren():
            if c.tag in ("duration", "date_spec"):
                pl = []
                for name in c.keys():
                    if name != "id":
                        pl.append([name, c.get(name)])
                l.append(cli_pairs(pl))
    return ' '.join(l)


def binary_op_format(op):
    l = op.split(':')
    if len(l) == 2:
        return "%s:%s" % (l[0], cli_display.keyword(l[1]))
    else:
        return cli_display.keyword(op)


def exp2cli(node):
    operation = node.get("operation")
    type = node.get("type")
    if type:
        operation = "%s:%s" % (type, operation)
    attribute = node.get("attribute")
    value = node.get("value")
    if not value:
        return "%s %s" % (binary_op_format(operation), attribute)
    else:
        return "%s %s %s" % (attribute, binary_op_format(operation), value)


def abs_pos_score(score):
    return score in ("inf", "+inf", "Mandatory")


def get_kind(node):
    kind = node.get("kind")
    if not kind:
        kind = ""
    return kind


def get_score(node):
    score = node.get("score")
    if not score:
        score = node.get("score-attribute")
    else:
        if score.find("INFINITY") >= 0:
            score = score.replace("INFINITY", "inf")
    if not score:
        score = ""
    return score


def cli_rule(node):
    s = []
    node_id = node.get("id")
    if node_id:
        s.append('$id="%s"' % node_id)
    else:
        idref = node.get("id-ref")
        if idref:
            return '$id-ref="%s"' % idref
    rsc_role = node.get("role")
    if rsc_role:
        s.append('$role="%s"' % rsc_role)
    s.append("%s:" % cli_display.score(get_score(node)))
    bool_op = node.get("boolean-op")
    if not bool_op:
        bool_op = "and"
    exp = []
    for c in node.iterchildren():
        if c.tag == "date_expression":
            exp.append(date_exp2cli(c))
        elif c.tag == "expression":
            exp.append(exp2cli(c))
    expression = (" %s " % cli_display.keyword(bool_op)).join(exp)
    return "%s %s" % (' '.join(s), expression)


def mkrscrole(node, n):
    rsc = cli_display.rscref(node.get(n))
    rsc_role = node.get(n + "-role")
    rsc_instance = node.get(n + "-instance")
    if rsc_role:
        return "%s:%s" % (rsc, rsc_role)
    elif rsc_instance:
        return "%s:%s" % (rsc, rsc_instance)
    else:
        return rsc


def mkrscaction(node, n):
    rsc = cli_display.rscref(node.get(n))
    rsc_action = node.get(n + "-action")
    rsc_instance = node.get(n + "-instance")
    if rsc_action:
        return "%s:%s" % (rsc, rsc_action)
    elif rsc_instance:
        return "%s:%s" % (rsc, rsc_instance)
    else:
        return rsc


def rsc_set_constraint(node, obj_type):
    col = []
    cnt = 0
    for n in node.findall("resource_set"):
        add_seq = False
        sequential = utils.get_boolean(n.get("sequential"), True)
        require_all = utils.get_boolean(n.get("require-all"), True)
        if not require_all:
            col.append("[")
            if sequential:
                add_seq = True
        elif not sequential:
            col.append("(")
        role = n.get("role")
        action = n.get("action")
        for r in n.findall("resource_ref"):
            rsc = cli_display.rscref(r.get("id"))
            q = (obj_type == "order") and action or role
            col.append(q and "%s:%s" % (rsc, q) or rsc)
            cnt += 1
        if not require_all:
            if add_seq:
                col.append('sequential="true"')
            col.append("]")
        elif not sequential:
            col.append(")")
    if (sequential and require_all and obj_type != "rsc_ticket" and cnt <= 2) or \
            (obj_type == "rsc_ticket" and cnt <= 1):  # a degenerate thingie
        col.insert(0, "_rsc_set_")
    return col


def simple_rsc_constraint(node, obj_type):
    col = []
    if obj_type == "colocation":
        col.append(mkrscrole(node, "rsc"))
        col.append(mkrscrole(node, "with-rsc"))
    elif obj_type == "order":
        col.append(mkrscaction(node, "first"))
        col.append(mkrscaction(node, "then"))
    else:  # rsc_ticket
        col.append(mkrscrole(node, "rsc"))
    return col


# this pre (or post)-processing is oversimplified
# but it will do for now
# (a shortcut with more than one placeholder in a single expansion
# cannot have more than one expansion)
# ("...'@@'...'@@'...","...") <- that won't work
def build_exp_re(exp_l):
    return [x.replace(r'@@', r'([a-zA-Z_][a-zA-Z0-9_.-]*)') for x in exp_l]


def match_acl_shortcut(xpath, re_l):
    import re
    for i in range(len(re_l)):
        s = ''.join(re_l[0:i+1])
        r = re.match(s + r"$", xpath)
        if r:
            return (True, r.groups()[0:i+1])
    return (False, None)


def find_acl_shortcut(xpath):
    for shortcut in vars.acl_shortcuts:
        l = build_exp_re(vars.acl_shortcuts[shortcut])
        (ec, spec_l) = match_acl_shortcut(xpath, l)
        if ec:
            return (shortcut, spec_l)
    return (None, None)


def acl_spec_format(xml_spec, v):
    key_f = cli_display.keyword(vars.acl_spec_map[xml_spec])
    if xml_spec == "xpath":
        (shortcut, spec_l) = find_acl_shortcut(v)
        if shortcut:
            key_f = cli_display.keyword(shortcut)
            v_f = ':'.join([cli_display.attr_value(x) for x in spec_l])
        else:
            v_f = '"%s"' % cli_display.attr_value(v)
    elif xml_spec == "ref":
        v_f = '%s' % cli_display.attr_value(v)
    else:  # tag and attribute
        v_f = '%s' % cli_display.attr_value(v)
    return v_f and '%s:%s' % (key_f, v_f) or key_f


def cli_acl_rule(node, format=1):
    l = []
    acl_rule_name = node.tag
    l.append(cli_display.keyword(acl_rule_name))
    for xml_spec in vars.acl_spec_map:
        v = node.get(xml_spec)
        if v:
            l.append(acl_spec_format(xml_spec, v))
    return ' '.join(l)


def cli_acl_roleref(node, format=1):
    l = []
    l.append(cli_display.keyword("role"))
    l.append(":")
    l.append(cli_display.attr_value(node.get("id")))
    return ''.join(l)

#
################################################################

cli_display = CliDisplay.getInstance()

# vim:ts=4:sw=4:et:
