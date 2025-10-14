# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# See COPYING for license information.

from . import constants
from . import clidisplay
from . import utils
from . import xmlutil
from . import cibconfig


#
# CLI format generation utilities (from XML)
#
def cli_format(pl, break_lines=True, xml=False):
    if break_lines and xml:
        return ' \\\n'.join(pl)
    elif break_lines:
        return ' \\\n\t'.join(pl)
    else:
        return ' '.join(pl)


def head_id_format(nodeid):
    "Special format for property list / node id"
    if utils.noquotes(nodeid):
        return "%s:" % (clidisplay.ident(nodeid))
    return '%s="%s"' % (clidisplay.ident('$id'),
                        clidisplay.attr_value(nodeid))


def quote_wrap(v):
    if utils.noquotes(v):
        return v
    elif '"' in v:
        return '"%s"' % v.replace('"', '\\"')
    else:
        return '"%s"' % v


def nvpair_format(n, v):
    if v is None:
        return clidisplay.attr_name(n)
    else:
        return '='.join((clidisplay.attr_name(n),
                         clidisplay.attr_value(quote_wrap(v))))


def cli_nvpair(nvp):
    'Converts an nvpair tag or a (name, value) pair to CLI syntax'
    nodeid = nvp.get('id')
    idref = nvp.get('id-ref')
    name = nvp.get('name')
    value = nvp.get('value')
    value = utils.obscured(name, value)
    if idref is not None:
        if name is not None:
            return '@%s:%s' % (idref, name)
        return '@%s' % (idref)
    elif nodeid is not None and cibconfig.cib_factory_instance().is_id_refd(nvp.tag, nodeid):
        return '$%s:%s' % (nodeid, nvpair_format(name, value))
    return nvpair_format(name, value)


def cli_nvpairs(nvplist):
    'Return a string of name="value" pairs (passed in a list of nvpairs).'
    return ' '.join([cli_nvpair(nvp) for nvp in nvplist])


def nvpairs2list(node, add_id=False):
    '''
    Convert an attribute node to a list of nvpairs.
    Also converts an id-ref or id into plain nvpairs.
    The id attribute is normally skipped, since they tend to be
    long and therefore obscure the relevant content. For some
    elements, however, they are included (e.g. properties).
    '''
    ret = []
    if 'id-ref' in node:
        ret.append(xmlutil.nvpair('$id-ref', node.get('id-ref')))
    nvpairs = node.xpath('./nvpair | ./attributes/nvpair')
    if 'id' in node and (add_id or len(nvpairs) == 0):
        ret.append(xmlutil.nvpair('$id', node.get('id')))
    ret.extend(nvpairs)
    return ret


def date_exp2cli(node):
    kwmap = {'in_range': 'in', 'date_spec': 'spec'}
    l = []
    operation = node.get("operation")
    l.append(clidisplay.keyword("date"))
    l.append(clidisplay.keyword(kwmap.get(operation, operation)))
    if operation in utils.olist(constants.simple_date_ops):
        value = node.get(utils.keyword_cmp(operation, 'lt') and "end" or "start")
        l.append(clidisplay.attr_value(quote_wrap(value)))
    else:
        if operation == 'in_range':
            for name in constants.in_range_attrs:
                if name in node.attrib:
                    l.append(nvpair_format(name, node.attrib[name]))
        for c in node.iterchildren():
            if c.tag in ("duration", "date_spec"):
                l.extend([nvpair_format(name, c.get(name))
                          for name in list(c.keys()) if name != 'id'])
    return ' '.join(l)


def binary_op_format(op):
    l = op.split(':')
    if len(l) == 2:
        return "%s:%s" % (l[0], clidisplay.keyword(l[1]))
    else:
        return clidisplay.keyword(op)


def exp2cli(node):
    operation = node.get("operation")
    typ = node.get("type")
    if typ:
        operation = "%s:%s" % (typ, operation)
    attribute = node.get("attribute")
    value = node.get("value")
    if not value:
        return "%s %s" % (binary_op_format(operation), attribute)
    else:
        value_source = node.get("value-source")
        if not value_source or value_source == "literal":
            return "%s %s %s" % (attribute, binary_op_format(operation), value)
        else:
            return "%s %s %s{%s}" % (attribute, binary_op_format(operation), value_source, value)


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


def cli_rule_score(node):
    score = node.get("score")
    if score == "INFINITY":
        return None
    return get_score(node)


def cli_exprs(node):
    bool_op = node.get("boolean-op")
    if not bool_op:
        bool_op = "and"
    exp = []
    for c in node.iterchildren():
        if c.tag == "date_expression":
            exp.append(date_exp2cli(c))
        elif c.tag == "expression":
            exp.append(exp2cli(c))
    return (" %s " % clidisplay.keyword(bool_op)).join(exp)


def cli_rule(node):
    s = []
    node_id = node.get("id")
    if node_id and cibconfig.cib_factory_instance().is_id_refd(node.tag, node_id):
        s.append(nvpair_format('$id', node_id))
    else:
        idref = node.get("id-ref")
        if idref:
            return nvpair_format('$id-ref', idref)
    rsc_role = node.get("role")
    if rsc_role:
        s.append(nvpair_format('$role', rsc_role))
    score = cli_rule_score(node)
    if score:
        s.append("%s:" % (clidisplay.score(score)))
    s.append(cli_exprs(node))
    return ' '.join(s)


def mkrscrole(node, n):
    rsc = clidisplay.rscref(node.get(n))
    rsc_role = node.get(n + "-role")
    rsc_instance = node.get(n + "-instance")
    if rsc_role:
        return "%s:%s" % (rsc, rsc_role)
    elif rsc_instance:
        return "%s:%s" % (rsc, rsc_instance)
    else:
        return rsc


def mkrscaction(node, n):
    rsc = clidisplay.rscref(node.get(n))
    rsc_action = node.get(n + "-action")
    rsc_instance = node.get(n + "-instance")
    if rsc_action:
        return "%s:%s" % (rsc, rsc_action)
    elif rsc_instance:
        return "%s:%s" % (rsc, rsc_instance)
    else:
        return rsc


def cli_path(p):
    return clidisplay.attr_value(quote_wrap(p))


def boolean_maybe(v):
    "returns True/False or None"
    if v is None:
        return None
    return utils.get_boolean(v)


def rsc_set_constraint(node, obj_type):
    col = []
    cnt = 0
    for n in node.findall("resource_set"):
        sequential = boolean_maybe(n.get("sequential"))
        require_all = boolean_maybe(n.get("require-all"))
        if require_all is False:
            col.append("[")
        elif sequential is False:
            col.append("(")
        role = n.get("role")
        action = n.get("action")
        for r in n.findall("resource_ref"):
            rsc = clidisplay.rscref(r.get("id"))
            q = (obj_type == "order") and action or role
            col.append(q and "%s:%s" % (rsc, q) or rsc)
            cnt += 1
        if require_all is False:
            if sequential in (None, True):
                col.append(nvpair_format('sequential', 'true'))
            col.append("]")
        elif sequential is False:
            if require_all is False:
                col.append(nvpair_format('require-all', 'false'))
            col.append(")")
    is_ticket = obj_type == 'rsc_ticket'
    is_location = obj_type == 'location'
    is_seq_all = sequential in (None, True) and require_all in (None, True)
    if not is_location and ((is_seq_all and not is_ticket and cnt <= 2) or
                            (is_ticket and cnt <= 1)):  # a degenerate thingie
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
    for shortcut in constants.acl_shortcuts:
        l = build_exp_re(constants.acl_shortcuts[shortcut])
        (ec, spec_l) = match_acl_shortcut(xpath, l)
        if ec:
            return (shortcut, spec_l)
    return (None, None)


def acl_spec_format(xml_spec, v):
    key_f = clidisplay.keyword(constants.acl_spec_map[xml_spec])
    if xml_spec == "xpath":
        (shortcut, spec_l) = find_acl_shortcut(v)
        if shortcut:
            key_f = clidisplay.keyword(shortcut)
            v_f = ':'.join([clidisplay.attr_value(x) for x in spec_l])
        else:
            v_f = clidisplay.attr_value(quote_wrap(v))
    elif xml_spec == "ref":
        v_f = '%s' % clidisplay.attr_value(v)
    else:  # tag and attribute
        v_f = '%s' % clidisplay.attr_value(v)
    return v_f and '%s:%s' % (key_f, v_f) or key_f


def cli_acl_rule(node, format_mode=1):
    l = []
    acl_rule_name = node.tag
    l.append(clidisplay.keyword(acl_rule_name))
    for xml_spec in constants.acl_spec_map:
        v = node.get(xml_spec)
        if v:
            l.append(acl_spec_format(xml_spec, v))
    return ' '.join(l)


def cli_acl_roleref(node, format_mode=1):
    return "%s:%s" % (clidisplay.keyword("role"),
                      clidisplay.attr_value(node.get("id")))


def cli_acl_role(node):
    return clidisplay.attr_value(node.get("id"))


def cli_acl_spec2_format(xml_spec, v):
    key_f = clidisplay.keyword(xml_spec)
    if xml_spec == "xpath":
        (shortcut, spec_l) = find_acl_shortcut(v)
        if shortcut:
            key_f = clidisplay.keyword(shortcut)
            v_f = ':'.join([clidisplay.attr_value(x) for x in spec_l])
        else:
            v_f = clidisplay.attr_value(quote_wrap(v))
    else:  # ref, type and attr
        v_f = clidisplay.attr_value(v)
    return v_f and '%s:%s' % (key_f, v_f) or key_f


def cli_acl_permission(node):
    s = [clidisplay.keyword(node.get('kind'))]
    # if node.get('id'):
    #     s.append(head_id_format(node.get('id')))
    if node.get('description'):
        s.append(nvpair_format('description', node.get('description')))
    for attrname, cliname in constants.acl_spec_map_2_rev:
        if attrname in node.attrib:
            s.append(cli_acl_spec2_format(cliname, node.get(attrname)))
    return ' '.join(s)

#
################################################################

# vim:ts=4:sw=4:et:
