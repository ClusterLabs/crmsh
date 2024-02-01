# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2013-2016 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import shlex
import re
import inspect
from lxml import etree
from . import ra
from . import constants
from .ra import disambiguate_ra_type, ra_type_validate
from . import schema
from .utils import keyword_cmp, verify_boolean, lines2cli
from .utils import get_boolean, olist, canonical_boolean
from .utils import handle_role_for_ocf_1_1, compatible_role, add_time_unit_if_needed
from . import xmlutil
from . import log


logger = log.setup_logger(__name__)
logger_utils = log.LoggerUtils(logger)


_NVPAIR_RE = re.compile(r'([^=@$][^=]*)=(.*)$')
_NVPAIR_ID_RE = re.compile(r'\$([^:=]+)(?::(.+))?=(.*)$')
_NVPAIR_REF_RE = re.compile(r'@([^:]+)(?::(.+))?$')
_NVPAIR_KEY_RE = re.compile(r'([^:=]+)$', re.IGNORECASE)
_IDENT_RE = re.compile(r'([a-z0-9_#$-][^=]*)$', re.IGNORECASE)
_DISPATCH_RE = re.compile(r'[a-z0-9_]+$', re.IGNORECASE)
_DESC_RE = re.compile(r'description=(.+)$', re.IGNORECASE)
_ATTR_RE = re.compile(r'\$?([^=]+)=(.*)$')
_ALERT_PATH_RE = re.compile(r'(.*)$')
_RESOURCE_RE = re.compile(r'([a-z_#$][^=]*)$', re.IGNORECASE)
_IDSPEC_RE = re.compile(r'(\$id-ref|\$id)=(.*)$', re.IGNORECASE)
_ID_RE = re.compile(r'\$id=(.*)$', re.IGNORECASE)
_ID_NEW_RE = re.compile(r'([\w-]+):$', re.IGNORECASE)
_SCORE_RE = re.compile(r"([^:]+):$")
_ROLE_RE = re.compile(r"\$?role=(.+)$", re.IGNORECASE)
_BOOLOP_RE = re.compile(r'(%s)$' % ('|'.join(constants.boolean_ops)), re.IGNORECASE)
_UNARYOP_RE = re.compile(r'(%s)$' % ('|'.join(constants.unary_ops)), re.IGNORECASE)
_ACL_RIGHT_RE = re.compile(r'(%s)$' % ('|'.join(constants.acl_rule_names)), re.IGNORECASE)
_ROLE_REF_RE = re.compile(r'role:(.+)$', re.IGNORECASE)
_PERM_RE = re.compile(r"([^:]+)(?::(.+))?$", re.I)
_UNAME_RE = re.compile(r'([^:]+)(:(normal|member|ping|remote))?$', re.IGNORECASE)
_TEMPLATE_RE = re.compile(r'@(.+)$')
_RA_TYPE_RE = re.compile(r'[a-z0-9_:-]+$', re.IGNORECASE)
_TAG_RE = re.compile(r"([a-zA-Z_][^\s:]*):?$")
_ROLE2_RE = re.compile(r"role=(.+)$", re.IGNORECASE)
_TARGET_RE = re.compile(r'([^:]+):$')
_TARGET_ATTR_RE = re.compile(r'attr:([\w-]+)=([\w-]+)$', re.IGNORECASE)
_TARGET_PATTERN_RE = re.compile(r'pattern:(.+)$', re.IGNORECASE)
TERMINATORS = ('params', 'meta', 'utilization', 'operations', 'op', 'op_params', 'op_meta', 'rule', 'attributes')


class ParseError(Exception):
    '''
    Raised by parsers when parsing fails.
    No error message, parsers should write
    error messages before raising the exception.
    '''


class Validation(object):
    def resource_roles(self):
        'returns list of valid resource roles'
        return schema.rng_attr_values('resource_set', 'role')

    def resource_actions(self):
        'returns list of valid resource actions'
        return schema.rng_attr_values('resource_set', 'action')

    def date_ops(self):
        'returns list of valid date operations'
        return schema.rng_attr_values_l('date_expression', 'operation')

    def expression_types(self):
        'returns list of valid expression types'
        return schema.rng_attr_values_l('expression', 'type')

    def rsc_order_kinds(self):
        return schema.rng_attr_values('rsc_order', 'kind')

    def class_provider_type(self, value):
        """
        Unravel [class:[provider:]]type
        returns: (class, provider, type)
        """
        c_p_t = disambiguate_ra_type(value)
        if not ra_type_validate(value, *c_p_t):
            return None
        return c_p_t

    def canonize(self, value, lst):
        'case-normalizes value to what is in lst'
        value = value.lower()
        for x in lst:
            if value == x.lower():
                return x
        return None

    def classify_role(self, role):
        if not role:
            return role, None
        elif role in olist(self.resource_roles()):
            return self.canonize(role, self.resource_roles()), 'role'
        elif role.isdigit():
            return role, 'instance'
        return role, None

    def classify_action(self, action):
        if not action:
            return action, None
        elif action in olist(self.resource_actions()):
            return self.canonize(action, self.resource_actions()), 'action'
        elif action.isdigit():
            return action, 'instance'
        return action, None

    def op_attributes(self):
        return olist(schema.get('attr', 'op', 'a'))

    def acl_2_0(self):
        vname = schema.validate_name()
        sp = vname.split('-')
        try:
            return sp[0] == 'pacemaker' and sp[1] == 'next' or float(sp[1]) >= 2.0
        except Exception:
            return False

    def node_type_optional(self):
        ns = {'t': 'http://relaxng.org/ns/structure/1.0'}
        path = '//t:element[@name="nodes"]'
        path = path + '//t:element[@name="node"]/t:optional/t:attribute[@name="type"]'
        has_optional = schema.rng_xpath(path, namespaces=ns)
        return len(has_optional) > 0


validator = Validation()


class BaseParser(object):
    _BINOP_RE = None
    _VALUE_SOURCE_RE = None

    def parse(self, cmd):
        "Called by do_parse(). Raises ParseError if parsing fails."
        raise NotImplementedError

    def err(self, msg, context=None, token=None):
        "Report a parse error and abort."
        if token is None and self.has_tokens():
            token = self._cmd[self._currtok]
        if context is None:
            context = self._cmd[0]
        logger_utils.syntax_err(self._cmd, context=context, token=token, msg=msg)
        raise ParseError

    def begin(self, cmd, min_args=-1):
        self._cmd = cmd
        self._currtok = 0
        self._lastmatch = None
        if min_args > -1 and len(cmd) < min_args + 1:
            self.err("Expected at least %d arguments" % (min_args))

    def begin_dispatch(self, cmd, min_args=-1):
        """
        Begin parsing cmd.
        Dispatches to parse_<resource> based on the first token.
        """
        self.begin(cmd, min_args=min_args)
        return self.match_dispatch(errmsg="Unknown command")

    def do_parse(self, cmd, ignore_empty, complete_advised):
        """
        Called by CliParser. Calls parse()
        Parsers should pass their return value through this method.
        """
        self.ignore_empty = ignore_empty
        self.complete_advised = complete_advised
        out = self.parse(cmd)
        if self.has_tokens():
            self.err("Unknown arguments: " + ' '.join(self._cmd[self._currtok:]))
        return out

    def try_match(self, rx):
        """
        Try to match the given regex with the curren token.
        rx: compiled regex or string
        returns: the match object, if the match is successful
        """
        tok = self.current_token()
        if not tok:
            return None
        if isinstance(rx, str):
            if not rx.endswith('$'):
                rx = rx + '$'
            self._lastmatch = re.match(rx, tok, re.IGNORECASE)
        else:
            self._lastmatch = rx.match(tok)
        if self._lastmatch is not None:
            if not self.has_tokens():
                self.err("Unexpected end of line")
            self._currtok += 1
        return self._lastmatch

    def match(self, rx, errmsg=None):
        """
        Match the given regex with the current token.
        If match fails, parse is aborted and an error reported.
        rx: compiled regex or string.
        errmsg: optional error message if match fails.
        Returns: The matched token.
        """
        if not self.try_match(rx):
            if errmsg:
                self.err(errmsg)
            elif isinstance(rx, str):
                self.err("Expected " + rx)
            else:
                self.err("Expected " + rx.pattern.rstrip('$'))
        return self.matched(0)

    def matched(self, idx=0):
        """
        After a successful match, returns
        the groups generated by the match.
        """
        if hasattr(self._lastmatch, "group"):
            return self._lastmatch.group(idx)
        return None

    def lastmatch(self):
        return self._lastmatch

    def rewind(self):
        "useful for when validation fails, to undo the match"
        if self._currtok > 0:
            self._currtok -= 1

    def current_token(self):
        if self.has_tokens():
            return self._cmd[self._currtok]
        return None

    def has_tokens(self):
        return self._currtok < len(self._cmd)

    def match_rest(self):
        '''
        matches and returns the rest
        of the tokens in a list
        '''
        ret = self._cmd[self._currtok:]
        self._currtok = len(self._cmd)
        return ret

    def match_any(self):
        if not self.has_tokens():
            self.err("Unexpected end of line")
        tok = self.current_token()
        self._currtok += 1
        self._lastmatch = tok
        return tok

    def match_nvpairs_bykey(self, valid_keys, minpairs=1):
        """
        matches string of p=v | p tokens, but only if p is in valid_keys
        Returns list of <nvpair> tags
        """
        _KEY_RE = re.compile(r'(%s)=(.+)$' % '|'.join(valid_keys))
        _NOVAL_RE = re.compile(r'(%s)$' % '|'.join(valid_keys))
        ret = []
        while True:
            if self.try_match(_KEY_RE):
                ret.append(xmlutil.nvpair(self.matched(1), self.matched(2)))
            elif self.try_match(_NOVAL_RE):
                ret.append(xmlutil.nvpair(self.matched(1), ""))
            else:
                break
        if len(ret) < minpairs:
            if minpairs == 1:
                self.err("Expected at least one name-value pair")
            else:
                self.err("Expected at least %d name-value pairs" % (minpairs))
        return ret

    def match_nvpairs(self, terminator=None, minpairs=1, allow_empty=True):
        """
        Matches string of p=v tokens
        Returns list of <nvpair> tags
        p tokens are also accepted and an nvpair tag with no value attribute
        is created, as long as they are not in the terminator list
        """
        ret = []
        if terminator is None:
            terminator = TERMINATORS
        while True:
            tok = self.current_token()
            if tok is not None and tok.lower() in terminator:
                break
            elif self.try_match(_NVPAIR_REF_RE):
                ret.append(xmlutil.nvpair_ref(self.matched(1),
                                              self.matched(2)))
            elif self.try_match(_NVPAIR_ID_RE):
                ret.append(xmlutil.nvpair_id(self.matched(1),
                                             self.matched(2),
                                             self.matched(3)))
            elif self.try_match(_NVPAIR_RE):
                if not allow_empty and not self.matched(2):
                    self.err("Empty value for {} is not allowed".format(self.matched(1)))
                ret.append(xmlutil.nvpair(self.matched(1),
                                          self.matched(2)))
            elif len(terminator) and self.try_match(_NVPAIR_KEY_RE):
                ret.append(xmlutil.new("nvpair", name=self.matched(1)))
            else:
                break
        if len(ret) < minpairs:
            if minpairs == 1:
                self.err("Expected at least one name-value pair")
            else:
                self.err("Expected at least %d name-value pairs" % (minpairs))
        return ret

    def try_match_nvpairs(self, name, terminator=None):
        """
        Matches sequence of <name> [<key>=<value> [<key>=<value> ...] ...]
        """
        if self.try_match(name):
            self._lastmatch = self.match_nvpairs(terminator=terminator, minpairs=1)
        else:
            self._lastmatch = []
        return self._lastmatch

    def match_identifier(self):
        return self.match(_IDENT_RE, errmsg="Expected identifier")

    def match_resource(self):
        return self.match(_RESOURCE_RE, errmsg="Expected resource")

    def match_idspec(self):
        """
        matches $id=<id> | $id-ref=<id>
        matched(1) = $id|$id-ref
        matched(2) = <id>
        """
        return self.match(_IDSPEC_RE, errmsg="Expected $id-ref=<id> or $id=<id>")

    def try_match_idspec(self):
        """
        matches $id=<value> | $id-ref=<value>
        matched(1) = $id|$id-ref
        matched(2) = <value>
        """
        return self.try_match(_IDSPEC_RE)

    def try_match_initial_id(self):
        """
        Used as the first match on certain commands
        like node and property, to match either
        node $id=<id>
        or
        node <id>:
        """
        m = self.try_match(_ID_RE)
        if m:
            return m
        return self.try_match(_ID_NEW_RE)

    def match_split(self):
        """
        matches value[:value]
        """
        if not self.current_token():
            self.err("Expected value[:value]")
        sp = self.current_token().split(':')
        if len(sp) > 2:
            self.err("Expected value[:value]")
        while len(sp) < 2:
            sp.append(None)
        self.match_any()
        return sp

    def match_dispatch(self, errmsg=None):
        """
        Match on the next token. Looks
        for a method named parse_<token>.
        If found, the named function is called.
        Else, an error is reported.
        """
        t = self.match(_DISPATCH_RE, errmsg=errmsg)
        t = 'parse_' + t.lower()
        if hasattr(self, t) and callable(getattr(self, t)):
            return getattr(self, t)()
        self.rewind()  # rewind for more accurate error message
        self.err(errmsg)

    def try_match_description(self):
        """
        reads a description=? token if one is next
        """
        if self.try_match(_DESC_RE):
            return self.matched(1)
        return None

    def match_until(self, end_token):
        tokens = []
        while self.current_token() is not None and self.current_token() != end_token:
            tokens.append(self.match_any())
        return tokens

    def match_attr_list(self, name, tag, allow_empty=True, terminator=None):
        """
        matches [$id=<id>] [<score>:] <n>=<v> <n>=<v> ... | $id-ref=<id-ref>
        if matchname is False, matches:
        <n>=<v> <n>=<v> ...
        """
        from .cibconfig import cib_factory

        xmlid = None
        if self.try_match_idspec():
            if self.matched(1) == '$id-ref':
                r = xmlutil.new(tag)
                ref = cib_factory.resolve_id_ref(name, self.matched(2))
                r.set('id-ref', ref)
                return r
            else:
                xmlid = self.matched(2)
        score = None
        if self.try_match(_SCORE_RE):
            score = self.matched(1)
        rules = self.match_rules()
        values = self.match_nvpairs(minpairs=0, terminator=terminator)
        if (allow_empty, xmlid, score, len(rules), len(values)) == (False, None, None, 0, 0):
            return None
        return xmlutil.attributes(tag, rules, values, xmlid=xmlid, score=score)

    def match_attr_lists(self, name_map, implicit_initial=None, terminator=None):
        """
        generator which matches attr_lists
        name_map: maps CLI name to XML name
        """
        to_match = '|'.join(list(name_map.keys()))
        if self.try_match(to_match):
            name = self.matched(0).lower()
            yield self.match_attr_list(name, name_map[name], terminator=terminator)
        elif implicit_initial is not None:
            attrs = self.match_attr_list(implicit_initial,
                                         name_map[implicit_initial],
                                         allow_empty=False,
                                         terminator=terminator)
            if attrs is not None:
                yield attrs
        while self.try_match(to_match):
            name = self.matched(0).lower()
            yield self.match_attr_list(name, name_map[name], terminator=terminator)

    def match_rules(self):
        '''parse rule definitions'''
        from .cibconfig import cib_factory

        rules = []
        while self.try_match('rule'):
            rule = xmlutil.new('rule')
            rules.append(rule)
            idref = False
            if self.try_match_idspec():
                idtyp, idval = self.matched(1)[1:], self.matched(2)
                if idtyp == 'id-ref':
                    idval = cib_factory.resolve_id_ref('rule', idval)
                    idref = True
                rule.set(idtyp, idval)
            if self.try_match(_ROLE_RE):
                rule.set('role', handle_role_for_ocf_1_1(self.matched(1)))
            if idref:
                continue
            if self.try_match(_SCORE_RE):
                rule.set(*self.validate_score(self.matched(1)))
            else:
                rule.set('score', 'INFINITY')
            boolop, exprs = self.match_rule_expression()
            if boolop and not keyword_cmp(boolop, 'and'):
                rule.set('boolean-op', boolop)
            for expr in exprs:
                rule.append(expr)
        return rules

    def match_rule_expression(self):
        """
        expression :: <simple_exp> [bool_op <simple_exp> ...]
        bool_op :: or | and
        simple_exp :: <attribute> [type:]<binary_op> <value>
                      | <unary_op> <attribute>
                      | date <date_expr>
        type :: string | version | number
        binary_op :: lt | gt | lte | gte | eq | ne
        unary_op :: defined | not_defined

        date_expr :: lt <end>
                     | gt <start>
                     | in_range start=<start> end=<end>
                     | in_range start=<start> <duration>
                     | date_spec <date_spec>
        duration|date_spec ::
                     hours=<value>
                     | monthdays=<value>
                     | weekdays=<value>
                     | yearsdays=<value>
                     | months=<value>
                     | weeks=<value>
                     | years=<value>
                     | weekyears=<value>
                     | moon=<value>
        """
        boolop = None
        exprs = [self._match_simple_exp()]
        while self.try_match(_BOOLOP_RE):
            if boolop and self.matched(1) != boolop:
                self.err("Mixing bool ops not allowed: %s != %s" % (boolop, self.matched(1)))
            else:
                boolop = self.matched(1)
            exprs.append(self._match_simple_exp())
        return boolop, exprs

    def _match_simple_exp(self):
        if self.try_match('date'):
            return self.match_date()
        elif self.try_match(_UNARYOP_RE):
            unary_op = self.matched(1)
            attr = self.match_identifier()
            return xmlutil.new('expression', operation=unary_op, attribute=attr)
        else:
            attr = self.match_identifier()
            if not self._BINOP_RE:
                self._BINOP_RE = re.compile(r'((%s):)?(%s)$' % (
                    '|'.join(validator.expression_types()),
                    '|'.join(constants.binary_ops)), re.IGNORECASE)
            self.match(self._BINOP_RE)
            optype = self.matched(2)
            binop = self.matched(3)
            node = xmlutil.new('expression', operation=binop, attribute=attr)
            xmlutil.maybe_set(node, 'type', optype)
            val = self.match_any()
            if not self._VALUE_SOURCE_RE:
                self._VALUE_SOURCE_RE = re.compile(r"^(?P<val_src>[^\s{}]+)({(?P<val>\S+)})?$")
            val_src_match = re.match(self._VALUE_SOURCE_RE, val)
            if val_src_match.group('val') is None:
                node.set('value', val)
            else:
                node.set('value', val_src_match.group('val'))
                node.set('value-source', val_src_match.group('val_src'))
            return node

    def match_date(self):
        """
        returns for example:
        <date_expression id="" operation="op">
        <date_spec hours="9-16"/>
        </date_expression>
        """
        node = xmlutil.new('date_expression')

        date_ops = validator.date_ops()
        # spec -> date_spec
        if 'date_spec' in date_ops:
            date_ops.append('spec')
        # in -> in_range
        if 'in_range' in date_ops:
            date_ops.append('in')
        self.match('(%s)$' % ('|'.join(date_ops)))
        op = self.matched(1)
        opmap = {'in': 'in_range', 'spec': 'date_spec'}
        node.set('operation', opmap.get(op, op))
        if op in olist(constants.simple_date_ops):
            # lt|gt <value>
            val = self.match_any()
            if keyword_cmp(op, 'lt'):
                node.set('end', val)
            else:
                node.set('start', val)
            return node
        elif op in ('in_range', 'in'):
            # date in start=<start> end=<end>
            # date in start=<start> <duration>
            valid_keys = list(constants.in_range_attrs) + constants.date_spec_names
            vals = self.match_nvpairs_bykey(valid_keys, minpairs=2)
            return xmlutil.set_date_expression(node, 'duration', vals)
        elif op in ('date_spec', 'spec'):
            valid_keys = constants.date_spec_names
            vals = self.match_nvpairs_bykey(valid_keys, minpairs=1)
            return xmlutil.set_date_expression(node, 'date_spec', vals)
        else:
            self.err("Unknown date operation '%s', please upgrade crmsh" % (op))

    def validate_score(self, score, noattr=False, to_kind=False):
        if not noattr and score in olist(constants.score_types):
            return ["score", constants.score_types[score.lower()]]
        elif re.match("^[+-]?(inf(inity)?|INF(INITY)?|[0-9]+)$", score):
            score = re.sub("inf(inity)?|INF(INITY)?", "INFINITY", score)
            if to_kind:
                return ["kind", score_to_kind(score)]
            else:
                return ["score", score]
        if noattr:
            # orders have the special kind attribute
            kind = validator.canonize(score, validator.rsc_order_kinds())
            if not kind:
                self.err("Invalid kind: " + score)
            return ['kind', kind]
        else:
            return ['score-attribute', score]

    def match_arguments(self, out, name_map, implicit_initial=None, terminator=None):
        """
        [<name> attr_list]
        [operations id_spec]
        [op op_type [<attribute>=<value> ...] ...]

        attr_list :: [$id=<id>] <attr>=<val> [<attr>=<val>...] | $id-ref=<id>
        id_spec :: $id=<id> | $id-ref=<id>
        op_type :: start | stop | monitor

        implicit_initial: when matching attr lists, if none match at first
        parse an implicit initial token and then continue.
        This is so for example: primitive foo Dummy state=1 is accepted when
        params is the implicit initial.
        """
        names = olist(list(name_map.keys()))
        oplist = olist([op for op in name_map if op.lower() in ('operations', 'op')])
        for op in oplist:
            del name_map[op]
        bundle_list = olist([op for op in name_map if op.lower()
                            in ('docker', 'rkt', 'network', 'port-mapping', 'storage', 'primitive')])
        for bl in bundle_list:
            del name_map[bl]
        initial = True
        while self.has_tokens():
            t = self.current_token().lower()
            if t in names:
                initial = False
                if t in oplist:
                    self.match_operations(out, t == 'operations')
                if t in bundle_list:
                    self.match_container(out, t)
                else:
                    if bundle_list:
                        terminator = ['network', 'storage', 'primitive']
                    for attr_list in self.match_attr_lists(name_map, terminator=terminator):
                        out.append(attr_list)
            elif initial:
                initial = False
                for attr_list in self.match_attr_lists(name_map,
                                                       implicit_initial=implicit_initial,
                                                       terminator=terminator):
                    out.append(attr_list)
            else:
                break

        self.complete_advised_ops(out)

    def complete_advised_ops(self, out):
        """
        Complete operation actions advised values
        """
        if not self.complete_advised or out.tag != "primitive":
            return
        ra_inst = ra.RAInfo(out.get('class'), out.get('type'), out.get('provider'))
        ra_actions_dict = ra_inst.actions()
        if not ra_actions_dict:
            return

        def extract_advised_value(advised_dict, action, attr, role=None):
            adv_attr_value = None
            try:
                if action == "monitor":
                    if role:
                        for monitor_item in advised_dict[action]:
                            if compatible_role(role, monitor_item['role']):
                                adv_attr_value = monitor_item[attr]
                    else:
                        adv_attr_value = advised_dict[action][0][attr]
                else:
                    adv_attr_value = advised_dict[action][attr]
            except KeyError:
                pass
            return adv_attr_value

        action_advised_attr_dict = {k:v for k, v in ra_actions_dict.items() if k in constants.ADVISED_ACTION_LIST}
        operations_node = out.find("operations")
        configured_action_list = []
        # no operations configured
        if operations_node is None:
            operations_node = xmlutil.child(out, 'operations')
        # has operations configured
        else:
            op_nodes_list = operations_node.findall("op")
            for op_node in op_nodes_list:
                action = op_node.get('name')
                # complete advised value if interval or timeout not configured
                adv_interval = extract_advised_value(action_advised_attr_dict, action, 'interval', op_node.get('role')) or \
                        constants.DEFAULT_INTERVAL_IN_ACTION
                adv_timeout = extract_advised_value(action_advised_attr_dict, action, 'timeout', op_node.get('role'))
                if op_node.get('interval') is None:
                    op_node.set('interval', add_time_unit_if_needed(adv_interval))
                if op_node.get('timeout') is None and adv_timeout:
                    op_node.set('timeout', add_time_unit_if_needed(adv_timeout))
                configured_action_list.append(action)

        for action in action_advised_attr_dict:
            if action in configured_action_list:
                continue
            # complete advised value if the operation not configured
            value = action_advised_attr_dict[action]
            # for multi actions, like multi monitor
            if isinstance(value, list):
                for v_dict in value:
                    op_node = xmlutil.new('op', name=action)
                    for k, v in v_dict.items():
                        # set normal attributes
                        if k in constants.ADVISED_KEY_LIST:
                            if k in ('interval', 'timeout'):
                                v = add_time_unit_if_needed(v)
                            op_node.set(k, handle_role_for_ocf_1_1(v))
                    operations_node.append(op_node)
            else:
                for k, v in value.items():
                    if k in ('interval', 'timeout'):
                        v = add_time_unit_if_needed(v)
                        value.update({k: v})
                op_node = xmlutil.new('op', name=action, **value)
                operations_node.append(op_node)

        out.append(operations_node)

    def match_container(self, out, _type):
        bundle_id = out.get('id')
        container_node = None
        self.match(_type)
        all_attrs = self.match_nvpairs(minpairs=0, terminator=['network', 'storage', 'meta', 'primitive'])

        if _type != "primitive":
            exist_node = out.find(_type)
            if exist_node is None:
                container_node = xmlutil.new(_type)
            else:
                container_node = exist_node

            child_flag = False
            index = 0
            for nvp in all_attrs:
                name = nvp.get('name')
                if name in ('port-mapping', 'storage-mapping'):
                    index += 1
                    inst_attrs = xmlutil.child(container_node, name)
                    # set meaningful id for port-mapping and storage-mapping
                    # when the bundle is newly created
                    if self.complete_advised:
                        id_str = f"{bundle_id}_{name.replace('-', '_')}_{index}"
                        inst_attrs.set('id', id_str)
                    child_flag = True
                    continue
                if child_flag:
                    inst_attrs.set(name, nvp.get('value'))
                else:
                    container_node.set(name, nvp.get('value'))
            out.append(container_node)

        else:
            if len(all_attrs) != 1 or all_attrs[0].get('value'):
                self.err("Expected primitive reference, got {}".format(", ".join("{}={}".format(nvp.get('name'), nvp.get('value') or "") for nvp in all_attrs)))
            xmlutil.child(out, 'crmsh-ref', id=all_attrs[0].get('name'))

    def match_op(self, out, pfx='op'):
        """
        op <optype> [<n>=<v> ...]

        to:
          <op name="monitor" timeout="30" interval="10" id="p_mysql-monitor-10">
            <instance_attributes id="p_mysql-monitor-10-instance_attributes">
              <nvpair name="depth" value="0" id="p_mysql-monitor-10-instance_attributes-depth"/>
            </instance_attributes>
          </op>
        """
        self.match('op')
        op_type = self.match_identifier()
        all_attrs = self.match_nvpairs(minpairs=0)
        node = xmlutil.new('op', name=op_type)
        if not any(nvp.get('name') == 'interval' for nvp in all_attrs) and op_type != "monitor":
            all_attrs.append(xmlutil.nvpair('interval', '0s'))
        valid_attrs = validator.op_attributes()
        inst_attrs = None
        for nvp in all_attrs:
            name = nvp.get('name')
            if name in valid_attrs:
                if inst_attrs is not None:
                    self.err(f"Attribute order error: {name} must appear before any instance attribute")
                value = nvp.get('value')
                if name in ('interval', 'timeout'):
                    value = add_time_unit_if_needed(value)
                node.set(name, value)
            else:
                if inst_attrs is None:
                    inst_attrs = xmlutil.child(node, 'instance_attributes')
                inst_attrs.append(nvp)
        if inst_attrs is not None:
            node.append(inst_attrs)
        for attr_list in self.match_attr_lists({'op_params': 'instance_attributes',
                                                'op_meta': 'meta_attributes'},
                                               implicit_initial='op_params'):
            node.append(attr_list)
        out.append(node)

    def match_operations(self, out, match_id):
        from .cibconfig import cib_factory

        def is_op():
            return self.has_tokens() and self.current_token().lower() == 'op'
        if match_id:
            self.match('operations')
        node = xmlutil.child(out, 'operations')
        if match_id:
            self.match_idspec()
            match_id = self.matched(1)[1:].lower()
            idval = self.matched(2)
            if match_id == 'id-ref':
                idval = cib_factory.resolve_id_ref('operations', idval)

            node.set(match_id, idval)

        # The ID assignment skips the operations node if possible,
        # so we need to pass the prefix (id of the owner node)
        # to match_op
        pfx = out.get('id') or 'op'

        while is_op():
            self.match_op(node, pfx=pfx)


_parsers = {}


def parser_for(*lst):
    def decorator(thing):
        if inspect.isfunction(thing):
            def parse(self, cmd):
                return thing(self, cmd)
            ret = type("Parser-" + '-'.join(lst), (BaseParser,), {'parse': parse})
        else:
            ret = thing
        ret.can_parse = lst
        for x in lst:
            _parsers[x] = ret()
        return ret
    return decorator


@parser_for('node')
def parse_node(self, cmd):
    """
    node [<id>:|$id=<id>] <uname>[:<type>]
      [description=<description>]
      [attributes <param>=<value> [<param>=<value>...]]
      [utilization <param>=<value> [<param>=<value>...]]

    type :: normal | member | ping | remote
    """
    self.begin(cmd, min_args=1)
    self.match('node')
    out = xmlutil.new('node')
    xmlutil.maybe_set(out, "id", self.try_match_initial_id() and self.matched(1))
    self.match(_UNAME_RE, errmsg="Expected uname[:type]")
    out.set("uname", self.matched(1))
    if validator.node_type_optional():
        xmlutil.maybe_set(out, "type", self.matched(3))
    else:
        out.set("type", self.matched(3) or constants.node_default_type)
    xmlutil.maybe_set(out, "description", self.try_match_description())
    self.match_arguments(out, {'attributes': 'instance_attributes',
                               'utilization': 'utilization'},
                         implicit_initial='attributes')
    return out


@parser_for('primitive', 'group', 'clone', 'ms', 'master', 'rsc_template', 'bundle')
class ResourceParser(BaseParser):
    def match_ra_type(self, out):
        "[<class>:[<provider>:]]<type>"
        if not self.current_token():
            self.err("Expected resource type")
        cpt = validator.class_provider_type(self.current_token())
        if not cpt:
            self.err("Unknown resource type")
        self.match_any()
        xmlutil.maybe_set(out, 'class', cpt[0])
        xmlutil.maybe_set(out, 'provider', cpt[1])
        xmlutil.maybe_set(out, 'type', cpt[2])

    def parse(self, cmd):
        return self.begin_dispatch(cmd, min_args=2)

    def _primitive_or_template(self):
        """
        primitive <rsc> {[<class>:[<provider>:]]<type>|@<template>]
          [params attr_list]
          [meta attr_list]
          [utilization attr_list]
          [operations id_spec]
          [op op_type [<attribute>=<value> ...] ...]

        attr_list :: [$id=<id>] <attr>=<val> [<attr>=<val> ...] | $id-ref=<id>
        id_spec :: $id=<id> | $id-ref=<id>
        op_type :: start | stop | monitor
        """
        t = self.matched(0).lower()
        if t == 'primitive':
            out = xmlutil.new('primitive')
        else:
            out = xmlutil.new('template')
        out.set('id', self.match_identifier())
        if t == 'primitive' and self.try_match(_TEMPLATE_RE):
            out.set('template', self.matched(1))
        else:
            self.match_ra_type(out)
        xmlutil.maybe_set(out, 'description', self.try_match_description())
        self.match_arguments(out, {'params': 'instance_attributes',
                                   'meta': 'meta_attributes',
                                   'utilization': 'utilization',
                                   'operations': 'operations',
                                   'op': 'op'}, implicit_initial='params')
        return out

    parse_primitive = _primitive_or_template
    parse_rsc_template = _primitive_or_template

    def _master_or_clone(self):
        if self.matched(0).lower() == 'clone':
            out = xmlutil.new('clone')
        else:
            out = xmlutil.new('master')
        out.set('id', self.match_identifier())

        child = xmlutil.new('crmsh-ref', id=self.match_resource())
        xmlutil.maybe_set(out, 'description', self.try_match_description())
        self.match_arguments(out, {'params': 'instance_attributes',
                                   'meta': 'meta_attributes'}, implicit_initial='params')
        out.append(child)
        return out

    parse_master = _master_or_clone
    parse_ms = _master_or_clone
    parse_clone = _master_or_clone

    def _try_group_resource(self):
        t = self.current_token()
        if (not t) or ('=' in t) or (t.lower() in ('params', 'meta')):
            return None
        return self.match_any()

    def parse_group(self):
        out = xmlutil.new('group')
        out.set('id', self.match_identifier())
        children = []
        while self._try_group_resource():
            child = self.lastmatch()
            if child in children:
                self.err("child %s listed more than once in group %s" %
                         (child, out.get('id')))
            children.append(child)
        xmlutil.maybe_set(out, 'description', self.try_match_description())
        self.match_arguments(out, {'params': 'instance_attributes',
                                   'meta': 'meta_attributes'},
                             implicit_initial='params')
        for child in children:
            xmlutil.child(out, 'crmsh-ref', id=child)
        return out

    def parse_bundle(self):
        out = xmlutil.new('bundle')
        out.set('id', self.match_identifier())
        xmlutil.maybe_set(out, 'description', self.try_match_description())
        self.match_arguments(out, {'docker': 'docker',
                                   'rkt': 'rkt',
                                   'network': 'network',
                                   'port-mapping': 'port-mapping',
                                   'storage': 'storage',
                                   'meta': 'meta_attributes',
                                   'primitive': 'primitive'})
        return out


@parser_for('location', 'colocation', 'collocation', 'order', 'rsc_ticket')
class ConstraintParser(BaseParser):
    def parse(self, cmd):
        return self.begin_dispatch(cmd, min_args=2)

    def parse_location(self):
        """
        location <id> <rsc> [[$]<attribute>=<value>] <score>: <node>
        location <id> <rsc> [[$]<attribute>=<value>] <rule> [<rule> ...]
        rsc :: /<rsc-pattern>/
            | { <rsc-set> }
            | <rsc>
        attribute :: role | resource-discovery
        """
        out = xmlutil.new('rsc_location', id=self.match_identifier())
        if self.try_match('^/(.+)/$'):
            out.set('rsc-pattern', self.matched(1))
        elif self.try_match('{'):
            tokens = self.match_until('}')
            self.match('}')
            if not tokens:
                self.err("Empty resource set")
            parser = ResourceSet('role', tokens, self)
            for rscset in parser.parse():
                out.append(rscset)
        else:
            out.set('rsc', self.match_resource())

        while self.try_match(_ATTR_RE):
            name = self.matched(1)
            value = handle_role_for_ocf_1_1(self.matched(2), name=name)
            out.set(name, value)

        # not sure this is necessary after parse _ATTR_RE in a while loop
        if self.try_match(_ROLE_RE) or self.try_match(_ROLE2_RE):
            out.set('role', handle_role_for_ocf_1_1(self.matched(1)))

        score = False
        if self.try_match(_SCORE_RE):
            score = True
            out.set(*self.validate_score(self.matched(1)))
            out.set('node', self.match_identifier())
            # backwards compatibility: role used to be read here
            if 'role' not in out:
                if self.try_match(_ROLE_RE) or self.try_match(_ROLE2_RE):
                    out.set('role', handle_role_for_ocf_1_1(self.matched(1)))
        if not score:
            rules = self.match_rules()
            out.extend(rules)
            if not rules:
                self.err("expected <score>: <node> or <rule> [<rule> ...]")
        return out

    def parse_colocation(self):
        """
        colocation <id> <score>: <rsc>[:<role>] <rsc>[:<role>] ...
          [node-attribute=<node_attr>]
        """
        out = xmlutil.new('rsc_colocation', id=self.match_identifier())
        self.match(_SCORE_RE, errmsg="Expected <score>:")
        out.set(*self.validate_score(self.matched(1)))
        if self.try_match_tail('node-attribute=(.+)$'):
            out.set('node-attribute', self.matched(1).lower())
        self.try_match_rscset(out, 'role')
        return out

    parse_collocation = parse_colocation

    def parse_order(self):
        '''
        order <id> [kind] <rsc>[:<action>] <rsc>[:<action>] ...
          [symmetrical=<bool>]

        kind :: Mandatory | Optional | Serialize
        '''
        out = xmlutil.new('rsc_order', id=self.match_identifier())
        if self.try_match('(%s):$' % ('|'.join(validator.rsc_order_kinds()))):
            out.set('kind', validator.canonize(
                self.matched(1), validator.rsc_order_kinds()))
        elif self.try_match(_SCORE_RE):
            out.set(*self.validate_score(self.matched(1), noattr=True, to_kind=True))
        if self.try_match_tail('symmetrical=(true|false|yes|no|on|off)$'):
            out.set('symmetrical', canonical_boolean(self.matched(1)))
        self.try_match_rscset(out, 'action')
        return out

    def parse_rsc_ticket(self):
        '''
        rsc_ticket <id> <ticket_id>: <rsc>[:<role>] [<rsc>[:<role>] ...]
        [loss-policy=<loss_policy_action>]

        loss_policy_action :: stop | demote | fence | freeze
        '''
        out = xmlutil.new('rsc_ticket', id=self.match_identifier())
        self.match(_SCORE_RE, errmsg="Expected <ticket-id>:")
        out.set('ticket', self.matched(1))
        if self.try_match_tail('loss-policy=(stop|demote|fence|freeze)$'):
            out.set('loss-policy', self.matched(1))
        self.try_match_rscset(out, 'role', simple_count=1)
        return out

    def try_match_rscset(self, out, suffix_type, simple_count=2):
        simple, resources = self.match_resource_set(suffix_type, simple_count=simple_count)
        if simple:
            for n, v in resources:
                out.set(n, v)
        elif resources:
            for rscset in resources:
                out.append(rscset)
        else:
            def repeat(v, n):
                for _ in range(0, n):
                    yield v
            self.err("Expected %s | resource_sets" %
                     " ".join(repeat("<rsc>[:<%s>]" % (suffix_type), simple_count)))

    def try_match_tail(self, rx):
        "ugly hack to prematurely extract a tail attribute"
        pos = self._currtok
        self._currtok = len(self._cmd) - 1
        ret = self.try_match(rx)
        if ret:
            self._cmd = self._cmd[:-1]
        self._currtok = pos
        return ret

    def remaining_tokens(self):
        return len(self._cmd) - self._currtok

    def match_resource_set(self, suffix_type, simple_count=2):
        simple = False
        if self.remaining_tokens() == simple_count:
            simple = True
            if suffix_type == 'role':
                return True, self.match_simple_role_set(simple_count)
            else:
                return True, self.match_simple_action_set()
        tokens = self.match_rest()
        parser = ResourceSet(suffix_type, tokens, self)
        return simple, parser.parse()

    def _fmt(self, info, name):
        if info[1]:
            return [[name, info[0]], [name + '-' + info[2], info[1]]]
        return [[name, info[0]]]

    def _split_setref(self, typename, classifier):
        rsc, typ = self.match_split()
        typ, t = classifier(handle_role_for_ocf_1_1(typ, name=typename))
        if typ and not t:
            self.err("Invalid %s '%s' for '%s'" % (typename, typ, rsc))
        return rsc, typ, t

    def match_simple_role_set(self, count):
        ret = self._fmt(self._split_setref('role', validator.classify_role), 'rsc')
        if count == 2:
            ret += self._fmt(self._split_setref('role', validator.classify_role), 'with-rsc')
        return ret

    def match_simple_action_set(self):
        ret = self._fmt(self._split_setref('action', validator.classify_action), 'first')
        return ret + self._fmt(self._split_setref('action', validator.classify_action), 'then')


@parser_for('monitor')
class OpParser(BaseParser):
    def parse(self, cmd):
        return self.begin_dispatch(cmd, min_args=2)

    def parse_monitor(self):
        out = xmlutil.new('op', name="monitor")
        resource, role = self.match_split()
        if role:
            role, role_class = validator.classify_role(role)
            if not role_class:
                self.err("Invalid role '%s' for resource '%s'" % (role, resource))
            out.set(role_class, role)
        out.set('rsc', resource)
        interval, timeout = self.match_split()
        xmlutil.maybe_set(out, 'interval', interval)
        xmlutil.maybe_set(out, 'timeout', timeout)
        return out


@parser_for('property', 'rsc_defaults', 'op_defaults')
def property_parser(self, cmd):
    """
    property = <cluster_property_set>...</>
    rsc_defaults = <rsc_defaults><meta_attributes>...</></>
    op_defaults = <op_defaults><meta_attributes>...</></>
    """
    from .cibconfig import cib_factory

    setmap = {'property': 'cluster_property_set',
              'rsc_defaults': 'meta_attributes',
              'op_defaults': 'meta_attributes'}
    self.begin(cmd, min_args=1)
    self.match('(%s)$' % '|'.join(self.can_parse))
    if self.matched(1) in constants.defaults_tags:
        root = xmlutil.new(self.matched(1))
        attrs = xmlutil.child(root, setmap[self.matched(1)])
    else:  # property -> cluster_property_set
        root = xmlutil.new(setmap[self.matched(1)])
        attrs = root
    if self.try_match_initial_id():
        attrs.set('id', self.matched(1))
    elif self.try_match_idspec():
        idkey = self.matched(1)[1:]
        idval = self.matched(2)
        if idkey == 'id-ref':
            idval = cib_factory.resolve_id_ref(attrs.tag, idval)
        attrs.set(idkey, idval)
    for rule in self.match_rules():
        attrs.append(rule)
    if self.ignore_empty:
        res_list = self.match_nvpairs(minpairs=0)
    else:
        res_list = self.match_nvpairs(terminator=[], minpairs=0, allow_empty=False)
    for nvp in res_list:
        attrs.append(nvp)
    return root


@parser_for('fencing-topology', 'fencing_topology')
class FencingOrderParser(BaseParser):
    '''
    <fencing-topology>
    <fencing-level id=<id> target=<text> index=<+int> devices=r"\\w,\\w..."/>
    </fencing-topology>

    new:

    from 1.1.14 on, target can be a node attribute value mapping:

    attr:<name>=<value> maps to XML:

    <fencing-topology>
    <fencing-level id=<id> target-attribute=<text> target-value=<text>
                   index=<+int> devices=r"\\w,\\w..."/>
    </fencing-topology>

    from 1.1.14 on, target can be a regexp pattern:

    pattern:<pattern> maps to XML:

    <fencing-topology>
    <fencing-level id=<id> target-pattern=<pattern>
                   index=<+int> devices=r"\\w,\\w..."/>
    </fencing-topology>

    fencing-topology \
      pcmk-1: poison-pill power \
      pcmk-2: disk,network power

    '''
    def parse(self, cmd):
        self.begin(cmd)
        if not self.try_match("fencing-topology"):
            self.match("fencing_topology")
        target = "@@"
        # (target, devices)
        raw_levels = []
        while self.has_tokens():
            if self.try_match(_TARGET_ATTR_RE):
                target = (self.matched(1), self.matched(2))
            elif self.try_match(_TARGET_PATTERN_RE):
                target = (None, self.matched(1))
            elif self.try_match(_TARGET_RE):
                target = self.matched(1)
            else:
                raw_levels.append((target, self.match_any()))
        return self._postprocess_levels(raw_levels)

    def _postprocess_levels(self, raw_levels):
        from collections import defaultdict
        from itertools import repeat
        from .cibconfig import cib_factory
        if len(raw_levels) == 0:
            def no_levels():
                return []
            lvl_generator = no_levels
        elif raw_levels[0][0] == "@@":
            def node_levels():
                for node in cib_factory.node_id_list():
                    for target, devices in raw_levels:
                        yield node, devices
            lvl_generator = node_levels
        else:
            def wrap_levels():
                return raw_levels
            lvl_generator = wrap_levels

        out = xmlutil.new('fencing-topology')
        targets = defaultdict(repeat(1).__next__)
        for target, devices in lvl_generator():
            if isinstance(target, tuple):
                if target[0] is None:
                    # pattern
                    c = xmlutil.child(out, 'fencing-level',
                                      index=str(targets[target[1]]),
                                      devices=devices)
                    c.set('target-pattern', target[1])
                    targets[target[1]] += 1
                else:
                    c = xmlutil.child(out, 'fencing-level',
                                      index=str(targets[target[0]]),
                                      devices=devices)
                    c.set('target-attribute', target[0])
                    c.set('target-value', target[1])
                    targets[target[0]] += 1
            else:
                xmlutil.child(out, 'fencing-level',
                              target=target,
                              index=str(targets[target]),
                              devices=devices)
                targets[target] += 1

        return out


@parser_for('tag')
def parse_tag(self, cmd):
    """
    <tag id=id>
      <obj_ref id=rsc/>
      ...
    </tag>
    """
    self.begin(cmd, min_args=2)
    self.match('tag')
    self.match(_TAG_RE, errmsg="Expected tag name")
    out = xmlutil.new('tag', id=self.matched(1))
    while self.has_tokens():
        e = xmlutil.new('obj_ref', id=self.match_resource())
        out.append(e)
    if len(out) == 0:
        self.err("Expected at least one resource")
    return out


@parser_for('user', 'role', 'acl_target', 'acl_group')
class AclParser(BaseParser):
    def parse(self, cmd):
        return self.begin_dispatch(cmd, min_args=2)

    def parse_user(self):
        out = xmlutil.new('acl_user')
        out.set('id', self.match_identifier())
        while self.has_tokens():
            # role identifier
            if self.try_match(_ROLE_REF_RE):
                xmlutil.child(out, 'role_ref', id=self.matched(1))
            # acl right rule
            else:
                out.append(self._add_rule())
        return out

    def parse_acl_target(self):
        out = xmlutil.new('acl_target')
        out.set('id', self.match_identifier())
        while self.has_tokens():
            xmlutil.child(out, 'role', id=self.match_identifier())
        return out

    def parse_acl_group(self):
        out = xmlutil.new('acl_group')
        out.set('id', self.match_identifier())
        while self.has_tokens():
            xmlutil.child(out, 'role', id=self.match_identifier())
        return out

    def parse_role(self):
        out = xmlutil.new('acl_role')
        out.set('id', self.match_identifier())

        if validator.acl_2_0():
            xmlutil.maybe_set(out, "description", self.try_match_description())
            while self.has_tokens():
                self._add_permission(out)
        else:
            while self.has_tokens():
                out.append(self._add_rule())
        return out

    def _is_permission(self, val):
        def permission(x):
            return x in constants.acl_spec_map_2 or x in constants.acl_shortcuts
        x = val.split(':', 1)
        return len(x) > 0 and permission(x[0])

    def _add_permission(self, out):
        rule = xmlutil.new('acl_permission')
        rule.set('kind', self.match(_ACL_RIGHT_RE).lower())
        if self.try_match_initial_id():
            rule.set('id', self.matched(1))
        xmlutil.maybe_set(rule, "description", self.try_match_description())

        attributes = {}

        while self.has_tokens():
            if not self._is_permission(self.current_token()):
                break
            self.match(_PERM_RE, errmsg="Expected <type>:<spec>")
            typ = self.matched(1)
            typ = constants.acl_spec_map_2.get(typ, typ)
            val = self.matched(2)
            if typ in constants.acl_shortcuts:
                typ, val = self._expand_shortcuts_2(typ, val)
            elif val is None:
                self.err("Expected <type>:<spec>")
            attributes[typ] = val
        # valid combinations of rule attributes:
        # xpath
        # reference
        # object-type + attribute
        # split other combinations here
        from copy import deepcopy
        if 'xpath' in attributes:
            rule2 = deepcopy(rule)
            rule2.set('xpath', attributes['xpath'])
            out.append(rule2)
        if 'reference' in attributes:
            rule2 = deepcopy(rule)
            rule2.set('reference', attributes['reference'])
            out.append(rule2)
        if 'object-type' in attributes:
            rule2 = deepcopy(rule)
            rule2.set('object-type', attributes['object-type'])
            if 'attribute' in attributes:
                rule2.set('attribute', attributes['attribute'])
            out.append(rule2)
        if 'attribute' in attributes and 'object-type' not in attributes:
            self.err("attribute is only valid in combination with tag/object-type")

    def _add_rule(self):
        rule = xmlutil.new(self.match(_ACL_RIGHT_RE).lower())
        eligible_specs = list(constants.acl_spec_map.values())
        while self.has_tokens():
            a = self._expand_shortcuts(self.current_token().split(':', 1))
            if len(a) != 2 or a[0] not in eligible_specs:
                break
            self.match_any()
            rule.set(a[0], a[1])
            if self._remove_spec(eligible_specs, a[0]):
                break
        return rule

    def _remove_spec(self, speclist, spec):
        """
        Remove spec from list of eligible specs.
        Returns true if spec parse is complete.
        """
        try:
            speclist.remove(spec)
            if spec == 'xpath':
                speclist.remove('ref')
                speclist.remove('tag')
            elif spec in ('ref', 'tag'):
                speclist.remove('xpath')
            else:
                return True
        except ValueError:
            pass
        return False

    def _remove_spec_2(self, speclist, spec):
        """
        Remove spec from list of eligible specs.
        Returns true if spec parse is complete.
        """
        try:
            speclist.remove(spec)
            if spec == 'xpath':
                speclist.remove('reference')
                speclist.remove('object-type')
            elif spec in ('reference', 'object-type'):
                speclist.remove('xpath')
            else:
                return True
        except ValueError:
            pass
        return False

    def _expand_shortcuts_2(self, typ, val):
        '''
        expand xpath shortcuts: the typ prefix names the shortcut
        '''
        expansion = constants.acl_shortcuts[typ]
        if val is None:
            if '@@' in expansion[0]:
                self.err("Missing argument to ACL shortcut %s" % (typ))
            return 'xpath', expansion[0]
        a = val.split(':')
        xpath = ""
        exp_i = 0
        for tok in a:
            try:
                # some expansions may contain no id placeholders
                # of course, they don't consume input tokens
                if '@@' not in expansion[exp_i]:
                    xpath += expansion[exp_i]
                    exp_i += 1
                xpath += expansion[exp_i].replace('@@', tok)
                exp_i += 1
            except:
                return []
        # need to remove backslash chars which were there to escape
        # special characters in expansions when used as regular
        # expressions (mainly '[]')
        val = xpath.replace("\\", "")
        return 'xpath', val

    def _expand_shortcuts(self, l):
        '''
        Expand xpath shortcuts. The input list l contains the user
        input. If no shortcut was found, just return l.
        In case of syntax error, return empty list. Otherwise, l[0]
        contains 'xpath' and l[1] the expansion as found in
        constants.acl_shortcuts. The id placeholders '@@' are replaced
        with the given attribute names or resource references.
        '''
        try:
            expansion = constants.acl_shortcuts[l[0]]
        except KeyError:
            return l
        l[0] = "xpath"
        if len(l) == 1:
            if '@@' in expansion[0]:
                return []
            l.append(expansion[0])
            return l
        a = l[1].split(':')
        xpath = ""
        exp_i = 0
        for tok in a:
            try:
                # some expansions may contain no id placeholders
                # of course, they don't consume input tokens
                if '@@' not in expansion[exp_i]:
                    xpath += expansion[exp_i]
                    exp_i += 1
                xpath += expansion[exp_i].replace('@@', tok)
                exp_i += 1
            except:
                return []
        # need to remove backslash chars which were there to escape
        # special characters in expansions when used as regular
        # expressions (mainly '[]')
        l[1] = xpath.replace("\\", "")
        return l


@parser_for('xml')
def parse_xml(self, cmd):
    self.begin(cmd, min_args=1)
    self.match('xml')
    if not self.has_tokens():
        self.err("Expected XML data")
    xml_data = ' '.join(self.match_rest())
    # strip spaces between elements
    # they produce text elements
    try:
        e = etree.fromstring(xml_data)
    except Exception as err:
        logger.error("Cannot parse XML data: %s" % xml_data)
        self.err(err)
    if e.tag not in constants.cib_cli_map:
        self.err("Element %s not recognized" % (e.tag))
    return e


@parser_for('alert')
def parse_alert(self, cmd):
    """
    <alerts>
    <alert id=ID path=PATH>
      <recipient id=RID value=VALUE/>
      <meta_attributes ..>
      <instance_attributes ..>
      ...

      meta attributes "timeout", "tstamp_format"
    </tag>

    alert ID PATH [attributes ...] [meta ...] [to [{] recipient [}] ...]
    recipient :: PATH [attributes ...] [meta ...]
    """
    self.begin(cmd, min_args=2)
    self.match('alert')
    alertid = self.match_identifier()
    path = self.match(_ALERT_PATH_RE, errmsg="Expected path")
    out = xmlutil.new('alert', id=alertid, path=path)
    desc = self.try_match_description()
    if desc is not None:
        out.attrib['description'] = desc
    rcount = 1
    root_selector = [None]

    def wrap_select(tag):
        if tag[0] is None:
            tag[0] = xmlutil.child(out, 'select')
        return tag[0]

    while self.has_tokens():
        if self.current_token() in ('attributes', 'meta'):
            self.match_arguments(out, {'attributes': 'instance_attributes',
                                       'meta': 'meta_attributes'},
                                 terminator=['attributes', 'meta', 'to', 'select'])
            continue
        if self.current_token() == 'select':
            selector_types = ('nodes', 'fencing', 'resources', 'attributes')
            self.match('select')
            root_selector[0] = None
            while self.current_token() in selector_types:
                selector = self.match_identifier()
                if selector == 'attributes':
                    if not self.try_match('{'):
                        self.rewind()
                        break
                seltag = xmlutil.child(wrap_select(root_selector), 'select_{}'.format(selector))
                if selector == 'attributes':
                    while self.current_token() != '}':
                        name = self.match_identifier()
                        xmlutil.child(seltag, 'attribute', name=name)
                    self.match('}')
            continue
        self.match('to')
        rid = '%s-recipient-%s' % (alertid, rcount)
        rcount += 1
        bracer = self.try_match('{')
        elem = xmlutil.new('recipient', id=rid, value=self.match_any())
        desc = self.try_match_description()
        terminators = ['attributes', 'meta', 'to']
        if bracer:
            terminators.append('}')
        if desc is not None:
            elem.attrib['description'] = desc
        self.match_arguments(elem, {'attributes': 'instance_attributes',
                                    'meta': 'meta_attributes'},
                             terminator=terminators)
        if bracer:
            self.match('}')
        out.append(elem)
    return out


class ResourceSet(object):
    '''
    Constraint resource set parser. Parses sth like:
    a ( b c:start ) d:Master e ...
    Appends one or more resource sets to cli_list.
    Resource sets are in form:
    <resource_set [sequential=false] [require-all=false] [action=<action>] [role=<role>]>
        <resource_ref id="<rsc>"/>
        ...
    </resource_set>
    Action/role change makes a new resource set.
    '''
    open_set = ('(', '[')
    close_set = (')', ']')
    matching = {
        '[': ']',
        '(': ')',
    }

    def __init__(self, q_attr, s, parent):
        self.parent = parent
        self.q_attr = q_attr
        self.tokens = s
        self.cli_list = []
        self.reset_set()
        self.opened = ''
        self.sequential = True
        self.require_all = True
        self.fix_parentheses()

    def fix_parentheses(self):
        newtoks = []
        for p in self.tokens:
            if p[0] in self.open_set and len(p) > 1:
                newtoks.append(p[0])
                newtoks.append(p[1:])
            elif p[len(p)-1] in self.close_set and len(p) > 1:
                newtoks.append(p[0:len(p)-1])
                newtoks.append(p[len(p)-1])
            else:
                newtoks.append(p)
        self.tokens = newtoks

    def reset_set(self):
        self.set_pl = xmlutil.new("resource_set")
        self.prev_q = ''  # previous qualifier (action or role)
        self.curr_attr = ''  # attribute (action or role)

    def save_set(self):
        if not len(self.set_pl):
            return
        if not self.require_all:
            self.set_pl.set("require-all", "false")
        if not self.sequential:
            self.set_pl.set("sequential", "false")
        if self.curr_attr:
            self.set_pl.set(self.curr_attr, self.prev_q)
        self.make_resource_set()
        self.reset_set()

    def make_resource_set(self):
        self.cli_list.append(self.set_pl)

    def parseattr(self, p, tokpos):
        attrs = {"sequential": "sequential",
                 "require-all": "require_all"}
        l = p.split('=')
        if len(l) != 2:
            self.err('Extra = in %s' % (p),
                     token=self.tokens[tokpos])
        if l[0] not in attrs:
            self.err('Unknown attribute',
                     token=self.tokens[tokpos])
        k, v = l
        if not verify_boolean(v):
            self.err('Not a boolean: %s' % (v),
                     token=self.tokens[tokpos])
        setattr(self, attrs[k], get_boolean(v))
        return True

    def splitrsc(self, p):
        l = p.split(':')
        if len(l) == 2:
            if self.q_attr == 'action':
                l[1] = validator.canonize(
                    l[1],
                    validator.resource_actions())
            else:
                l[1] = validator.canonize(
                    handle_role_for_ocf_1_1(l[1]),
                    validator.resource_roles())
            if not l[1]:
                self.err('Invalid %s for %s' % (self.q_attr, p))
        elif len(l) == 1:
            l = [p, '']
        return l

    def err(self, errmsg, token=''):
        self.parent.err(msg=errmsg, context=self.q_attr, token=token)

    def update_attrs(self, bracket, tokpos):
        if bracket in ('(', '['):
            if self.opened:
                self.err('Cannot nest resource sets',
                         token=self.tokens[tokpos])
            self.sequential = False
            if bracket == '[':
                self.require_all = False
            self.opened = bracket
        elif bracket in (')', ']'):
            if not self.opened:
                self.err('Unmatched closing bracket',
                         token=self.tokens[tokpos])
            if bracket != self.matching[self.opened]:
                self.err('Mismatched closing bracket',
                         token=self.tokens[tokpos])
            self.sequential = True
            self.require_all = True
            self.opened = ''

    def parse(self):
        tokpos = -1
        for p in self.tokens:
            tokpos += 1
            if p == "_rsc_set_":
                continue  # a degenerate resource set
            if p in self.open_set:
                self.save_set()
                self.update_attrs(p, tokpos)
                continue
            if p in self.close_set:
                # empty sets not allowed
                if not len(self.set_pl):
                    self.err('Empty resource set',
                             token=self.tokens[tokpos])
                self.save_set()
                self.update_attrs(p, tokpos)
                continue
            if '=' in p:
                self.parseattr(p, tokpos)
                continue
            rsc, q = self.splitrsc(p)
            if q != self.prev_q:  # one set can't have different roles/actions
                self.save_set()
                self.prev_q = q
            if q:
                if not self.curr_attr:
                    self.curr_attr = self.q_attr
            else:
                self.curr_attr = ''
            self.set_pl.append(xmlutil.new("resource_ref", id=rsc))
        if self.opened:  # no close
            self.err('Unmatched opening bracket',
                     token=self.tokens[tokpos])
        if len(self.set_pl):  # save the final set
            self.save_set()
        ret = self.cli_list
        self.cli_list = []
        return ret


def parse(s, comments=None, ignore_empty=True, complete_advised=False):
    '''
    Input: a list of tokens (or a CLI format string).
    Return: a cibobject
    On failure, returns either False or None.
    comments holds comment state between parses
    Handles basic normalization of the input string.
    Converts unicode to ascii, XML data to CLI format,
    lexing etc.
    '''
    if comments is None:
        comments = []

    if isinstance(s, str):
        try:
            s = s.encode('ascii', errors='xmlcharrefreplace')
            s = s.decode('utf-8')
        except Exception as e:
            logger.error(e)
            return False
    if isinstance(s, str):
        if s and s.startswith('#'):
            comments.append(s)
            return None
        if s.startswith('xml'):
            try:
                s = [x for p in lines2cli(s) for x in p.split()]
            except ValueError as e:
                logger.error(e)
                return False
        else:
            s = shlex.split(s)
    # but there shouldn't be any newlines (?)
    while '\n' in s:
        s.remove('\n')
    if s:
        s[0] = s[0].lower()
    if not s:
        return s
    kw = s[0]
    parser = _parsers.get(kw)
    if parser is None:
        logger_utils.syntax_err(s, token=s[0], msg="Unknown command")
        return False

    try:
        ret = parser.do_parse(s, ignore_empty, complete_advised)
        if ret is not None and len(comments) > 0:
            if ret.tag in constants.defaults_tags:
                xmlutil.stuff_comments(ret[0], comments)
            else:
                xmlutil.stuff_comments(ret, comments)
            del comments[:]
        return ret
    except ParseError:
        return False


def score_to_kind(score):
    """
    Convert score to kind for rsc_order
    """
    return "Optional" if score == "0" else "Mandatory"
# vim:ts=4:sw=4:et:
