# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import time
from . import command
from . import completers as compl
from . import config
from . import utils
from . import constants
from . import userdir
from . import xmlutil
from . import ra
from .cibconfig import mkset_obj, cib_factory
from . import clidisplay
from . import term
from . import options
from .msg import common_err, common_info, common_warn
from .msg import err_buf, syntax_err
from . import rsctest
from . import schema
from . import ui_cib
from . import ui_cibstatus
from . import ui_ra
from . import ui_template
from . import ui_history
from . import ui_utils
from . import ui_assist
from .crm_gv import gv_types


def _type_completions():
    "completer for type: use in show"
    typelist = cib_factory.type_list()
    return ['type:%s' % (t) for t in typelist]


def _tag_completions():
    "completer for tag: use in show"
    return ['tag:%s' % (t) for t in cib_factory.tag_list()]


# Tab completion helpers
_id_list = compl.call(cib_factory.id_list)
_id_xml_list = compl.join(_id_list, compl.choice(['xml']))
_id_show_list = compl.join(_id_list,
                           compl.choice(['xml', 'changed']),
                           compl.call(_type_completions),
                           compl.call(_tag_completions))
_prim_id_list = compl.call(cib_factory.prim_id_list)
_f_prim_free_id_list = compl.call(cib_factory.f_prim_free_id_list)
_f_group_id_list = compl.call(cib_factory.f_group_id_list)
_f_children_id_list = compl.call(cib_factory.f_children_id_list)
_rsc_id_list = compl.call(cib_factory.rsc_id_list)
_top_rsc_id_list = compl.call(cib_factory.top_rsc_id_list)
_node_id_list = compl.call(cib_factory.node_id_list)
_rsc_template_list = compl.call(cib_factory.rsc_template_list)
_container_type = compl.choice(constants.container_type)


def _group_completer(args):
    '''
    completer for group resource
    '''
    completing = args[-1]
    id_list = cib_factory.f_prim_free_id_list()
    if completing in id_list:
        return [completing]
    # complete resources id first
    if len(args) == 3:
        return [s for s in id_list if s not in args]
    # complete meta or params attributes
    key_words = ["meta", "params"]
    keyw = last_keyword(args, key_words)
    if keyw in key_words:
        return _advanced_completer(args)

    # otherwise, complete resources ids and some key words
    return [s for s in id_list if s not in args] + _advanced_completer(args)


def _advanced_completer(args):
    '''
    meta completers for group/ms/clone resource type 
    '''
    key_words = ["meta", "params"]
    completing = args[-1]
    resource_type = args[0]
    return_list = []
    if completing.endswith('='):
        # TODO add some help messages
        return []
    keyw = last_keyword(args, key_words)
    if keyw and keyw == "meta":
        if resource_type == "group":
            return_list = utils.filter_keys(constants.group_meta_attributes, args)
        if resource_type == "clone":
            return_list = utils.filter_keys(constants.clone_meta_attributes, args)
        if resource_type in ["ms", "master"]:
            return_list = utils.filter_keys(constants.ms_meta_attributes, args)
    return return_list + key_words


def _list_resource(args):
    if len(args) > 3:
        if args[2] == "remove":
            res = cib_factory.f_prim_list_in_group(args[1])
            if len(res) <= 1:
                return []
            else:
                return res
        if args[2] == "add":
            return cib_factory.f_prim_free_id_list()


def _list_resource_2(args):
    if len(args) > 5:
        return cib_factory.f_prim_list_in_group(args[1])


def _pick_position(args):
    if args[2] == "remove":
        return []
    else:
        return ["after", "before"]


def top_rsc_tmpl_id_list(args):
    return cib_factory.top_rsc_id_list() + cib_factory.rsc_template_list()


def ra_classes_or_tmpl(args):
    return ui_ra.complete_class_provider_type(args) + \
           ['@'+x for x in cib_factory.rsc_template_list()]


def op_attr_list(args):
    schema_attr = [schema.get('attr', 'op', 'o') + '=']
    extra_attrs = [s + '=' for s in constants.op_extra_attrs]
    return schema_attr + extra_attrs


def node_id_colon_list(args):
    return [s + ':' for s in _node_id_list(args)]


def stonith_resource_list(args):
    return [x.obj_id for x in
            cib_factory.get_elems_on_type("type:primitive")
            if x.node.get("class") == "stonith"]


def _load_2nd_completer(args):
    if args[1] == 'xml':
        return ['replace', 'update', 'push']
    return []


# completion for primitives including help for parameters
# (help also available for properties)

def get_prim_token(words, n):
    for key in ("primitive", "rsc_template"):
        try:
            if key in words:
                return words[words.index(key) + n - 1]
        except IndexError:
            pass
    return ''


def ra_agent_for_template(tmpl):
    '''@template -> ra.agent'''
    obj = cib_factory.find_resource(tmpl[1:])
    if obj is None:
        return None
    return ra.get_ra(obj.node)


def ra_agent_for_cpt(cpt):
    '''class:provider:type -> ra.agent'''
    agent = None
    ra_class, provider, rsc_type = ra.disambiguate_ra_type(cpt)
    if ra.ra_type_validate(cpt, ra_class, provider, rsc_type):
        agent = ra.RAInfo(ra_class, rsc_type, provider)
    return agent


class CompletionHelp(object):
    '''
    Print some help on whatever last word in the line.
    '''
    timeout = 60  # don't print again and again
    laststamp = 0
    lasttopic = ''

    @classmethod
    def help(cls, topic, helptxt, args):
        if cls.lasttopic == topic and \
                time.time() - cls.laststamp < cls.timeout:
            return True
        if helptxt:
            import readline
            cmdline = readline.get_line_buffer()
            print("\n%s" % helptxt, end='')
            if cmdline.split()[0] != args[0]:
                prompt = '   > '
            else:
                if clidisplay.colors_enabled():
                    prompt = term.render(clidisplay.prompt_noreadline(constants.prompt))
                else:
                    prompt = constants.prompt
            print("\n%s%s" % (prompt, cmdline), end=' ')
            cls.laststamp = time.time()
            cls.lasttopic = topic
            return True
        else:
            return False


def _prim_params_completer(agent, args, keywords=None):
    import re

    completing = args[-1]
    token = "" if len(args) <= 1 else args[-2]
    if token == "property":
        return utils.filter_keys(agent.params(completion=True), args)
    if completing == 'params':
        return ['params']

    this_params = args[utils.rindex(args, "params"):]
    if 'rule' in this_params:
        rules_options = rules_completer(this_params[this_params.index("rule"):])
        if "endable_" in rules_options:
            rules_options.remove("endable_")
            return rules_options + keywords
        else:
            return rules_options

    if completing.endswith('='):
        if len(completing) > 1 and options.interactive:
            topic = completing[:-1]
            CompletionHelp.help(topic, agent.meta_parameter(topic), args)
        return []
    elif '=' in completing:
        return []

    if token == "extra":
        return ["rule", "score="]
    if re.match(r"score=(.+)$", token) and args[-3] == "extra":
        return keywords + ["rule"]

    _options = utils.filter_keys(agent.params(completion=True), this_params) + ["extra"]
    if len(this_params) > 2 and keywords:
        _options += keywords
    return _options


def _prim_meta_completer(agent, args, keywords):
    completing = args[-1]
    if completing == 'meta':
        return ['meta']
    if '=' in completing:
        return []
    return utils.filter_keys(constants.rsc_meta_attributes, args)


def _prim_op_completer(agent, args, keywords=None):
    if keywords is None:
        return []

    import re

    completing = args[-1]
    token = "" if len(args) <= 1 else args[-2]
    op_list = list(constants.op_cli_names)
    op_attr_list = list(constants.op_attr_names)
    this_op = args[utils.rindex(args, "op"):]

    actions = agent.actions()
    if "monitor_Master" in actions:
        op_list.append("monitor_Master")
    if "monitor_Slave" in actions:
        op_list.append("monitor_Slave")
    for item in ["monitor", "demote", "promote", "notify"]:
        if item not in actions:
            op_list.remove(item)

    if completing.endswith('='):
        return []
    if completing in op_list + ["op", "extra"]:
        return [completing]
    if token == "extra":
        return ["rule", "score=", "op_type="]

    last_keyw = last_keyword(this_op, op_list+["extra"])
    if last_keyw == "extra":
        section = this_op[utils.rindex(this_op, "extra"):]
        if "rule" in section:
            rules_options = rules_completer(section[utils.rindex(section, "rule"):])
            if "endable_" in rules_options:
                rules_options.remove("endable_")
                return rules_options + keywords + ["extra"]
            else:
                return rules_options
        if len(section) > 2:
            return keywords + ["rule", "extra"] + utils.filter_keys(["score", "op_type"], section)
        return keywords + ["rule"] + utils.filter_keys(["score", "op_type"], section)

    _options = []
    if last_keyw in op_list:
        res = []
        section = this_op[this_op.index(last_keyw):]
        if last_keyw in actions:
            for k, v in list(actions[last_keyw].items()):
                res += ["%s=%s" % (k, v)]
                op_attr_list.remove(k)

            _options += utils.filter_keys(res, section, sign="")
            _options += utils.filter_keys(op_attr_list, section)

        if len(section) > 2:
            return _options + keywords + ["extra"]
        else:
            return _options

    return op_list


def last_keyword(words, keyw):
    '''returns the last occurance of an element in keyw in words'''
    for w in reversed(words):
        if w in keyw or w.split('=')[0] in keyw:
            return w
    return None


def _ticket_completer(args):
    import re

    completing = args[-1]
    token = "" if len(args) <= 1 else args[-2]
    _rsc_ids = cib_factory.top_rsc_id_list()

    if completing.endswith('='):
        return []
    if completing == "options":
        return ["options"]
    if len(args) == 3:
        return ["ticket=", ""]
    if len(args) == 4:
        return _rsc_ids + ["resource_set"]
    if len(args) == 5 and token in _rsc_ids:
        return ["role=", "options"]

    last_keyw = last_keyword(args, ["resource_set", "options"])
    if last_keyw and last_keyw == "resource_set":
        _options = resource_set_completer(args)
        if "endable_" in _options:
            _options.remove("endable_")
            _options += ["options"]
        return _options

    if re.match(r"role=(.+)$", token) and \
       "resource_set" not in args:
        return ["options", ""]
    if token == "options":
        return ["loss-policy=", ""]


def _nvpair_completer(args, other_items=None, next_items=None):
    completing = args[-1]
    token = "" if len(args) <= 1 else args[-2]
    _options = ["score"]
    if other_items:
        _options += list(other_items)

    if 'rule' in args[:-1]:
        rule_options = rules_completer(args)
        if "endable_" in rule_options:
            rule_options.remove("endable_")
            if next_items:
                return rule_options + next_items
        return rule_options
    if completing.endswith("="):
        return []
    if len(args) > 2 and next_items:
        return utils.filter_keys(_options, args) + ["rule"] + next_items

    return utils.filter_keys(_options, args) + ["rule"]


def _property_completer(args):
    '''context-sensitive completer'''
    agent = ra.get_properties_meta()
    return _prim_params_completer(agent, args)


def _op_defaults_completer(args):
    return _nvpair_completer(args, constants.op_attr_names)


def _node_completer(args):
    completing = args[-1]
    token = "" if len(args) <= 1 else args[-2]
    _options = ["type", "score"]
    _others = ["attributes", "utilization"]

    if completing in _others:
        return [completing]
    if len(args) == 2:
        return cib_factory.node_id_list()
    last_keyw = last_keyword(args, _others+["rule"])
    if last_keyw:
        return _nvpair_completer(args[utils.rindex(args, last_keyw):],
                                 next_items=_others)
    if completing.endswith('='):
        return []

    return utils.filter_keys(_options, args) + _others


def primitive_complete_complex(args):
    '''
    This completer depends on the content of the line, i.e. on
    previous tokens, in particular on the type of the RA.
    '''
    cmd = get_prim_token(args, 1)
    type_word = get_prim_token(args, 3)
    with_template = cmd == 'primitive' and type_word.startswith('@')

    if with_template:
        agent = ra_agent_for_template(type_word)
    else:
        agent = ra_agent_for_cpt(type_word)
    if agent is None:
        return []

    completers_set = {
        "params": _prim_params_completer,
        "meta": _prim_meta_completer,
        "op": _prim_op_completer,
    }

    keywords = list(completers_set.keys())
    if len(args) == 4:  # <cmd> <id> <type> <?>
        return keywords

    last_keyw = last_keyword(args, keywords)
    if last_keyw is None:
        return []

    return completers_set[last_keyw](agent, args, keywords)


def container_helptxt(params, helptxt, topic):
    for item in reversed(params):
        if item in ["storage", "network", "docker", "rkt"]:
            return helptxt[item][topic] + "\n"
        if item == "port-mapping":
            return helptxt["network"][item][topic] + "\n"


def _container_remove_exist_keywords(args, _keywords):
    for item in ["network", "primitive"]:
        if item in args:
            _keywords.remove(item)


def _container_network_completer(args, _help, _keywords):
    key_words = ["network", "port-mapping"]
    completing = args[-1]
    token = "" if len(args) <= 1 else args[-2]
    if completing.endswith("="):
        return []
    if completing in key_words:
        return [completing]

    tmp = list(_help["network"].keys())
    # port-mapping is element, not a network option
    tmp.remove("port-mapping")
    network_keys = utils.filter_keys(tmp, args)
    # bundle contain just one <network>/<primitive> element
    _container_remove_exist_keywords(args, _keywords)

    last_keyw = last_keyword(args, key_words)
    if last_keyw == "network":
        if token == "network":
            return network_keys
        else:
            # complete port-mapping or other parts
            return network_keys + ["port-mapping"] + _keywords

    if last_keyw == "port-mapping":
        mapping_required = ["id"]
        mapping_params = args[utils.rindex(args, "port-mapping"):]
        mapping_keys = utils.filter_keys(_help["network"]["port-mapping"].keys(), mapping_params)
        if token == "port-mapping":
            return mapping_keys
        # required options must be completed
        for s in mapping_required:
            if utils.any_startswith(mapping_params, s+'=') is None:
                return mapping_keys
        # complete port-mapping or other parts
        return mapping_keys + ["port-mapping"] + _keywords


def _container_storage_completer(args, _help, _keywords):
    completing = args[-1]
    if completing.endswith("="):
        return []
    if completing == "storage":
        return [completing]
    if args[-2] == "storage":
        return ["storage-mapping"]

    storage_required = ["id", "target-dir"]
    # get last storage part
    mapping_params = args[utils.rindex(args, "storage-mapping"):]
    storage_keys = utils.filter_keys(_help["storage"].keys(), mapping_params)

    # required options must be completed
    for s in storage_required:
        if utils.any_startswith(mapping_params, s+"=") is None:
            return storage_keys
    # bundle contain just one <network>/<primitive> element
    _container_remove_exist_keywords(args, _keywords)
    # complete storage or other parts
    return storage_keys + _keywords


def _container_primitive_completer(args, _help, _keywords):
    completing = args[-1]
    if completing == "primitive":
        return [completing]

    _id_list = cib_factory.f_prim_free_id_list()
    if _id_list is None:
        return []
    # bundle contain just one <network>/<primitive> element
    _container_remove_exist_keywords(args, _keywords)
    if args[-3] == "primitive" and args[-2] in _id_list:
        return _keywords
    return _id_list


def _container_meta_completer(args, helptxt, _keywords):
    completing = args[-1]
    if completing.endswith("="):
        return []
    if completing == "meta":
        return [completing]

    # bundle contain just one <network>/<primitive> element
    _container_remove_exist_keywords(args, _keywords)

    return utils.filter_keys(constants.bundle_meta_attributes, args) + _keywords


def container_complete_complex(args):
    '''
    Complete five parts:
    container options, network, storage, primitive and meta
    '''
    container_options_required = ["image"]
    completing = args[-1]
    container_type = args[2]

    completers_set = {
        "network": _container_network_completer,
        "storage": _container_storage_completer,
        "primitive": _container_primitive_completer,
        "meta": _container_meta_completer
    }
    keywords = list(completers_set.keys())
    last_keyw = last_keyword(args, keywords)

    # to show help messages
    if completing.endswith('='):
        if len(completing) > 1 and options.interactive:
            topic = completing[:-1]
            CompletionHelp.help(topic, container_helptxt(args, constants.container_helptxt, topic), args)
        return []

    container_options = utils.filter_keys(constants.container_helptxt[container_type].keys(), args)

    # required options must be completed
    for s in container_options_required:
        if utils.any_startswith(args, s+'=') is None:
            return container_options

    if last_keyw is None:
        return container_options + keywords

    # to complete network, storage, primitive and meta
    return completers_set[last_keyw](args, constants.container_helptxt, keywords)


def _date_common_completer():
    '''
    Completers for date-common
    '''
    key_words = ["hours", "monthdays", "weekdays", "yearsdays", "months",
                 "weeks", "years", "weekyears", "moon"]

    return [x+'=' for x in key_words]


def _date_completer(args):
    '''
    Completers for date_expression

    situations:
      operation="in_range" end=xxx
      operation="in_range" start=xxx end=xxx
      operation="in_range" start=xxx duration <date-common>
      operation="gt" start=xxx
      operation="lt" end=xxx
      operation="date_spec" <date-common>
    '''
    import re

    completing = args[-1]
    token = "" if len(args) <= 1 else args[-2]
    _this_arg = args[utils.rindex(args, "date"):]
    _options = []

    if completing == "date":
        return ["date"]
    if token == "date":
        return ["", "operation="]
    if re.match(r'operation="?in_range"?', token):
        _options = ["start=", "end="]
    if re.search(r'operation="?in_range"?', ' '.join(_this_arg)) and \
       re.match(r'start=(.+)$', token):
        _options = ["end=", "duration"]
    if re.match(r'operation="?gt"?', token):
        _options = ["", "start="]
    if re.match(r'operation="?lt"?', token):
        _options = ["", "end="]
    if re.match(r'operation="?date_spec"?', token) or token == "duration":
        _options = _date_common_completer()

    if not _options:
        _options += ["endable_", "and", "or"]
    return _options


def _expression_completer(args):
    '''
    Completers for rule expression
    '''
    import re

    completing = args[-1]
    token = "" if len(args) <= 1 else args[-2]
    _this_arg = args[utils.rindex(args, "expression"):]

    if completing == "expression":
        return ["expression"]
    if token == "expression":
        return ["", "attribute="]
    if re.match(r'attribute=(.+)$', token):
        return ["", "operation="]
    if re.match(r'operation="?(lt|gt|lte|gte|eq|ne)"?', token):
        return ["", "value="]

    _options = []
    if re.search(r' value=(.+) ', ' '.join(_this_arg)):
        _options = utils.filter_keys(["type", "value-source"], _this_arg)
    return _options + ["endable_", "and", "or"]


def help_completer(args, help_txt):
    completing = args[-1]
    res = False
    if completing.endswith('='):
        if len(completing) > 1 and options.interactive:
            topic = completing[:-1]
            res = CompletionHelp.help(topic, helptxt_filter(args, help_txt, topic), args)
        return res
    else:
        return res


def helptxt_filter(params, helptxt, topic):
    if topic in helptxt.keys():
        return helptxt[topic] + "\n"
    for item in reversed(params):
        if item in ["duration", "date_spec"] and "date-common" in helptxt.keys():
            return helptxt["date-common"][topic] + "\n"
        if item in ["date", "expression"] and item in helptxt.keys():
            return helptxt[item][topic] + "\n"
    return None


def bad_id(id_list):
    key_words = ["first", "then", "resource_set", "on", "rule", "with", "options"]
    for item in key_words:
        if item in id_list:
            print(" Id \"%s\" is a reserved word" % item)
            return True
    return False


def rules_completer(args):
    '''
    Completers for rules
    '''
    import re

    completing = args[-1]
    token = "" if len(args) <= 1 else args[-2]

    rule_properties = ["role", "score", "score-attribute"]
    if re.search(r"score=(.+)$", ' '.join(args)):
        rule_properties.remove("score-attribute")
    if re.search(r"score-attribute=(.+)$", ' '.join(args)):
        rule_properties.remove("score")

    # help messages
    if help_completer(args, constants.rules_helptxt):
        return []
    if completing == "rule":
        return ["rule"]
    if token in ["and", "or"]:
        return utils.filter_keys(rule_properties, args) + ["expression", "date"]

    completers_set = {
        "date":        _date_completer,
        "expression":  _expression_completer
    }
    last_keyw = last_keyword(args, list(completers_set.keys()))
    if last_keyw:
        return completers_set[last_keyw](args)

    return utils.filter_keys(rule_properties, args) + ["expression", "date"]


def location_complete_complex(args):
    '''
    Completer for location

    Examples:
      location loc1 r1 on node1 score=100
      location id=loc1 r1 on node1 score=100 options role=Started

      location id=loc1 rsc-pattern="r*" on node1 score=200
      location id=loc1 rsc-pattern="/r*/" on node1 score=200
      location id=loc1 rsc-pattern='x' \
          rule score=100 expression attribute=#uname operation=eq value=node1

      location loc1 resource_set r1 r2 r3 on node1 score=-inf
      location id=loc1 r1 rule expression attribute=#uname operation=eq value=node1
      location id=loc1 r1 rule expression attribute="cpu_mips" operation="lt" value=3000
    '''
    import re

    completing = args[-1]
    token = "" if len(args) <= 1 else args[-2]

    _rsc_ids = cib_factory.top_rsc_id_list()
    if len(_rsc_ids) < 1:
        return
    _node_ids = cib_factory.node_id_list()
    if bad_id(_node_ids + _rsc_ids):
        return

    # complete guide for resource_set and rule
    _options = []
    last_keyw = last_keyword(args, ["resource_set", "rule", "options", "on"])
    if last_keyw == "rule":
        _options = rules_completer(args[utils.rindex(args, "rule"):])
        if "endable_" in _options:
            _options += ["rule"]

    if last_keyw == "resource_set":
        _options = resource_set_completer(args)
        if "endable_" in _options:
            _options += ["on", "rule"]

    if help_completer(args, constants.location_helptxt):
        return []
    if completing == "options":
        return ["options"]

    # complete guide for location's options
    _option_words = ["role", "resource-discovery"]
    if last_keyw == "options":
        if "resource_set" in args:
            _option_words.remove("role")
        _options = options_completer(args, _option_words)

    if _options:
        return handle_options(args, _options)

    # complete guide for base
    if len(args) == 3:
        return _rsc_ids + ["rsc-pattern=", "resource_set"]
    if (token in _rsc_ids or token.startswith("rsc-pattern")) and len(args) == 4:
        return ["on", "rule"]
    if token == "on":
        return _node_ids
    if token in _node_ids:
        return ["score=", ""]
    if re.match(r'score=(.+)$', token):
        return ["options", ""]


def order_complete_complex(args):
    '''
    Completer for order

    Examples:
        order id=ord-1 first r1 then r2 options kind=Mandatory
        order id=ord-2 resource_set r1 r2 r3 r4 sequential=true
        order id=ord-3 resource_set r1 r2 sequential=false resource_set r3 r4 sequential=false
        order id=ord-4 first r2 first-action=start then r3 then-action=promote
        order id=ord-5 first r1 then r2
    '''
    import re

    completing = args[-1]
    token = "" if len(args) <= 1 else args[-2]
    _rsc_ids = cib_factory.top_rsc_id_list()
    if len(_rsc_ids) <= 1:
        return
    if bad_id(_rsc_ids):
        return

    if completing in _rsc_ids + ["options"]:
        return [completing]

    # complete guide for resource_set
    _options = []
    last_keyw = last_keyword(args, ["resource_set", "options"])
    if last_keyw == "resource_set":
        _options = resource_set_completer(args)

    # help messages
    if help_completer(args, constants.order_helptxt):
        return []

    # complete guide for order's options
    _option_words = ["symmetrical", "require-all", "score", "kind"]
    if last_keyw == "options":
        if re.search(r"options .*score=(.+)", ' '.join(args)):
            _option_words.remove("kind")
        if re.search(r"options .*kind=(.+)", ' '.join(args)):
            _option_words.remove("score")
        _options = options_completer(args, _option_words)

    if _options:
        return handle_options(args, _options)

    # complete guide for base
    if len(args) == 3:
        return ["first", "resource_set"]
    if token == "first" and len(args) == 4:
        return _rsc_ids
    if token in _rsc_ids and len(args) == 5 and "first" in args:
        return ["then", "first-action="]
    if token == "then" and len(args) in [6, 7]:
        return [x for x in _rsc_ids if x not in args]
    if re.match(r'first-action=(.+)$', token) and len(args) == 6:
        return ["then"]
    if token in _rsc_ids and len(args) in [7, 8] and "then" in args:
        return ["then-action=", "options"]
    if re.match(r'then-action=(.+)$', token) and len(args) in [8, 9]:
        return ["", "options"]


def colocation_complete_complex(args):
    '''
    Completer for colocation

    Examples:
        colocation id=col-1 r1 with r2 options score=inf
        colocation id=col-2 resource_set r2 r3 r4 r1 sequential=true options score=inf
        colocation id=col-3 resource_set r1 r2 r3 sequential=false \
                            resource_set r4 sequential=true options score=inf
        colocation id=col-4 resource_set r1 r2 sequential=true \
                            resource_set r3 r4 sequential=false \
                            resource_set r5 r6 sequential=true role=Master
        colocation id=col-5 r1 role=Started with r2 options score=inf
    '''
    import re

    completing = args[-1]
    token = "" if len(args) <= 1 else args[-2]
    _rsc_ids = cib_factory.top_rsc_id_list()
    if len(_rsc_ids) <= 1:
        return
    if bad_id(_rsc_ids):
        return

    if completing in _rsc_ids + ["options"]:
        return [completing]

    # complete guide for resource_set
    _options = []
    last_keyw = last_keyword(args, ["resource_set", "options"])
    if last_keyw == "resource_set":
        _options = resource_set_completer(args)

    # help messages
    if help_completer(args, constants.colocation_helptxt):
        return []

    # complete guide for colocation's options
    _option_words = ["score", "node-attribute"]
    if last_keyw == "options":
        if "resource_set" in args:
            _option_words.remove("node-attribute")
        _options = options_completer(args, _option_words)

    if _options:
        return handle_options(args, _options)

    # complete guide for base
    _ROLE_ = re.compile(r'role="?(Started|Master|Slave)"?')
    _WITH_ROLE_ = re.compile(r'with_role="?(Started|Master|Slave)"?')
    _SCORE_ = re.compile(r"score=(.+)$")
    if len(args) == 3:
        return _rsc_ids + ["resource_set"]
    if re.match(_SCORE_, token) and len(args) == 4:
        return _rsc_ids + ["resource_set"]
    if token in _rsc_ids and len(args) in [4, 5]:
        return ["role=", "with"]
    if token in _rsc_ids and len(args) in [6, 7, 8]:
        return ["with_role=", "options"]
    if token == "with" and len(args) in [5, 6, 7]:
        return [x for x in _rsc_ids if x not in args]
    if re.match(_ROLE_, token) and len(args) in [5, 6]:
        return ["with"]
    if re.match(_WITH_ROLE_, token):
        return ["", "options"]


def handle_options(args, _options, append_list=["options"]):
    if "endable_" in _options:
        _options.remove("endable_")
        if "on" in _options and "rule" in _options:
            return _options
        for item in append_list:
            if item not in args:
                _options.append(item)
    if len(_options) == 1:
        _options += [""]
    return _options


def options_completer(args, option_words):
    _options = []
    _options = utils.filter_keys(option_words, args[args.index("options"):])
    if len(args[args.index("options"):]) > 2:
        _options.append("endable_")
    return _options


def resource_set_completer(args):
    '''
    '''
    completing = args[-1]
    token = "" if len(args) <= 1 else args[-2]
    _rsc_ids = cib_factory.top_rsc_id_list()
    set_options = ["sequential", "require-all", "action", "score", "role"]

    if help_completer(args, constants.rscset_helptxt):
        return []
    if completing in _rsc_ids + set_options + ["resource_set"]:
        return [completing]

    rsc_options = [x for x in _rsc_ids if x not in args]
    _set_options = utils.filter_keys(set_options, args[utils.rindex(args, "resource_set"):])
    _options = rsc_options + _set_options

    if len(rsc_options) == len(_rsc_ids):
        return rsc_options
    if len(rsc_options) < len(_rsc_ids):
        if token in _rsc_ids + ['resource_set']:
            _options += ['resource_set']
        else:
            _options = _set_options + ['resource_set']
    if len(rsc_options) == 0:
        _options.remove("resource_set")

    return _options + ['endable_']


class CibConfig(command.UI):
    '''
    The configuration class
    '''
    name = "configure"

    def __init__(self):
        command.UI.__init__(self)
        # for interactive use, we want to populate the CIB
        # immediately so that tab completion works

    def requires(self):
        if not cib_factory.initialize():
            return False
        # see the configure ptest/simulate command
        has_ptest = utils.is_program('ptest')
        has_simulate = utils.is_program('crm_simulate')
        if not has_ptest:
            constants.simulate_programs["ptest"] = "crm_simulate"
        if not has_simulate:
            constants.simulate_programs["simulate"] = "ptest"
        if not (has_ptest or has_simulate):
            common_warn("neither ptest nor crm_simulate exist, check your installation")
            constants.simulate_programs["ptest"] = ""
            constants.simulate_programs["simulate"] = ""
        return True

    @command.name('_test')
    @command.skill_level('administrator')
    def do_check_structure(self, context):
        return cib_factory.check_structure()

    @command.name('_regtest')
    @command.skill_level('administrator')
    def do_regression_testing(self, context, param):
        return cib_factory.regression_testing(param)

    @command.name('_objects')
    @command.skill_level('administrator')
    def do_showobjects(self, context):
        cib_factory.showobjects()

    @command.name('_keywords')
    @command.skill_level('administrator')
    def do_keywords(self, context):
        for k, v in sorted(iter(constants.keywords.items()), key=lambda v: v[0].lower()):
            print("%-16s %s" % (k, v))

    @command.level(ui_ra.RA)
    def do_ra(self):
        pass

    @command.level(ui_cib.CibShadow)
    def do_cib(self):
        pass

    @command.level(ui_cibstatus.CibStatusUI)
    def do_cibstatus(self):
        pass

    @command.level(ui_template.Template)
    def do_template(self):
        pass

    @command.level(ui_history.History)
    def do_history(self):
        pass

    @command.level(ui_assist.Assist)
    def do_assist(self):
        pass

    @command.skill_level('administrator')
    @command.completers_repeating(_id_show_list)
    def do_show(self, context, *args):
        "usage: show [xml] [<id>...]"
        from .utils import obscure
        osargs = [arg[8:] for arg in args if arg.startswith('obscure:')]
        args = [arg for arg in args if not arg.startswith('obscure:')]
        with obscure(osargs):
            set_obj = mkset_obj(*args)
            return set_obj.show()

    @command.name("get_property")
    @command.alias("get-property")
    @command.skill_level('administrator')
    @command.completers_repeating(compl.call(ra.get_properties_list))
    def do_get_property(self, context, *args):
        "usage: get-property [-t|--true [<name>...]"
        properties = [a for a in args if a not in ('-t', '--true')]
        truth = any(a for a in args if a in ('-t', '--true'))

        if not properties:
            utils.multicolumn(ra.get_properties_list())
            return

        def print_value(v):
            if truth:
                print(utils.canonical_boolean(v))
            else:
                print(v)
        for p in properties:
            v = cib_factory.get_property_w_default(p)
            if v is not None:
                print_value(v)
            elif truth:
                print("false")
            else:
                context.fatal_error("%s: Property not set" % (p))

    @command.skill_level('administrator')
    @command.completers_repeating(compl.null, _id_xml_list, _id_list)
    def do_filter(self, context, filterprog, *args):
        "usage: filter <prog> [xml] [<id>...]"
        set_obj = mkset_obj(*args)
        return set_obj.filter(filterprog)

    @command.skill_level('administrator')
    @command.completers(_id_list)
    def do_set(self, context, path, value):
        "usage: set <path> <value>"
        def split_path():
            for oid in cib_factory.id_list():
                if path.startswith(oid + "."):
                    return oid, path[len(oid)+1:]
            context.fatal_error("Invalid path: " + path)
        obj_id, obj_attr = split_path()
        rsc = cib_factory.find_object(obj_id)
        if not rsc:
            context.fatal_error("Resource %s not found" % (obj_id))
        nvpairs = rsc.node.xpath(".//nvpair[@name='%s']" % (obj_attr))
        if not nvpairs:
            context.fatal_error("Attribute not found: %s" % (path))
        if len(nvpairs) != 1:
            context.fatal_error("Expected 1 attribute named %s, found %s" %
                                (obj_attr, len(nvpairs)))
        rsc.set_updated()
        nvpairs[0].set("value", value)
        return True

    @command.skill_level('administrator')
    @command.completers(_f_group_id_list, compl.choice(['add', 'remove']),
                        _list_resource, _pick_position, _list_resource_2)
    def do_modgroup(self, context, group_id, subcmd, prim_id, *args):
        """usage: modgroup <id> add <id> [after <id>|before <id>]
        modgroup <id> remove <id>"""
        if subcmd not in ("add", "remove"):
            common_err("modgroup subcommand %s unknown" % subcmd)
            return False
        after_before = None
        if args:
            if subcmd != 'add':
                context.fatal_error("Expected add (found %s)" % subcmd)
            if args[0] not in ("after", "before"):
                context.fatal_error("Expected after|before (found %s)" % args[0])
            if len(args) != 2:
                context.fatal_error("Expected 'after|before <id>' (%d arguments given)" %
                                    len(args))
            after_before = args[0]
            ref_member_id = args[1]
        g = cib_factory.find_object(group_id)
        if not g:
            context.fatal_error("group %s does not exist" % group_id)
        if not xmlutil.is_group(g.node):
            context.fatal_error("element %s is not a group" % group_id)
        children = xmlutil.get_rsc_children_ids(g.node)
        if after_before and ref_member_id not in children:
            context.fatal_error("%s is not member of %s" % (ref_member_id, group_id))
        if subcmd == "remove" and prim_id not in children:
            context.fatal_error("%s is not member of %s" % (prim_id, group_id))
        # done checking arguments
        # have a group and children
        if not after_before:
            after_before = "after"
            ref_member_id = children[-1]
        # just do the filter
        # (i wonder if this is a feature abuse?)
        if subcmd == "add":
            if after_before == "after":
                sed_s = r's/ %s( |$)/& %s /' % (ref_member_id, prim_id)
            else:
                sed_s = r's/ %s( |$)/ %s& /' % (ref_member_id, prim_id)
        else:
            sed_s = r's/ %s( |$)/ /' % prim_id
        l = (group_id,)
        set_obj = mkset_obj(*l)
        return set_obj.filter("sed -r '%s'" % sed_s)

    @command.skill_level('administrator')
    @command.completers_repeating(_id_xml_list, _id_list)
    def do_edit(self, context, *args):
        "usage: edit [xml] [<id>...]"
        err_buf.buffer()  # keep error messages
        set_obj = mkset_obj(*args)
        err_buf.release()  # show them, but get an ack from the user
        return set_obj.edit()

    def _verify(self, set_obj_semantic, set_obj_all):
        rc1 = set_obj_all.verify()
        if config.core.check_frequency != "never":
            rc2 = set_obj_semantic.semantic_check(set_obj_all)
        else:
            rc2 = 0
        return rc1 and rc2 <= 1

    @command.skill_level('administrator')
    def do_verify(self, context):
        "usage: verify"
        set_obj_all = mkset_obj("xml")
        return self._verify(set_obj_all, set_obj_all)

    @command.name('validate-all')
    @command.alias('validate_all')
    @command.skill_level('administrator')
    @command.completers_repeating(_id_list)
    def do_validate_all(self, context, rsc):
        "usage: validate-all <rsc>"
        from . import ra
        from . import cibconfig
        from . import cliformat
        obj = cib_factory.find_object(rsc)
        if not obj:
            context.error("Not found: %s" % (rsc))
        if obj.obj_type != "primitive":
            context.error("Not a primitive: %s" % (rsc))
        rnode = cibconfig.reduce_primitive(obj.node)
        if rnode is None:
            context.error("No resource template %s for %s" % (obj.node.get("template"), rsc))
        params = []
        for attrs in rnode.iterchildren("instance_attributes"):
            params.extend(cliformat.nvpairs2list(attrs))
        if not all(nvp.get('name') is not None and nvp.get('value') is not None for nvp in params):
            context.error("Primitive too complex: %s" % (rsc))
        params = dict([(nvp.get('name'), nvp.get('value')) for nvp in params])
        agentname = xmlutil.mk_rsc_type(rnode)
        if not ra.can_validate_agent(agentname):
            context.error("%s: Cannot run validate-all for agent: %s" % (rsc, agentname))
        rc, _ = ra.validate_agent(agentname, params, log=True)
        return rc == 0

    @command.skill_level('administrator')
    @command.completers_repeating(_id_show_list)
    def do_save(self, context, *args):
        "usage: save [xml] [<id>...] <filename>"
        if not args:
            context.fatal_error("Expected 1 argument (0 given)")
        filename = args[-1]
        setargs = args[:-1]
        set_obj = mkset_obj(*setargs)
        return set_obj.save_to_file(filename)

    @command.skill_level('administrator')
    @command.completers(compl.choice(['xml', 'replace', 'update', 'push']), _load_2nd_completer)
    def do_load(self, context, *args):
        "usage: load [xml] {replace|update|push} {<url>|<path>}"
        if len(args) < 2:
            context.fatal_error("Expected 2 arguments (0 given)")
        if args[0] == "xml":
            if len(args) != 3:
                context.fatal_error("Expected 3 arguments (%d given)" % len(args))
            url = args[2]
            method = args[1]
            xml = True
        else:
            if len(args) != 2:
                context.fatal_error("Expected 2 arguments (%d given)" % len(args))
            url = args[1]
            method = args[0]
            xml = False
        if method not in ("replace", "update", "push"):
            context.fatal_error("Unknown method %s" % method)
        if method == "replace":
            if options.interactive and cib_factory.has_cib_changed():
                if not utils.ask("This operation will erase all changes. Do you want to proceed?"):
                    return False
            cib_factory.erase()
        if xml:
            set_obj = mkset_obj("xml")
        else:
            set_obj = mkset_obj()
        return set_obj.import_file(method, url)

    @command.skill_level('administrator')
    @command.completers(compl.choice(list(gv_types.keys()) + ['exportsettings']))
    def do_graph(self, context, *args):
        "usage: graph [<gtype> [<file> [<img_format>]]]"
        if args and args[0] == "exportsettings":
            return utils.save_graphviz_file(userdir.GRAPHVIZ_USER_FILE, constants.graph)
        set_obj = mkset_obj()
        rc = set_obj.query_graph(*args)
        if rc is None:
            context.fatal_error("Failed to create graph")
        return rc

    def _stop_if_running(self, rscs):
        rscstate = xmlutil.RscState()
        to_stop = [rsc for rsc in rscs if rscstate.is_running(rsc)]
        from .ui_resource import set_deep_meta_attr
        if len(to_stop) > 0:
            ok = all(set_deep_meta_attr(rsc, 'target-role', 'Stopped',
                                        commit=False) for rsc in to_stop)
            if not ok or not cib_factory.commit():
                raise ValueError("Failed to stop one or more running resources: %s" %
                                 (', '.join(to_stop)))
        return len(to_stop)

    @command.skill_level('administrator')
    @command.completers_repeating(_id_list)
    @command.alias('rm')
    def do_delete(self, context, *args):
        "usage: delete [-f|--force] <id> [<id>...]"
        argl = list(args)
        arg_force = any((x in ('-f', '--force')) for x in argl)
        argl = [x for x in argl if x not in ('-f', '--force')]
        if arg_force or config.core.force:
            if self._stop_if_running(argl) > 0:
                utils.wait4dc(what="Stopping %s" % (", ".join(argl)))
        return cib_factory.delete(*argl)

    @command.name('default-timeouts')
    @command.alias('default_timeouts')
    @command.completers_repeating(_id_list)
    def do_default_timeouts(self, context, *args):
        "usage: default-timeouts <id> [<id>...]"
        return cib_factory.default_timeouts(*args)

    @command.skill_level('administrator')
    @command.completers(_id_list)
    def do_rename(self, context, old_id, new_id):
        "usage: rename <old_id> <new_id>"
        return cib_factory.rename(old_id, new_id)

    @command.skill_level('administrator')
    @command.completers(compl.choice(['nodes']))
    def do_erase(self, context, nodes=None):
        "usage: erase [nodes]"
        if nodes is None:
            return cib_factory.erase()
        if nodes != 'nodes':
            context.fatal_error("Expected 'nodes' (found '%s')" % (nodes))
        return cib_factory.erase_nodes()

    @command.skill_level('administrator')
    def do_refresh(self, context):
        "usage: refresh"
        if options.interactive and cib_factory.has_cib_changed():
            if not utils.ask("All changes will be dropped. Do you want to proceed?"):
                return
        cib_factory.refresh()

    @command.alias('simulate')
    @command.completers(compl.choice(['nograph']))
    def do_ptest(self, context, *args):
        "usage: ptest [nograph] [v...] [scores] [utilization] [actions]"
        # use ptest/crm_simulate depending on which command was
        # used
        config.core.ptest = constants.simulate_programs[context.get_command_name()]
        if not config.core.ptest:
            return False
        set_obj = mkset_obj("xml")
        return ui_utils.ptestlike(set_obj.ptest, 'vv', context.get_command_name(), args)

    def _commit(self, force=False, replace=False):
        if not cib_factory.has_cib_changed():
            common_info("apparently there is nothing to commit")
            common_info("try changing something first")
            return True
        replace = replace or not utils.cibadmin_can_patch()
        rc1 = True
        if replace and not force:
            rc1 = cib_factory.is_current_cib_equal()
        rc2 = cib_factory.has_no_primitives() or \
            self._verify(mkset_obj("xml", "changed"), mkset_obj("xml"))
        if rc1 and rc2:
            return cib_factory.commit(replace=replace)
        if force or config.core.force:
            common_info("commit forced")
            return cib_factory.commit(force=True, replace=replace)
        if utils.ask("Do you still want to commit?"):
            return cib_factory.commit(force=True, replace=replace)
        return False

    @command.skill_level('administrator')
    @command.wait
    @command.completers(compl.choice(['force', 'replace']), compl.choice(['force', 'replace']))
    def do_commit(self, context, arg0=None, arg1=None):
        "usage: commit [force] [replace]"
        force = "force" in [arg0, arg1]
        replace = "replace" in [arg0, arg1]
        if arg0 is not None and arg0 not in ("force", "replace"):
            syntax_err(('configure.commit', arg0))
            return False
        if arg1 is not None and arg1 not in ("force", "replace"):
            syntax_err(('configure.commit', arg1))
            return False
        return self._commit(force=force, replace=replace)

    @command.skill_level('administrator')
    @command.completers(compl.choice(['force']))
    def do_upgrade(self, context, force=None):
        "usage: upgrade [force]"
        if force and force != "force":
            context.fatal_error("Expected 'force' or no argument")
        return cib_factory.upgrade_validate_with(force=config.core.force or force)

    @command.skill_level('administrator')
    def do_schema(self, context, schema_st=None):
        "usage: schema [<schema>]"
        if not schema_st:
            print(cib_factory.get_schema())
            return True
        return cib_factory.change_schema(schema_st)

    def __conf_object(self, cmd, *args):
        "The configure object command."
        if cmd in list(constants.cib_cli_map.values()) and \
                not cib_factory.is_elem_supported(cmd):
            common_err("%s not supported by the RNG schema" % cmd)
            return False
        if not args:
            return cib_factory.create_object(cmd, *args)
        if args[0].startswith("id="):
            object_id = args[0][3:]
        else:
            object_id = args[0]
        params = (object_id,) + args[1:]
        return cib_factory.create_object(cmd, *params)

    @command.skill_level('administrator')
    #@command.completers(_node_id_list, compl.choice(constants.node_attributes_keyw))
    @command.completers_repeating(_node_completer)
    def do_node(self, context, *args):
        """usage: node <uname>[:<type>]
           [attributes <param>=<value> [<param>=<value>...]]
           [utilization <param>=<value> [<param>=<value>...]]"""
        return self.__conf_object(context.get_command_name(), *args)

    @command.skill_level('administrator')
    @command.completers_repeating(compl.attr_id, ra_classes_or_tmpl, primitive_complete_complex)
    @command.alias('resource')
    def do_primitive(self, context, *args):
        """usage: primitive <rsc> {[<class>:[<provider>:]]<type>|@<template>}
        [[params] <param>=<value> [<param>=<value>...]]
        [meta <attribute>=<value> [<attribute>=<value>...]]
        [utilization <attribute>=<value> [<attribute>=<value>...]]
        [operations id_spec
            [op op_type [<attribute>=<value>...]
                        [[op_params] <param>=<value> [<param>=<value>...]]
                        [op_meta <attribute>=<value> [<attribute>=<value>...]] ...]]"""
        tmp = list(args)
        for item in ['monitor_Master', 'monitor_Slave']:
            if item in tmp:
                idx = tmp.index(item)
                tmp.remove(item)
                tmp.insert(idx, "monitor")
                tmp.insert(idx+1, "role=%s" % item.split('_')[1])
        return self.__conf_object(context.get_command_name(), *tuple(tmp))

    @command.completers_repeating(compl.attr_id, _container_type, container_complete_complex)
    def do_bundle(self, context, *args):
        """usage: bundle <bundle id> <container type> [<container option>...]
        network [<network option>...]
        storage [<storage option>...]
        primitive <resource id> {[<class>:[<provider>:]]<type>|@<template>}"""
        return self.__conf_object(context.get_command_name(), *args)

    @command.skill_level('administrator')
    @command.completers_repeating(compl.attr_id, _group_completer)
    def do_group(self, context, *args):
        """usage: group <name> <rsc> [<rsc>...]
        [params <param>=<value> [<param>=<value>...]]
        [meta <attribute>=<value> [<attribute>=<value>...]]"""
        return self.__conf_object(context.get_command_name(), *args)

    @command.skill_level('administrator')
    @command.completers_repeating(compl.attr_id, _f_children_id_list, _advanced_completer)
    def do_clone(self, context, *args):
        """usage: clone <name> <rsc>
        [params <param>=<value> [<param>=<value>...]]
        [meta <attribute>=<value> [<attribute>=<value>...]]"""
        return self.__conf_object(context.get_command_name(), *args)

    @command.alias('master')
    @command.skill_level('administrator')
    @command.completers_repeating(compl.attr_id, _f_children_id_list, _advanced_completer)
    def do_ms(self, context, *args):
        """usage: ms <name> <rsc>
        [params <param>=<value> [<param>=<value>...]]
        [meta <attribute>=<value> [<attribute>=<value>...]]"""
        return self.__conf_object(context.get_command_name(), *args)

    @command.skill_level('administrator')
    @command.completers_repeating(compl.attr_id, ui_ra.complete_class_provider_type,
                                  primitive_complete_complex)
    def do_rsc_template(self, context, *args):
        """usage: rsc_template <name> [<class>:[<provider>:]]<type>
        [params <param>=<value> [<param>=<value>...]]
        [meta <attribute>=<value> [<attribute>=<value>...]]
        [utilization <attribute>=<value> [<attribute>=<value>...]]
        [operations id_spec
            [op op_type [<attribute>=<value>...] ...]]"""
        return self.__conf_object(context.get_command_name(), *args)

    @command.skill_level('administrator')
    @command.completers_repeating(compl.attr_id, location_complete_complex)
    def do_location(self, context, *args):
        """usage: location <id> <rsc> {node_pref|rules}

        node_pref :: <score>: <node>

        rules ::
          rule [id_spec] [$role=<role>] <score>: <expression>
          [rule [id_spec] [$role=<role>] <score>: <expression> ...]

        id_spec :: $id=<id> | $id-ref=<id>
        score :: <number> | <attribute> | [-]inf
        expression :: <simple_exp> [bool_op <simple_exp> ...]
        bool_op :: or | and
        simple_exp :: <attribute> [type:]<binary_op> <value>
                      | <unary_op> <attribute>
                      | date <date_expr>
        type :: string | version | number
        binary_op :: lt | gt | lte | gte | eq | ne
        unary_op :: defined | not_defined"""
        return self.__conf_object(context.get_command_name(), *args)

    @command.alias('collocation')
    @command.skill_level('administrator')
    @command.completers_repeating(compl.attr_id, colocation_complete_complex)
    def do_colocation(self, context, *args):
        """usage: colocation <id> <score>: <rsc>[:<role>] <rsc>[:<role>] ...
        [node-attribute=<node_attr>]"""
        return self.__conf_object(context.get_command_name(), *args)

    @command.skill_level('administrator')
    @command.completers_repeating(compl.attr_id, order_complete_complex)
    def do_order(self, context, *args):
        """usage: order <id> {kind|<score>}: <rsc>[:<action>] <rsc>[:<action>] ...
        [symmetrical=<bool>]"""
        return self.__conf_object(context.get_command_name(), *args)

    @command.skill_level('administrator')
    @command.completers_repeating(compl.attr_id, _ticket_completer)
    def do_rsc_ticket(self, context, *args):
        """usage: rsc_ticket <id> <ticket_id>: <rsc>[:<role>] [<rsc>[:<role>] ...]
        [loss-policy=<loss_policy_action>]"""
        return self.__conf_object(context.get_command_name(), *args)

    @command.skill_level('administrator')
    @command.completers_repeating(_property_completer)
    def do_property(self, context, *args):
        "usage: property [$id=<set_id>] <option>=<value>"
        return self.__conf_object(context.get_command_name(), *args)

    @command.skill_level('administrator')
    @command.completers_repeating(_prim_meta_completer)
    def do_rsc_defaults(self, context, *args):
        "usage: rsc_defaults [$id=<set_id>] <option>=<value>"
        return self.__conf_object(context.get_command_name(), *args)

    @command.skill_level('administrator')
    @command.completers_repeating(_op_defaults_completer)
    def do_op_defaults(self, context, *args):
        "usage: op_defaults [$id=<set_id>] <option>=<value>"
        return self.__conf_object(context.get_command_name(), *args)

    @command.skill_level('administrator')
    @command.completers_repeating(node_id_colon_list, stonith_resource_list)
    def do_fencing_topology(self, context, *args):
        "usage: fencing_topology [<node>:] stonith_resources [stonith_resources ...]"
        return self.__conf_object(context.get_command_name(), *args)

    @command.skill_level('administrator')
    def do_xml(self, context, *args):
        "usage: xml <xml>"
        return self.__conf_object(context.get_command_name(), *args)

    @command.skill_level('administrator')
    @command.completers(_f_children_id_list)
    def do_monitor(self, context, *args):
        "usage: monitor <rsc>[:<role>] <interval>[:<timeout>]"
        return self.__conf_object(context.get_command_name(), *args)

    @command.skill_level('expert')
    @command.completers_repeating(compl.null, compl.choice(["role:", "read", "write", "deny"]))
    def do_user(self, context, *args):
        """user <uid> {roles|rules}

        roles :: role:<role-ref> [role:<role-ref> ...]
        rules :: rule [rule ...]

        (See the role command for details on rules.)"""
        return self.__conf_object(context.get_command_name(), *args)

    @command.skill_level('expert')
    @command.completers_repeating(compl.null, compl.choice(["read", "write", "deny"]))
    def do_role(self, context, *args):
        """role <role-id> rule [rule ...]

        rule :: acl-right cib-spec [attribute:<attribute>]

        acl-right :: read | write | deny

        cib-spec :: xpath-spec | tag-ref-spec
        xpath-spec :: xpath:<xpath> | shortcut
        tag-ref-spec :: tag:<tag> | ref:<id> | tag:<tag> ref:<id>

        shortcut :: meta:<rsc>[:<attr>]
                    params:<rsc>[:<attr>]
                    utilization:<rsc>
                    location:<rsc>
                    property[:<attr>]
                    node[:<node>]
                    nodeattr[:<attr>]
                    nodeutil[:<node>]
                    status"""
        return self.__conf_object(context.get_command_name(), *args)

    @command.skill_level('expert')
    def do_acl_target(self, context, *args):
        return self.__conf_object(context.get_command_name(), *args)

    @command.skill_level('administrator')
    @command.completers_repeating(compl.null, top_rsc_tmpl_id_list)
    def do_tag(self, context, *args):
        return self.__conf_object(context.get_command_name(), *args)

    @command.skill_level('administrator')
    def do_alert(self, context, *args):
        return self.__conf_object(context.get_command_name(), *args)

    @command.skill_level('expert')
    @command.completers_repeating(_rsc_id_list)
    def do_rsctest(self, context, *args):
        "usage: rsctest <rsc_id> [<rsc_id> ...] [<node_id> ...]"
        rc = True
        rsc_l = []
        node_l = []
        current = "r"
        for ident in args:
            el = cib_factory.find_object(ident)
            if not el:
                common_err("element %s does not exist" % ident)
                rc = False
            elif current == "r" and xmlutil.is_resource(el.node):
                if xmlutil.is_container(el.node):
                    rsc_l += el.node.findall("primitive")
                else:
                    rsc_l.append(el.node)
            elif xmlutil.is_normal_node(el.node):
                current = "n"
                node_l.append(el.node.get("uname"))
            else:
                syntax_err((context.get_command_name(), ident), context='rsctest')
                return False
        if not rc:
            return False
        if not rsc_l:
            common_err("specify at least one resource")
            return False
        all_nodes = cib_factory.node_id_list()
        if not node_l:
            node_l = all_nodes
        return rsctest.test_resources(rsc_l, node_l, all_nodes)

    def should_wait(self):
        return cib_factory.has_cib_changed()

    def end_game(self, no_questions_asked=False):
        ok = True
        if cib_factory.has_cib_changed():
            if no_questions_asked or not options.interactive:
                ok = self._commit()
            elif utils.ask("There are changes pending. Do you want to commit them?"):
                ok = self._commit()
        cib_factory.reset()
        return ok
