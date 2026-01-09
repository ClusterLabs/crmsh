# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import os
import re
import time
import difflib
from packaging import version
from . import command
from . import completers as compl
from . import config
from . import utils
from . import constants
from . import userdir
from . import xmlutil
from . import ra
from . import cibconfig
from . import clidisplay
from . import cliformat
from . import term
from . import options
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
from .ui_node import get_resources_on_nodes, remove_redundant_attrs


from . import log
logger = log.setup_logger(__name__)
logger_utils = log.LoggerUtils(logger)


cib_factory = cibconfig.cib_factory_instance()


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
    meta completers for group/clone resource type
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


def schema_completer(args):
    complete_results = []

    directory = '/usr/share/pacemaker/'
    version_pattern = re.compile(r'^pacemaker-(\d+\.\d+)')
    for filename in os.listdir(directory):
        if version_pattern.match(filename):
            complete_results.append(filename.strip('.rng'))

    if complete_results:
        # Sort files using packaging.version
        complete_results.sort(key=lambda x: version.parse(version_pattern.match(x).group(1)))
        command.enable_custom_sort_order()

    return complete_results


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
            return
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


def _prim_params_completer(agent, args):
    completing = args[-1]
    if completing == 'params':
        return ['params']
    if completing.endswith('='):
        if len(completing) > 1 and options.interactive:
            topic = completing[:-1]
            CompletionHelp.help(topic, agent.meta_parameter(topic), args)
        return []
    elif '=' in completing:
        return []
    command.enable_custom_sort_order()
    return utils.filter_keys(agent.params(), args)


def _prim_meta_completer(agent, args):
    completing = args[-1]
    if completing == 'meta':
        return ['meta']
    if completing.endswith('='):
        if len(completing) > 1 and options.interactive:
            topic = completing[:-1]
            CompletionHelp.help(topic, agent.meta_parameter(topic), args)
        return []
    if '=' in completing:
        return []
    return utils.filter_keys(ra.get_resource_meta_list(), args)


def _prim_op_completer(agent, args):

    def concat_kv(k, v):
        return "{}={}".format(k, v)

    if args[-1] == 'op':
        return ['op']
    actions = agent.actions()
    if not actions:
        return []
    # list all actions, select one to complete
    if args[-2] == 'op':
        return actions.keys()
    # list all attributes of the action, select one to complete
    if args[-3] == 'op':
        res = []
        op_name = args[-2]
        if op_name == 'monitor':
            for one_monitor in actions[op_name]:
                res += [concat_kv(k, v) for k, v in one_monitor.items()]
        else:
            res = [concat_kv(k, v) for k, v in actions[op_name].items()]
        return res

    args.pop()
    if '=' in args[-1]:
        res = []
        # find latest action
        op_name = None
        for i, item in enumerate(reversed(args)):
            if item in actions:
                op_name = item
                break
        if not op_name:
            return []
        # list all left attributes of the action, select one to complete
        actions_list_in_args = [arg.split('=')[0] for arg in args[len(args)-i:]]
        if op_name == 'monitor':
            for one_monitor in actions[op_name]:
                res += [concat_kv(k, v) for k, v in one_monitor.items() if k not in actions_list_in_args]
        else:
            res = [concat_kv(k, v) for k, v in actions[op_name].items() if k not in actions_list_in_args]
        return res

    return []


def last_keyword(words, keyw):
    '''returns the last occurance of an element in keyw in words'''
    for w in reversed(words):
        if w in keyw:
            return w
    return None


def _property_completer(args):
    '''context-sensitive completer'''
    agent = ra.get_properties_meta()
    return _prim_params_completer(agent, args)


def _rsc_meta_completer(args):
    agent = ra.get_resource_meta()
    return _prim_meta_completer(agent, args)


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

    if last_keyw == 'meta':
        agent = ra.get_resource_meta()
    complete_results = completers_set[last_keyw](agent, args)
    if len(args) > 4 and '=' in args[-1]:
        return complete_results + keywords

    return complete_results


def container_helptxt(params, helptxt, topic):
    for item in reversed(params):
        if item in constants.container_type:
            return helptxt["container"][topic] + "\n"
        if item in ("storage", "network"):
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
    token = args[-2]
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

    container_options = utils.filter_keys(constants.container_helptxt["container"].keys(), args)

    # required options must be completed
    for s in container_options_required:
        if utils.any_startswith(args, s+'=') is None:
            return container_options

    if last_keyw is None:
        return container_options + keywords

    # to complete network, storage, primitive and meta
    return completers_set[last_keyw](args, constants.container_helptxt, keywords)


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
        if not cib_factory.initialize(no_side_effects=True):
            return True
        # see the configure ptest/simulate command
        has_ptest = utils.is_program('ptest')
        has_simulate = utils.is_program('crm_simulate')
        if not has_ptest:
            constants.simulate_programs["ptest"] = "crm_simulate"
        if not has_simulate:
            constants.simulate_programs["simulate"] = "ptest"
        if not (has_ptest or has_simulate):
            logger.warning("neither ptest nor crm_simulate exist, check your installation")
            constants.simulate_programs["ptest"] = ""
            constants.simulate_programs["simulate"] = ""
        return True

    @command.name('_test')
    @command.skill_level('administrator')
    def do_check_structure(self, context):
        cib_factory.ensure_cib_updated()
        return cib_factory.check_structure()

    @command.name('_regtest')
    @command.skill_level('administrator')
    def do_regression_testing(self, context, param):
        return cib_factory.regression_testing(param)

    @command.name('_objects')
    @command.skill_level('administrator')
    def do_showobjects(self, context):
        cib_factory.showobjects()

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

    def _show_diff(self):
        obj_orig = cibconfig.mkset_obj("orig")
        obj_orig_str = obj_orig.repr()
        obj_changed = cibconfig.mkset_obj()
        obj_changed_str = obj_changed.repr()

        diff = difflib.unified_diff(obj_orig_str.splitlines(), obj_changed_str.splitlines())
        diff = [
                line for line in diff
                if not line.startswith('+++ ') and not line.startswith('--- ')
        ]

        utils.page_string('\n'.join(diff))

    @command.skill_level('administrator')
    @command.completers_repeating(_id_show_list)
    def do_show(self, context, *args):
        "usage: show [xml] [<id>...]"
        utils.load_cib_file_env()
        osargs = [arg[8:] for arg in args if arg.startswith('obscure:')]
        if not osargs and config.core.obscure_pattern:
            # obscure_pattern could be
            #   1. "pattern1 pattern2 pattern3"
            #   2. "pattern1|pattern2|pattern3"
            # regrex here also filter out possible spaces
            osargs = re.split(r'\s*\|\s*|\s+', config.core.obscure_pattern.strip('|'))
        args = [arg for arg in args if not arg.startswith('obscure:')]
        cib_factory.ensure_cib_updated()
        with utils.obscure(osargs):
            if args and args[0] == "changed":
                self._show_diff()
                return True
            set_obj = cibconfig.mkset_obj(*args)
            return set_obj.show()

    @command.name("get_property")
    @command.alias("get-property")
    @command.skill_level('administrator')
    @command.completers_repeating(compl.call(ra.get_properties_list))
    def do_get_property(self, context, *args):
        "usage: get-property [-t|--true [<name>...]"
        utils.load_cib_file_env()
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
        cib_factory.ensure_cib_updated()
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
        cib_factory.ensure_cib_updated()
        set_obj = cibconfig.mkset_obj(*args)
        return set_obj.filter(filterprog)

    @command.skill_level('administrator')
    @command.completers(_id_list)
    def do_set(self, context, path, value):
        """
        usage: set <path> <value>

        path:: id.[op_type.][interval.]name
        """
        path_errmsg = "Invalid path: \"{}\"; Valid path: \"id.[op_type.][interval.]name\"".format(path)
        path_list = path.split('.')
        if len(path_list) < 2 or len(path_list) > 4:
            context.fatal_error(path_errmsg)

        cib_factory.ensure_cib_updated()
        obj_id, *other_path_list = path_list
        rsc = cib_factory.find_object(obj_id)
        if not rsc:
            context.fatal_error("Object {} not found".format(obj_id))

        # Use case for: set id.name value
        if len(other_path_list) == 1:
            obj_attr = other_path_list[0]
            nvpairs = rsc.node.xpath(".//nvpair[@name='{}']".format(obj_attr))
            if not nvpairs:
                context.fatal_error("Attribute not found: {}".format(path))
            if len(nvpairs) != 1:
                context.fatal_error("Expected 1 attribute named {}, found {}".format(obj_attr, len(nvpairs)))
            nvpairs[0].set("value", value)

        # Use case for: set id.op_type.name value
        if len(other_path_list) == 2:
            op_type, name = other_path_list
            op_res = rsc.node.xpath(".//operations/op[@name='{}']".format(op_type))
            if not op_res:
                context.fatal_error("Operation \"{}\" not found for resource {}".format(op_type, obj_id))
            if len(op_res) > 1:
                context.fatal_error("Should specify interval of {}".format(op_type))
            if name in ('interval', 'timeout'):
                value = utils.add_time_unit_if_needed(value)
            if name == 'interval':
                op_res[0].set('id', f'{obj_id}-{op_type}-{value}')
            op_res[0].set(name, value)

        # Use case for: set id.op_type.interval.name value
        if len(other_path_list) == 3:
            op_type, iv, name = other_path_list
            iv = iv[:-1] if utils.time_value_with_unit(iv) else iv
            # Search for IDs both with and without the associated time unit
            op_res = rsc.node.xpath(f".//operations/op[@id='{obj_id}-{op_type}-{iv}' or @id='{obj_id}-{op_type}-{iv}s']")
            if not op_res:
                context.fatal_error(f"Operation \"{op_type}\" interval \"{iv}s\" not found for resource {obj_id}")
            if name == 'interval':
                value = utils.add_time_unit_if_needed(value)
                op_res[0].set('id', f'{obj_id}-{op_type}-{value}')
            op_res[0].set(name, value)

        rsc.set_updated()
        return True

    @command.skill_level('administrator')
    @command.completers(_f_group_id_list, compl.choice(['add', 'remove']),
                        _list_resource, _pick_position, _list_resource_2)
    def do_modgroup(self, context, group_id, subcmd, prim_id, *args):
        """usage: modgroup <id> add <id> [after <id>|before <id>]
        modgroup <id> remove <id>"""
        if subcmd not in ("add", "remove"):
            logger.error("modgroup subcommand %s unknown" % subcmd)
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
        cib_factory.ensure_cib_updated()
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
        set_obj = cibconfig.mkset_obj(*l)
        return set_obj.filter("sed -r '%s'" % sed_s)

    @command.skill_level('administrator')
    @command.completers_repeating(_id_xml_list, _id_list)
    def do_edit(self, context, *args):
        "usage: edit [xml] [<id>...]"
        cib_factory.ensure_cib_updated()
        with logger_utils.buffer():  # keep error messages
            set_obj = cibconfig.mkset_obj(*args)
        return set_obj.edit()

    def _verify(self, set_obj_semantic, set_obj_all) -> utils.VerifyResult:
        rc1 = set_obj_all.verify()
        rc2 = utils.VerifyResult.SUCCESS
        if config.core.check_frequency != "never":
            rc2 = set_obj_semantic.semantic_check(set_obj_all)
        return rc1 | rc2

    @command.skill_level('administrator')
    def do_verify(self, context):
        "usage: verify"
        utils.load_cib_file_env()
        cib_factory.ensure_cib_updated()
        set_obj_all = cibconfig.mkset_obj("xml")
        verify_result = self._verify(set_obj_all, set_obj_all)
        return bool(verify_result)

    @command.name('validate-all')
    @command.alias('validate_all')
    @command.skill_level('administrator')
    @command.completers_repeating(_id_list)
    def do_validate_all(self, context, rsc):
        "usage: validate-all <rsc>"
        cib_factory.ensure_cib_updated()
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
        cib_factory.ensure_cib_updated()
        filename = args[-1]
        setargs = args[:-1]
        set_obj = cibconfig.mkset_obj(*setargs)
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
        cib_factory.ensure_cib_updated()
        if method == "replace":
            if options.interactive and cib_factory.has_cib_changed():
                if not utils.ask("This operation will erase all changes. Do you want to proceed?"):
                    return False
            cib_factory.erase()
        if xml:
            set_obj = cibconfig.mkset_obj("xml")
        else:
            set_obj = cibconfig.mkset_obj()
        return set_obj.import_file(method, url)

    @command.skill_level('administrator')
    @command.completers(compl.choice(list(gv_types.keys()) + ['exportsettings']))
    def do_graph(self, context, *args):
        "usage: graph [<gtype> [<file> [<img_format>]]]"
        if args and args[0] == "exportsettings":
            return utils.save_graphviz_file(userdir.GRAPHVIZ_USER_FILE, constants.graph)
        cib_factory.ensure_cib_updated()
        set_obj = cibconfig.mkset_obj()
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
        if arg_force or options.force:
            if self._stop_if_running(argl) > 0:
                utils.wait_dc_stable(what="Stopping %s" % (", ".join(argl)))
        cib_factory.ensure_cib_updated()
        return cib_factory.delete(*argl)

    @command.name('default-timeouts')
    @command.alias('default_timeouts')
    @command.completers_repeating(_id_list)
    def do_default_timeouts(self, context, *args):
        "usage: default-timeouts <id> [<id>...]"
        cib_factory.ensure_cib_updated()
        return cib_factory.default_timeouts(*args)

    @command.skill_level('administrator')
    @command.completers(_id_list)
    def do_rename(self, context, old_id, new_id):
        "usage: rename <old_id> <new_id>"
        cib_factory.ensure_cib_updated()
        return cib_factory.rename(old_id, new_id)

    @command.skill_level('administrator')
    @command.completers(compl.choice(['nodes']))
    def do_erase(self, context, nodes=None):
        "usage: erase [nodes]"
        cib_factory.ensure_cib_updated()
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
        set_obj = cibconfig.mkset_obj("xml")
        return ui_utils.ptestlike(set_obj.ptest, 'vv', context.get_command_name(), args)

    def _commit(self, force=False, replace=False):
        if not cib_factory.has_cib_changed():
            logger.info("apparently there is nothing to commit")
            logger.info("try changing something first")
            return True
        rc1 = True
        if replace and not force:
            rc1 = cib_factory.is_current_cib_equal()

        verify_result = self._verify(cibconfig.mkset_obj("xml", "changed"), cibconfig.mkset_obj("xml"))
        if utils.VerifyResult.FATAL_ERROR in verify_result:
            return False

        if rc1 and bool(verify_result):
            return cib_factory.commit(replace=replace)
        if force or options.force:
            logger.info("commit forced")
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
            logger_utils.syntax_err(('configure.commit', arg0))
            return False
        if arg1 is not None and arg1 not in ("force", "replace"):
            logger_utils.syntax_err(('configure.commit', arg1))
            return False
        return self._commit(force=force, replace=replace)

    @command.skill_level('administrator')
    @command.completers(compl.choice(['force']))
    def do_upgrade(self, context, force=None):
        "usage: upgrade <force>"
        if (not force or force != "force") and not options.force:
            context.fatal_error("'force' option is required")
        cib_factory.ensure_cib_updated()
        if cib_factory.upgrade_validate_with(force or options.force):
            logger.info("Current schema version is %s", cib_factory.get_schema(refresh=True))
            return True
        return False

    @command.skill_level('administrator')
    @command.completers(schema_completer)
    def do_schema(self, context, schema_st=None):
        "usage: schema [<schema>]"
        utils.load_cib_file_env()
        if not schema_st and cib_factory.is_cib_sane():
            print(cib_factory.get_schema())
            return True
        return cib_factory.change_schema(schema_st)

    def __override_lower_level_attrs(self, *args):
        """
        When setting up an attribute of a cluster, the same
        attribute may already exist in one of the nodes an/or
        any resource.
        The user should be informed about it and, if he wants,
        he will have an option to delete the already existing
        attribute.
        """
        if not args:
            return

        nvpair = args[0].split('=', 1)
        if 2 != len(nvpair):
            return

        attr_name, attr_value = nvpair

        if "maintenance-mode" == attr_name:
            attr = "maintenance"
            conflicting_lower_level_attr = 'is-managed'
            # FIXME! the first argument is hardcoded
            objs = get_resources_on_nodes(cib_factory.node_id_list(), [ "primitive", "group", "clone"])
            remove_redundant_attrs(objs, "meta_attributes", attr, conflicting_lower_level_attr)

            objs = get_resources_on_nodes(cib_factory.node_id_list(), [ "node" ])
            remove_redundant_attrs(objs, "instance_attributes", attr, conflicting_lower_level_attr)

    def __conf_object(self, cmd, *args):
        "The configure object command."
        if cmd in list(constants.cib_cli_map.values()) and \
                not cib_factory.is_elem_supported(cmd):
            logger.error("%s not supported by the RNG schema" % cmd)
            return False
        cib_factory.ensure_cib_updated()
        if not args:
            return cib_factory.create_object(cmd, *args)
        if args[0].startswith("id="):
            object_id = args[0][3:]
        else:
            object_id = args[0]
        params = (object_id,) + args[1:]
        return cib_factory.create_object(cmd, *params)

    @command.skill_level('administrator')
    @command.completers(_node_id_list, compl.choice(constants.node_attributes_keyw))
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
        return self.__conf_object(context.get_command_name(), *args)

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
    @command.completers(compl.attr_id, _top_rsc_id_list)
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
    @command.completers_repeating(compl.attr_id, compl.null, top_rsc_tmpl_id_list)
    def do_colocation(self, context, *args):
        """usage: colocation <id> <score>: <rsc>[:<role>] <rsc>[:<role>] ...
        [node-attribute=<node_attr>]"""
        return self.__conf_object(context.get_command_name(), *args)

    @command.skill_level('administrator')
    @command.completers_repeating(compl.attr_id,
                                  compl.call(
                                      lambda *args: [v + ":" for v in schema.rng_attr_values(*args)],
                                      'rsc_order',
                                      'kind'
                                  ),
                                  top_rsc_tmpl_id_list)
    def do_order(self, context, *args):
        """usage: order <id> [kind]: <rsc>[:<action>] <rsc>[:<action>] ...
        [symmetrical=<bool>]"""
        return self.__conf_object(context.get_command_name(), *args)

    @command.skill_level('administrator')
    @command.completers_repeating(compl.attr_id, compl.null, top_rsc_tmpl_id_list)
    def do_rsc_ticket(self, context, *args):
        """usage: rsc_ticket <id> <ticket_id>: <rsc>[:<role>] [<rsc>[:<role>] ...]
        [loss-policy=<loss_policy_action>]"""
        return self.__conf_object(context.get_command_name(), *args)

    @command.skill_level('administrator')
    @command.completers_repeating(_property_completer)
    def do_property(self, context, *args):
        "usage: property [$id=<set_id>] <option>=<value>"
        self.__override_lower_level_attrs(*args)
        if not args:
            utils.multicolumn(ra.get_properties_list())
            return
        return self.__conf_object(context.get_command_name(), *args)

    @command.skill_level('administrator')
    @command.completers_repeating(_rsc_meta_completer)
    def do_rsc_defaults(self, context, *args):
        "usage: rsc_defaults [$id=<set_id>] <option>=<value>"
        return self.__conf_object(context.get_command_name(), *args)

    @command.skill_level('administrator')
    @command.completers_repeating(op_attr_list)
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
        cib_factory.ensure_cib_updated()
        rc = True
        rsc_l = []
        node_l = []
        current = "r"
        for ident in args:
            el = cib_factory.find_object(ident)
            if not el:
                logger.error("element %s does not exist" % ident)
                rc = False
            elif current == "r" and xmlutil.is_resource(el.node):
                if xmlutil.is_container(el.node):
                    rsc_l += el.node.findall("primitive")
                else:
                    rsc_l.append(el.node)
            elif xmlutil.is_member_node(el.node):
                current = "n"
                node_l.append(el.node.get("uname"))
            else:
                logger_utils.syntax_err((context.get_command_name(), ident), context='rsctest')
                return False
        if not rc:
            return False
        if not rsc_l:
            logger.error("specify at least one resource")
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
            else:
                print("There are changes pending:")
                self._show_diff()
                confirm_msg = "Do you want to commit them, or cancel the operation?"
                rc = utils.ask(confirm_msg, cancel_option=True)
                if rc:
                    ok = self._commit()
        cib_factory.reset()
        return ok
