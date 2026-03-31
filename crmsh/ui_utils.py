# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import re
import inspect
from . import utils
from . import log
from argparse import ArgumentParser, RawDescriptionHelpFormatter


logger = log.setup_logger(__name__)
logger_utils = log.LoggerUtils(logger)


def _get_attr_cmd(attr_ext_commands, subcmd):
    try:
        attr_cmd = attr_ext_commands[subcmd]
        if attr_cmd:
            return attr_cmd
    except KeyError as msg:
        raise ValueError(msg)
    raise ValueError("Bad attr_cmd " + repr(attr_ext_commands))


def _dispatch_attr_cmd(cmd, attr_cmd, rsc, subcmd, attr, value):
    def sanity_check(arg):
        if not utils.is_name_sane(arg):
            raise ValueError("Expected valid name, got '%s'" % (arg))
    if subcmd in ['set', 'set_p']:
        if value is None:
            raise ValueError("Missing value argument to set")
        sanity_check(rsc)
        sanity_check(attr)
        sanity_check(value)
        return utils.ext_cmd(attr_cmd % (rsc, attr, value)) == 0
    elif subcmd in ('delete', 'show') or \
            (cmd == "secret" and subcmd in ('stash', 'unstash', 'check')):
        if value is not None:
            raise ValueError("Too many arguments to %s" % (subcmd))
        sanity_check(rsc)
        sanity_check(attr)
        return utils.ext_cmd(attr_cmd % (rsc, attr)) == 0
    raise ValueError("Unknown command " + repr(subcmd))


def manage_attr(cmd, attr_ext_commands, rsc, subcmd, attr, value):
    '''
    TODO: describe.
    '''
    try:
        attr_cmd = _get_attr_cmd(attr_ext_commands, subcmd)
        if re.search(r"\w+=\w+", attr):
            attr, value = attr.split('=')
        return _dispatch_attr_cmd(cmd, attr_cmd, rsc, subcmd, attr, value)
    except ValueError as msg:
        cmdline = [rsc, subcmd, attr]
        if value is not None:
            cmdline.append(value)
        logger_utils.bad_usage(cmd, ' '.join(cmdline), msg)
        return False


def ptestlike(simfun, def_verb, cmd, args):
    verbosity = def_verb  # default verbosity
    nograph = False
    scores = False
    utilization = False
    actions = False
    for p in args:
        if p == "nograph":
            nograph = True
        elif p == "scores":
            scores = True
        elif p == "utilization":
            utilization = True
        elif p == "actions":
            actions = True
        elif re.match("^vv*$", p):
            verbosity = p
        else:
            logger_utils.bad_usage(cmd, ' '.join(args))
            return False
    return simfun(nograph, scores, utilization, actions, verbosity)


def graph_args(args):
    '''
    Common parameters for two graph commands:
        configure graph [<gtype> [<file> [<img_format>]]]
        history graph <pe> [<gtype> [<file> [<img_format>]]]
    '''
    def tryarg(n, orelse):
        try:
            return args[n]
        except IndexError:
            return orelse
        except TypeError:
            return orelse

    from .crm_gv import gv_types
    gtype, outf, ftype = None, None, None
    gtype = tryarg(0, "dot")
    if gtype not in gv_types:
        logger.error("graph type %s is not supported", gtype)
        return False, gtype, outf, ftype
    outf = tryarg(1, None)
    if outf is not None and not utils.is_path_sane(outf):
        return False, gtype, outf, ftype
    ftype = tryarg(2, gtype)
    return True, gtype, outf, ftype


def pretty_arguments(f, nskip=0):
    '''
    Returns a prettified representation
    of the command arguments
    '''
    specs = inspect.getfullargspec(f)
    named_args = []
    if specs.defaults is None:
        named_args += specs.args
    else:
        named_args += specs.args[:-len(specs.defaults)]
        named_args += [("[%s]" % a) for a in specs.args[-len(specs.defaults):]]
    if specs.varargs:
        named_args += ['[%s ...]' % (specs.varargs)]
    if nskip:
        named_args = named_args[nskip:]
    return ' '.join(named_args)


def validate_arguments(f, args, nskip=0):
    '''
    Compares the declared arguments of f to
    the given arguments in args, and raises
    ValueError if the arguments don't match.

    nskip: When reporting an error, skip these
    many initial arguments when counting.
    For example, pass 1 to not count self on a
    method.

    Note: Does not support keyword arguments.
    '''
    specs = inspect.getfullargspec(f)
    min_args = len(specs.args)
    if specs.defaults is not None:
        min_args -= len(specs.defaults)
    max_args = len(specs.args)
    if specs.varargs:
        max_args = -1

    def mknamed():
        return pretty_arguments(f, nskip=nskip)

    if min_args == max_args and len(args) != min_args:
        raise ValueError("Expected (%s), takes exactly %d arguments (%d given)" %
                         (mknamed(), min_args-nskip, len(args)-nskip))
    elif len(args) < min_args:
        raise ValueError("Expected (%s), takes at least %d arguments (%d given)" %
                         (mknamed(), min_args-nskip, len(args)-nskip))
    if max_args >= 0 and len(args) > max_args:
        raise ValueError("Expected (%s), takes at most %d arguments (%d given)" %
                         (mknamed(), max_args-nskip, len(args)-nskip))


def parse_and_validate_node_args(command_name, *args) -> list:
    '''
    Parses option for node-related commands
    Then validates and returns the reachable node list
    '''
    action_target = "node" if command_name in ["standby", "online"] else "cluster service"
    action = f"{command_name} {action_target}"
    usage_template = """
Specify node(s) on which to {action}.
If no nodes are specified, {action} on the local node.
If --all is specified, {action} on all nodes."""
    addtion_usage = ""
    if command_name == "standby":
        usage_template += """
\n\nAdditionally, you may specify a lifetime for the standby---if set to
"reboot", the node will be back online once it reboots. "forever" will
keep the node in standby after reboot. The life time defaults to
"forever"."""
        addtion_usage = " [lifetime]"

    parser = ArgumentParser(
            description=usage_template.format(action=action),
            usage=f"{command_name} [--all | <node>... ]{addtion_usage}",
            add_help=False,
            formatter_class=RawDescriptionHelpFormatter
    )
    parser.add_argument("-h", "--help", action="store_true", dest="help", help="Show this help message")
    parser.add_argument("--all", help=f"To {action} on all nodes", action="store_true", dest="all")

    options, args = parser.parse_known_args(args)
    if options.help:
        parser.print_help()
        raise utils.TerminateSubCommand(success=True)
    if options is None or args is None:
        raise utils.TerminateSubCommand
    if options.all and args:
        raise ValueError("Should either use --all or specific node(s)")

    include_remote = command_name in ["standby", "online"]
    return utils.validate_and_get_reachable_nodes(args, options.all, include_remote)
