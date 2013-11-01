# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

import re
import inspect
from msg import bad_usage, common_err
import utils


def _get_attr_cmd(attr_ext_commands, args):
    try:
        attr_cmd = attr_ext_commands[args[1]]
        if attr_cmd:
            return attr_cmd
    except KeyError, msg:
        raise ValueError(msg)
    raise ValueError("Bad attr_cmd " + repr(attr_ext_commands))


def _dispatch_attr_cmd(cmd, attr_cmd, args):
    if args[1] == 'set':
        if len(args) != 4:
            raise ValueError("Expected 4 arguments to 'set'")
        if not utils.is_name_sane(args[0]) \
                or not utils.is_name_sane(args[2]) \
                or not utils.is_value_sane(args[3]):
            raise ValueError("Argument failed sanity check")
        return utils.ext_cmd(attr_cmd % (args[0], args[2], args[3])) == 0
    elif args[1] in ('delete', 'show') or \
            (cmd == "secret" and args[1] in ('stash', 'unstash', 'check')):
        if len(args) != 3:
            raise ValueError("Expected 3 arguments to " + args[1])
        if not utils.is_name_sane(args[0]) \
                or not utils.is_name_sane(args[2]):
            raise ValueError("Argument failed sanity check")
        return utils.ext_cmd(attr_cmd % (args[0], args[2])) == 0
    raise ValueError("Unknown command " + repr(args[1]))


def manage_attr(cmd, attr_ext_commands, args):
    '''
    TODO: describe.
    '''
    if len(args) < 3:
        bad_usage(cmd, ' '.join(args), "Too few arguments")
        return False
    try:
        attr_cmd = _get_attr_cmd(attr_ext_commands, args)
        return _dispatch_attr_cmd(cmd, attr_cmd, args)
    except ValueError, msg:
        bad_usage(cmd, ' '.join(args), msg)
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
            bad_usage(cmd, ' '.join(args))
            return False
    return simfun(nograph, scores, utilization, actions, verbosity)


def graph_args(args):
    '''
    Common parameters for two graph commands:
        configure graph [<gtype> [<file> [<img_format>]]]
        history graph <pe> [<gtype> [<file> [<img_format>]]]
    '''
    from crm_gv import gv_types
    gtype, outf, ftype = None, None, None
    try:
        gtype = args[0]
        if gtype not in gv_types:
            common_err("graph type %s is not supported" % gtype)
            return False, gtype, outf, ftype
    except:
        gtype = "dot"
    try:
        outf = args[1]
        if not utils.is_path_sane(outf):
            return False, gtype, outf, ftype
    except:
        outf = None
    try:
        ftype = args[2]
    except:
        ftype = gtype
    return True, gtype, outf, ftype


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
    specs = inspect.getargspec(f)
    min_args = len(specs.args)
    if specs.defaults is not None:
        min_args -= len(specs.defaults)
    max_args = len(specs.args)
    if specs.varargs:
        max_args = -1

    def mknamed():
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

    if min_args == max_args and len(args) != min_args:
        raise ValueError("Expected (%s), takes exactly %d arguments (%d given)" %
                         (mknamed(), min_args-nskip, len(args)-nskip))
    elif len(args) < min_args:
        raise ValueError("Expected (%s), takes at least %d arguments (%d given)" %
                         (mknamed(), min_args-nskip, len(args)-nskip))
    if max_args >= 0 and len(args) > max_args:
        raise ValueError("Expected (%s), takes at most %d arguments (%d given)" %
                         (mknamed(), max_args-nskip, len(args)-nskip))
