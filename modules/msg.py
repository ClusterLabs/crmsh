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

import sys
from lxml import etree
from singletonmixin import Singleton
from userprefs import Options, UserPrefs


class ErrorBuffer(Singleton):
    '''
    Show error messages either immediately or buffered.
    '''
    def __init__(self):
        self.msg_list = []
        self.mode = "immediate"
        self.lineno = -1
        self.written = {}

    def buffer(self):
        self.mode = "keep"

    def release(self):
        if self.msg_list:
            print >> sys.stderr, '\n'.join(self.msg_list)
            if not options.batch:
                try:
                    raw_input("Press enter to continue... ")
                except EOFError:
                    pass
            self.msg_list = []
        self.mode = "immediate"

    def writemsg(self, msg):
        if self.mode == "immediate":
            if options.regression_tests:
                print msg
            else:
                print >> sys.stderr, msg
        else:
            self.msg_list.append(msg)

    def reset_lineno(self):
        self.lineno = 0

    def incr_lineno(self):
        if self.lineno >= 0:
            self.lineno += 1

    def start_tmp_lineno(self):
        self._save_lineno = self.lineno
        self.reset_lineno()

    def stop_tmp_lineno(self):
        self.lineno = self._save_lineno

    def add_lineno(self, s):
        if self.lineno > 0:
            return "%d: %s" % (self.lineno, s)
        else:
            return s

    def error(self, s):
        self.writemsg("ERROR: %s" % self.add_lineno(s))

    def warning(self, s):
        self.writemsg("WARNING: %s" % self.add_lineno(s))

    def one_warning(self, s):
        if not s in self.written:
            self.written[s] = 1
            self.writemsg("WARNING: %s" % self.add_lineno(s))

    def info(self, s):
        self.writemsg("INFO: %s" % self.add_lineno(s))

    def debug(self, s):
        if user_prefs.debug:
            self.writemsg("DEBUG: %s" % self.add_lineno(s))


def common_error(s):
    err_buf.error(s)


def common_err(s):
    err_buf.error(s)


def common_warning(s):
    err_buf.warning(s)


def common_warn(s):
    err_buf.warning(s)


def warn_once(s):
    err_buf.one_warning(s)


def common_info(s):
    err_buf.info(s)


def common_debug(s):
    err_buf.debug(s)


def no_prog_err(name):
    err_buf.error("%s not available, check your installation" % name)


def no_file_err(name):
    err_buf.error("%s does not exist" % name)


def missing_prog_warn(name):
    err_buf.warning("could not find any %s on the system" % name)


def node_err(msg, node):
    err_buf.error("%s: %s" % (msg, etree.tostring(node, pretty_print=True)))


def node_debug(msg, node):
    err_buf.debug("%s: %s" % (msg, etree.tostring(node, pretty_print=True)))


def no_attribute_err(attr, obj_type):
    err_buf.error("required attribute %s not found in %s" % (attr, obj_type))


def bad_def_err(what, msg):
    err_buf.error("bad %s definition: %s" % (what, msg))


def unsupported_err(name):
    err_buf.error("%s is not supported" % name)


def no_such_obj_err(name):
    err_buf.error("%s object is not supported" % name)


def obj_cli_warn(name):
    err_buf.info("object %s cannot be represented in the CLI notation" % name)


def missing_obj_err(node):
    err_buf.error("object %s:%s missing (shouldn't have happened)" %
                  (node.tag, node.get("id")))


def constraint_norefobj_err(constraint_id, obj_id):
    err_buf.error("constraint %s references a resource %s which doesn't exist" %
        (constraint_id, obj_id))


def obj_exists_err(name):
    err_buf.error("object %s already exists" % name)


def no_object_err(name):
    err_buf.error("object %s does not exist" % name)


def invalid_id_err(obj_id):
    err_buf.error("%s: invalid object id" % obj_id)


def id_used_err(node_id):
    err_buf.error("%s: id is already in use" % node_id)


def skill_err(s):
    err_buf.error("%s: this command is not allowed at this skill level" % s)


def syntax_err(s, token='', context='', msg=''):
    err = "syntax"
    if context:
        err += " in "
        err += context
    if msg:
        err += ": %s" % (msg)
    if isinstance(s, basestring):
        err += " parsing '%s'" % (s)
    elif token:
        err += " near <%s> parsing '%s'" % (token, ' '.join(s))
    else:
        err += " parsing '%s'" % (' '.join(s))
    err_buf.error(err)


def bad_usage(cmd, args, msg=None):
    if not msg:
        err_buf.error("Bad usage: '%s %s'" % (cmd, args))
    else:
        err_buf.error("Bad usage: %s, command: '%s %s'" % (msg, cmd, args))


def empty_cib_err():
    err_buf.error("No CIB!")


def cib_parse_err(msg, s):
    err_buf.error("%s" % msg)
    err_buf.info("offending string: %s" % s)


def cib_no_elem_err(el_name):
    err_buf.error("CIB contains no '%s' element!" % el_name)


def cib_ver_unsupported_err(validator, rel):
    err_buf.error("CIB not supported: validator '%s', release '%s'" %
                  (validator, rel))
    err_buf.error("You may try the upgrade command")


def update_err(obj_id, cibadm_opt, xml, rc):
    if cibadm_opt == '-U':
        task = "update"
    elif cibadm_opt == '-D':
        task = "delete"
    elif cibadm_opt == '-P':
        task = "patch"
    else:
        task = "replace"
    err_buf.error("could not %s %s (rc=%d)" % (task, obj_id, rc))
    if rc == 54:
        err_buf.info("Permission denied.")
    elif task == "patch":
        err_buf.info("offending xml diff: %s" % xml)
    else:
        err_buf.info("offending xml: %s" % xml)


def not_impl_info(s):
    err_buf.info("%s is not implemented yet" % s)


user_prefs = UserPrefs.getInstance()
err_buf = ErrorBuffer.getInstance()
options = Options.getInstance()
# vim:ts=4:sw=4:et:
