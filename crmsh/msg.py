# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# See COPYING for license information.

import sys
from . import config
from . import clidisplay
from . import options

ERR_STREAM = sys.stderr


class ErrorBuffer(object):
    '''
    Show error messages either immediately or buffered.
    '''
    def __init__(self):
        try:
            from . import term
            self._term = term
        except:
            self._term = None
        self.msg_list = []
        self.mode = "immediate"
        self.lineno = -1
        self.__save_lineno = -1
        self.written = {}

    def buffer(self):
        self.mode = "keep"

    def release(self):
        if self.msg_list:
            if ERR_STREAM:
                print('\n'.join(self.msg_list), file=ERR_STREAM)
            else:
                print('\n'.join(self.msg_list))
            if not options.batch:
                try:
                    input("Press enter to continue... ")
                except EOFError:
                    pass
            self.msg_list = []
        self.mode = "immediate"

    def writemsg(self, msg, to=None):
        if to is None:
            to = ERR_STREAM
        if msg.endswith('\n'):
            msg = msg[:-1]
        if self.mode == "immediate":
            if options.regression_tests or not to:
                print(msg)
            else:
                print(msg, file=to)
        else:
            self.msg_list.append(msg)

    def reset_lineno(self, to=0):
        self.lineno = to

    def incr_lineno(self):
        if self.lineno >= 0:
            self.lineno += 1

    def start_tmp_lineno(self):
        self.__save_lineno = self.lineno
        self.reset_lineno()

    def stop_tmp_lineno(self):
        self.lineno = self.__save_lineno

    def add_lineno(self, s):
        if self.lineno > 0:
            return "%d: %s" % (self.lineno, s)
        else:
            return s

    def _prefix(self, pfx, s, to=None):
        self.writemsg(self._render("%s: %s" % (pfx, self.add_lineno(s))), to=to)

    def ok(self, s):
        self._prefix(clidisplay.ok("OK"), s, to=sys.stdout)

    def error(self, s):
        self._prefix(clidisplay.error("ERROR"), s)

    def warning(self, s):
        self._prefix(clidisplay.warn("WARNING"), s)

    def one_warning(self, s):
        if s not in self.written:
            self.written[s] = 1
            self.writemsg(self._render(clidisplay.warn("WARNING")) + ": %s" %
                          self.add_lineno(s))

    def info(self, s):
        self._prefix(clidisplay.info("INFO"), s, to=sys.stdout)

    def debug(self, s):
        if config.core.debug:
            self._prefix("DEBUG", s)

    def _render(self, s):
        'Render for TERM.'
        if self._term:
            return self._term.render(s)
        return s


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


def unsupported_err(name):
    err_buf.error("%s is not supported" % name)


def missing_obj_err(node):
    err_buf.error("object %s:%s missing (shouldn't have happened)" %
                  (node.tag, node.get("id")))


def constraint_norefobj_err(constraint_id, obj_id):
    err_buf.error("constraint %s references a resource %s which doesn't exist" %
                  (constraint_id, obj_id))


def no_object_err(name):
    err_buf.error("object %s does not exist" % name)


def invalid_id_err(obj_id):
    err_buf.error("%s: invalid object id" % obj_id)


def id_used_err(node_id):
    err_buf.error("%s: id is already in use" % node_id)


def syntax_err(s, token='', context='', msg=''):
    err = "syntax"
    if context:
        err += " in "
        err += context
    if msg:
        err += ": %s" % (msg)
    if isinstance(s, str):
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


def cib_ver_unsupported_err(validator, rel):
    err_buf.error("Unsupported CIB: validator '%s', release '%s'" %
                  (validator, rel))
    err_buf.error("To upgrade an old (<1.0) schema, use the upgrade command.")


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


err_buf = ErrorBuffer()
# vim:ts=4:sw=4:et:
