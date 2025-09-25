# -*- coding: utf-8 -*-

import os
import sys
import socket
import shutil
import logging
import logging.config
import typing
from contextlib import contextmanager

from . import options
from . import constants

DEBUG2 = logging.DEBUG + 5
CRMSH_LOG_FILE = "/var/log/crmsh/crmsh.log"


class DEBUG2Logger(logging.Logger):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def debug2(self, msg, *args, **kwargs):
        if self.isEnabledFor(DEBUG2):
            self._log(DEBUG2, msg, args, **kwargs)


class NumberedLoggerInterface(DEBUG2Logger):
    """
    Interface to prepend a number to the message, used for regression test. When this class is used directly, no numbers are prepend.
    """
    lineno = -1

    @classmethod
    def reset_lineno(cls, to=0):
        pass

    @classmethod
    def incr_lineno(cls):
        pass


class NumberedLogger(NumberedLoggerInterface):
    """
    Prepend a number to the message, used for regression test
    """
    lineno = -1

    def _log( self, level, msg, args, **kwargs):
        if NumberedLogger.lineno > 0:
            msg = f'{self.lineno}: {msg}'
        super()._log(level, msg, args, **kwargs)

    @classmethod
    def reset_lineno(cls, to=0):
        cls.lineno = to

    @classmethod
    def incr_lineno(cls):
        cls.lineno += 1

    if (sys.version_info.major, sys.version_info.minor) > (3, 6):
        def findCaller(self, stack_info=False, stacklevel=1):
            return super().findCaller(stack_info, stacklevel+1)
    else:
        def findCaller(self, stack_info=False):
            if stack_info:
                return super().findCaller(stack_info)
            else:
                f = sys._getframe(4)
                co = f.f_code
                sinfo = None
                return co.co_filename, f.f_lineno, co.co_name, sinfo


class ConsoleCustomHandler(logging.StreamHandler):
    """
    A custom handler for console

    Redirect ERROR/WARNING/DEBUG message to sys.stderr
    Redirect INFO message to sys.stdout
    """

    def emit(self, record):
        if record.levelno == logging.INFO:
            stream = sys.stdout
        else:
            stream = sys.stderr
        msg = self.format(record)
        stream.write(msg)
        stream.write(self.terminator)


class NoBacktraceFormatter(logging.Formatter):
    """Suppress backtrace unless option debug is set."""
    def format(self, record):
        """
        Format the specified record as text.

        The record's attribute dictionary is used as the operand to a
        string formatting operation which yields the returned string.
        Before formatting the dictionary, a couple of preparatory steps
        are carried out. The message attribute of the record is computed
        using LogRecord.getMessage(). If the formatting string uses the
        time (as determined by a call to usesTime(), formatTime() is
        called to format the event time. If there is exception information,
        it is formatted using formatException() and appended to the message.
        """
        if record.exc_info or record.stack_info:
            from crmsh import config
            if config.core.debug:
                return super().format(record)
            else:
                record.message = record.getMessage()
                if self.usesTime():
                    record.asctime = self.formatTime(record, self.datefmt)
            return self.formatMessage(record)
        else:
            return super().format(record)


class ConsoleColoredFormatter(NoBacktraceFormatter):
    """Print levelname with colors and suppress backtrace."""
    COLORS = {
        logging.WARNING: constants.YELLOW,
        logging.INFO: constants.GREEN,
        logging.ERROR: constants.RED
    }
    FORMAT = "%(levelname)s: %(message)s"

    def __init__(self, fmt=None):
        super().__init__(fmt)
        if not fmt:
            fmt = self.FORMAT
        self._colored_formatter: typing.Mapping[int, logging.Formatter] = {
            level: NoBacktraceFormatter(fmt.replace('%(levelname)s', f'{color}%(levelname)s{constants.END}'))
            for level, color in self.COLORS.items()
        }

    def format(self, record):
        colored_formatter = self._colored_formatter.get(record.levelno)
        if colored_formatter is not None:
            return colored_formatter.format(record)
        else:
            return super().format(record)


class LeveledFormatter(logging.Formatter):
    """Format log according to log level."""
    def __init__(self, base_formatter_factory, default_fmt: str = None, level_fmt: typing.Mapping[int, str] = None):
        super().__init__()
        self.default_formatter = base_formatter_factory(default_fmt)
        self.level_formatter = {
            level: base_formatter_factory(fmt)
            for level, fmt in level_fmt.items()
        }

    def format(self, record):
        formatter = self.level_formatter.get(record.levelno)
        if formatter is None:
            formatter = self.default_formatter
        return formatter.format(record)


class DebugCustomFilter(logging.Filter):
    """
    A custom filter for debug and debug2 messages
    """
    def filter(self, record):
        from .config import core, report
        if record.levelno == logging.DEBUG:
            return core.debug or int(report.verbosity) >= 1
        elif record.levelno == DEBUG2:
            return int(report.verbosity) > 1
        else:
            return True


class GroupWriteRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """
    A custom rotating file handler which keeps log files group wirtable after rotating
    Source: https://stackoverflow.com/a/6779307
    """
    def _open(self):
        rtv = super()._open()
        try:
            shutil.chown(rtv.name, group=constants.HA_GROUP)
            os.fchmod(rtv.fileno(), 0o664)
            shutil.chown(rtv.name, user=constants.HA_USER)
        except PermissionError:
            # The file has been open, and FileHandler can write to it.
            # Failing to change owner or mode is not a fatal error.
            pass
        return rtv


LOGGING_CFG = {
    "version": 1,
    "disable_existing_loggers": "False",
    "formatters": {
        "console_report": {
            "()": LeveledFormatter,
            "base_formatter_factory": ConsoleColoredFormatter,
            "default_fmt": "{}: %(levelname)s: %(message)s".format(socket.gethostname()),
            "level_fmt": {
                DEBUG2: "{}: %(levelname)s: %(funcName)s: %(message)s".format(socket.gethostname()),
            },
        },
        "console": {
            "()": LeveledFormatter,
            "base_formatter_factory": ConsoleColoredFormatter,
            "default_fmt": "%(levelname)s: %(message)s",
            "level_fmt": {
                DEBUG2: "%(levelname)s: %(funcName)s %(message)s",
            },
        },
        "file": {
            "format": "%(asctime)s {} %(name)s: %(levelname)s: %(message)s".format(socket.gethostname()),
            "datefmt": "%Y-%m-%dT%H:%M:%S%z",
        }
    },
    "filters": {
        "filter": {
            "()": DebugCustomFilter
        },
    },
    "handlers": {
        'null': {
            'class': 'logging.NullHandler'
        },
        "console_report": {
            "()": ConsoleCustomHandler,
            "formatter": "console_report",
            "filters": ["filter"]
        },
        "console": {
            "()": ConsoleCustomHandler,
            "formatter": "console",
            "filters": ["filter"]
        },
        "buffer": {
            "class": "logging.handlers.MemoryHandler",
            "capacity": 1024*100,
            "flushLevel": logging.CRITICAL,
        },
        "file": {
            "()": GroupWriteRotatingFileHandler,
            "filename": CRMSH_LOG_FILE,
            "formatter": "file",
            "filters": ["filter"],
            "maxBytes": 1*1024*1024,
            "backupCount": 10
        }
    },
    "loggers": {
        "crmsh": {
            "handlers": ["null", "file", "console", "buffer"],
            "level": "DEBUG"
        },
        "crmsh.crash_test": {
            "handlers": ["null", "file", "console"],
            "propagate": False,
            "level": "DEBUG"
        },
        "crmsh.report": {
            "handlers": ["null", "file", "console_report"],
            "propagate": False,
            "level": "DEBUG"
        }
    }
}


NO_COLOR_FORMATTERS = {
    "console_report": {
        "()": LeveledFormatter,
        "base_formatter_factory": logging.Formatter,
        "default_fmt": "{}: %(levelname)s: %(message)s".format(socket.gethostname()),
        "level_fmt": {
            DEBUG2: "{}: %(levelname)s: %(funcName)s: %(message)s".format(socket.gethostname()),
        },
    },
    "console": {
        "()": LeveledFormatter,
        "base_formatter_factory": logging.Formatter,
        "default_fmt": "%(levelname)s: %(message)s",
        "level_fmt": {
            DEBUG2: "%(levelname)s: %(funcName)s %(message)s",
        },
    },
    "file": {
        "format": "%(asctime)s {} %(name)s: %(levelname)s: %(message)s".format(socket.gethostname()),
        "datefmt": "%b %d %H:%M:%S",
    }
}


class LoggerUtils(object):
    """
    A class to keep/update some attributes related with logger
    Also has methods related with handler and formatter
    And a set of wrapped log message for specific scenarios
    """
    def __init__(self, logger: NumberedLogger):
        """
        Init function
        """
        self.logger = logger
        # used in regression test
        self.__save_lineno = 0

    def get_handler(self, _type):
        """
        Get logger specific handler
        """
        for h in self.logger.handlers:
            if getattr(h, '_name') == _type:
                return h
        else:
            raise ValueError("Failed to find \"{}\" handler in logger \"{}\"".format(_type, self.logger.name))

    def disable_info_in_console(self):
        """
        Set log level as warning in console
        """
        console_handler = self.get_handler("console")
        console_handler.setLevel(logging.WARNING)

    def reset_lineno(self, to=0):
        """
        Reset line number
        """
        self.logger.reset_lineno(to)

    def incr_lineno(self):
        """
        Increase line number
        """
        self.logger.incr_lineno()

    @contextmanager
    def only_file(self):
        """
        Only log to file in bootstrap logger
        """
        console_handler = self.get_handler("console")
        try:
            self.logger.removeHandler(console_handler)
            yield
        finally:
            self.logger.addHandler(console_handler)

    def log_only_to_file(self, msg, level=logging.INFO):
        from .config import core
        if core.debug:
            self.logger.log(logging.DEBUG, msg)
        else:
            with self.only_file():
                self.logger.log(level, msg)

    @contextmanager
    def buffer(self):
        """
        Keep log messages in memory and finally show them in console
        """
        console_handler = self.get_handler("console")
        buffer_handler = self.get_handler("buffer")
        try:
            # remove console handler temporarily
            self.logger.removeHandler(console_handler)
            buffer_handler.buffer.clear()
            # set the target of buffer handler as console
            buffer_handler.setTarget(console_handler)
            yield
        finally:
            empty = not buffer_handler.buffer
            # close the buffer handler(flush to console handler)
            buffer_handler.close()
            # add console handler back
            self.logger.addHandler(console_handler)
            if not empty and not options.batch:
                try:
                    input("Press enter to continue... ")
                except EOFError:
                    pass

    @contextmanager
    def line_number(self):
        """
        Mark the line number in the log record
        """
        try:
            self.__save_lineno = self.logger.lineno
            self.reset_lineno()
            yield
        finally:
            self.logger.reset_lineno(self.__save_lineno)

    @contextmanager
    def status_long(self, msg):
        """
        To wait and mark something finished, start with BEGIN msg, end of END msg
        """
        self.logger.info("BEGIN %s", msg)
        pb = ProgressBar()
        try:
            yield pb
            pb._end()
        except Exception:
            self.logger.error("FAIL %s", msg)
            raise
        else:
            self.logger.info("END %s", msg)

    def wait_input(self, prompt_string, default=""):
        """
        Wrap input function with recording prompt string and input result
        """
        with self.only_file():
            self.logger.info(prompt_string)
        value = input(prompt_string)
        if not value:
            value = default
        with self.only_file():
            self.logger.info("input result: %s", value)
        return value

    def confirm(self, msg):
        """
        To ask question
        Return True when input y
        Record question and answer by wait_input
        """
        while True:
            ans = self.wait_input("{} (y/n)? ".format(msg.strip("? ")))
            if not ans or ans.lower() not in ('y', 'n'):
                continue
            return ans.lower() == 'y'

    def syntax_err(self, s, token='', context='', msg=''):
        err = "syntax"
        if context:
            err += " in {}".format(context)
        if msg:
            err += ": {}".format(msg)
        if isinstance(s, str):
            err += " parsing '{}'".format(s)
        elif token:
            err += " near <{}> parsing '{}'".format(token, ' '.join(s))
        else:
            err += " parsing '{}'".format(' '.join(s))
        self.logger.error(err)

    def no_prog_err(self, name):
        self.logger.error("%s not available, check your installation", name)

    def unsupported_err(self, name):
        self.logger.error("%s is not supported", name)

    def missing_obj_err(self, node):
        self.logger.error("object %s:%s missing (shouldn't have happened)", node.tag, node.get("id"))

    def constraint_norefobj_err(self, constraint_id, obj_id):
        self.logger.error("constraint %s references a resource %s which doesn't exist", constraint_id, obj_id)

    def no_object_err(self, name):
        self.logger.error("object %s does not exist", name)

    def invalid_id_err(self, obj_id):
        self.logger.error("%s: invalid object id", obj_id)

    def id_used_err(self, node_id):
        self.logger.error("%s: id is already in use", node_id)

    def bad_usage(self, cmd, args, msg=None):
        if not msg:
            self.logger.error("Bad usage: '%s %s'", cmd, args)
        else:
            self.logger.error("Bad usage: %s, command: '%s %s'", msg, cmd, args)

    def empty_cib_err(self):
        self.logger.error("No CIB!")

    def text_xml_parse_err(self, msg, s):
        self.logger.error(msg)
        self.logger.info("offending string: %s", s)

    def cib_ver_unsupported_err(self, validator, rel):
        self.logger.error("Unsupported CIB: validator '%s', release '%s'", validator, rel)
        self.logger.error("To upgrade an old (<1.0) schema, use the upgrade command.")

    def update_err(self, obj_id, cibadm_opt, xml, rc):
        CIB_PERMISSION_DENIED_CODE = 54
        task_table = {"-U": "update", "-D": "delete", "-P": "patch"}
        task = task_table.get(cibadm_opt, "replace")
        self.logger.error("could not %s %s (rc=%d)", task, obj_id, int(rc))
        if int(rc) == CIB_PERMISSION_DENIED_CODE:
            self.logger.info("Permission denied.")
        elif task == "patch":
            self.logger.info("offending xml diff: %s", xml)
        else:
            self.logger.info("offending xml: %s", xml)


class ProgressBar:
    def __init__(self):
        self._i = 0

    def progress(self):
        try:
            width, _ = os.get_terminal_size()
        except OSError:
            # not a terminal
            return
        if width == 0:
            return
        self._i = (self._i + 1) % width
        line = '\r{}{}'.format('.' * self._i, ' ' * (width - self._i))
        sys.stdout.write(line)
        sys.stdout.flush()

    def _end(self):
        try:
            width, _ = os.get_terminal_size()
        except OSError:
            # not a terminal
            return
        if width == 0:
            return
        if self._i == 0:
            pass
        elif self._i < width:
            line = '\r{}\n'.format('.' * self._i)
            sys.stdout.write(line)
        else:
            # the terminal is resized and narrower than the progress bar printed before
            # just write an LF in this case
            sys.stdout.write('\n')
        sys.stdout.flush()



def setup_logging(only_help=False):
    """
    Setup log directory and loadding logging config dict
    """
    # To avoid the potential "permission denied" error under other users (boo#1192754)
    if only_help:
        LOGGING_CFG["handlers"]["file"] = {'class': 'logging.NullHandler'}
    # dirname(CRMSH_LOG_FILE) should be created by package manager during installation
    try:
        with open(CRMSH_LOG_FILE, 'a'):
            pass
    except (PermissionError, FileNotFoundError) as e:
        print('{}WARNING:{} Failed to open log file: {}'.format(constants.YELLOW, constants.END, e), file=sys.stderr)
        LOGGING_CFG["handlers"]["file"] = {'class': 'logging.NullHandler'}
    logging.addLevelName(DEBUG2, "DEBUG2")
    if os.environ.get('CRMSH_REGRESSION_TEST'):
        logging.setLoggerClass(NumberedLogger)
        LOGGING_CFG['formatters'] = NO_COLOR_FORMATTERS
        logging.config.dictConfig(LOGGING_CFG)
    else:
        logging.setLoggerClass(NumberedLoggerInterface)
        logging.config.dictConfig(LOGGING_CFG)


def setup_logger(name):
    """
    Get the logger
    name could be any module name
    should assign parent's handlers for inherit
    """
    logger = logging.getLogger(name)
    logger.handlers = logger.parent.handlers
    logger.propagate = False
    return logger


def setup_report_logger(name):
    """
    Get the logger for crm report
    """
    logger = setup_logger(name)
    return logger
