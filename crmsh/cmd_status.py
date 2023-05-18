# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# See COPYING for license information.

import re
from . import clidisplay
from . import utils

_crm_mon = None

_WARNS = ['pending',
          'complete',
          'Timed Out',
          'NOT SUPPORTED',
          'Error',
          'Not installed',
          r'UNKNOWN\!',
          'Stopped',
          'standby',
          'WITHOUT quorum']
_OKS = ['Masters', 'Slaves', 'Started', 'Master', 'Slave', 'Online', 'online', 'ok', 'master',
        'with quorum']
_ERRORS = ['not running',
           'unknown error',
           'invalid parameter',
           'unimplemented feature',
           'insufficient privileges',
           'not installed',
           'not configured',
           'not running',
           r'master \(failed\)',
           'OCF_SIGNAL',
           'OCF_NOT_SUPPORTED',
           'OCF_TIMEOUT',
           'OCF_OTHER_ERROR',
           'OCF_DEGRADED',
           'OCF_DEGRADED_MASTER',
           'unknown',
           'Unknown',
           'OFFLINE',
           'Failed actions']


class CrmMonFilter(object):
    _OK = re.compile(r'(%s)' % '|'.join(r"(?:\b%s\b)" % (w) for w in _OKS))
    _WARNS = re.compile(r'(%s)' % '|'.join(_WARNS))
    _ERROR = re.compile(r'(%s)' % ('|'.join(_ERRORS)))
    _NODES = re.compile(r'(\d+ Nodes configured)')
    _RESOURCES = re.compile(r'(\d+ Resources configured)')

    _RESOURCE = re.compile(r'(\S+)(\s+)\((\S+:\S+)\):')
    _GROUP = re.compile(r'((?:Resource Group)|(?:Clone Set)|(?:Master/Slave Set)): (\S+)')

    def _filter(self, line):
        line = self._RESOURCE.sub("%s%s(%s):" % (clidisplay.help_header(r'\1'),
                                                 r'\2',
                                                 r'\3'), line)
        line = self._NODES.sub(clidisplay.help_header(r'\1'), line)
        line = self._RESOURCES.sub(clidisplay.help_header(r'\1'), line)
        line, ngroups = self._GROUP.subn(r'\1: ' + clidisplay.help_header(r'\2'), line)
        if ngroups == 0:
            line = self._WARNS.sub(clidisplay.warn(r'\1'), line)
            line = self._OK.sub(clidisplay.ok(r'\1'), line)
            line = self._ERROR.sub(clidisplay.error(r'\1'), line)
        return line

    def __call__(self, text):
        return '\n'.join([self._filter(line) for line in text.splitlines()]) + '\n'


def crm_mon(opts=''):
    """
    Run 'crm_mon -1'
    opts: Additional options to pass to crm_mon
    returns: rc, stdout
    """
    global _crm_mon
    if _crm_mon is None:
        prog = utils.is_program("crm_mon")
        if not prog:
            raise IOError("crm_mon not available, check your installation")
        _, out = utils.get_stdout("%s --help" % (prog))
        if "--pending" in out:
            _crm_mon = "%s -1 -j" % (prog)
        else:
            _crm_mon = "%s -1" % (prog)

    status_cmd = "%s %s" % (_crm_mon, opts)
    return utils.get_stdout(utils.add_sudo(status_cmd))


def cmd_status(args):
    '''
    Calls crm_mon -1, passing optional extra arguments.
    Displays the output, paging if necessary.
    Raises IOError if crm_mon fails.
    '''
    opts = {
        "bynode": "-n",
        "inactive": "-r",
        "ops": "-o",
        "timing": "-t",
        "failcounts": "-f",
        "verbose": "-V",
        "quiet": "-Q",
        "html": "--output-as html",
        "xml": "--output-as xml",
        "simple": "-s",
        "tickets": "-c",
        "noheaders": "-D",
        "detail": "-R",
        "brief": "-b",
        "full": "-ncrft",
    }
    extra = ' '.join(opts.get(arg, arg) for arg in args)
    if not args:
        extra = "-r"
    rc, s = crm_mon(extra)
    if rc != 0:
        raise IOError("crm_mon (rc=%d): %s" % (rc, s))

    utils.page_string(CrmMonFilter()(s))
    return True


def cmd_verify(args):
    '''
    Calls crm_verify -LV; ptest -L -VVVV
    '''
    from . import config
    if "ptest" in config.core.ptest:
        cmd1 = "crm_verify -LVVV; %s -L -VVVV" % (config.core.ptest)
    else:
        cmd1 = "crm_verify -LVVV; %s -LjV" % (config.core.ptest)

        if "scores" in args:
            cmd1 += " -s"

    cmd1 = utils.add_sudo(cmd1)
    rc, s, e = utils.get_stdout_stderr(cmd1)
    e = '\n'.join(clidisplay.error(l) for l in e.split('\n')).strip()
    utils.page_string("\n".join((s, e)))
    return rc == 0 and not e
