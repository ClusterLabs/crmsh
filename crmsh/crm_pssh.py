# Modified pssh
# Copyright (c) 2011, Dejan Muhamedagic
# Copyright (c) 2009, Andrew McNabb
# Copyright (c) 2003-2008, Brent N. Chun

"""Parallel ssh to the set of nodes in hosts.txt.

For each node, this essentially does an "ssh host -l user prog [arg0] [arg1]
...". The -o option can be used to store stdout from each remote node in a
directory.  Each output file in that directory will be named by the
corresponding remote node's hostname or IP address.
"""

import os
import glob
import typing

from . import config
from . import log
from .prun import prun

logger = log.setup_logger(__name__)


_DEFAULT_TIMEOUT = 60
_EC_LOGROT = 120


def get_output(odir, host):
    '''
    Looks for the output returned by the given host.
    This is somewhat problematic, since it is possible that
    different hosts can have similar hostnames. For example naming
    hosts "host.1" and "host.2" will confuse this code.
    '''
    l = []
    for fname in ["%s/%s" % (odir, host)] + glob.glob("%s/%s.[0-9]*" % (odir, host)):
        try:
            if os.path.isfile(fname):
                with open(fname) as f:
                    l += f.readlines()
        except IOError:
            continue
    return l


def show_output(odir, hosts, desc):
    '''
    Display output from hosts. See get_output for caveats.
    '''
    for host in hosts:
        out_l = get_output(odir, host)
        if out_l:
            print("%s %s:" % (host, desc))
            print(''.join(out_l))


def do_pssh(host_cmdline: typing.Sequence[typing.Tuple[str, str]], outdir, errdir):
    if outdir:
        os.makedirs(outdir, exist_ok=True)
    if errdir:
        os.makedirs(errdir, exist_ok=True)

    class StdoutStderrInterceptor(prun.PRunInterceptor):
        def __init__(self):
            self._task_count = -1
            self._stdout_path = None
            self._stderr_path = None

        def task(self, task: prun.Task) -> prun.Task:
            self._task_count += 1
            if outdir:
                path = f'{outdir}/{task.context["host"]}.{self._task_count}'
                task.stdout = prun.Task.RedirectToFile(path)
                self._stdout_path = path
            if errdir:
                path = f'{errdir}/{task.context["host"]}.{self._task_count}'
                task.stderr = prun.Task.RedirectToFile(path)
                self._stderr_path = path
            return task

        def result(self, result: prun.ProcessResult) -> prun.ProcessResult:
            result.stdout_path = self._stdout_path
            result.stderr_path = self._stderr_path
            return result

    # TODO: implement timeout
    return prun.prun_multimap(host_cmdline, interceptor=StdoutStderrInterceptor())


def examine_outcome(
        results: typing.Sequence[typing.Tuple[str, typing.Union[prun.ProcessResult, prun.SSHError]]],
        errdir: str,
):
    '''
    A custom function to show stderr in case there were issues.
    Not suited for callers who want better control of output or
    per-host processing.
    '''
    if any(isinstance(result, prun.SSHError) for host, result in results):
        logger.warning("ssh processes failed")
        show_output(errdir, [host for host, result in results], "stderr")
        return False
    elif any((0 > result.returncode for host, result in results)):
        # At least one process was killed.
        logger.error("ssh process was killed")
        show_output(errdir, [host for host, result in results], "stderr")
        return False
    elif any(0 != result.returncode and _EC_LOGROT != result.returncode for host, result in results):
        logger.warning("some ssh processes failed")
        show_output(errdir, [host for host, result in results], "stderr")
        return False
    return True


def next_loglines(a, outdir, errdir, from_time):
    '''
    pssh to nodes to collect new logs.
    '''
    l = []
    for node, rptlog, logfile, nextpos in a:
        logger.debug("updating %s from %s (pos %d)", logfile, node, nextpos)
        if logfile.startswith("/tmp") and logfile.endswith("/journal.log"):
            cmdline = "/usr/bin/journalctl -o short-iso --since '%s' --no-pager" % (from_time)
        else:
            cmdline = "perl -e 'exit(%d) if (stat(\"%s\"))[7]<%d' && tail -c +%d %s" % (
                _EC_LOGROT, logfile, nextpos-1, nextpos, logfile)
        l.append([node, cmdline])
    results = do_pssh(l, outdir, errdir)
    if results:
        return examine_outcome(results, errdir)
    else:
        return False


def next_peinputs(node_pe_l, outdir, errdir):
    '''
    pssh to nodes to collect new logs.
    '''
    pe_dir = config.path.pe_state_dir
    vardir = os.path.dirname(pe_dir)
    l = []
    for node, pe_l in node_pe_l:
        red_pe_l = [os.path.join("pengine", os.path.basename(x)) for x in pe_l]
        cmdline = "tar -C %s -chf - %s" % (vardir, ' '.join(red_pe_l))
        logger.debug("getting new PE inputs %s from %s", red_pe_l, node)
        l.append([node, cmdline])
    if not l:
        # is this a failure?
        return True
    results = do_pssh(l, outdir, errdir)
    return examine_outcome(results, errdir)


def do_pssh_cmd(cmd, node_l, outdir, errdir, timeout=20000):
    '''
    pssh to nodes and run cmd.
    '''
    l = []
    for node in node_l:
        l.append([node, cmd])
    if not l:
        return True
    return do_pssh(l, outdir, errdir)

# vim:ts=4:sw=4:et:
