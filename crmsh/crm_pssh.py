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

from parallax.manager import Manager, FatalError
from parallax.task import Task
from parallax import Options

from . import config
from . import log


logger = log.setup_logger(__name__)


_DEFAULT_TIMEOUT = 60
_EC_LOGROT = 120


def parse_args(outdir, errdir, t=_DEFAULT_TIMEOUT):
    '''
    Parse the given commandline arguments.
    '''
    opts = Options()
    opts.timeout = int(t)
    opts.quiet = True
    opts.inline = False
    opts.outdir = outdir
    opts.errdir = errdir
    return opts


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
                l += open(fname).readlines()
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


def do_pssh(l, opts):
    '''
    Adapted from psshlib. Perform command across list of hosts.
    l = [(host, command), ...]
    '''
    if opts.outdir and not os.path.exists(opts.outdir):
        os.makedirs(opts.outdir)
    if opts.errdir and not os.path.exists(opts.errdir):
        os.makedirs(opts.errdir)
    manager = Manager(opts)
    user = ""
    port = ""
    hosts = []
    for host, cmdline in l:
        cmd = ['ssh', host,
               '-o', 'PasswordAuthentication=no',
               '-o', 'SendEnv=PARALLAX_NODENUM',
               '-o', 'StrictHostKeyChecking=no']
        if hasattr(opts, 'options'):
            for opt in opts.options:
                cmd += ['-o', opt]
        if user:
            cmd += ['-l', user]
        if port:
            cmd += ['-p', port]
        if hasattr(opts, 'extra'):
            cmd.extend(opts.extra)
        if cmdline:
            cmd.append(cmdline)
        hosts.append(host)
        t = Task(host, port, user, cmd,
                 stdin=opts.input_stream,
                 verbose=opts.verbose,
                 quiet=opts.quiet,
                 print_out=opts.print_out,
                 inline=opts.inline,
                 inline_stdout=opts.inline_stdout,
                 default_user=opts.default_user)
        manager.add_task(t)
    try:
        return manager.run()  # returns a list of exit codes
    except FatalError:
        logger.error("SSH to nodes failed")
        show_output(opts.errdir, hosts, "stderr")
        return False


def examine_outcome(l, opts, statuses):
    '''
    A custom function to show stderr in case there were issues.
    Not suited for callers who want better control of output or
    per-host processing.
    '''
    hosts = [x[0] for x in l]
    if min(statuses) < 0:
        # At least one process was killed.
        logger.error("ssh process was killed")
        show_output(opts.errdir, hosts, "stderr")
        return False
    # The any builtin was introduced in Python 2.5 (so we can't use it yet):
    # elif any(x==255 for x in statuses):
    for status in statuses:
        if status == 255:
            logger.warning("ssh processes failed")
            show_output(opts.errdir, hosts, "stderr")
            return False
    for status in statuses:
        if status not in (0, _EC_LOGROT):
            logger.warning("some ssh processes failed")
            show_output(opts.errdir, hosts, "stderr")
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
        opts = parse_args(outdir, errdir)
        l.append([node, cmdline])
    statuses = do_pssh(l, opts)
    if statuses:
        return examine_outcome(l, opts, statuses)
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
        opts = parse_args(outdir, errdir)
        l.append([node, cmdline])
    if not l:
        # is this a failure?
        return True
    statuses = do_pssh(l, opts)
    if statuses:
        return examine_outcome(l, opts, statuses)
    else:
        return False


def do_pssh_cmd(cmd, node_l, outdir, errdir, timeout=20000):
    '''
    pssh to nodes and run cmd.
    '''
    l = []
    for node in node_l:
        l.append([node, cmd])
    if not l:
        return True
    opts = parse_args(outdir, errdir, t=int(timeout // 1000))
    return do_pssh(l, opts)

# vim:ts=4:sw=4:et:
