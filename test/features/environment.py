import logging
import re
import socket
import subprocess
import time

import crmsh.userdir
import crmsh.utils
from crmsh.sh import ShellUtils
import steps.behave_agent_client as behave_agent


def get_online_nodes():
    _, out, _ = ShellUtils().get_stdout_stderr('sudo crm_node -l')
    if out:
        return re.findall(r'[0-9]+ (.*) member', out)
    else:
        return None


def resource_cleanup():
    subprocess.run(
        ['sudo', 'crm', 'resource', 'cleanup'],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def before_step(context, step):
    context.logger = logging.getLogger("Step:{}".format(step.name))


CLUSTER_INIT_STEP_RE = re.compile(r'^(?:Run|Try) "(?P<cmd>.*crm cluster init.*?)"(?: OK)?(?: on "(?P<addr>[^"]+)")?$')
CLUSTER_INIT_STAGE_RE = re.compile(r'crm cluster init(?:\s+(?P<stage>\w+))?')
SBD_OPTION_RE = re.compile(r'\s(?:-s|-S|--sbd-device|--enable-sbd)(?:\s|=|$)')


def after_step(context, step):
    """
    The CI has no fence resource, and "crm cluster init" ends with fencing-enabled=true in that case,
    which makes pacemaker complain and block the following "crm configure" commits and resources start.
    So disable fencing after the cluster is created by "crm cluster init", for all the scenarios.
    """
    m = CLUSTER_INIT_STEP_RE.match(step.name)
    if not m or step.status.name != "passed" or getattr(context, "return_code", None) != 0:
        return
    cmd = m.group("cmd")
    stage = CLUSTER_INIT_STAGE_RE.search(cmd).group("stage")
    if stage not in (None, "cluster") or SBD_OPTION_RE.search(cmd):
        return
    disable_fencing_cmd = "crm configure property fencing-enabled=false"
    for node in (m.group("addr") or socket.gethostname()).split(","):
        if node == socket.gethostname():
            ShellUtils().get_stdout_stderr(disable_fencing_cmd, input_s="")
        else:
            sudoer = crmsh.userdir.get_sudoer()
            behave_agent.call(node, 1122, f"sudo {disable_fencing_cmd}" if sudoer else disable_fencing_cmd, user=sudoer)


def before_tag(context, tag):
    # tag @clean means need to stop cluster service
    if tag == "clean":
        time.sleep(3)
        online_nodes = get_online_nodes()
        if online_nodes:
            resource_cleanup()
            while True:
                time.sleep(1)
                rc, stdout, _ = ShellUtils().get_stdout_stderr('sudo crmadmin -D -t 1')
                if rc == 0 and stdout.startswith('Designated'):
                    break
            subprocess.call(
                ['sudo', 'crm', 'cluster', 'stop', '--all'],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    if tag == "skip_non_root":
        sudoer = crmsh.userdir.get_sudoer()
        if sudoer or crmsh.userdir.getuser() != 'root':
            context.scenario.skip()
