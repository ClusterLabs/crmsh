import logging
import re
import subprocess
import time

import crmsh.userdir
import crmsh.utils


def get_online_nodes():
    _, out, _ = crmsh.utils.get_stdout_stderr('sudo crm_node -l')
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


def before_tag(context, tag):
    # tag @clean means need to stop cluster service
    if tag == "clean":
        time.sleep(3)
        online_nodes = get_online_nodes()
        if online_nodes:
            resource_cleanup()
            while True:
                time.sleep(1)
                rc, stdout, _ = crmsh.utils.get_stdout_stderr('sudo crmadmin -D -t 1')
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
