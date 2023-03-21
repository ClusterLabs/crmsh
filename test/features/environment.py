import logging
import re
from crmsh import utils, parallax, userdir
import time


def get_online_nodes():
    _, out, _ = utils.get_stdout_stderr('sudo crm_node -l')
    if out:
        return re.findall(r'[0-9]+ (.*) member', out)
    else:
        return None


def resource_cleanup():
    utils.get_stdout_stderr('sudo crm resource cleanup')


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
                if utils.get_dc():
                    break
            utils.get_stdout_or_raise_error("sudo crm cluster stop --all")
    if tag == "skip_non_root":
        sudoer = userdir.get_sudoer()
        if sudoer or userdir.getuser() != 'root':
            context.scenario.skip()
