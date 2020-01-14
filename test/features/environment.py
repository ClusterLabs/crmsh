import logging
import re
from crmsh import utils, parallax_helper


def get_online_nodes():
    _, out, _ = utils.get_stdout_stderr('crm_node -l')
    if out:
        return re.findall(r'[0-9]+ (.*) member', out)
    else:
        return None


def resource_cleanup():
    utils.get_stdout_stderr('crm resource cleanup')


def before_step(context, step):
    context.logger = logging.getLogger("Step:{}".format(step.name))


def before_tag(context, tag):
    # tag @clean means need to stop cluster service
    if tag == "clean":
        online_nodes = get_online_nodes()
        if online_nodes:
            resource_cleanup()
            try:
                parallax_helper.parallax_call(online_nodes, 'crm cluster stop')
            except ValueError as err:
                context.logger.error("{}\n".format(err))
                context.failed = True
