import logging
import re
from crmsh import utils, parallax


def get_online_nodes(context):
    rc, out, err = utils.get_stdout_stderr('crm_node -l')
    if rc != 0 and err:
        context.logger.error("{}\n".format(err))
        return []
    return re.findall(r'[0-9]+ (.*) member', out)


def before_tag(context, tag):
    context.logger = logging.getLogger("test.{}".format(tag))
    # tag @clean means need to stop cluster service
    if tag == "clean":
        online_nodes = get_online_nodes(context)
        if online_nodes:
            try:
                parallax.parallax_call(online_nodes, 'crm cluster stop')
            except ValueError as err:
                context.logger.error("{}\n".format(err))
        else:
            context.logger.error("Can't get online node list\n")
