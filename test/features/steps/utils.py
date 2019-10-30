import socket
from crmsh import utils, bootstrap, parallax


def me():
    return socket.gethostname()


def run_command(context, cmd):
    rc, out, err = utils.get_stdout_stderr(cmd)
    if rc != 0 and err:
        context.logger.error("{}\n".format(err))
        context.failed = True
    return out


def check_cluster_state(context, state, addr):
    if state not in ["started", "stopped"]:
        context.logger.error("Cluster service state should be \"started/stopped\"\n")
        context.failed = True

    state_dict = {"started": True, "stopped": False}

    if addr == me():
        return bootstrap.service_is_active('pacemaker.service') is state_dict[state]
    else:
        test_active = "systemctl -q is-active pacemaker.service"
        try:
            parallax.parallax_call([addr], test_active)
        except ValueError:
            return state_dict[state] is False
        else:
            return state_dict[state] is True


def online(context, nodelist):
    rc = True
    _, out = utils.get_stdout("crm_node -l")
    for node in nodelist.split():
        node_info = "{} member".format(node)
        if not node_info in out:
            rc = False
            context.logger.error("Node \"{}\" not online\n".format(node))
    return rc
