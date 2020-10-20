import socket
from crmsh import utils, bootstrap, parallax_helper


def me():
    return socket.gethostname()


def run_command(context, cmd, err_record=False):
    rc, out, err = utils.get_stdout_stderr(cmd)
    if rc != 0 and err:
        if err_record:
            context.command_error_output = err
            return rc, out
        if out:
            context.logger.info("\n{}\n".format(out))
        context.logger.error("\n{}\n".format(err))
        context.failed = True
    return rc, out


def run_command_local_or_remote(context, cmd, addr, err_record=False):
    if addr == me():
        _, out = run_command(context, cmd, err_record)
        return out
    else:
        try:
            results = parallax_helper.parallax_call([addr], cmd)
        except ValueError as err:
            if err_record:
                context.command_error_output = str(err)
                return
            context.logger.error("\n{}\n".format(err))
            context.failed = True
        else:
            return results[0][1][1]


def check_service_state(context, service_name, state, addr):
    if state not in ["started", "stopped"]:
        context.logger.error("\nService state should be \"started/stopped\"\n")
        context.failed = True

    state_dict = {"started": True, "stopped": False}

    remote_addr = None if addr == me() else addr
    return utils.service_is_active(service_name, remote_addr) is state_dict[state]


def check_cluster_state(context, state, addr):
    return check_service_state(context, 'pacemaker.service', state, addr)


def online(context, nodelist):
    rc = True
    _, out = utils.get_stdout("crm_node -l")
    for node in nodelist.split():
        node_info = "{} member".format(node)
        if not node_info in out:
            rc = False
            context.logger.error("\nNode \"{}\" not online\n".format(node))
    return rc
