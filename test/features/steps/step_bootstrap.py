import re
import logging
from behave import given, when, then
from crmsh import utils, bootstrap, corosync, parallax


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

    if addr == "local":
        assert bootstrap.service_is_active('pacemaker.service') is state_dict[state]
    else:
        test_active = "systemctl -q is-active pacemaker.service"
        try:
            parallax.parallax_call([addr], test_active)
        except ValueError:
            assert state_dict[state] is False
        else:
            assert state_dict[state] is True


def online(context, nodelist):
    rc = True
    _, out = utils.get_stdout("crm_node -l")
    for node in nodelist.split():
        node_info = "{} member".format(node)
        if not node_info in out:
            rc = False
            context.logger.error("Node \"{}\" not online\n".format(node))
    return rc


@given('Cluster service is "{state}" on "{addr}"')
def step_impl(context, state, addr):
    check_cluster_state(context, state, addr)


@given('Online nodes are "{nodelist}"')
def step_impl(context, nodelist):
    assert online(context, nodelist) is True


@given('IP "{addr}" is belong to "{iface}"')
def step_impl(context, addr, iface):
    cmd = 'ip address show dev {}'.format(iface)
    res = re.search(r' {}/'.format(addr), run_command(context, cmd))
    assert bool(res) is True


@when('Run "{cmd}" on "{addr}"')
def step_impl(context, cmd, addr):
    if addr == "local":
        out = run_command(context, cmd)
        if out:
            context.command_out = out
    else:
        try:
            results = parallax.parallax_call([addr], cmd)
        except ValueError as err:
            context.logger.error("{}\n".format(err))
            context.failed = True


@then('Cluster service is "{state}" on "{addr}"')
def step_impl(context, state, addr):
    check_cluster_state(context, state, addr)


@then('Online nodes are "{nodelist}"')
def step_impl(context, nodelist):
    assert online(context, nodelist) is True


@then('IP "{addr}" is used by corosync')
def step_impl(context, addr):
    out = run_command(context, 'corosync-cfgtool -s')
    res = re.search(r' {}\n'.format(addr), out)
    assert bool(res) is True


@then('Cluster name is "{name}"')
def step_impl(context, name):
    out = run_command(context, 'corosync-cmapctl -b totem.cluster_name')
    assert out.split()[-1] == name


@then('Cluster virtual IP is "{addr}"')
def step_impl(context, addr):
    out = run_command(context, 'crm configure show|grep -A1 IPaddr2')
    res = re.search(r' ip={}'.format(addr), out)
    assert bool(res) is True


@then('Cluster is using udpu transport mode')
def step_impl(context):
    assert corosync.get_value('totem.transport') == 'udpu'
