import re
from behave import given, when, then
from crmsh import corosync, parallax
from utils import check_cluster_state, online, run_command, me


@given('Cluster service is "{state}" on "{addr}"')
def step_impl(context, state, addr):
    assert check_cluster_state(context, state, addr) is True


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
    if addr == me():
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
    assert check_cluster_state(context, state, addr) is True


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
