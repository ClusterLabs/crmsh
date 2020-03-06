import re
import time
from behave import given, when, then
from crmsh import corosync, parallax
from utils import check_cluster_state, check_service_state, online, run_command, me, \
                  run_command_local_or_remote
import const


@given('Cluster service is "{state}" on "{addr}"')
def step_impl(context, state, addr):
    assert check_cluster_state(context, state, addr) is True


@given('Service "{name}" is "{state}" on "{addr}"')
def step_impl(context, name, state, addr):
    assert check_service_state(context, name, state, addr) is True


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
    out = run_command_local_or_remote(context, cmd, addr)
    context.stdout = out


@when('Try "{cmd}" on "{addr}"')
def step_impl(context, cmd, addr):
    run_command_local_or_remote(context, cmd, addr, err_record=True)


@when('Try "{cmd}"')
def step_impl(context, cmd):
    run_command(context, cmd, err_record=True)


@when('Wait "{second}" seconds')
def step_impl(context, second):
    time.sleep(int(second))


@then('Got output "{msg}"')
def step_impl(context, msg):
    assert context.stdout == msg
    context.stdout = None


@then('Expected multiple lines')
def step_impl(context):
    assert context.stdout == context.text
    context.stdout = None


@then('Expected "{msg}" in stdout')
def step_impl(context, msg):
    assert msg in context.stdout
    context.stdout = None


@then('Expected "{msg}" not in stdout')
def step_impl(context, msg):
    assert msg not in context.stdout
    context.stdout = None


@then('Except "{msg}"')
def step_impl(context, msg):
    assert context.command_error_output == msg
    context.command_error_output = None


@then('Except "{msg}" in stderr')
def step_impl(context, msg):
    assert msg in context.command_error_output
    context.command_error_output = None


@then('Cluster service is "{state}" on "{addr}"')
def step_impl(context, state, addr):
    assert check_cluster_state(context, state, addr) is True


@then('Service "{name}" is "{state}" on "{addr}"')
def step_impl(context, name, state, addr):
    assert check_service_state(context, name, state, addr) is True


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


@then('Show cluster status on "{addr}"')
def step_impl(context, addr):
    out = run_command_local_or_remote(context, 'crm_mon -1', addr)
    if out:
        context.logger.info("\n{}".format(out))


@then('Show corosync ring status')
def step_impl(context):
    out = run_command(context, 'crm corosync status')
    if out:
        context.logger.info("\n{}".format(out))


@then('Resource "{res}" type "{res_type}" is "{state}"')
def step_impl(context, res, res_type, state):
    try_count = 0
    result = None
    while try_count < 5:
        time.sleep(1)
        out = run_command(context, "crm_mon -1")
        if out:
            result = re.search(r'\s{}\s+.*:{}\):\s+{} '.format(res, res_type, state), out)
            if not result:
                try_count += 1
            else:
                break
    assert result is not None


@then('Resource "{res}" failcount on "{node}" is "{number}"')
def step_impl(context, res, node, number):
    cmd = "crm resource failcount {} show {}".format(res, node)
    out = run_command(context, cmd)
    if out:
        result = re.search(r'name=fail-count-{} value={}'.format(res, number), out)
        assert result is not None


@then('Output is the same with expected "{cmd}" help output')
def step_impl(context, cmd):
    cmd_help = {}
    cmd_help["crm"] = const.CRM_H_OUTPUT
    cmd_help["crm_cluster_init"] = const.CRM_CLUSTER_INIT_H_OUTPUT
    cmd_help["crm_cluster_join"] = const.CRM_CLUSTER_JOIN_H_OUTPUT
    cmd_help["crm_cluster_add"] = const.CRM_CLUSTER_ADD_H_OUTPUT
    cmd_help["crm_cluster_remove"] = const.CRM_CLUSTER_REMOVE_H_OUTPUT
    cmd_help["crm_cluster_geo-init"] = const.CRM_CLUSTER_GEO_INIT_H_OUTPUT
    cmd_help["crm_cluster_geo-join"] = const.CRM_CLUSTER_GEO_JOIN_H_OUTPUT
    cmd_help["crm_cluster_geo-init-arbitrator"] = const.CRM_CLUSTER_GEO_INIT_ARBIT_H_OUTPUT
    key = '_'.join(cmd.split())
    assert context.stdout == cmd_help[key]
