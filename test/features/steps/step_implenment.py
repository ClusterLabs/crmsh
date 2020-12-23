import re
import time
import os
import datetime
from behave import given, when, then
from crmsh import corosync, parallax
from utils import check_cluster_state, check_service_state, online, run_command, me, \
                  run_command_local_or_remote, file_in_archive
import const

@when('Write multi lines to file "{f}"')
def step_impl(context, f):
    with open(f, 'w') as fd:
        fd.write(context.text)

@given('Cluster service is "{state}" on "{addr}"')
def step_impl(context, state, addr):
    assert check_cluster_state(context, state, addr) is True


@given('Service "{name}" is "{state}" on "{addr}"')
def step_impl(context, name, state, addr):
    assert check_service_state(context, name, state, addr) is True


@given('Has disk "{disk}" on "{addr}"')
def step_impl(context, disk, addr):
    out = run_command_local_or_remote(context, "fdisk -l", addr)
    assert re.search(r'{} '.format(disk), out) is not None


@given('Online nodes are "{nodelist}"')
def step_impl(context, nodelist):
    assert online(context, nodelist) is True


@given('IP "{addr}" is belong to "{iface}"')
def step_impl(context, addr, iface):
    cmd = 'ip address show dev {}'.format(iface)
    res = re.search(r' {}/'.format(addr), run_command(context, cmd)[1])
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
    rc, out = run_command(context, cmd, err_record=True)
    context.return_code = rc


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


@then('Expected regrex "{reg_str}" in stdout')
def step_impl(context, reg_str):
    res = re.search(reg_str, context.stdout)
    assert res is not None
    context.stdout = None


@then('Expected return code is "{num}"')
def step_impl(context, num):
    assert context.return_code == int(num)


@then('Expected "{msg}" not in stdout')
def step_impl(context, msg):
    assert msg not in context.stdout
    context.stdout = None


@then('Except "{msg}"')
def step_impl(context, msg):
    assert msg in context.command_error_output
    context.command_error_output = None


@then('Except multiple lines')
def step_impl(context):
    assert context.command_error_output.split('\n') == context.text.split('\n')
    context.command_error_output = None


@then('Expected multiple lines in output')
def step_impl(context):
    assert context.text in context.stdout
    context.stdout = None


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


@then('IP "{addr}" is used by corosync on "{node}"')
def step_impl(context, addr, node):
    out = run_command_local_or_remote(context, 'corosync-cfgtool -s', node)
    res = re.search(r' {}\n'.format(addr), out)
    assert bool(res) is True


@then('Cluster name is "{name}"')
def step_impl(context, name):
    _, out = run_command(context, 'corosync-cmapctl -b totem.cluster_name')
    assert out.split()[-1] == name


@then('Cluster virtual IP is "{addr}"')
def step_impl(context, addr):
    _, out = run_command(context, 'crm configure show|grep -A1 IPaddr2')
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
    _, out = run_command(context, 'crm corosync status ring')
    if out:
        context.logger.info("\n{}".format(out))


@then('Show crm configure')
def step_impl(context):
    _, out = run_command(context, 'crm configure show')
    if out:
        context.logger.info("\n{}".format(out))


@then('Show status from qnetd')
def step_impl(context):
    _, out = run_command(context, 'crm corosync status qnetd')
    if out:
        context.logger.info("\n{}".format(out))


@then('Show corosync qdevice configuration')
def step_impl(context):
    _, out = run_command(context, "sed -n -e '/quorum/,/^}/ p' /etc/corosync/corosync.conf")
    if out:
        context.logger.info("\n{}".format(out))


@then('Resource "{res}" type "{res_type}" is "{state}"')
def step_impl(context, res, res_type, state):
    try_count = 0
    result = None
    while try_count < 5:
        time.sleep(1)
        _, out = run_command(context, "crm_mon -1")
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
    _, out = run_command(context, cmd)
    if out:
        result = re.search(r'name=fail-count-{} value={}'.format(res, number), out)
        assert result is not None


@then('Resource "{res_type}" not configured')
def step_impl(context, res_type):
    _, out = run_command(context, "crm configure show")
    result = re.search(r' {} '.format(res_type), out)
    assert result is None


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


@then('Corosync working on "{transport_type}" mode')
def step_impl(context, transport_type):
    if transport_type == "multicast":
        assert corosync.get_value("totem.transport") != "udpu"
    if transport_type == "unicast":
        assert corosync.get_value("totem.transport") == "udpu"


@then('Expected votes will be "{votes}"')
def step_impl(context, votes):
    assert int(corosync.get_value("quorum.expected_votes")) == int(votes)


@then('Default hb_report tar file created')
def step_impl(context):
    default_file_name = 'hb_report-{}.tar.bz2'.format(datetime.datetime.now().strftime("%w-%d-%m-%Y"))
    assert os.path.exists(default_file_name) is True


@when('Remove default hb_report tar file')
def step_impl(context):
    default_file_name = 'hb_report-{}.tar.bz2'.format(datetime.datetime.now().strftime("%w-%d-%m-%Y"))
    os.remove(default_file_name)


@then('File "{f}" in "{archive}"')
def step_impl(context, f, archive):
    assert file_in_archive(f, archive) is True


@then('File "{f}" not in "{archive}"')
def step_impl(context, f, archive):
    assert file_in_archive(f, archive) is False


@then('File "{f}" was synced in cluster')
def step_impl(context, f):
    cmd = "crm cluster diff {}".format(f)
    rc, out = run_command(context, cmd)
    assert out == ""
