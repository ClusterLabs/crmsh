import os
import re
import time
import datetime
from behave import given, when, then
from crmsh import corosync, parallax
from utils import check_cluster_state, check_service_state, online, run_command, me, \
        run_command_local_or_remote, get_file_type, get_all_files, file_in_archive, \
        get_file_content
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
    if out:
        context.stdout = out
        context.logger.info("\n{}".format(out))


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


@when('Get "{file_name}" content from "{archive_name}"')
def step_impl(context, file_name, archive_name):
    context.stdout = get_file_content(archive_name, file_name)
    context.logger.info("\n{}".format(context.stdout))


@then('Expected multiple lines')
def step_impl(context):
    assert context.stdout == context.text
    context.stdout = None


@then('Expected multiple lines in output')
def step_impl(context):
    assert context.text in context.stdout
    context.stdout = None


@then('Expected multiple lines not in output')
def step_impl(context):
    assert context.text not in context.stdout
    context.stdout = None


@then('Expected "{msg}" in stdout')
def step_impl(context, msg):
    assert msg in context.stdout
    context.stdout = None


@then('Expected return code is "{num}"')
def step_impl(context, num):
    assert context.return_code == int(num)


@then('Except "{msg}"')
def step_impl(context, msg):
    assert context.command_error_output == msg
    context.command_error_output = None


@then('Except multiple lines')
def step_impl(context):
    assert context.command_error_output.split('\n') == context.text.split('\n')
    context.command_error_output = None


@then('Except "{msg}" in stderr')
def step_impl(context, msg):
    assert msg in context.command_error_output
    context.command_error_output = None


@then('Except multiline')
def step_impl(context):
    assert context.command_error_output == context.text
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
    _, out = run_command(context, 'corosync-cfgtool -s')
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


@then('File "{f}" in "{archive}"')
def step_impl(context, f, archive):
    assert file_in_archive(f, archive) is True


@then('File "{f}" not in "{archive}"')
def step_impl(context, f, archive):
    assert file_in_archive(f, archive) is False


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


@then('Default hb_report tar file created')
def step_impl(context):
    default_file_name = 'hb_report-{}.tar.bz2'.format(datetime.datetime.now().strftime("%a-%d-%b-%Y"))
    assert os.path.exists(default_file_name) is True


@when('Write multi lines to file "{f}"')
def step_impl(context, f):
    with open(f, 'w') as fd:
        fd.write(context.text)


@when('Remove default hb_report tar file')
def step_impl(context):
    default_file_name = 'hb_report-{}.tar.bz2'.format(datetime.datetime.now().strftime("%a-%d-%b-%Y"))
    os.remove(default_file_name)


@then('Default hb_report directory created')
def step_impl(context):
    default_file_name = 'hb_report-{}'.format(datetime.datetime.now().strftime("%a-%d-%b-%Y"))
    assert os.path.isdir(default_file_name) is True


@then('"{file_name}" created')
def step_impl(context, file_name):
    file_type = get_file_type(file_name)
    if file_type == "bzip2":
        assert os.path.exists(file_name) is True
    if file_type == "directory":
        assert os.path.isdir(file_name) is True


@then('"{archive_name}" include essential files for "{nodes}"')
def step_impl(context, archive_name, nodes):
    files = 'cib.txt cib.xml context.txt corosync.conf crm_mon.txt journal.log sysinfo.txt'
    essential_files_list = []
    base_archive_name = ""
    archive_type = get_file_type(archive_name)

    if archive_type == "bzip2":
        base_archive_name = '.'.join(os.path.basename(archive_name).split('.')[:-2])
    if archive_type == "directory":
        base_archive_name = archive_name
    for node in nodes.split():
        essential_files_list += ["{}/{}/{}".format(base_archive_name, node, f) for f in files.split()]
    
    all_files = get_all_files(archive_name)
    for ef in essential_files_list:
        assert ef in all_files
