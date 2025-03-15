import ast
import re
import time
import os
import datetime
import yaml

import behave
from behave import given, when, then
import behave_agent
from crmsh import corosync, userdir, bootstrap
from crmsh import utils as crmutils
from crmsh import sbd
from crmsh import ui_configure
from crmsh.sh import ShellUtils
from utils import check_cluster_state, check_service_state, online, run_command, me, \
                  run_command_local_or_remote, file_in_archive, \
                  assert_eq, is_unclean, assert_in
import const


def _parse_str(text):
    return ast.literal_eval(text)
_parse_str.pattern='"([^"]|\\")*?"'


behave.use_step_matcher("cfparse")
behave.register_type(str=_parse_str)


@when('Write multi lines to file "{f}" on "{addr}"')
def step_impl(context, f, addr):
    data_list = context.text.split('\n')
    for line in data_list:
        echo_option = " -n" if line == data_list[-1] else ""
        cmd = "echo{} \"{}\"|sudo tee -a {}".format(echo_option, line, f)
        if addr != me():
            sudoer = userdir.get_sudoer()
            user = f"{sudoer}@" if sudoer else ""
            cmd = f"ssh {user}{addr} '{cmd}'"
        run_command(context, cmd)


@given('Cluster service is "{state}" on "{addr}"')
def step_impl(context, state, addr):
    assert check_cluster_state(context, state, addr) is True


@given('Nodes [{nodes:str+}] are cleaned up')
def step_impl(context, nodes):
    run_command(context, 'crm resource cleanup || true')
    for node in nodes:
        # wait for ssh service
        for _ in range(10):
            rc, _, _ = ShellUtils().get_stdout_stderr('ssh {} true'.format(node))
            if rc == 0:
                break
            time.sleep(1)
        run_command_local_or_remote(context, "crm cluster stop {} || true".format(node), node)
        assert check_cluster_state(context, 'stopped', node) is True


@given('Service "{name}" is "{state}" on "{addr}"')
def step_impl(context, name, state, addr):
    assert check_service_state(context, name, state, addr) is True


@given('Has disk "{disk}" on "{addr}"')
def step_impl(context, disk, addr):
    _, out, _ = run_command_local_or_remote(context, "fdisk -l", addr)
    assert re.search(r'{} '.format(disk), out) is not None


@given('Online nodes are "{nodelist}"')
def step_impl(context, nodelist):
    assert online(context, nodelist) is True


@given('Run "{cmd}" OK')
def step_impl(context, cmd):
    rc, _, _ = run_command(context, cmd)
    assert rc == 0


@then('Run "{cmd}" OK')
def step_impl(context, cmd):
    rc, _, _ = run_command(context, cmd)
    assert rc == 0


@when('Run "{cmd}" OK')
def step_impl(context, cmd):
    rc, _, _ = run_command(context, cmd)
    assert rc == 0


@given('IP "{addr}" is belong to "{iface}"')
def step_impl(context, addr, iface):
    cmd = 'ip address show dev {}'.format(iface)
    res = re.search(r' {}/'.format(addr), run_command(context, cmd)[1])
    assert bool(res) is True


@given('Run "{cmd}" OK on "{addr}"')
def step_impl(context, cmd, addr):
    _, out, _ = run_command_local_or_remote(context, cmd, addr, True)

@when('Run "{cmd}" on "{addr}"')
def step_impl(context, cmd, addr):
    _, out, _ = run_command_local_or_remote(context, cmd, addr)


@then('Run "{cmd}" OK on "{addr}"')
def step_impl(context, cmd, addr):
    _, out, _ = run_command_local_or_remote(context, cmd, addr)


@then('Print stdout')
def step_impl(context):
    context.logger.info("\n{}".format(context.stdout))


@then('Print stderr')
def step_impl(context):
    context.logger.info("\n{}".format(context.stderr))


@then('No crmsh tracebacks')
def step_impl(context):
    if "Traceback (most recent call last):" in context.stderr and \
            re.search('File "/usr/lib/python.*/crmsh/', context.stderr):
        context.logger.info("\n{}".format(context.stderr))
        context.failed = True


@when('Try "{cmd}" on "{addr}"')
def step_impl(context, cmd, addr):
    run_command_local_or_remote(context, cmd, addr, exit_on_fail=False)


@when('Try "{cmd}"')
def step_impl(context, cmd):
    _, out, _ = run_command(context, cmd, exit_on_fail=False)


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
    assert_in(msg, context.stdout)
    context.stdout = None


@then('Expected "{msg}" in stderr')
def step_impl(context, msg):
    assert_in(msg, context.stderr)
    context.stderr = None


@then('Expect stdout contains snippets [{snippets:str+}].')
def step_impl(context, snippets):
    for snippet in snippets:
        assert_in(snippet, context.stdout)
    context.stdout = None


@then('Expected regex "{reg_str}" in stdout')
def step_impl(context, reg_str):
    res = re.search(reg_str, context.stdout)
    assert res is not None
    context.stdout = None


@then('Expected regex "{reg_str}" in stderr')
def step_impl(context, reg_str):
    assert context.stderr is not None and re.search(reg_str, context.stderr)
    context.stderr = None


@then('Expected return code is "{num}"')
def step_impl(context, num):
    assert context.return_code == int(num)


@then('Expected "{msg}" not in stdout')
def step_impl(context, msg):
    assert msg not in context.stdout
    context.stdout = None


@then('Expected "{msg}" not in stderr')
def step_impl(context, msg):
    assert context.stderr is None or msg not in context.stderr
    context.stderr = None


@then('Except "{msg}"')
def step_impl(context, msg):
    assert_in(msg, context.stderr)
    context.stderr = None


@then('Except multiple lines')
def step_impl(context):
    assert_in(context.text, context.stderr)
    context.stderr = None


@then('Expected multiple lines in output')
def step_impl(context):
    assert_in(context.text, context.stdout)
    context.stdout = None


@then('Except "{msg}" in stderr')
def step_impl(context, msg):
    assert_in(msg, context.stderr)
    context.stderr = None


@then('Cluster service is "{state}" on "{addr}"')
def step_impl(context, state, addr):
    assert check_cluster_state(context, state, addr) is True


@then('Service "{name}" is "{state}" on "{addr}"')
def step_impl(context, name, state, addr):
    assert check_service_state(context, name, state, addr) is True


@then('Online nodes are "{nodelist}"')
def step_impl(context, nodelist):
    assert online(context, nodelist) is True


@then('Node "{node}" is standby')
def step_impl(context, node):
    assert crmutils.is_standby(node) is True


@then('Node "{node}" is online')
def step_impl(context, node):
    assert crmutils.is_standby(node) is False


@then('IP "{addr}" is used by corosync on "{node}"')
def step_impl(context, addr, node):
    nodeid = crmutils.get_nodeid_from_name(node)
    _, out, _ = run_command_local_or_remote(context, f'corosync-cfgtool -a {nodeid}', node)
    assert addr in out.split()


@then('Cluster name is "{name}"')
def step_impl(context, name):
    _, out, _ = run_command(context, 'corosync-cmapctl -b totem.cluster_name')
    assert out.split()[-1] == name


@then('Cluster virtual IP is "{addr}"')
def step_impl(context, addr):
    _, out, _ = run_command(context, 'crm configure show|grep -A1 IPaddr2')
    res = re.search(r' ip={}'.format(addr), out)
    assert bool(res) is True


@then('Cluster is using "{transport_type}" transport mode')
def step_impl(context, transport_type):
    assert corosync.get_value('totem.transport') == transport_type
    _, out, _ = run_command(context, 'corosync-cfgtool -s')
    assert re.search(f'transport {transport_type}\n', out) is not None


@then('two_node in corosync.conf is "{number}"')
def step_impl(context, number):
    assert corosync.get_value('quorum.two_node') == number


@then('Show cluster status on "{addr}"')
def step_impl(context, addr):
    _, out, _ = run_command_local_or_remote(context, 'crm_mon -1', addr)
    if out:
        context.logger.info("\n{}".format(out))


@then('Show corosync ring status')
def step_impl(context):
    _, out, _ = run_command(context, 'crm corosync status ring')
    if out:
        context.logger.info("\n{}".format(out))


@then('Show crm configure')
def step_impl(context):
    _, out, _ = run_command(context, 'crm configure show')
    if out:
        context.logger.info("\n{}".format(out))


@then('Show status from qnetd')
def step_impl(context):
    _, out, _ = run_command(context, 'crm corosync status qnetd')
    if out:
        context.logger.info("\n{}".format(out))


@then('Show qdevice status')
def step_impl(context):
    _, out, _ = run_command(context, 'crm corosync status qdevice')
    if out:
        context.logger.info("\n{}".format(out))


@then('Show corosync qdevice configuration')
def step_impl(context):
    _, out, _ = run_command(context, "sed -n -e '/quorum/,/^}/ p' /etc/corosync/corosync.conf")
    if out:
        context.logger.info("\n{}".format(out))


@then('Resource "{res}" type "{res_type}" is "{state}"')
def step_impl(context, res, res_type, state):
    try_count = 0
    result = None
    while try_count < 20:
        time.sleep(1)
        _, out, _ = run_command(context, "crm_mon -1rR")
        if out:
            result = re.search(r'\s{}\s+.*:+{}\):\s+{} '.format(res, res_type, state), out)
            if not result:
                try_count += 1
            else:
                break
    assert result is not None


@then('Resource "{res}" failcount on "{node}" is "{number}"')
def step_impl(context, res, node, number):
    cmd = "crm resource failcount {} show {}".format(res, node)
    _, out, _ = run_command(context, cmd)
    if out:
        result = re.search(r'name=fail-count-{} value={}'.format(res, number), out)
        assert result is not None


@then('Resource "{res_type}" not configured')
def step_impl(context, res_type):
    _, out, _ = run_command(context, "crm configure show")
    result = re.search(r' {} '.format(res_type), out)
    assert result is None


@then('Output is the same with expected "{cmd}" help output')
def step_impl(context, cmd):
    cmd_help = {}
    cmd_help["crm"] = const.CRM_H_OUTPUT
    cmd_help["crm_cluster_init"] = const.CRM_CLUSTER_INIT_H_OUTPUT
    cmd_help["crm_cluster_join"] = const.CRM_CLUSTER_JOIN_H_OUTPUT
    cmd_help["crm_cluster_remove"] = const.CRM_CLUSTER_REMOVE_H_OUTPUT
    cmd_help["crm_cluster_geo-init"] = const.CRM_CLUSTER_GEO_INIT_H_OUTPUT
    cmd_help["crm_cluster_geo-join"] = const.CRM_CLUSTER_GEO_JOIN_H_OUTPUT
    cmd_help["crm_cluster_geo-init-arbitrator"] = const.CRM_CLUSTER_GEO_INIT_ARBIT_H_OUTPUT
    key = '_'.join(cmd.split())
    assert_eq(cmd_help[key], context.stdout)


@then('Corosync working on "{transport_type}" mode')
def step_impl(context, transport_type):
    if transport_type == "multicast":
        assert corosync.get_value("totem.transport") is None
    if transport_type == "unicast":
        assert_eq("udpu", corosync.get_value("totem.transport"))


@then('Expected votes will be "{votes}"')
def step_impl(context, votes):
    assert_eq(int(votes), int(corosync.get_value("quorum.expected_votes")))


@then('Directory "{directory}" created')
def step_impl(context, directory):
    assert os.path.isdir(directory) is True


@then('Directory "{directory}" not created')
def step_impl(context, directory):
    assert os.path.isdir(directory) is False


@then('Default crm_report tar file created')
def step_impl(context):
    default_file_name = 'crm_report-{}.tar.bz2'.format(datetime.datetime.now().strftime("%a-%d-%b-%Y"))
    assert os.path.exists(default_file_name) is True


@when('Remove default crm_report tar file')
def step_impl(context):
    default_file_name = 'crm_report-{}.tar.bz2'.format(datetime.datetime.now().strftime("%a-%d-%b-%Y"))
    os.remove(default_file_name)


@then('File "{f}" in "{archive}"')
def step_impl(context, f, archive):
    assert file_in_archive(f, archive) is True


@then('Directory "{f}" in "{archive}"')
def step_impl(context, f, archive):
    assert file_in_archive(f, archive) is True


@then('File "{f}" not in "{archive}"')
def step_impl(context, f, archive):
    assert file_in_archive(f, archive) is False


@then('File "{f}" was synced in cluster')
def step_impl(context, f):
    cmd = "crm cluster diff {}".format(f)
    rc, out, _ = run_command(context, cmd)
    assert_eq("", out)


@given('Resource "{res_id}" is started on "{node}"')
def step_impl(context, res_id, node):
    rc, out, err = ShellUtils().get_stdout_stderr("crm_mon -1")
    assert re.search(r'\*\s+{}\s+.*Started\s+{}'.format(res_id, node), out) is not None


@then('Resource "{res_id}" is started on "{node}"')
def step_impl(context, res_id, node):
    rc, out, err = ShellUtils().get_stdout_stderr("crm_mon -1")
    assert re.search(r'\*\s+{}\s+.*Started\s+{}'.format(res_id, node), out) is not None


@then('SBD option "{key}" value is "{value}"')
def step_impl(context, key, value):
    res = sbd.SBDUtils.get_sbd_value_from_config(key)
    assert_eq(value, res)


@then('SBD option "{key}" value for "{dev}" is "{value}"')
def step_impl(context, key, dev, value):
    res = sbd.SBDTimeout.get_sbd_msgwait(dev)
    assert_eq(int(value), res)


@then('Cluster property "{key}" is "{value}"')
def step_impl(context, key, value):
    res = crmutils.get_property(key)
    assert res is not None
    assert_eq(value.strip('s'), str(res).strip('s'))


@then('Property "{key}" in "{type}" is "{value}"')
def step_impl(context, key, type, value):
    res = crmutils.get_property(key, type)
    assert res is not None
    assert_eq(value.strip('s'), str(res).strip('s'))


@then('Parameter "{param_name}" not configured in "{res_id}"')
def step_impl(context, param_name, res_id):
    _, out, _ = run_command(context, "crm configure show {}".format(res_id))
    result = re.search("params .*{}=".format(param_name), out)
    assert result is None


@then('Parameter "{param_name}" configured in "{res_id}"')
def step_impl(context, param_name, res_id):
    _, out, _ = run_command(context, "crm configure show {}".format(res_id))
    result = re.search("params .*{}=".format(param_name), out)
    assert result is not None


@given('Yaml "{path}" value is "{value}"')
def step_impl(context, path, value):
    yaml_file = "/etc/crm/profiles.yml"
    with open(yaml_file) as f:
        data = yaml.load(f, Loader=yaml.SafeLoader)
    sec_name, key = path.split(':')
    assert_eq(str(value), str(data[sec_name][key]))


@when('Wait for DC')
def step_impl(context):
    while True:
        time.sleep(1)
        if crmutils.get_dc():
            break


@then('File "{path}" exists on "{node}"')
def step_impl(context, path, node):
    rc, _, stderr = behave_agent.call(node, 1122, 'test -f {}'.format(path), user='root')
    assert rc == 0


@given('File "{path}" not exist on "{node}"')
def step_impl(context, path, node):
    cmd = '[ ! -f {} ]'.format(path)
    rc, _, stderr = behave_agent.call(node, 1122, cmd, user='root')
    assert rc == 0


@then('File "{path}" not exist on "{node}"')
def step_impl(context, path, node):
    cmd = '[ ! -f {} ]'.format(path)
    rc, _, stderr = behave_agent.call(node, 1122, cmd, user='root')
    assert rc == 0


@then('Directory "{path}" is empty on "{node}"')
def step_impl(context, path, node):
    cmd = '[ ! "$(ls -A {})" ]'.format(path)
    rc, _, stderr = behave_agent.call(node, 1122, cmd, user='root')
    assert rc == 0


@then('Directory "{path}" not empty on "{node}"')
def step_impl(context, path, node):
    cmd = '[ "$(ls -A {})" ]'.format(path)
    rc, _, stderr = behave_agent.call(node, 1122, cmd, user='root')
    assert rc == 0


@then('Node "{node}" is UNCLEAN')
def step_impl(context, node):
    assert is_unclean(node) is True


@then('Wait "{count}" seconds for "{node}" successfully fenced')
def step_impl(context, count, node):
    index = 0
    while index <= int(count):
        rc, out, _ = ShellUtils().get_stdout_stderr("stonith_admin -h {}".format(node))
        if "Node {} last fenced at:".format(node) in out:
            return True
        time.sleep(1)
        index += 1
    return False

@then('Check passwordless for hacluster between "{nodelist}" "{result}"')
def step_impl(context, nodelist, result):
    assert result in ("successfully", "failed")
    if userdir.getuser() != 'root' or userdir.get_sudoer():
        return True
    failed = False
    nodes = nodelist.split()
    for i in range(0, len(nodes)):
        for j in range(i + 1, len(nodes)):
            rc, _, _ = behave_agent.call(
                nodes[i], 1122,
                f'ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 {nodes[j]} true',
                user='hacluster',
            )
            if rc != 0:
                failed = True
                context.logger.error(f"There is no passwordless configured from {nodes[i]} to {nodes[j]} under 'hacluster'")
    if result == "successfully":
        assert not failed
    else:
        assert failed


@then('Check user shell for hacluster between "{nodelist}"')
def step_impl(context, nodelist):
    if userdir.getuser() != 'root' or userdir.get_sudoer():
        return True
    for node in nodelist.split():
        if node == me():
            assert bootstrap.is_nologin('hacluster') is False
        else:
            assert bootstrap.is_nologin('hacluster', node) is False


@given('ssh-agent is started at "{path}" on nodes [{nodes:str+}]')
def step_impl(context, path, nodes):
    user =  userdir.get_sudoer()
    if not user:
        user = userdir.getuser()
    for node in nodes:
        rc, _, _ = behave_agent.call(node, 1122, f"systemd-run --uid '{user}' -u ssh-agent /usr/bin/ssh-agent -D -a '{path}'", user='root')
        assert 0 == rc


@then('This file "{target_file}" will trigger UnicodeDecodeError exception')
def step_impl(context, target_file):
    try:
        with open(target_file, "r", encoding="utf-8") as file:
            content = file.read()
    except UnicodeDecodeError as e:
        return True
    else:
        return False

@given('crm.conf poisoned on nodes [{nodes:str+}]')
def step_impl(context, nodes):
    for node in nodes:
        rc, _, _ = behave_agent.call(
            node, 1122,
            f'''mkdir -p /root/.config/crm && cat > /root/.config/crm/crm.conf << EOF
{const.CRM_CONF_CONTENT_POSIONED}
EOF''',
            user='root',
        )


@when('Set to previous schema version')
def step_impl(context):
    _, current_schema, _ = ShellUtils().get_stdout_stderr("crm configure schema")
    assert current_schema
    schema_list = ui_configure.schema_completer(None)
    assert schema_list
    assert current_schema in schema_list
    previous_schema = schema_list[schema_list.index(current_schema) - 1]
    context.previous_schema = previous_schema
    rc, _, _ = ShellUtils().get_stdout_stderr(f"crm configure schema {previous_schema}")
    assert rc == 0


@then('The schema version is the previous')
def step_impl(context):
    rc, schema, _ = ShellUtils().get_stdout_stderr("crm configure schema")
    assert rc == 0
    assert schema == context.previous_schema


@given('Get the latest schema version')
def step_impl(context):
    schema_list = ui_configure.schema_completer(None)
    assert schema_list
    context.schema_latest = schema_list[-1]


@when('Use crm configure upgrade to upgrade the schema')
def step_impl(context):
    rc, _, _ = ShellUtils().get_stdout_stderr("crm configure upgrade force")
    assert rc == 0


@then('The schema version is the latest')
def step_impl(context):
    rc, schema, _ = ShellUtils().get_stdout_stderr("crm configure schema")
    assert rc == 0
    assert schema == context.schema_latest
