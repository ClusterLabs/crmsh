import random
from behave import given, when, then

import behave_agent


_rng = random.SystemRandom()


def _gen_random_string():
    return 'random-' + _rng.randbytes(8).hex()


@given('Permit root ssh login with password on "{node}"')
def step_impl(context, node):
    eof = _gen_random_string()
    script = '''echo 'PermitRootLogin yes' > /etc/ssh/sshd_config.d/permit-root-login.conf
systemctl restart sshd.service
'''
    rc, stdout, stderr = behave_agent.call(node, 1122, script, user='root')
    if 0 == rc:
        return
    else:
        print(stderr.decode('utf-8', errors='backslashreplace'))
        assert 0 == rc


@given('The password of user "{user}" set to "{password}" on "{node}"')
def step_impl(context, user, password, node):
    eof = _gen_random_string()
    script = f'''chpasswd << '{eof}'
{user}:{password}
{eof}
'''
    rc, stdout, stderr = behave_agent.call(node, 1122, script, user='root')
    if 0 == rc:
        return
    else:
        print(stderr.decode('utf-8', errors='backslashreplace'))
        assert 0 == rc



@given('Directory ~{user}/.ssh is empty on "{node}"')
def step_impl(context, user, node):
    rc, stdout, stderr = behave_agent.call(node, 1122, f'rm -rf ~{user}/.ssh', user='root')
    if 0 == rc:
        return
    else:
        print(stderr.decode('utf-8', errors='backslashreplace'))
        assert 0 == rc


@then('This expect program exits with 0 on "{user}"@"{node}"')
def step_impl(context, user, node):
    eof = _gen_random_string()
    script = f'''expect <(cat << '{eof}'
{context.text}
{eof}
)
'''
    rc, stdout, stderr = behave_agent.call(node, 1122, script, user)
    if 0 == rc:
        print(stdout.decode('utf-8', errors='backslashreplace'))
        return
    else:
        print(stderr.decode('utf-8', errors='backslashreplace'))
        assert 0 == rc
