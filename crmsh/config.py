# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.
'''
Holds user-configurable options.
'''

import os
import re
import configparser
from contextlib import contextmanager
from . import userdir


@contextmanager
def _disable_exception_traceback():
    """
    All traceback information is suppressed and only the exception type and value are printed
    """
    default_value = getattr(sys, "tracebacklimit", 1000)  # `1000` is a Python's default value
    sys.tracebacklimit = 0
    yield
    sys.tracebacklimit = default_value  # revert changes


def configure_libdir():
    '''
    sysconfig is only available in 2.7 and above
    MULTIARCH is a debian specific configuration variable
    '''
    dirs = ('/usr/lib64', '/usr/libexec', '/usr/lib',
            '/usr/local/lib64', '/usr/local/libexec', '/usr/local/lib')
    try:
        import sysconfig
        multiarch = sysconfig.get_config_var('MULTIARCH')
        if multiarch:
            dirs += ('/usr/lib/%s' % multiarch,
                     '/usr/local/lib/%s' % multiarch)
    except ImportError:
        pass
    return dirs


_SYSTEMWIDE = '/etc/crm/crm.conf'
_PERUSER = os.getenv("CRM_CONFIG_FILE") or os.path.join(userdir.CONFIG_HOME, 'crm.conf')

_PATHLIST = {
    'datadir': ('/usr/share', '/usr/local/share', '/opt'),
    'cachedir': ('/var/cache', '/opt/cache'),
    'libdir': configure_libdir(),
    'varlib': ('/var/lib', '/opt/var/lib'),
    'wwwdir': ('/srv/www', '/var/www')
}


def make_path(path):
    """input: path containing %(?)s-statements
    output: path with no such statements"""
    m = re.match(r'\%\(([^\)]+)\)(.+)', path)
    if m:
        t = m.group(1)
        for dd in _PATHLIST[t]:
            if os.path.isdir(path % {t: dd}):
                return path % {t: dd}
        return path % {t: _PATHLIST[t][0]}
    return path


def find_pacemaker_daemons():
    '''
    Search for the pacemaker daemon location by trying to find
    where the daemons are. The control daemon is either
    pacemaker-controld (2.0+) or crmd depending on the version.
    '''
    candidate_dirs = ('{}/pacemaker'.format(d) for d in configure_libdir())
    for d in candidate_dirs:
        daemon = '{}/pacemaker-controld'.format(d)
        if os.path.exists(daemon):
            return d
        daemon = '{}/crmd'.format(d)
        if os.path.exists(daemon):
            return d
    return '/usr/lib/pacemaker'


# opt_ classes
# members: default, completions, validate()

class opt_program(object):
    def __init__(self, envvar, proglist):
        self.default = ''
        if envvar and os.getenv(envvar):
            self.default = os.getenv(envvar)
        else:
            for prog in proglist:
                p = self._find_program(prog)
                if p is not None:
                    self.default = p
                    break
        self.completions = proglist

    def _find_program(self, prog):
        """Is this program available?"""
        paths = os.getenv("PATH").split(os.pathsep)
        paths.extend(['/usr/bin', '/usr/sbin', '/bin', '/sbin'])
        if prog.startswith('/'):
            filename = make_path(prog)
            if os.path.isfile(filename) and os.access(filename, os.X_OK):
                return filename
        elif prog.startswith('%'):
            prog = make_path(prog)
            for p in paths:
                filename = os.path.join(p, prog)
                if os.path.isfile(filename) and os.access(filename, os.X_OK):
                    return filename
        else:
            for p in paths:
                filename = make_path(os.path.join(p, prog))
                if os.path.isfile(filename) and os.access(filename, os.X_OK):
                    return filename
        return None

    def validate(self, prog):
        if self._find_program(prog) is None:
            raise ValueError("%s does not exist or is not a program" % prog)

    def get(self, value):
        if value.startswith('$'):
            return os.getenv(value[1:])
        elif value.startswith('\\$'):
            return value[1:]
        return value


class opt_string(object):
    def __init__(self, value):
        self.default = value
        self.completions = ()

    def validate(self, val):
        return True

    def get(self, value):
        return value


class opt_choice(object):
    def __init__(self, dflt, choices):
        self.default = dflt
        self.completions = choices

    def validate(self, val):
        if val not in self.completions:
            raise ValueError("%s not in %s" % (val, ', '.join(self.completions)))

    def get(self, value):
        return value


class opt_multichoice(object):
    def __init__(self, dflt, choices):
        self.default = dflt
        self.completions = choices

    def validate(self, val):
        vals = [x.strip() for x in val.split(',')]
        for otype in vals:
            if otype not in self.completions:
                raise ValueError("%s not in %s" % (val, ', '.join(self.completions)))

    def get(self, value):
        return value


class opt_boolean(object):
    def __init__(self, dflt):
        self.default = dflt
        self.completions = ('yes', 'true', 'on', '1', 'no', 'false', 'off', '0')

    def validate(self, val):
        if val is True:
            val = 'true'
        elif val is False:
            val = 'false'
        val = val.lower()
        if val not in self.completions:
            raise ValueError("Not a boolean: %s (try one of: %s)" % (
                val, ', '.join(self.completions)))

    def get(self, value):
        return value.lower() in ('yes', 'true', 'on', '1')


class opt_dir(object):
    def __init__(self, path):
        self.default = make_path(path)
        self.completions = []

    def validate(self, val):
        if not os.path.isdir(val):
            raise ValueError("Directory not found: %s" % (val))

    def get(self, value):
        return value


class opt_color(object):
    def __init__(self, val):
        self.default = val
        self.completions = ('black', 'blue', 'green', 'cyan',
                            'red', 'magenta', 'yellow', 'white',
                            'bold', 'blink', 'dim', 'reverse',
                            'underline', 'normal')

    def validate(self, val):
        for v in val.split(' '):
            if v not in self.completions:
                raise ValueError('Invalid color ' + val)

    def get(self, value):
        return [s.rstrip(',') for s in value.split(' ')] or ['normal']


class opt_list(object):
    def __init__(self, deflist):
        self.default = ' '.join(deflist)
        self.completions = deflist

    def validate(self, val):
        pass

    def get(self, value):
        return [s.rstrip(',') for s in value.split(' ')]


DEFAULTS = {
    'core': {
        'editor': opt_program('EDITOR', ('vim', 'vi', 'emacs', 'nano')),
        'pager': opt_program('PAGER', ('less', 'more', 'pg')),
        'user': opt_string(''),
        'skill_level': opt_choice('expert', ('operator', 'administrator', 'expert')),
        'sort_elements': opt_boolean('yes'),
        'check_frequency': opt_choice('always', ('always', 'on-verify', 'never')),
        'check_mode': opt_choice('strict', ('strict', 'relaxed')),
        'wait': opt_boolean('no'),
        'add_quotes': opt_boolean('yes'),
        'manage_children': opt_choice('ask', ('ask', 'never', 'always')),
        'force': opt_boolean('no'),
        'debug': opt_boolean('no'),
        'ptest': opt_program('', ('ptest', 'crm_simulate')),
        'dotty': opt_program('', ('dotty',)),
        'dot': opt_program('', ('dot',)),
        'ignore_missing_metadata': opt_boolean('no'),
        'report_tool_options': opt_string(''),
        'lock_timeout': opt_string('120'),
        'obscure_pattern': opt_string('passw*')
    },
    'path': {
        'sharedir': opt_dir('%(datadir)s/crmsh'),
        'cache': opt_dir('%(cachedir)s/crm'),
        'crm_config': opt_dir('%(varlib)s/pacemaker/cib'),
        'crm_daemon_dir': opt_dir(find_pacemaker_daemons()),
        'crm_daemon_user': opt_string('hacluster'),
        'ocf_root': opt_dir('%(libdir)s/ocf'),
        'crm_dtd_dir': opt_dir('%(datadir)s/pacemaker'),
        'pe_state_dir': opt_dir('%(varlib)s/pacemaker/pengine'),
        'heartbeat_dir': opt_dir('%(varlib)s/heartbeat'),
        'hb_delnode': opt_program('', ('%(datadir)s/heartbeat/hb_delnode',)),
        'nagios_plugins': opt_dir('%(libdir)s/nagios/plugins'),
        'hawk_wizards': opt_dir('%(wwwdir)s/hawk/config/wizard'),
    },
    'color': {
        'style': opt_multichoice('color', ('plain', 'color-always', 'color', 'uppercase')),
        'error': opt_color('red bold'),
        'ok': opt_color('green bold'),
        'warn': opt_color('yellow bold'),
        'info': opt_color('cyan'),
        'help_keyword': opt_color('blue bold underline'),
        'help_header': opt_color('normal bold'),
        'help_topic': opt_color('yellow bold'),
        'help_block': opt_color('cyan'),
        'keyword': opt_color('yellow'),
        'identifier': opt_color('normal'),
        'attr_name': opt_color('cyan'),
        'attr_value': opt_color('red'),
        'resource_reference': opt_color('green'),
        'id_reference': opt_color('green'),
        'score': opt_color('magenta'),
        'ticket': opt_color('magenta'),
    },
    'report': {
        'from_time': opt_string('-12H'),
        'compress': opt_boolean('yes'),
        'speed_up': opt_boolean('no'),
        'collect_extra_logs': opt_string('/var/log/messages /var/log/pacemaker/pacemaker.log /var/log/pacemaker.log /var/log/crmsh/crmsh.log'),
        'remove_exist_dest': opt_boolean('no'),
        'single_node': opt_boolean('no'),
        'sanitize_rule': opt_string('passw.*'),
        'verbosity': opt_string('0')
    }
}

_parser = None


def _stringify(val):
    if val is True:
        return 'true'
    elif val is False:
        return 'false'
    elif isinstance(val, str):
        return val
    else:
        return str(val)


class _Configuration(object):
    def __init__(self):
        self._defaults = None
        self._systemwide = None
        self._user = None

    def _safe_read(self, config_parser_inst, file_list):
        """
        Try to handle configparser.MissingSectionHeaderError while reading
        """
        try:
            config_parser_inst.read(file_list)
        except configparser.MissingSectionHeaderError:
            with _disable_exception_traceback():
                raise

    def load(self):
        self._defaults = configparser.ConfigParser()
        for section, keys in DEFAULTS.items():
            self._defaults.add_section(section)
            for key, opt in keys.items():
                self._defaults.set(section, key, opt.default)

        if os.path.isfile(_SYSTEMWIDE):
            self._systemwide = configparser.ConfigParser()
            self._safe_read(self._systemwide, [_SYSTEMWIDE])
        # for backwards compatibility with <=2.1.1 due to ridiculous bug
        elif os.path.isfile("/etc/crm/crmsh.conf"):
            self._systemwide = configparser.ConfigParser()
            self._safe_read(self._systemwide, ["/etc/crm/crmsh.conf"])
        if os.path.isfile(_PERUSER):
            self._user = configparser.ConfigParser()
            self._safe_read(self._user, [_PERUSER])

    def save(self):
        if self._user:
            if not os.path.isdir(os.path.dirname(_PERUSER)):
                os.makedirs(os.path.dirname(_PERUSER))
            fp = open(_PERUSER, 'w')
            self._user.write(fp)
            fp.close()

    def get_impl(self, section, name):
        try:
            if self._user and self._user.has_option(section, name):
                return self._user.get(section, name) or ''
            if self._systemwide and self._systemwide.has_option(section, name):
                return self._systemwide.get(section, name) or ''
            return self._defaults.get(section, name) or ''
        except configparser.NoOptionError as e:
            raise ValueError(e)

    def get(self, section, name, raw=False):
        if raw:
            return self.get_impl(section, name)
        return DEFAULTS[section][name].get(self.get_impl(section, name))

    def set(self, section, name, value):
        if section not in ('core', 'path', 'color', 'report'):
            raise ValueError("Setting invalid section " + str(section))
        if not self._defaults.has_option(section, name):
            raise ValueError("Setting invalid option %s.%s" % (section, name))
        DEFAULTS[section][name].validate(value)
        if self._user is None:
            self._user = configparser.ConfigParser()
        if not self._user.has_section(section):
            self._user.add_section(section)
        self._user.set(section, name, _stringify(value))

    def items(self, section):
        return [(k, self.get(section, k)) for k, _ in self._defaults.items(section)]

    def configured_keys(self, section):
        ret = []
        if self._systemwide and self._systemwide.has_section(section):
            ret += self._systemwide.options(section)
        if self._user and self._user.has_section(section):
            ret += self._user.options(section)
        return list(set(ret))

    def reset(self):
        '''reset to what is on disk'''
        self._user = configparser.ConfigParser()
        self._user.read([_PERUSER])


_configuration = _Configuration()


class _Section(object):
    def __init__(self, section):
        object.__setattr__(self, 'section', section)

    def __getattr__(self, name):
        return _configuration.get(self.section, name)

    def __setattr__(self, name, value):
        _configuration.set(self.section, name, value)

    def items(self):
        return _configuration.items(self.section)


def load():
    _configuration.load()

    os.environ["OCF_ROOT"] = _configuration.get('path', 'ocf_root')


def save():
    '''
    Only save options that are not default
    '''
    _configuration.save()


def set_option(section, option, value):
    _configuration.set(section, option, value)


def get_option(section, option, raw=False):
    '''
    Return the given option.
    If raw is True, return the configured value.
    Example: for a boolean, returns "yes", not True
    '''
    return _configuration.get(section, option, raw=raw)


def get_all_options():
    '''Returns a list of all configurable options'''
    ret = []
    for sname, section in DEFAULTS.items():
        ret += ['%s.%s' % (sname, option) for option in list(section.keys())]
    return sorted(ret)


def get_configured_options():
    '''Returns a list of all options that have a non-default value'''
    ret = []
    for sname in DEFAULTS:
        for key in _configuration.configured_keys(sname):
            ret.append('%s.%s' % (sname, key))
    return ret


def complete(section, option):
    s = DEFAULTS.get(section)
    if not s:
        return []
    o = s.get(option)
    if not o:
        return []
    return o.completions


def has_user_config():
    return os.path.isfile(_PERUSER)


def reset():
    _configuration.reset()


load()
core = _Section('core')
path = _Section('path')
color = _Section('color')
report = _Section('report')


def load_version():
    version = 'dev'
    versioninfo_file = os.path.join(path.sharedir, 'version')
    if os.path.isfile(versioninfo_file):
        with open(versioninfo_file) as f:
            version = f.readline().strip() or version
    return version


VERSION = load_version()
CRM_VERSION = str(VERSION)
