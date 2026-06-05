project('crmsh',
  version: '5.1.0',
  meson_version: '>= 0.64.0'
)

# Configuration Options
package_version = get_option('package_version')
if package_version == ''
  package_version = meson.project_version()
endif

ocf_root = get_option('ocf_root')
daemon_user = get_option('daemon_user')
tmpfilesdir = get_option('tmpfilesdir')
fwdefdir = get_option('fwdefdir')

datadir = get_option('datadir')
sysconfdir = get_option('sysconfdir')
localstatedir = get_option('localstatedir')
prefix = get_option('prefix')

# Absolute paths
if not localstatedir.startswith('/')
  localstatedir = prefix / localstatedir
endif

crm_cache_dir = localstatedir / 'cache' / 'crm'

# Prepare configuration substitutions
conf_data = configuration_data()
conf_data.set('PACKAGE_VERSION', package_version)
conf_data.set('OCF_ROOT_DIR', ocf_root)
conf_data.set('CRM_DAEMON_USER', daemon_user)
conf_data.set('CRM_CACHE_DIR', crm_cache_dir)

# Substitution configurations
version_file = configure_file(
  input: 'version.in',
  output: 'version',
  configuration: conf_data,
  install: false
)

crm_conf = configure_file(
  input: 'etc/crm.conf.in',
  output: 'crm.conf',
  configuration: conf_data,
  install: true,
  install_dir: sysconfdir / 'crm'
)

crm_spec = configure_file(
  input: 'crmsh.spec.in',
  output: 'crmsh.spec',
  configuration: conf_data,
  install: false
)

# Install static config files
install_data('etc/profiles.yml', install_dir: sysconfdir / 'crm')

# Install systemd tmpfiles config
install_data('crmsh.tmpfiles.d.conf',
  install_dir: tmpfilesdir,
  rename: 'crmsh.conf'
)

# Install bash completion
install_data('contrib/bash_completion.sh',
  install_dir: datadir / 'bash-completion/completions',
  rename: 'crm'
)

# Install firewalld service if directory provided
if fwdefdir != ''
  install_data('high-availability.xml', install_dir: fwdefdir)
endif

# Install executable bin/crm
install_data('bin/crm', install_dir: get_option('bindir'))

# Install Python sources dynamically using `find`
py = import('python').find_installation('python3')

find_res = run_command('find', 'crmsh', '-type', 'f', '!', '-path', '*/__pycache__/*', '!', '-name', '*.pyc', check: true)
py_sources = find_res.stdout().strip().split('\n')

if py_sources.length() > 0 and py_sources[0] != ''
  py.install_sources(py_sources, pure: true, preserve_path: true)
endif

# Register data-manifest installer script
meson.add_install_script(
  'meson_install_data.py',
  datadir,
)

# Process documentation
make = find_program('make')
sh = find_program('sh')
a2x = find_program('a2x')
asciidoc = find_program('asciidoc')

env = environment()
env.prepend('PATH', meson.project_source_root() / 'bin')
env.prepend('PATH', meson.project_source_root() / 'doc/toolchain/bin')
env.set('PYTHONPATH', meson.project_source_root())
env.set('CRM_HELP_FILE', meson.project_source_root() / 'doc/crm.8.adoc')

install_data('doc/crm.8.adoc', install_dir: datadir / 'crmsh')
crm_8 = custom_target('crm_8',
  input: ['doc/crm.8.adoc'],
  output: ['crm.8'],
  command: [
    sh, '-c',
    'make -C "@0@/doc" all && cp "@0@/doc/generated-sources/crm.8" "@OUTPUT@"'.format(meson.project_source_root())
  ],
  env: env,
  install: true,
  install_dir: get_option('mandir') / 'man8'
)

profiles_html = custom_target('profiles_html',
  input: ['doc/profiles.adoc'],
  output: ['profiles.html'],
  command: [asciidoc, '--unsafe', '--backend=xhtml11', '-o', '@OUTPUT@', '@INPUT@'],
  install: true,
  install_dir: get_option('datadir') / 'doc/crmsh'
)
crmsh_crm_report_html = custom_target('crmsh_crm_report_html',
  input: ['doc/crmsh_crm_report.8.adoc'],
  output: ['crmsh_crm_report.8.html'],
  command: [asciidoc, '--unsafe', '--backend=xhtml11', '-o', '@OUTPUT@', '@INPUT@'],
  install: true,
  install_dir: get_option('datadir') / 'doc/crmsh'
)
