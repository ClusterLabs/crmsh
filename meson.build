project('crmsh',
  version: '5.1.0',
  meson_version: '>= 0.64.0'
)

# Meson Options
datadir = get_option('datadir')
sysconfdir = get_option('sysconfdir')
localstatedir = get_option('localstatedir')
prefix = get_option('prefix')

# Configuration Options
package_version = get_option('package_version')
if package_version == ''
  package_version = meson.project_version()
endif
ocf_root = get_option('ocf_root')
daemon_user = get_option('daemon_user')
docdir = get_option('docdir')
if docdir == ''
  docdir = datadir / 'doc/crmsh'
endif
tmpfilesdir = get_option('tmpfilesdir')
fwdefdir = get_option('fwdefdir')

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

py_sources = run_command('find', 'crmsh', '-type', 'f', '-name', '*.py', '-or', '-name', '*.txt', check: true).stdout().strip().split('\n')
py.install_sources(py_sources, pure: true, preserve_path: true)
build_config = configure_file(
  input: 'crmsh/build_config.py.in',
  output: 'build_config.py',
  configuration: conf_data,
  install: true,
  install_dir: py.get_install_dir(pure: true, subdir: 'crmsh')
)


# Register data-manifest installer script
meson.add_install_script(
  'meson_install_data.py',
  datadir,
)

# Process documentation
a2x = find_program('a2x')
asciidoc = find_program('asciidoc')

env = environment()
env.set('PYTHONPATH', meson.project_source_root())
env.set('CRM_HELP_FILE', meson.project_source_root() / 'doc/crm.8.adoc')

install_data('doc/crm.8.adoc', install_dir: datadir / 'crmsh')
crm_8_aio_adoc = custom_target('crm_8_aio_adoc',
  input: ['doc/crm.8.adoc'],
  output: ['crm.8.aio.adoc'],
  depend_files: ['doc/profiles.adoc', 'bin/crm'] + py_sources,
  command: [
    py,
    meson.project_source_root() / 'doc/toolchain/bin/adocxt',
    '--crm', meson.project_source_root() / 'bin/crm',
    '-o', '@OUTPUT@',
    '@INPUT@',
  ],
  env: env,
)

crm_8 = custom_target('crm_8',
  input: [crm_8_aio_adoc],
  output: ['crm.8'],
  command: [a2x, '-f', 'manpage', '-D', '@OUTDIR@', '@INPUT@'],
  install: true,
  install_dir: get_option('mandir') / 'man8'
)

profiles_html = custom_target('profiles_html',
  input: ['doc/profiles.adoc'],
  output: ['profiles.html'],
  command: [asciidoc, '--unsafe', '--backend=xhtml11', '-o', '@OUTPUT@', '@INPUT@'],
  install: true,
  install_dir: docdir
)
