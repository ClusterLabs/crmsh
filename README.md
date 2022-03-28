# crmsh

[![Build Status](https://github.com/ClusterLabs/crmsh/actions/workflows/crmsh-ci.yml/badge.svg)](https://github.com/ClusterLabs/crmsh/actions/workflows/crmsh-ci.yml)


## Introduction

crmsh is a command-line interface for High-Availability cluster
management on GNU/Linux systems, and part of the Clusterlabs
project. It simplifies the configuration, management and
troubleshooting of Pacemaker-based clusters, by providing a powerful
and intuitive set of features.

crmsh can function both as an interactive shell with tab completion
and inline documentation, and as a command-line tool. It can also be
used in batch mode to execute commands from files.

## Documentation

* The website for crmsh is here: [crmsh @ Github.io](http://crmsh.github.io).
* Documentation for the latest stable release is found at the [Github.io documentation](http://crmsh.github.io) page.

## Installation

Crmsh is implemented in Python, and requires Python version 3.4 or
newer. Versions of crmsh older than the 4 series ran on Python 2, so
if you don't have access to a Python 3 interpreter, you will need to
use one of the older releases.

The GNU Autotools suite is used to configure the OCF root directory,
the Asciidoc tool which is used to generate documentation and the
default daemon user (usually hacluster).

It then calls the python setuptools setup.py to actually process the
Python module sources and install into the Python system site-packages
directory.

```shell
./autogen.sh
./configure
make
make install
```

## Test suites

There are two sets of tests: Unit tests and regression tests.

#### Unit tests
In local:
- `pip install tox`
- In root directory of crmsh project, run `tox`

#### Functional tests
In local:
- In root directory of crmsh project, run `./test/run-functional-tests [OPTIONS]|[TESTCASE INDEX]`

```
# ./test/run-functional-tests -h
Usage: run-functional-tests [OPTIONS]|[TESTCASE INDEX]
run-functional-tests is a tool for developers to setup the cluster in containers to run functional tests.
The container image is based on Tumbleweed with preinstalled packages of the cluster stack include pacemaker/corosync/crmsh and many others.
Users can make the code change under crmsh.git including test cases. This tool will pick up the code change and "make install" to all running containers.

OPTIONS:
  -h, --help		Show this help message and exit
  -l            	List existing functional test cases and exit
  -n NUM        	Only setup a cluster with NUM nodes(containers)
  -x			Don't config corosync on containers(with -n option)
  -d            	Cleanup the cluster containers
```

The docker base image used is defined in the `Dockerfile` included in the repository.

[In github action](https://github.com/ClusterLabs/crmsh/actions/workflows/crmsh-ci.yml)

## Manifest

```shell
./doc: man page, source for the website and other documentation
./crmsh: the code
./templates: configuration templates
./test: unit tests and regression tests
./contrib: vim highlighting scripts and other semi-related
           contributions
./crm report: log file collection and analysis tool
```

## Development

The source code for crmsh is kept in a git source repository. To check
out the latest development version, install git and run this command:

```shell
git clone https://github.com/ClusterLabs/crmsh
```

There is a git `pre-commit` hook used to update the data-manifest
which lists all the data files to be installed. To install this, run

```shell
cp contrib/git-hook-pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## Contributing

You can contribute following the standard `fork -> clone -> change -> pull request` Github process for code changes. The pull request process is integrated with the [openSUSE Build Service](https://build.opensuse.org/), and as soon as it gets merged, a new RPM package is built on [network:ha-clustering:Unstable](https://build.opensuse.org/project/show/network:ha-clustering:Unstable) and a `submit request` is created to the _crmsh_ package maintainers at [network:ha-clustering:Factory](https://build.opensuse.org/project/show/network:ha-clustering:Factory).

The commit messages are used to create the changelog, so, please, include relevant and comprehensive messages on your commits.

## Community

* Bugs and issues can be reported at the [crmsh issues @ Github.com](https://github.com/clusterlabs/crmsh/issues) page.
* Any other questions or comments can be made on the [Clusterlabs users mailing list](http://clusterlabs.org/mailman/listinfo/users).
