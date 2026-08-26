# crmsh

[![Build Status](https://github.com/ClusterLabs/crmsh/actions/workflows/crmsh-cd.yml/badge.svg)](https://github.com/ClusterLabs/crmsh/actions/workflows/crmsh-cd.yml)
[![codecov](https://codecov.io/gh/ClusterLabs/crmsh/graph/badge.svg?token=16HW9ntzmz)](https://codecov.io/gh/ClusterLabs/crmsh)

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

The website for crmsh is here: http://crmsh.github.io

## Installation

`crmsh` is implemented in Python and requires Python 3.11 or newer.

The Meson build system is used to configure the OCF root directory,
the Asciidoc tool which is used to generate documentation, and the
default daemon user (usually hacluster).

It then compiles and installs both non-Python files and the Python
module sources into the standard target system directories.

```shell
meson setup build
meson compile -C build
meson install -C build
```

## Community

* Bugs and issues can be reported at the [github issues](https://github.com/clusterlabs/crmsh/issues) page.
* Any other questions or comments can be made on the [Clusterlabs users mailing list](http://clusterlabs.org/mailman/listinfo/users).

## Contributing

Read our [CONTRIBUTING.md](CONTRIBUTING.md) guide for details on:

* Setting up your development environment.
* Our commit message style.
* Coding standards and Python conventions.
* Running unit and functional test suites.
