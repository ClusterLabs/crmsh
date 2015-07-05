# crmsh

[![Build Status](https://travis-ci.org/ClusterLabs/crmsh.svg?branch=master)](https://travis-ci.org/ClusterLabs/crmsh)

crmsh is a command-line interface for High-Availability cluster
management on GNU/Linux systems, and part of the Clusterlabs
project. It simplifies the configuration, management and
troubleshooting of Pacemaker-based clusters, by providing a powerful
and intuitive set of features.

crmsh can function both as an interactive shell with tab completion
and inline documentation, and as a command-line tool. It can also be
used in batch mode to execute commands from files.

<br />
##### More Information

* The website for crmsh is here: [crmsh @ Github.io](http://crmsh.github.io).
* Documentation for the latest stable release is found at the [Github.io documentation](http://crmsh.github.io) page.


<br />
## Installation

Autoconf is used to take care of platform dependent locations. It is mainly inherited from the Pacemaker source.

```shell
./autogen.sh
./configure
make
make install
```


<br />
## Manifest

```shell
./doc: man page, source for the website and other documentation
./modules: the code
./templates: configuration templates
./test: unit tests and regression tests
./contrib: vim highlighting scripts and other semi-related
           contributions
./hb_report: log file collection and analysis tool
```


<br />
## Development

crmsh is implemented in Python. The source code for crmsh is kept in a
git source repository. To check out the latest development
version, install git and run this command:

```shell
git clone https://github.com/ClusterLabs/crmsh
```

<br />
* Bugs and issues can be reported at the [crmsh issues @ Github.com](https://github.com/clusterlabs/crmsh/issues) page.
* Any other questions or comments can be made on the [Clusterlabs users mailing list](http://clusterlabs.org/mailman/listinfo/users).
