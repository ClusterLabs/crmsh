FROM opensuse/leap:15
MAINTAINER Kristoffer Gronlund version: 0.5

ENV container docker

RUN zypper -n install systemd; zypper clean ; \
(cd /usr/lib/systemd/system/sysinit.target.wants/; for i in *; do [ $i == systemd-tmpfiles-setup.service ] || rm -f $i; done); \
rm -f /usr/lib/systemd/system/multi-user.target.wants/*;\
rm -f /etc/systemd/system/*.wants/*;\
rm -f /usr/lib/systemd/system/local-fs.target.wants/*; \
rm -f /usr/lib/systemd/system/sockets.target.wants/*udev*; \
rm -f /usr/lib/systemd/system/sockets.target.wants/*initctl*; \
rm -f /usr/lib/systemd/system/basic.target.wants/*;\
rm -f /usr/lib/systemd/system/anaconda.target.wants/*;

VOLUME [ "/sys/fs/cgroup" ]

RUN zypper -n --gpg-auto-import-keys ar obs://network:ha-clustering:Factory network:ha-clustering:Factory
RUN zypper -n --gpg-auto-import-keys ref && zypper -n --gpg-auto-import-keys in pacemaker python3 python3-lxml python3-python-dateutil python3-parallax libglue-devel python3-setuptools python3-tox asciidoc autoconf automake make pkgconfig which libxslt-tools mailx procps python3-nose python3-PyYAML python3-curses tar

CMD ["/usr/lib/systemd/systemd", "--system"]

