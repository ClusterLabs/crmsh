FROM opensuse/leap:42.3
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

RUN zypper -n --gpg-auto-import-keys ref && zypper -n --gpg-auto-import-keys in pacemaker python python-lxml python-python-dateutil python-parallax libglue-devel python-setuptools python-tox asciidoc autoconf automake make pkgconfig which libxslt-tools mailx procps python-nose python-PyYAML python-curses tar

CMD ["/usr/lib/systemd/systemd", "--system"]

