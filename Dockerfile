FROM opensuse/leap:15.2
MAINTAINER Xin Liang <XLiang@suse.com>

ARG ssh_prv_key
ARG ssh_pub_key
# Above is for passwordless ssh
# docker build -t haleap --build-arg ssh_prv_key="$(cat /root/.ssh/id_rsa)" --build-arg ssh_pub_key="$(cat /root/.ssh/id_rsa.pub)" .

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

RUN mkdir -p /root/.ssh && chmod 0700 /root/.ssh
RUN echo "$ssh_prv_key" > /root/.ssh/id_rsa && chmod 600 /root/.ssh/id_rsa
RUN echo "$ssh_pub_key" > /root/.ssh/id_rsa.pub && chmod 600 /root/.ssh/id_rsa.pub
RUN echo "$ssh_pub_key" > /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys

RUN zypper -n install make autoconf automake vim which libxslt-tools mailx iproute2 iputils bzip2 openssh tar file
RUN zypper -n install python3 python3-lxml python3-python-dateutil python3-parallax python3-setuptools python3-PyYAML python3-curses python3-pip
RUN zypper -n install csync2 libglue-devel corosync corosync-qdevice pacemaker
RUN pip install --upgrade pip
RUN pip install behave tox

VOLUME [ "/sys/fs/cgroup" ]
CMD ["/usr/lib/systemd/systemd", "--system"]
