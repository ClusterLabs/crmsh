FROM opensuse/leap:15.1
MAINTAINER Xin Liang <XLiang@suse.com>
# docker build -t haleap --build-arg ssh_prv_key="$(cat /root/.ssh/id_rsa)" --build-arg ssh_pub_key="$(cat /root/.ssh/id_rsa.pub)" .

ARG ssh_prv_key
ARG ssh_pub_key

RUN mkdir -p /root/.ssh && chmod 0700 /root/.ssh
RUN echo "$ssh_prv_key" > /root/.ssh/id_rsa && chmod 600 /root/.ssh/id_rsa
RUN echo "$ssh_pub_key" > /root/.ssh/id_rsa.pub && chmod 600 /root/.ssh/id_rsa.pub
RUN echo "$ssh_pub_key" > /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys

RUN zypper -n install systemd dbus-1 make autoconf automake vim which libxslt-tools mailx iproute2 iputils bzip2 openssh tar file python3 python3-lxml python3-python-dateutil python3-parallax python3-setuptools python3-PyYAML python3-curses python3-pip csync2 libglue-devel pacemaker corosync booth hawk2
RUN zypper clean -a
RUN pip install --upgrade pip
RUN pip install behave tox

# Avoid unnecessary services starting
RUN systemctl mask systemd-remount-fs.service dev-hugepages.mount sys-fs-fuse-connections.mount

# Setup necessary directories and permissions for dbus
RUN mkdir -p /run/dbus && chmod 755 /run/dbus

# Allow systemd to recognize the container environment
ENV container docker

# systemd as the entrypoint to manage the system within the container
ENTRYPOINT ["/usr/lib/systemd/systemd"]

# Prevent systemd from being terminated by SIGRTMIN+3, allowing services to run
STOPSIGNAL SIGRTMIN+3
