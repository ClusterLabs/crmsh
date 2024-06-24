FROM opensuse/tumbleweed
MAINTAINER Xin Liang <XLiang@suse.com>

CMD ["/usr/lib/systemd/systemd", "--system"]

RUN zypper refresh && \
    zypper -n install systemd \
        make autoconf automake vim which libxslt-tools mailx iproute2 iputils bzip2 openssh tar file glibc-locale-base firewalld libopenssl1_1 dos2unix iptables cpio gawk \
        python3 python3-pip python3-lxml python3-python-dateutil python3-setuptools python3-PyYAML python3-curses python3-behave python3-coverage python3-packaging \
        csync2 libglue-devel corosync corosync-qdevice pacemaker booth corosync-qnetd libknet1-*

RUN ssh-keygen -t rsa -f /root/.ssh/id_rsa -N '' && \
    cp /root/.ssh/id_rsa.pub /root/.ssh/authorized_keys && \
    chmod 0600 /root/.ssh/authorized_keys

RUN mkdir -p /var/log/crmsh

COPY behave_agent.py /opt
COPY behave-agent.socket /etc/systemd/system
COPY behave-agent@.service /etc/systemd/system
RUN systemctl enable behave-agent.socket
