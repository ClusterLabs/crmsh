FROM docker.io/opensuse/tumbleweed
MAINTAINER Xin Liang <XLiang@suse.com>

CMD ["/usr/lib/systemd/systemd", "--system"]

RUN zypper -n install systemd openssh \
        firewalld iptables iptables-backend-nft \
        make autoconf automake vim which libxslt-tools mailx iproute2 iputils bzip2 tar file glibc-locale-base dos2unix cpio gawk \
        python311 python311-pip python311-lxml python311-python-dateutil python311-setuptools python311-PyYAML python311-curses python311-behave python311-coverage python311-packaging \
        csync2 corosync corosync-qdevice pacemaker booth corosync-qnetd

RUN ssh-keygen -t rsa -f /root/.ssh/id_rsa -N '' && \
    cp /root/.ssh/id_rsa.pub /root/.ssh/authorized_keys && \
    chmod 0600 /root/.ssh/authorized_keys

RUN mkdir -p /var/log/crmsh

COPY behave_agent.py /opt
COPY behave-agent.socket /etc/systemd/system
COPY behave-agent@.service /etc/systemd/system
RUN systemctl enable behave-agent.socket
