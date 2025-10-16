FROM docker.io/opensuse/tumbleweed
MAINTAINER Xin Liang <XLiang@suse.com>

CMD ["/usr/lib/systemd/systemd", "--system"]

RUN zypper -n dup && zypper -n install systemd openssh \
        firewalld iptables iptables-backend-nft \
        make autoconf vim which libxslt-tools asciidoc mailx iproute2 iputils bzip2 tar file glibc-locale-base dos2unix cpio gawk sudo expect\
        python313 python313-pip python313-lxml python313-python-dateutil python313-build python313-PyYAML python313-curses python313-behave python313-coverage python313-packaging \
        csync2 corosync corosync-qdevice pacemaker pacemaker-remote booth corosync-qnetd

RUN ssh-keygen -t rsa -f /root/.ssh/id_rsa -N '' && \
    cp /root/.ssh/id_rsa.pub /root/.ssh/authorized_keys && \
    chmod 0600 /root/.ssh/authorized_keys

RUN mkdir -p /var/log/crmsh

COPY behave_agent.py /opt
COPY behave-agent.socket /etc/systemd/system
COPY behave-agent@.service /etc/systemd/system
RUN systemctl enable behave-agent.socket
