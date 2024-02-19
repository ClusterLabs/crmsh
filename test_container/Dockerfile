FROM opensuse/leap:15.5
MAINTAINER Xin Liang <XLiang@suse.com>

CMD ["/usr/lib/systemd/systemd", "--system"]

RUN zypper refresh
RUN zypper -n install systemd
RUN zypper -n install make autoconf automake vim which libxslt-tools mailx iproute2 iputils bzip2 openssh tar file glibc-locale-base firewalld libopenssl1_1 dos2unix iptables
RUN zypper -n install python3 python3-pip python3-lxml python3-python-dateutil python3-setuptools python3-PyYAML python3-curses python3-behave
RUN zypper -n install csync2 libglue-devel corosync corosync-qdevice pacemaker booth corosync-qnetd
RUN zypper --non-interactive up zypper && \
    zypper ar -f -G https://download.opensuse.org/repositories/network:/ha-clustering:/Factory/SLE_15_SP4 repo_nhf && \
    zypper --non-interactive refresh && \
    zypper --non-interactive up --allow-vendor-change -y resource-agents libqb100 pacemaker

RUN ssh-keygen -t rsa -f /root/.ssh/id_rsa -N '' && \
    cp /root/.ssh/id_rsa.pub /root/.ssh/authorized_keys && \
    chmod 0600 /root/.ssh/authorized_keys


RUN python3 -m pip install coverage

RUN mkdir -p /var/log/crmsh

COPY behave_agent.py /opt
COPY behave-agent.socket /etc/systemd/system
COPY behave-agent@.service /etc/systemd/system
RUN systemctl enable behave-agent.socket
