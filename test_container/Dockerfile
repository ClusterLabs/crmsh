FROM opensuse/leap:15.6
MAINTAINER Xin Liang <XLiang@suse.com>

CMD ["/usr/lib/systemd/systemd", "--system"]

RUN zypper refresh && \
    zypper -n install systemd \
        make autoconf automake vim which libxslt-tools mailx iproute2 iputils bzip2 openssh tar file glibc-locale-base firewalld libopenssl1_1 dos2unix iptables \
        python3 python3-pip python3-lxml python3-python-dateutil python3-setuptools python3-PyYAML python3-curses python3-behave \
        csync2 libglue-devel corosync corosync-qdevice pacemaker pacemaker-remote booth corosync-qnetd

RUN zypper ar -f -G https://download.opensuse.org/repositories/home:/yan_gao:/branches:/network:/ha-clustering:/Factory:/2.1/openSUSE_Leap_15.6/ repo_update_pacemaker
RUN zypper --non-interactive refresh
RUN zypper --non-interactive up --allow-vendor-change -y pacemaker

RUN ssh-keygen -t rsa -f /root/.ssh/id_rsa -N '' && \
    cp /root/.ssh/id_rsa.pub /root/.ssh/authorized_keys && \
    chmod 0600 /root/.ssh/authorized_keys

RUN python3 -m pip install coverage

RUN mkdir -p /var/log/crmsh

COPY behave_agent.py /opt
COPY behave-agent.socket /etc/systemd/system
COPY behave-agent@.service /etc/systemd/system
RUN systemctl enable behave-agent.socket
