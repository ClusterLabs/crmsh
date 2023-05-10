FROM opensuse/leap:15.5
MAINTAINER Xin Liang <XLiang@suse.com>

ARG ssh_prv_key
ARG ssh_pub_key
# docker build -t haleap --build-arg ssh_prv_key="$(cat /root/.ssh/id_rsa)" --build-arg ssh_pub_key="$(cat /root/.ssh/id_rsa.pub)" .
# docker login
# docker tag haleap liangxin1300/haleap:15.5
# docker push liangxin1300/haleap:15.5

RUN zypper ref
RUN zypper -n install systemd
RUN zypper -n install make autoconf automake vim which libxslt-tools mailx iproute2 iputils bzip2 openssh tar file glibc-locale-base firewalld libopenssl1_1 dos2unix iptables
RUN zypper -n install python3 python3-lxml python3-python-dateutil python3-parallax python3-setuptools python3-PyYAML python3-curses python3-behave
RUN zypper -n install csync2 libglue-devel corosync corosync-qdevice pacemaker booth corosync-qnetd
RUN zypper --non-interactive up zypper
RUN zypper ar -f -G https://download.opensuse.org/repositories/network:/ha-clustering:/Factory/SLE_15_SP4 repo_nhf
RUN zypper --non-interactive refresh
RUN zypper --non-interactive up --allow-vendor-change -y python3-parallax resource-agents libqb100 pacemaker

RUN mkdir -p /var/log/crmsh
RUN mkdir -p /root/.ssh && chmod 0700 /root/.ssh
RUN echo "$ssh_prv_key" > /root/.ssh/id_rsa && chmod 600 /root/.ssh/id_rsa
RUN echo "$ssh_pub_key" > /root/.ssh/id_rsa.pub && chmod 600 /root/.ssh/id_rsa.pub
RUN echo "$ssh_pub_key" > /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys

CMD ["/usr/lib/systemd/systemd", "--system"]
