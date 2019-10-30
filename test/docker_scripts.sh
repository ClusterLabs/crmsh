#!/bin/bash
Tumbleweed_image='liangxin1300/hatbw'
HA_packages='pacemaker corosync corosync-qdevice csync2 python3 python3-lxml python3-python-dateutil python3-parallax libglue-devel python3-setuptools python3-tox asciidoc autoconf automake make pkgconfig which libxslt-tools mailx procps python3-nose python3-PyYAML python3-curses tar python3-behave iproute2 iputils vim bzip2'

before() {
docker pull ${Tumbleweed_image}
docker network create --subnet 10.10.10.0/24 first_net
docker network create --subnet 20.20.20.0/24 second_net

# deploy first node hanode1
docker run -d --name=hanode1 --hostname hanode1 \
	--net first_net --ip 10.10.10.2 \
	--privileged -v /sys/fs/cgroup:/sys/fs/cgroup:ro -v "$(pwd):/app" ${Tumbleweed_image}
docker network connect --ip=20.20.20.2 second_net hanode1
docker exec -t hanode1 /bin/sh -c "echo \"10.10.10.3 hanode2\" >> /etc/hosts"
docker exec -t hanode1 /bin/sh -c "zypper -n in ${HA_packages}"

# deploy second node hanode2
docker run -d --name=hanode2 --hostname hanode2 \
	--net first_net --ip 10.10.10.3 \
	--privileged -v /sys/fs/cgroup:/sys/fs/cgroup:ro -v "$(pwd):/app" ${Tumbleweed_image}
docker network connect --ip=20.20.20.3 second_net hanode2
docker exec -t hanode2 /bin/sh -c "echo \"10.10.10.2 hanode1\" >> /etc/hosts"
docker exec -t hanode2 /bin/sh -c "zypper -n in ${HA_packages}"
docker exec -t hanode2 /bin/sh -c "systemctl start sshd.service"
docker exec -t hanode2 /bin/sh -c "cd /app; ./test/run-in-travis.sh build"
}

run() {
docker exec -t hanode1 /bin/sh -c "cd /app; ./test/run-in-travis.sh bootstrap $1"
}

case "$1" in
  before_install)
    before
    ;;
  script)
    run $2
    ;;
esac
