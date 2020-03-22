#!/bin/bash
Docker_image='liangxin1300/haleap:15.2'
HA_packages='pacemaker corosync corosync-qdevice'
TEST_TYPE='bootstrap qdevice hb_report'

before() {
  docker pull ${Docker_image}
  docker network create --subnet 10.10.10.0/24 second_net

  # deploy first node hanode1
  docker run -d --name=hanode1 --hostname hanode1 \
             --privileged -v /sys/fs/cgroup:/sys/fs/cgroup:ro -v "$(pwd):/app" --shm-size="1g" ${Docker_image}
  docker network connect --ip=10.10.10.2 second_net hanode1
  docker exec -t hanode1 /bin/sh -c "echo \"10.10.10.3 hanode2\" >> /etc/hosts"
  if [ x"$1" == x"qdevice" ];then
    docker exec -t hanode1 /bin/sh -c "echo \"10.10.10.9 qnetd-node\" >> /etc/hosts"
    docker exec -t hanode1 /bin/sh -c "echo \"10.10.10.10 node-without-ssh\" >> /etc/hosts"
  fi
  docker exec -t hanode1 /bin/sh -c "zypper -n in ${HA_packages}"
  docker exec -t hanode1 /bin/sh -c "cd /app; ./test/run-in-travis.sh build"

  # deploy second node hanode2
  docker run -d --name=hanode2 --hostname hanode2 \
             --privileged -v /sys/fs/cgroup:/sys/fs/cgroup:ro -v "$(pwd):/app" --shm-size="1g" ${Docker_image}
  docker network connect --ip=10.10.10.3 second_net hanode2
  docker exec -t hanode2 /bin/sh -c "echo \"10.10.10.2 hanode1\" >> /etc/hosts"
  if [ x"$1" == x"qdevice" ];then
    docker exec -t hanode2 /bin/sh -c "echo \"10.10.10.9 qnetd-node\" >> /etc/hosts"
  fi
  docker exec -t hanode2 /bin/sh -c "zypper -n in ${HA_packages}"
  docker exec -t hanode2 /bin/sh -c "systemctl start sshd.service"
  docker exec -t hanode2 /bin/sh -c "cd /app; ./test/run-in-travis.sh build"

  if [ x"$1" == x"qdevice" ];then
    # deploy node qnetd-node for qnetd service
    docker run -d --name=qnetd-node --hostname qnetd-node \
	       --privileged -v /sys/fs/cgroup:/sys/fs/cgroup:ro --shm-size="1g" ${Docker_image}
    docker network connect --ip=10.10.10.9 second_net qnetd-node
    docker exec -t qnetd-node /bin/sh -c "zypper ref;zypper -n in corosync-qnetd"
    docker exec -t qnetd-node /bin/sh -c "systemctl start sshd.service"

    # deploy node without ssh.service running for validation
    docker run -d --name=node-without-ssh --hostname node-without-ssh \
	       --privileged -v /sys/fs/cgroup:/sys/fs/cgroup:ro ${Docker_image}
    docker network connect --ip=10.10.10.10 second_net node-without-ssh
    docker exec -t node-without-ssh /bin/sh -c "systemctl stop sshd.service"
  fi
}

run() {
  docker exec -t hanode1 /bin/sh -c "cd /app; ./test/run-in-travis.sh $1 $2"
}

usage() {
  echo "Usage: ./test/`basename $0` <`echo ${TEST_TYPE// /|}`>"
}

# $1 could be "bootstrap", "hb_report", "qdevice" etc.
# $2 could be "before_install" or "run"
# $3 could be suffix of feature file
case "$1/$2" in
  */before_install)
    before $1
    ;;
  */run)
    run $1 $3
    ;;
  *)
    if [ "$#" -eq 0 ] || ! [[ $TEST_TYPE =~ (^|[[:space:]])$1($|[[:space:]]) ]];then
      usage
      exit 1
    fi
    before $1
    run $1
    ;;
esac
