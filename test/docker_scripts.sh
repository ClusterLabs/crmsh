#!/bin/bash
Docker_image='liangxin1300/hatbw'
HA_packages='pacemaker corosync corosync-qdevice'
TEST_TYPE='bootstrap qdevice hb_report geo'

etc_hosts_content=`cat <<EOF
10.10.10.2 hanode1
10.10.10.3 hanode2
10.10.10.4 hanode3
10.10.10.5 hanode4
10.10.10.6 hanode5
20.20.20.7 qnetd-node
10.10.10.8 node-without-ssh
EOF`

deploy_node() {
  node_name=$1
  echo "##### Deploy $node_name start"

  docker run -d --name=$node_name --hostname $node_name \
             --privileged -v /sys/fs/cgroup:/sys/fs/cgroup:ro -v "$(pwd):/app" --shm-size="1g" ${Docker_image}
  docker network connect second_net $node_name
  docker network connect third_net $node_name
  docker exec -t $node_name /bin/sh -c "echo \"$etc_hosts_content\" | grep -v $node_name >> /etc/hosts"
  # https://unix.stackexchange.com/questions/335189/system-refuses-ssh-and-stuck-on-booting-up-after-systemd-installation
  #docker exec -t $node_name /bin/sh -c "systemctl start sshd.service; systemctl start systemd-user-sessions.service"

  if [ "$node_name" == "qnetd-node" ];then
    docker exec -t $node_name /bin/sh -c "zypper ref;zypper -n in corosync-qnetd"
  elif [ "$node_name" == "node-without-ssh" ];then
    docker exec -t $node_name /bin/sh -c "systemctl stop sshd.service"
  else
    docker exec -t $node_name /bin/sh -c "cd /app; ./test/run-in-travis.sh build"
  fi
  docker exec -t $node_name /bin/sh -c "rm -rf /run/nologin"
  echo "##### Deploy $node_name finished"
  echo
}

before() {
  docker pull ${Docker_image}
  docker network create --subnet 10.10.10.0/24 --ipv6 --subnet 2001:db8:10::/64 second_net
  docker network create --subnet 20.20.20.0/24 --ipv6 --subnet 2001:db8:20::/64 third_net

  deploy_node hanode1
  deploy_node hanode2
  deploy_node hanode3
  deploy_node hanode4
  deploy_node hanode5
  if [ "$1" == "qdevice" ];then
    deploy_node qnetd-node
    deploy_node node-without-ssh
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
