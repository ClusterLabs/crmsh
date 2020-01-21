#!/bin/bash
Docker_image='liangxin1300/haleap:15.1'
HA_packages='pacemaker corosync'
TEST_TYPE='bootstrap hb_report'

before() {
  docker pull ${Docker_image}
  docker network create --subnet 10.10.10.0/24 second_net

  # deploy first node hanode1
  docker run -d --name=hanode1 --hostname hanode1 \
             --privileged -v /sys/fs/cgroup:/sys/fs/cgroup:ro -v "$(pwd):/app" ${Docker_image}
  docker network connect --ip=10.10.10.2 second_net hanode1
  docker exec -t hanode1 /bin/sh -c "echo \"10.10.10.3 hanode2\" >> /etc/hosts"
  docker exec -t hanode1 /bin/sh -c "zypper -n in ${HA_packages}"
  docker exec -t hanode1 /bin/sh -c "cd /app; ./test/run-in-travis.sh build"

  # deploy second node hanode2
  docker run -d --name=hanode2 --hostname hanode2 \
             --privileged -v /sys/fs/cgroup:/sys/fs/cgroup:ro -v "$(pwd):/app" ${Docker_image}
  docker network connect --ip=10.10.10.3 second_net hanode2
  docker exec -t hanode2 /bin/sh -c "echo \"10.10.10.2 hanode1\" >> /etc/hosts"
  docker exec -t hanode2 /bin/sh -c "zypper -n in ${HA_packages}"
  docker exec -t hanode2 /bin/sh -c "systemctl start sshd.service"
  docker exec -t hanode2 /bin/sh -c "cd /app; ./test/run-in-travis.sh build"
}

run() {
  docker exec -t hanode1 /bin/sh -c "cd /app; ./test/run-in-travis.sh $1 $2"
}

usage() {
  echo "Usage: ./test/`basename $0` <`echo ${TEST_TYPE// /|}`>"
}

# $1 could be "bootstrap", "hb_report" etc.
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
