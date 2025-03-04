@gfs2
Feature: GFS2 configuration/verify using bootstrap

@clean
Scenario: Error cases
  Given   Has disk "/dev/sda1" on "hanode1"
  When    Run "crm cluster init -y" on "hanode1"
  Then    Cluster service is "started" on "hanode1"
  When    Try "crm cluster init gfs2 -g /dev/sda1 -y"
  Then    Expected "GFS2 requires stonith device configured and running" in stderr
  When    Run "crm cluster init sbd -s /dev/sda1 -y" on "hanode1"
  Then    Service "sbd.service" is "started" on "hanode1"
  When    Try "crm cluster init gfs2 -g /dev/sda1 -y"
  Then    Expected "/dev/sda1 cannot be the same with SBD device" in stderr
  When    Run "crm cluster init gfs2 -g /dev/sda2 -y" on "hanode1"
  Then    Resource "gfs2-clusterfs" type "heartbeat:Filesystem" is "Started"
  When    Try "crm cluster init gfs2 -g /dev/sda3 -y -m /tmp/data"
  Then    Expected "Already configured GFS2 related resources" in stderr

@clean
Scenario: Configure gfs2 along with init process
  Given   Has disk "/dev/sda1" on "hanode1"
  And     Has disk "/dev/sda2" on "hanode1"
  When    Run "crm cluster init -s /dev/sda1 -g /dev/sda2 -y" on "hanode1"
  Then    Cluster service is "started" on "hanode1"
  And     Service "sbd" is "started" on "hanode1"
  And     Resource "stonith-sbd" type "external/sbd" is "Started"
  And     Resource "dlm-controld-ra" type "pacemaker:controld" is "Started"
  And     Resource "gfs2-clusterfs" type "heartbeat:Filesystem" is "Started"

@clean
Scenario: Configure cluster lvm2 + gfs2 with init process
  Given   Has disk "/dev/sda1" on "hanode1"
  And     Has disk "/dev/sda2" on "hanode1"
  And     Has disk "/dev/sda3" on "hanode1"
  When    Run "crm cluster init -s /dev/sda1 -g /dev/sda2 -g /dev/sda3 -C -y" on "hanode1"
  Then    Cluster service is "started" on "hanode1"
  And     Service "sbd" is "started" on "hanode1"
  And     Resource "stonith-sbd" type "external/sbd" is "Started"
  And     Resource "dlm-controld-ra" type "pacemaker:controld" is "Started"
  And     Resource "gfs2-lvmlockd" type "heartbeat:lvmlockd" is "Started"
  And     Resource "gfs2-lvmactivate" type "heartbeat:LVM-activate" is "Started"
  And     Resource "gfs2-clusterfs" type "heartbeat:Filesystem" is "Started"

@clean
Scenario: Add gfs2 alone on a running cluster
  Given   Has disk "/dev/sda1" on "hanode1"
  And     Has disk "/dev/sda2" on "hanode1"
  And     Has disk "/dev/sda1" on "hanode2"
  And     Has disk "/dev/sda2" on "hanode2"
  When    Run "crm cluster init -s /dev/sda1 -y" on "hanode1"
  And     Run "crm cluster join -c hanode1 -y" on "hanode2"
  Then    Online nodes are "hanode1 hanode2"
  And     Service "sbd" is "started" on "hanode1"
  And     Service "sbd" is "started" on "hanode2"
  And     Resource "stonith-sbd" type "external/sbd" is "Started"
  When    Run "crm cluster init gfs2 -g /dev/sda2 -y" on "hanode1"
  Then    Resource "dlm-controld-ra" type "pacemaker:controld" is "Started"
  And     Resource "gfs2-clusterfs" type "heartbeat:Filesystem" is "Started"

@clean
Scenario: Add cluster lvm2 + gfs2 on a running cluster
  Given   Has disk "/dev/sda1" on "hanode1"
  And     Has disk "/dev/sda2" on "hanode1"
  And     Has disk "/dev/sda1" on "hanode2"
  And     Has disk "/dev/sda2" on "hanode2"
  When    Run "crm cluster init -s /dev/sda1 -y" on "hanode1"
  And     Run "crm cluster join -c hanode1 -y" on "hanode2"
  Then    Online nodes are "hanode1 hanode2"
  And     Service "sbd" is "started" on "hanode1"
  And     Service "sbd" is "started" on "hanode2"
  And     Resource "stonith-sbd" type "external/sbd" is "Started"
  When    Run "crm cluster init gfs2 -g /dev/sda2 -C -y" on "hanode1"
  Then    Resource "dlm-controld-ra" type "pacemaker:controld" is "Started"
  And     Resource "gfs2-lvmlockd" type "heartbeat:lvmlockd" is "Started"
  And     Resource "gfs2-lvmactivate" type "heartbeat:LVM-activate" is "Started"
  And     Resource "gfs2-clusterfs" type "heartbeat:Filesystem" is "Started"
