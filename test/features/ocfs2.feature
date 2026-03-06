@ocfs2
Feature: OCFS2 configuration/verify using bootstrap

@clean
Scenario: Configure ocfs2 along with init process
  Given   Has disk "/dev/sda1" on "hanode1"
  And     Has disk "/dev/sda2" on "hanode1"
  When    Run "crm cluster init -s /dev/sda1 -o /dev/sda2 -y" on "hanode1"
  Then    Cluster service is "started" on "hanode1"
  And     Service "sbd" is "started" on "hanode1"
  And     Resource "fencing-sbd" type "fence_sbd" is "Started"
  And     Resource "dlm-controld-ra" type "pacemaker:controld" is "Started"
  And     Resource "ocfs2-clusterfs" type "heartbeat:Filesystem" is "Started"

@clean
Scenario: Configure cluster lvm2 + ocfs2 with init process
  Given   Has disk "/dev/sda1" on "hanode1"
  And     Has disk "/dev/sda2" on "hanode1"
  And     Has disk "/dev/sda3" on "hanode1"
  When    Run "crm cluster init -s /dev/sda1 -o /dev/sda2 -o /dev/sda3 -C -y" on "hanode1"
  Then    Cluster service is "started" on "hanode1"
  And     Service "sbd" is "started" on "hanode1"
  And     Resource "fencing-sbd" type "fence_sbd" is "Started"
  And     Resource "dlm-controld-ra" type "pacemaker:controld" is "Started"
  And     Resource "ocfs2-lvmlockd" type "heartbeat:lvmlockd" is "Started"
  And     Resource "ocfs2-lvmactivate" type "heartbeat:LVM-activate" is "Started"
  And     Resource "ocfs2-clusterfs" type "heartbeat:Filesystem" is "Started"

@clean
Scenario: Add ocfs2 alone on a running cluster
  Given   Has disk "/dev/sda1" on "hanode1"
  And     Has disk "/dev/sda2" on "hanode1"
  And     Has disk "/dev/sda1" on "hanode2"
  And     Has disk "/dev/sda2" on "hanode2"
  When    Run "crm cluster init -s /dev/sda1 -y" on "hanode1"
  And     Run "crm cluster join -c hanode1 -y" on "hanode2"
  Then    Online nodes are "hanode1 hanode2"
  And     Service "sbd" is "started" on "hanode1"
  And     Service "sbd" is "started" on "hanode2"
  And     Resource "fencing-sbd" type "fence_sbd" is "Started"
  When    Run "crm cluster init ocfs2 -o /dev/sda2 -y" on "hanode1"
  Then    Resource "dlm-controld-ra" type "pacemaker:controld" is "Started"
  And     Resource "ocfs2-clusterfs" type "heartbeat:Filesystem" is "Started"

@clean
Scenario: Add cluster lvm2 + ocfs2 on a running cluster
  Given   Has disk "/dev/sda1" on "hanode1"
  And     Has disk "/dev/sda2" on "hanode1"
  And     Has disk "/dev/sda1" on "hanode2"
  And     Has disk "/dev/sda2" on "hanode2"
  When    Run "crm cluster init -s /dev/sda1 -y" on "hanode1"
  And     Run "crm cluster join -c hanode1 -y" on "hanode2"
  Then    Online nodes are "hanode1 hanode2"
  And     Service "sbd" is "started" on "hanode1"
  And     Service "sbd" is "started" on "hanode2"
  And     Resource "fencing-sbd" type "fence_sbd" is "Started"
  When    Run "crm cluster init ocfs2 -o /dev/sda2 -C -y" on "hanode1"
  Then    Resource "dlm-controld-ra" type "pacemaker:controld" is "Started"
  And     Resource "ocfs2-lvmlockd" type "heartbeat:lvmlockd" is "Started"
  And     Resource "ocfs2-lvmactivate" type "heartbeat:LVM-activate" is "Started"
  And     Resource "ocfs2-clusterfs" type "heartbeat:Filesystem" is "Started"
  # When cluster in maintenance mode and dlm is running, cannot do stop
  When    Run "crm maintenance on" on "hanode1"
  And     Try "crm cluster stop" on "hanode1"
  Then    Expected return code is "1"
  Then    Expected "Stopping pacemaker/corosync will trigger unexpected node fencing" in stderr
