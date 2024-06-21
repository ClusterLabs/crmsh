@sbd
Feature: crmsh bootstrap sbd management

  Tag @clean means need to stop cluster service if the service is available

  @clean
  Scenario: Verify sbd device
    When    Try "crm cluster init -s "/dev/sda1;/dev/sda2;/dev/sda3;/dev/sda4" -y"
    Then    Except "ERROR: cluster.init: Maximum number of SBD device is 3"
    When    Try "crm cluster init -s "/dev/sda1;/dev/sdaxxxx" -y"
    Then    Except "ERROR: cluster.init: /dev/sdaxxxx doesn't look like a block device"
    When    Try "crm cluster init -s "/dev/sda1;/dev/sda1" -y"
    Then    Except multiple lines
      """
      usage: init [options] [STAGE]
      crm: error: Duplicated input for '-s/--sbd-device' option
      """

  @clean
  Scenario: Setup sbd with init and join process(bsc#1170999)
    Given   Has disk "/dev/sda1" on "hanode1"
    Given   Cluster service is "stopped" on "hanode1"
    Given   Has disk "/dev/sda1" on "hanode2"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -s /dev/sda1 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode1"
    And     Resource "stonith-sbd" type "fence_sbd" is "Started"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Service "sbd" is "started" on "hanode2"

  @clean
  Scenario: Re-setup cluster without sbd(bsc#1166967)
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "sbd" is "stopped" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Service "sbd" is "stopped" on "hanode2"
    And     Resource "stonith:fence_sbd" not configured

  @clean
  Scenario: Configure diskless sbd(bsc#1181907)
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -S -y" on "hanode1"
    Then    Expected "Diskless SBD requires cluster with three or more nodes." in stderr
    Then    Cluster service is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Expected "Diskless SBD requires cluster with three or more nodes." in stderr
    Then    Cluster service is "started" on "hanode2"
    And     Service "sbd" is "started" on "hanode2"
    When    Run "crm cluster join -c hanode1 -y" on "hanode3"
    Then    Expected "Diskless SBD requires cluster with three or more nodes." not in stderr
    Then    Cluster service is "started" on "hanode3"
    And     Service "sbd" is "started" on "hanode3"
    And     Resource "stonith:fence_sbd" not configured

  @clean
  Scenario: Configure multi disks sbd
    Given   Has disk "/dev/sda1" on "hanode1"
    Given   Has disk "/dev/sda2" on "hanode1"
    Given   Cluster service is "stopped" on "hanode1"
    Given   Has disk "/dev/sda1" on "hanode2"
    Given   Has disk "/dev/sda2" on "hanode2"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -s /dev/sda1 -s /dev/sda2 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode1"
    And     Resource "stonith-sbd" type "fence_sbd" is "Started"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Service "sbd" is "started" on "hanode2"

  @clean
  Scenario: Configure sbd in several stages(bsc#1175057)
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init ssh -y" on "hanode1"
    And     Run "crm cluster init csync2 -y" on "hanode1"
    And     Run "crm cluster init corosync -y" on "hanode1"
    And     Run "crm cluster init sbd -s /dev/sda1 -y" on "hanode1"
    And     Run "crm cluster init cluster -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode1"
    When    Run "crm cluster join ssh -y -c hanode1" on "hanode2"
    And     Run "crm cluster join csync2 -y -c hanode1" on "hanode2"
    And     Run "crm cluster join ssh_merge -y -c hanode1" on "hanode2"
    And     Run "crm cluster join cluster -y -c hanode1" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Service "sbd" is "started" on "hanode2"
    And     Resource "stonith-sbd" type "fence_sbd" is "Started"

  @clean
  Scenario: Configure diskless sbd in several stages(bsc#1175057)
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init ssh -y" on "hanode1"
    And     Run "crm cluster init csync2 -y" on "hanode1"
    And     Run "crm cluster init corosync -y" on "hanode1"
    And     Run "crm cluster init sbd -S -y" on "hanode1"
    And     Run "crm cluster init cluster -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode1"
    When    Run "crm cluster join ssh -y -c hanode1" on "hanode2"
    And     Run "crm cluster join csync2 -y -c hanode1" on "hanode2"
    And     Run "crm cluster join ssh_merge -y -c hanode1" on "hanode2"
    And     Run "crm cluster join cluster -y -c hanode1" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Service "sbd" is "started" on "hanode2"
    And     Resource "stonith:fence_sbd" not configured

  @clean
  Scenario: Configure sbd on running cluster via stage(bsc#1181906)
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    When    Run "crm cluster init sbd -s /dev/sda1 -y" on "hanode1"
    Then    Service "sbd" is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode2"
    And     Resource "stonith-sbd" type "fence_sbd" is "Started"

  @clean
  Scenario: Configure sbd on running cluster via stage with ra running(bsc#1181906)
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    When    Run "crm configure primitive d Dummy op monitor interval=3s" on "hanode1"
    When    Run "crm cluster init sbd -s /dev/sda1 -y" on "hanode1"
    Then    Expected "WARNING: To start sbd.service, need to restart cluster service manually on each node" in stderr
    Then    Service "sbd" is "stopped" on "hanode1"
    And     Service "sbd" is "stopped" on "hanode2"
    When    Run "crm cluster restart" on "hanode1"
    Then    Service "sbd" is "started" on "hanode1"
    When    Run "crm cluster restart" on "hanode2"
    Then    Service "sbd" is "started" on "hanode2"
    When    Run "sleep 20" on "hanode1"
    Then    Resource "stonith-sbd" type "fence_sbd" is "Started"

  @clean
  Scenario: Configure sbd when no watchdog device(bsc#1154927, bsc#1178869)
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Try "lsmod |grep softdog && rmmod softdog" on "hanode1"
    And     Try "lsmod |grep softdog && rmmod softdog" on "hanode2"
    When    Run "crm cluster init -s /dev/sda1 -w softdog -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode1"
    When    Try "lsmod |grep softdog"
    Then    Expected return code is "0"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Service "sbd" is "started" on "hanode2"
    And     Resource "stonith-sbd" type "fence_sbd" is "Started"

  @clean
  Scenario: Setup sbd and test fence node
    Given   Has disk "/dev/sda1" on "hanode1"
    Given   Cluster service is "stopped" on "hanode1"
    Given   Has disk "/dev/sda1" on "hanode2"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -s /dev/sda1 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode1"
    And     Resource "stonith-sbd" type "fence_sbd" is "Started"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Service "sbd" is "started" on "hanode2"
    When    Run "stonith_admin -H hanode2 -c" on "hanode1"
    When    Run "crm -F node fence hanode2" on "hanode1"
    Then    Expected return code is "0"
    Then    Node "hanode2" is UNCLEAN
    Then    Wait "60" seconds for "hanode2" successfully fenced

  @skip_non_root
  @clean
  Scenario: Setup sbd and test fence node, use hacluster to fence
    Given   Has disk "/dev/sda1" on "hanode1"
    Given   Cluster service is "stopped" on "hanode1"
    Given   Has disk "/dev/sda1" on "hanode2"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -s /dev/sda1 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode1"
    And     Resource "stonith-sbd" type "fence_sbd" is "Started"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Service "sbd" is "started" on "hanode2"
    When    Run "stonith_admin -H hanode2 -c" on "hanode1"
    When    Run "su hacluster -c '/usr/sbin/crm -F node fence hanode2'" on "hanode1"
    Then    Expected return code is "0"
    Then    Node "hanode2" is UNCLEAN
    Then    Wait "60" seconds for "hanode2" successfully fenced

  @clean
  Scenario: Change existing diskbased sbd cluster as diskless sbd
    Given   Has disk "/dev/sda1" on "hanode1"
    Given   Cluster service is "stopped" on "hanode1"
    Given   Has disk "/dev/sda1" on "hanode2"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -s /dev/sda1 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode1"
    And     Resource "stonith-sbd" type "fence_sbd" is "Started"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Service "sbd" is "started" on "hanode2"
    And     Run "ps -ef|grep -v grep|grep 'watcher: /dev/sda1 '" OK

    When    Run "crm -F cluster init sbd -S -y" on "hanode1"
    Then    Service "sbd" is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode2"
    And     Resource "stonith:fence_sbd" not configured
    When    Try "ps -ef|grep -v grep|grep 'watcher: /dev/sda1 '"
    Then    Expected return code is "1"

  @clean
  Scenario: Change existing diskless sbd cluster as diskbased sbd
    Given   Has disk "/dev/sda1" on "hanode1"
    Given   Cluster service is "stopped" on "hanode1"
    Given   Has disk "/dev/sda1" on "hanode2"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -S -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Service "sbd" is "started" on "hanode2"
    And     Resource "stonith:fence_sbd" not configured

    When    Run "crm -F cluster init sbd -s /dev/sda1 -y" on "hanode1"
    Then    Service "sbd" is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode2"
    And     Resource "stonith-sbd" type "fence_sbd" is "Started"
    And     Run "ps -ef|grep -v grep|grep 'watcher: /dev/sda1 '" OK

  @clean
  Scenario: Change sbd device
    Given   Has disk "/dev/sda1" on "hanode1"
    Given   Has disk "/dev/sda2" on "hanode1"
    Given   Cluster service is "stopped" on "hanode1"
    Given   Has disk "/dev/sda1" on "hanode2"
    Given   Has disk "/dev/sda2" on "hanode2"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -s /dev/sda1 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Service "sbd" is "started" on "hanode2"
    And     Resource "stonith-sbd" type "fence_sbd" is "Started"
    And     Run "ps -ef|grep -v grep|grep 'watcher: /dev/sda1 '" OK

    When    Run "crm -F cluster init sbd -s /dev/sda2 -y" on "hanode1"
    Then    Service "sbd" is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode2"
    And     Resource "stonith-sbd" type "fence_sbd" is "Started"
    And     Run "ps -ef|grep -v grep|grep 'watcher: /dev/sda2 '" OK
    When    Try "ps -ef|grep -v grep|grep 'watcher: /dev/sda1 '"
    Then    Expected return code is "1"
