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
    Then    Except "ERROR: cluster.init: Duplicated input for -s/--sbd-device option"

  @clean
  Scenario: Setup sbd with init and join process(bsc#1170999)
    Given   Has disk "/dev/sda1" on "hanode1"
    Given   Cluster service is "stopped" on "hanode1"
    Given   Has disk "/dev/sda1" on "hanode2"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -s /dev/sda1 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode1"
    And     Resource "stonith-sbd" type "external/sbd" is "Started"
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
    And     Resource "stonith:external/sbd" not configured

  @clean
  Scenario: Configure diskless sbd
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -S -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Service "sbd" is "started" on "hanode2"
    And     Resource "stonith:external/sbd" not configured

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
    And     Resource "stonith-sbd" type "external/sbd" is "Started"
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
    And     Resource "stonith-sbd" type "external/sbd" is "Started"

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
    And     Resource "stonith:external/sbd" not configured

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
    And     Resource "stonith-sbd" type "external/sbd" is "Started"

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
    Then    Expected "WARNING: To start sbd.service, need to restart cluster service manually on each node" in stdout
    Then    Service "sbd" is "stopped" on "hanode1"
    And     Service "sbd" is "stopped" on "hanode2"
    When    Run "crm cluster restart" on "hanode1"
    Then    Service "sbd" is "started" on "hanode1"
    When    Run "crm cluster restart" on "hanode2"
    Then    Service "sbd" is "started" on "hanode2"
    When    Run "sleep 20" on "hanode1"
    Then    Resource "stonith-sbd" type "external/sbd" is "Started"
