@bootstrap
Feature: crmsh bootstrap sbd management

  Tag @clean means need to stop cluster service if the service is available

  @clean
  Scenario: Check prerequisites for SBD
    Given   Has disk "/dev/sda1" on "hanode1"

    When    Run "mv /usr/sbin/sbd /tmp" on "hanode1"
    And     Try "crm cluster init -s /dev/sda1 -y"
    Then    Except "ERROR: cluster.init: sbd executable not found! Cannot configure SBD"
    When    Run "mv /tmp/sbd /usr/sbin" on "hanode1"

    When    Run "mv /dev/watchdog /tmp" on "hanode1"
    And     Try "crm cluster init -s /dev/sda1 -y"
    Then    Except "ERROR: cluster.init: Watchdog device must be configured in order to use SBD"
    When    Run "mv /tmp/watchdog /dev" on "hanode1"

  @clean
  Scenario: Verify sbd device
    When    Try "crm cluster init -s "/dev/sda1;/dev/sda2;/dev/sda3;/dev/sda4" -y"
    Then    Except "ERROR: cluster.init: Maximum number of SBD device is 3"
    When    Try "crm cluster init -s "/dev/sda1;/dev/sdaxxxx" -y"
    Then    Except "ERROR: cluster.init: /dev/sdaxxxx doesn't look like a block device"

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
