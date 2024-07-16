@sbd
Feature: crm sbd ui test cases

  Tag @clean means need to stop cluster service if the service is available

  @clean
  Scenario: Syntax check for crm sbd
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    Given   Has disk "/dev/sda5" on "hanode1"
    Given   Has disk "/dev/sda6" on "hanode1"
    Given   Has disk "/dev/sda7" on "hanode1"
    Given   Has disk "/dev/sda8" on "hanode1"
    Given   Has disk "/dev/sda5" on "hanode2"
    Given   Has disk "/dev/sda6" on "hanode2"
    Given   Has disk "/dev/sda7" on "hanode2"
    Given   Has disk "/dev/sda8" on "hanode2"
    When    Try "crm sbd configure watchdog-timeout=30"
    Then    Except "ERROR: pacemaker.service is not active"
    When    Run "crm cluster init -y" on "hanode1"
    And     Run "crm cluster join -c hanode1 -y" on "hanode2"
    And     Try "crm sbd configure watchdog-timeout=30"
    Then    Except "ERROR: sbd.service is not active"
    When    Run "crm cluster init sbd -s /dev/sda5 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    Then    Cluster service is "started" on "hanode2"
    And     Service "sbd" is "started" on "hanode1"
    And     Resource "stonith-sbd" type "fence_sbd" is "Started"

    When    Try "crm sbd configure show sysconfig xxx"
    Then    Except "ERROR: Invalid argument"
    When    Try "crm sbd configure show testing"
    Then    Except "ERROR: Unknown argument: testing"
    When    Try "crm sbd configure"
    Then    Except "ERROR: No argument"
    When    Try "crm sbd configure testing"
    Then    Except "ERROR: Invalid argument: testing"
    When    Try "crm sbd configure watchdog-timeout=f"
    Then    Except "ERROR: Invalid timeout value: f"
    When    Try "crm sbd configure name=testing"
    Then    Except "ERROR: Unknown argument: name=testing"
    When    Try "crm sbd device add /dev/sda6 /dev/sda6"
    Then    Expected "Duplicated device path detected" in stderr
    When    Try "crm sbd device add /dev/sda6 /dev/sda7 /dev/sda8"
    Then    Expected "Maximum number of SBD device is 3" in stderr

  Scenario: sbd configure for diskbased sbd
    # Update disk metadata
    When    Run "crm sbd configure watchdog-timeout=30 msgwait-timeout=60" on "hanode1"
    Then    Run "crm sbd configure show disk_metadata|grep -E "watchdog.*30"" OK
    Then    Run "crm sbd configure show disk_metadata|grep -E "msgwait.*60"" OK

  Scenario: sbd device add and remove
    # Add a sbd disk
    Given   Run "crm sbd configure show sysconfig|grep "SBD_DEVICE=/dev/sda5"" OK
    When    Run "crm -F sbd device add /dev/sda6" on "hanode1"
    Then    Run "crm sbd configure show sysconfig|grep -E "SBD_DEVICE=\"/dev/sda5;/dev/sda6\""" OK
    Then    Run "crm sbd configure show sysconfig|grep -E "SBD_DEVICE=\"/dev/sda5;/dev/sda6\""" OK on "hanode2"
    And     Run "crm sbd configure show disk_metadata |grep -A 8 '/dev/sda6'|grep -E "watchdog.*30"" OK
    And     Run "crm sbd configure show disk_metadata |grep -A 8 '/dev/sda6'|grep -E "msgwait.*60"" OK
    When    Run "crm cluster restart --all" on "hanode1"
    And     Wait for DC
    # Remove a sbd disk
    When    Run "crm sbd device remove /dev/sda5" on "hanode1"
    Then    Run "crm sbd configure show sysconfig|grep "SBD_DEVICE=/dev/sda6"" OK
    Then    Run "crm sbd configure show sysconfig|grep "SBD_DEVICE=/dev/sda6"" OK on "hanode2"
    When    Run "crm cluster restart --all" on "hanode1"
    And     Wait for DC
    # Replace a sbd disk
    When    Run "crm -F sbd device add /dev/sda7" on "hanode1"
    Then    Run "crm sbd configure show sysconfig|grep -E "SBD_DEVICE=\"/dev/sda6;/dev/sda7\""" OK
    Then    Run "crm sbd configure show sysconfig|grep -E "SBD_DEVICE=\"/dev/sda6;/dev/sda7\""" OK on "hanode2"
    And     Run "crm sbd configure show disk_metadata |grep -A 8 '/dev/sda7'|grep -E "watchdog.*30"" OK
    And     Run "crm sbd configure show disk_metadata |grep -A 8 '/dev/sda7'|grep -E "msgwait.*60"" OK
    When    Run "crm cluster restart --all" on "hanode1"
    And     Wait for DC
    # Purge sbd from cluster
    When    Run "crm sbd purge" on "hanode1"
    And     Run "crm cluster restart --all" on "hanode1"
    Then    Service "sbd.service" is "stopped" on "hanode1"
    Then    Service "sbd.service" is "stopped" on "hanode2"

  @clean
  Scenario: sbd configure for diskless sbd
    # Newly setup
    When    Run "crm cluster init -S -y" on "hanode1"
    And     Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode1"
    Then    Cluster service is "started" on "hanode2"
    Then    Service "sbd" is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode2"
    And     Resource "stonith:fence_sbd" not configured
    # Shoud not has any sbd device configured
    When    Try "crm sbd configure show sysconfig|grep -E "SBD_DEVICE=.+""
    Then    Expected return code is "1"
    # Purge sbd from cluster
    When    Run "crm sbd purge" on "hanode1"
    And     Run "crm cluster restart --all" on "hanode1"
    Then    Service "sbd.service" is "stopped" on "hanode1"
    Then    Service "sbd.service" is "stopped" on "hanode2"
