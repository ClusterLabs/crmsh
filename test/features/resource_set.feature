@resource
Feature: Use "crm configure set" to update attributes and operations

  Tag @clean means need to stop cluster service if the service is available

  Background: Setup one node cluster and configure some resources
    Given     Cluster service is "stopped" on "hanode1"
    When      Run "crm cluster init -y --no-overwrite-sshkey" on "hanode1"
    Then      Cluster service is "started" on "hanode1"
    When      Run "crm configure primitive d Dummy op monitor interval=3s" on "hanode1"
    Then      Resource "d" type "Dummy" is "Started"
    When      Run "crm configure primitive vip IPaddr2 params ip=10.10.10.123 op monitor interval=3s" on "hanode1"
    Then      Resource "vip" type "IPaddr2" is "Started"
    And       Cluster virtual IP is "10.10.10.123"
    When      Run "crm configure primitive s ocf:pacemaker:Stateful op monitor_Master interval=3s op monitor_Slave interval=5s" on "hanode1"
    Then      Resource "s" type "Stateful" is "Started"

  @clean
  Scenario: Validation, input the wrong parameters
    When    Try "crm configure set path"
    Then    Except "ERROR: configure.set: Expected (path value), takes exactly 2 arguments (1 given)"
    When    Try "crm configure set xxxx value"
    Then    Except "ERROR: configure.set: Invalid path: "xxxx"; Valid path: "id.[op_type.][interval.]name""
    When    Try "crm configure set xxxx.name value"
    Then    Except "ERROR: configure.set: Object xxxx not found"
    When    Try "crm configure set d.name value"
    Then    Except "ERROR: configure.set: Attribute not found: d.name"
    When    Try "crm configure set d.start.timeout 30"
    Then    Except "ERROR: configure.set: Operation "start" not found for resource d"
    When    Try "crm configure set d.monitor.100.timeout 10"
    Then    Except "ERROR: configure.set: Operation "monitor" interval "100" not found for resource d"
    When    Try "crm configure set s.monitor.interval 20"
    Then    Except "ERROR: configure.set: Should specify interval of monitor"

  @clean
  Scenario: Using configure.set to update resource parameters and operation values
    When    Run "crm configure set vip.ip 10.10.10.124" on "hanode1"
    Then    Cluster virtual IP is "10.10.10.124"
    When    Run "crm configure set d.monitor.on-fail ignore" on "hanode1"
    And     Run "crm configure show d" on "hanode1"
    Then    Expected "on-fail=ignore" in stdout
    When    Run "crm configure set s.monitor.5s.interval 20s" on "hanode1"
    And     Run "crm configure show s" on "hanode1"
    Then    Expected "interval=20s" in stdout
    When    Run "crm configure set op-options.timeout 101" on "hanode1"
    And     Run "crm configure show op-options" on "hanode1"
    Then    Expected "timeout=101" in stdout
