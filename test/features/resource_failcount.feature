@resource
Feature: Use "crm resource failcount" to manage failcounts

  Tag @clean means need to stop cluster service if the service is available

  Background: Setup one node cluster and configure a Dummy resource
    Given     Cluster service is "stopped" on "hanode1"
    When      Run "crm cluster init -y" on "hanode1"
    Then      Cluster service is "started" on "hanode1"
    When      Run "crm configure primitive d Dummy op monitor interval=3s" on "hanode1"
    Then      Resource "d" type "Dummy" is "Started"

  @clean
  Scenario: Validation, input the wrong parameters
    When    Try "crm resource failcount d showss hanode1"
    Then    Except "ERROR: resource.failcount: showss is not valid command(should be one of ['set', 'delete', 'show'])"
    When    Try "crm resource failcount d set hanode11 0"
    Then    Except "ERROR: resource.failcount: Node hanode11 not in this cluster"

  @clean
  Scenario: Set the failcount to 0
    When    Run "rm -f /run/resource-agents/Dummy-d.state" on "hanode1"
    And     Wait "5" seconds
    Then    Resource "d" failcount on "hanode1" is "1"
    When    Run "crm resource failcount d set hanode1 0" on "hanode1"
    Then    Resource "d" failcount on "hanode1" is "0"

  @clean
  Scenario: Set multiple failcounts to 0
    When    Run "sed -i -e '/rm \${OCF_RESKEY_state}/a\' -e "else\nreturn \$OCF_ERR_GENERIC" /usr/lib/ocf/resource.d/heartbeat/Dummy" on "hanode1"
    And     Run "rm -f /run/resource-agents/Dummy-d.state" on "hanode1"
    And     Wait "5" seconds
    Then    Resource "d" failcount on "hanode1" is "INFINITY"
        """
        now have two failcount entries, one is monitor, another is stop
	"""
    When    Run "crm resource failcount d set hanode1 0" on "hanode1"
        """
        set all failcounts to 0
	"""
    Then    Resource "d" failcount on "hanode1" is "0"
    When    Run "crm resource cleanup" on "hanode1"
    And     Wait "5" seconds
    And     Run "rm -f /run/resource-agents/Dummy-d.state" on "hanode1"
    And     Wait "5" seconds
    Then    Resource "d" failcount on "hanode1" is "INFINITY"
        """
        now have two failcount entries, one is monitor, another is stop
	"""
    When    Run "crm resource failcount d set hanode1 0 stop" on "hanode1"
        """
        set stop failcounts to 0
	"""
    Then    Resource "d" failcount on "hanode1" is "1"
    When    Run "crm resource failcount d set hanode1 0 monitor" on "hanode1"
        """
        set monitor failcounts to 0
	"""
    Then    Resource "d" failcount on "hanode1" is "0"

