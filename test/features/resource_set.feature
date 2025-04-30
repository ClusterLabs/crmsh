@resource
Feature: Use "crm configure set" to update attributes and operations

  Tag @clean means need to stop cluster service if the service is available
  Need nodes: hanode1 hanode2

  Background: Setup cluster and configure some resources
    Given     Cluster service is "stopped" on "hanode1"
    When      Run "crm cluster init -y" on "hanode1"
    Then      Cluster service is "started" on "hanode1"
    When      Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then      Cluster service is "started" on "hanode2"
    When      Run "crm configure primitive d Dummy op monitor interval=3s" on "hanode1"
    Then      Resource "d" type "Dummy" is "Started"
    When      Run "crm configure primitive vip IPaddr2 params ip=@vip.0 op monitor interval=3s" on "hanode1"
    Then      Resource "vip" type "IPaddr2" is "Started"
    And       Cluster virtual IP is "@vip.0"
    When      Run "crm configure primitive s ocf:pacemaker:Stateful op monitor role=Promoted interval=3s op monitor role=Unpromoted interval=5s" on "hanode1"
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
    When    Try "crm configure set d.monitor.100.timeout 10"
    Then    Except "ERROR: configure.set: Operation "monitor" interval "100s" not found for resource d"
    When    Try "crm configure set s.monitor.interval 20"
    Then    Except "ERROR: configure.set: Should specify interval of monitor"

  @clean
  Scenario: Using configure.set to update resource parameters and operation values
    When    Run "crm configure set vip.ip @vip.0" on "hanode1"
    Then    Cluster virtual IP is "@vip.0"
    When    Run "crm configure set d.monitor.on-fail ignore" on "hanode1"
    And     Run "crm configure show d" on "hanode1"
    Then    Expected "on-fail=ignore" in stdout
    When    Run "crm configure set s.monitor.5s.interval 20s" on "hanode1"
    And     Run "crm configure show s" on "hanode1"
    Then    Expected "interval=20s" in stdout
    When    Run "crm configure set s.monitor.20s.interval 60s" on "hanode1"
    And     Run "crm configure show s" on "hanode1"
    Then    Expected "interval=60s" in stdout
    When    Run "crm configure set s.monitor.60.interval 50" on "hanode1"
    And     Run "crm configure show s" on "hanode1"
    Then    Expected "interval=50s" in stdout

    When    Run "crm configure primitive d2 Dummy op monitor interval=10 timeout=20 op start timeout=66" on "hanode1"
    And     Run "crm configure show d2" on "hanode1"
    Then    Expected "monitor interval=10s timeout=20s" in stdout
    When    Run "crm configure show d2" on "hanode1"
    Then    Expected "start timeout=66s" in stdout
    When    Run "crm configure set d2.monitor.interval 33" on "hanode1"
    And     Run "crm configure show d2" on "hanode1"
    Then    Expected "interval=33s" in stdout
    When    Run "crm configure set d2.monitor.33s.interval 50" on "hanode1"
    And     Run "crm configure show d2" on "hanode1"
    Then    Expected "interval=50s" in stdout

    When    Run "crm configure set op-options.timeout 101" on "hanode1"
    And     Run "crm configure show op-options" on "hanode1"
    Then    Expected "timeout=101" in stdout

  @clean
  Scenario: Parse node and lifetime correctly (bsc#1192618)
    Given   Resource "d" is started on "hanode1"
    # move <res> <node>
    When    Run "crm resource move d hanode2" on "hanode1"
    When    Run "sleep 2" on "hanode1"
    Then    Resource "d" is started on "hanode2"
    When    Run "crm resource clear d" on "hanode1"

    # move <res> <node> force
    When    Run "crm resource move d hanode1" on "hanode1"
    When    Run "sleep 2" on "hanode1"
    Then    Resource "d" is started on "hanode1"
    When    Run "crm resource clear d" on "hanode1"

    # move <res> force
    When    Run "crm resource move d force" on "hanode1"
    When    Run "sleep 2" on "hanode1"
    Then    Resource "d" is started on "hanode2"
    When    Run "crm resource clear d" on "hanode1"

    # move <res> <lifetime> force
    When    Run "crm resource move d PT5M force" on "hanode1"
    When    Run "sleep 2" on "hanode1"
    Then    Resource "d" is started on "hanode1"
    When    Run "crm resource clear d" on "hanode1"

    # move <res> <node> <lifetime>
    When    Run "crm resource move d hanode2 PT5M" on "hanode1"
    When    Run "sleep 2" on "hanode1"
    Then    Resource "d" is started on "hanode2"
    When    Run "crm resource clear d" on "hanode1"

    # move <res> <node> <lifetime> force
    When    Run "crm resource move d hanode1 PT5M force" on "hanode1"
    When    Run "sleep 2" on "hanode1"
    Then    Resource "d" is started on "hanode1"
    When    Run "crm resource clear d" on "hanode1"

    When    Try "crm resource move d hanode2 PT5M force xxx"
    Then    Except "ERROR: resource.move: usage: move <rsc> [<node>] [<lifetime>] [force]"
    When    Try "crm resource move d hanode2 PT5M forcd"
    Then    Except "ERROR: resource.move: usage: move <rsc> [<node>] [<lifetime>] [force]"
    When    Try "crm resource move d xxxx PT5M force"
    Then    Except "ERROR: resource.move: Not our node: xxxx"
    When    Try "crm resource move d"
    Then    Except "ERROR: resource.move: No target node: Move requires either a target node or 'force'"

  @clean
  Scenario: promote and demote promotable clone resource (bsc#1194125)
    When    Run "crm configure primitive s2 ocf:pacemaker:Stateful op monitor role=Promoted interval=3s op monitor role=Unpromoted interval=5s" on "hanode1"
    And     Run "crm configure clone p2 s2 meta promotable=true" on "hanode1"
    And     Run "crm resource demote p2" on "hanode1"
    Then    Run "sleep 2;! crm_resource --locate -r p2|grep -E 'Master|Promoted'" OK
    When    Run "crm resource promote p2" on "hanode2"
    Then    Run "sleep 2;crm_resource --locate -r p2|grep -E 'Master|Promoted'" OK

  @clean
  Scenario: operation warning
    When    Run "crm configure primitive id=d2 Dummy op start interval=5s" on "hanode1"
    Then    Expected "WARNING: d2: Specified interval for start is 5s, it must be 0" in stderr
    When    Run "crm configure primitive id=d3 Dummy op monitor interval=0" on "hanode1"
    Then    Expected "WARNING: d3: interval in monitor should be larger than 0, advised is 10s" in stderr
    When    Run "crm configure primitive s2 ocf:pacemaker:Stateful op monitor role=Promoted interval=3s op monitor role=Unpromoted interval=3s" on "hanode1"
    Then    Expected "WARNING: s2: interval in monitor must be unique, advised is 11s" in stderr
    When    Run "crm configure primitive id=d4 Dummy op start timeout=10s" on "hanode1"
    Then    Expected "WARNING: d4: specified timeout 10s for start is smaller than the advised 20s" in stderr

  @clean
  Scenario: trace ra with specific directory
    When    Run "crm resource trace d monitor" on "hanode1"
    Then    Expected "Trace for d:monitor is written to /var/lib/heartbeat/trace_ra/Dummy" in stdout
    When    Wait "10" seconds
    Then    Run "bash -c 'ls /var/lib/heartbeat/trace_ra/Dummy/d.monitor.*'" OK
    When    Run "crm resource untrace d" on "hanode1"
    Then    Expected "Stop tracing d" in stdout
    When    Run "crm resource trace d monitor /trace_log_d" on "hanode1"
    Then    Expected "Trace for d:monitor is written to /trace_log_d/Dummy" in stdout
    When    Wait "10" seconds
    Then    Run "bash -c 'ls /trace_log_d/Dummy/d.monitor.*'" OK
    When    Run "crm resource untrace d" on "hanode1"
    Then    Expected "Stop tracing d" in stdout

  @clean
  Scenario: Add promotable=true and interleave=true automatically (bsc#1205522)
    When    Run "crm configure primitive s2 ocf:pacemaker:Stateful" on "hanode1"
    And     Run "crm configure clone p2 s2" on "hanode1"
    Then    Run "sleep 2;crm configure show|grep -A1 'clone p2 s2'|grep 'promotable=true interleave=true'" OK
    When    Run "crm configure primitive s3 ocf:pacemaker:Stateful" on "hanode1"
    And     Run "crm configure clone p3 s3 meta promotable=false" on "hanode1"
    Then    Run "sleep 2;crm configure show|grep -A1 'clone p3 s3'|grep 'promotable=false interleave=true'" OK
    When    Run "crm configure primitive d2 Dummy" on "hanode1"
    And     Run "crm configure clone p4 d2" on "hanode1"
    Then    Run "sleep 2;crm configure show|grep -A1 'clone p4 d2'|grep 'interleave=true'" OK

  @clean
  Scenario: Run rsctest
    When    Run "crm resource stop d vip" on "hanode1"
    When    Run "crm configure rsctest d vip" on "hanode1"
    Then    Expected multiple lines in output
      """
      INFO: Probing resources
      INFO: Testing on hanode1: d vip
      INFO: Testing on hanode2: d vip
      """

  @clean
  Scenario: Run ra info cluster
    When    Run "crm ra info cluster" on "hanode1"
    Then    Expected "Pacemaker cluster options" in stdout

  @clean
  Scenario: Auto convert deprecated roles
    When    Run "crm configure primitive stateful-1 ocf:pacemaker:Stateful op monitor role=Master interval=10s op monitor role=Slave interval=5s" on "hanode1"
    Then    Expected multiple lines in output
      """
      INFO: Convert deprecated "Master" to "Promoted"
      INFO: Convert deprecated "Slave" to "Unpromoted"
      """
    When    Run "crm configure clone promotable-1 stateful-1 meta promotable=true" on "hanode1"
    Then    Run "sleep 2;crm resource status promotable-1|grep 'Promoted$'" OK

  @clean
  Scenario: Use rsc_template
    When    Run "crm configure rsc_template dummy_template ocf:pacemaker:Dummy op monitor interval=12s" on "hanode1"
    And     Try "crm configure primitive d8 @dummy_template params passwd=123" on "hanode1"
    Then    Expected "got no meta-data, does this RA exist" not in stderr

  @clean
  Scenario: Don't add time units to values for existing CIB (bsc#1228817)
    When    Run "crm configure show xml d > /tmp/d.xml" on "hanode1"
    And     Run "sed -i '/<op name="monitor"/s/timeout="20s"/timeout="20"/' /tmp/d.xml" on "hanode1"
    And     Run "crm configure load xml update /tmp/d.xml" on "hanode1"
    And     Try "crm configure show|grep -E "^xml <primitive""
    Then    Expected return code is "1"

  @clean
  Scenario: Prevent adding unknown operation (bsc#1236442)
    When    Try "crm configure primitive stateful-1 ocf:pacemaker:Stateful op monitor_Slave interval=10s op monitor_Master interval=5s" on "hanode1"
    Then    Expected return code is "1"
    Then    Expected "not found in Resource Agent meta-data" in stderr
    When    Try "crm configure show stateful-1" on "hanode1"
    Then    Expected "object stateful-1 does not exist" in stderr
