@cluster_api
Feature: Functional test to cover SAP clusterAPI

  To avoid possible regression on crmsh side when adapting SAP Applications 
  Tag @clean means need to stop cluster service if the service is available
  Need nodes: hanode1 hanode2

  Background: Setup a two nodes cluster
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Show cluster status on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    When    Run "crm configure primitive d Dummy" on "hanode1"
    And     Wait "3" seconds
    Then    Resource "d" type "Dummy" is "Started"
    And     Show cluster status on "hanode1"
    When    Run "echo 'export PATH=$PATH:/usr/sbin/' > ~hacluster/.bashrc" on "hanode1"
    When    Run "echo 'export PATH=$PATH:/usr/sbin/' > ~hacluster/.bashrc" on "hanode2"

  @clean
  Scenario: Start and stop resource by hacluster
    When    Run "su - hacluster -c 'crm resource stop d'" on "hanode1"
    Then    Expected return code is "0"
    When    Wait "3" seconds
    Then    Resource "d" type "Dummy" is "Stopped"
    And     Show cluster status on "hanode1"
    When    Run "su - hacluster -c 'crm resource start d'" on "hanode1"
    Then    Expected return code is "0"
    When    Wait "3" seconds
    Then    Resource "d" type "Dummy" is "Started"
    And     Show cluster status on "hanode1"

  @clean
  Scenario: Resource move by hacluster
    Given   Resource "d" is started on "hanode1"
    # move <res> <node>
    When    Run "su - hacluster -c 'crm resource move d hanode2'" on "hanode1"
    Then    Expected return code is "0"
    When    Run "sleep 2" on "hanode1"
    Then    Resource "d" is started on "hanode2"
    When    Run "su - hacluster -c 'crm resource clear d'" on "hanode1"
    Then    Expected return code is "0"

    # move <res> <node> force
    When    Run "su - hacluster -c 'crm resource move d hanode1'" on "hanode1"
    Then    Expected return code is "0"
    When    Run "sleep 2" on "hanode1"
    Then    Resource "d" is started on "hanode1"
    When    Run "su - hacluster -c 'crm resource clear d'" on "hanode1"
    Then    Expected return code is "0"

    # move <res> force
    When    Run "su - hacluster -c 'crm resource move d force'" on "hanode1"
    Then    Expected return code is "0"
    When    Run "sleep 2" on "hanode1"
    Then    Resource "d" is started on "hanode2"
    When    Run "su - hacluster -c 'crm resource clear d'" on "hanode1"
    Then    Expected return code is "0"

    # move <res> <lifetime> force
    When    Run "su - hacluster -c 'crm resource move d PT5M force'" on "hanode1"
    Then    Expected return code is "0"
    When    Run "sleep 2" on "hanode1"
    Then    Resource "d" is started on "hanode1"
    When    Run "su - hacluster -c 'crm resource clear d'" on "hanode1"
    Then    Expected return code is "0"

    # move <res> <node> <lifetime>
    When    Run "su - hacluster -c 'crm resource move d hanode2 PT5M'" on "hanode1"
    Then    Expected return code is "0"
    When    Run "sleep 2" on "hanode1"
    Then    Resource "d" is started on "hanode2"
    When    Run "su - hacluster -c 'crm resource clear d'" on "hanode1"
    Then    Expected return code is "0"

    # move <res> <node> <lifetime> force
    When    Run "su - hacluster -c 'crm resource move d hanode1 PT5M force'" on "hanode1"
    Then    Expected return code is "0"
    When    Run "sleep 2" on "hanode1"
    Then    Resource "d" is started on "hanode1"
    When    Run "su - hacluster -c 'crm resource clear d'" on "hanode1"
    Then    Expected return code is "0"

    When    Try "crm resource move d hanode2 PT5M force xxx"
    Then    Except "ERROR: resource.move: usage: move <rsc> [<node>] [<lifetime>] [force]"
    When    Try "crm resource move d hanode2 PT5M forcd"
    Then    Except "ERROR: resource.move: usage: move <rsc> [<node>] [<lifetime>] [force]"
    When    Try "crm resource move d xxxx PT5M force"
    Then    Except "ERROR: resource.move: Not our node: xxxx"
    When    Try "crm resource move d"
    Then    Except "ERROR: resource.move: No target node: Move requires either a target node or 'force'"

  @clean
  Scenario: Run "crm configure show" by hacluster
    When    Run "crm configure primitive d2 Dummy op monitor interval=10s timeout=20s on-fail=restart params fake=test meta resource-stickiness=5000" on "hanode1"
    And     Run "crm configure group g d2 meta resource-stickiness=3000" on "hanode1"
    And     Wait "3" seconds
    Then    Resource "d2" type "Dummy" is "Started"
    And     Show cluster status on "hanode1"
    When    Run "su - hacluster -c 'crm configure show'" on "hanode1"
    Then    Expected return code is "0"

  @clean
  Scenario: pacemaker ACL related operations by hacluster
    When    Run "su - hacluster -c 'crm configure primitive d2 Dummy'" on "hanode1"
    And     Wait "3" seconds
    Then    Resource "d2" type "Dummy" is "Started"
    When    Run "su - hacluster -c 'crm maintenance on'" on "hanode1"
    When    Run "crm_mon -1" on "hanode1"
    Then    Expected "Resource management is DISABLED" in stdout
    When    Run "su - hacluster -c 'crm maintenance off'" on "hanode1"
    When    Run "crm_mon -1" on "hanode1"
    Then    Expected "Resource management is DISABLED" not in stdout
    When    Run "su - hacluster -c 'crm node standby hanode2'" on "hanode1"
    Then    Node "hanode2" is standby
    When    Run "su - hacluster -c 'crm node online hanode2'" on "hanode1"
    Then    Node "hanode2" is online
    When    Run "su - hacluster -c 'crm ra providers Dummy'" on "hanode1"
    Then    Expected "heartbeat pacemaker" in stdout
    When    Run "su - hacluster -c 'crm status'" on "hanode1"
    Then    Expected "Online: [ hanode1 hanode2 ]" in stdout
    When    Run "su - hacluster -c '/usr/sbin/crm report /tmp/report'" on "hanode1"
    Then    No crmsh tracebacks
    Then    File "/tmp/report.tar.bz2" exists on "hanode1"
    And     Directory "hanode1" in "/tmp/report.tar.bz2"
    And     Directory "hanode2" in "/tmp/report.tar.bz2"
    And     File "pacemaker.log" in "/tmp/report.tar.bz2"
    And     File "corosync.conf" in "/tmp/report.tar.bz2"
