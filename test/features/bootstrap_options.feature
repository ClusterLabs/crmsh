@bootstrap
Feature: crmsh bootstrap process - options

  Test crmsh bootstrap options:
      "--nodes": Additional nodes to add to the created cluster
      "-i":      Bind to IP address on interface IF
      "-M":      Configure corosync with second heartbeat line
      "-n":      Set the name of the configured cluster
      "-A":      Configure IP address as an administration virtual IP
      "-u":      Configure corosync to communicate over unicast
  Tag @clean means need to stop cluster service if the service is available

  @clean
  Scenario: Check help output
    When    Run "crm -h" on "hanode1"
    Then    Output is the same with expected "crm" help output
    When    Run "crm cluster init -h" on "hanode1"
    Then    Output is the same with expected "crm cluster init" help output
    When    Run "crm cluster join -h" on "hanode1"
    Then    Output is the same with expected "crm cluster join" help output
    When    Run "crm cluster add -h" on "hanode1"
    Then    Output is the same with expected "crm cluster add" help output
    When    Run "crm cluster remove -h" on "hanode1"
    Then    Output is the same with expected "crm cluster remove" help output
    When    Run "crm cluster geo-init -h" on "hanode1"
    Then    Output is the same with expected "crm cluster geo-init" help output
    When    Run "crm cluster geo-join -h" on "hanode1"
    Then    Output is the same with expected "crm cluster geo-join" help output
    When    Run "crm cluster geo-init-arbitrator -h" on "hanode1"
    Then    Output is the same with expected "crm cluster geo-init-arbitrator" help output

  @clean
  Scenario: Init whole cluster service on node "hanode1" using "--nodes" option
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y --no-overwrite-sshkey --nodes \"hanode1 hanode2\"" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    And     Show cluster status on "hanode1"

  @clean
  Scenario: Bind specific network interface using "-i" option
    Given   Cluster service is "stopped" on "hanode1"
    And     IP "10.10.10.2" is belong to "eth1"
    When    Run "crm cluster init -i eth1 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     IP "10.10.10.2" is used by corosync
    And     Show corosync ring status

  @clean
  Scenario: Using multiple network interface using "-M" option
    Given   Cluster service is "stopped" on "hanode1"
    And     IP "172.17.0.2" is belong to "eth0"
    And     IP "10.10.10.2" is belong to "eth1"
    When    Run "crm cluster init -M -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     IP "172.17.0.2" is used by corosync
    And     IP "10.10.10.2" is used by corosync
    And     Show corosync ring status

  @clean
  Scenario: Setup cluster name and virtual IP using "-A" option
    Given   Cluster service is "stopped" on "hanode1"
    When    Run "crm cluster init -n hatest -A 10.10.10.123 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Cluster name is "hatest"
    And     Cluster virtual IP is "10.10.10.123"
    And     Show cluster status on "hanode1"

  @clean
  Scenario: Init cluster service with udpu using "-u" option
    Given   Cluster service is "stopped" on "hanode1"
    When    Run "crm cluster init -u -y --no-overwrite-sshkey" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Cluster is using udpu transport mode
    And     IP "172.17.0.2" is used by corosync
    And     Show corosync ring status
