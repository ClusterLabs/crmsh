@bootstrap
Feature: crmsh bootstrap process - options

  Test crmsh bootstrap options:
      "--node": Additional nodes to add to the created cluster
      "-i":      Bind to IP address on interface IF
      "-n":      Set the name of the configured cluster
      "-A":      Configure IP address as an administration virtual IP
  Tag @clean means need to stop cluster service if the service is available
  Need nodes: hanode1 hanode2 hanode3 qnetd-node

  @clean
  Scenario: Check help output
    When    Run "crm configure help primitive" OK		
    When    Run "crm -h" on "hanode1"
    Then    Output is the same with expected "crm" help output
    When    Run "crm cluster init -h" on "hanode1"
    Then    Output is the same with expected "crm cluster init" help output
    When    Run "crm cluster join -h" on "hanode1"
    Then    Output is the same with expected "crm cluster join" help output
    When    Run "crm cluster remove -h" on "hanode1"
    Then    Output is the same with expected "crm cluster remove" help output
    When    Run "crm cluster geo_init -h" on "hanode1"
    Then    Output is the same with expected "crm cluster geo-init" help output
    When    Run "crm cluster geo_join -h" on "hanode1"
    Then    Output is the same with expected "crm cluster geo-join" help output
    When    Run "crm cluster geo_init_arbitrator -h" on "hanode1"
    Then    Output is the same with expected "crm cluster geo-init-arbitrator" help output
    When    Try "crm cluster init -i eth1 -i eth1 -y"
    Then    Except multiple lines
      """
      usage: init [options] [STAGE]
      crm: error: Duplicated input for '-i/--interface' option
      """
    When    Try "crm cluster init -N hanode2" on "hanode1"
    Then    Expected "Can't use -N/--nodes option without -y/--yes option" in stderr
    When    Try "crm cluster init sbd -N hanode1 -N hanode2 -y" on "hanode1"
    Then    Expected "Can't use -N/--nodes option and stage(sbd) together" in stderr
    When    Try "crm corosync link help add" on "hanode1"
    Then    Expected return code is "0"

  @clean
  Scenario: Stage validation
    When    Try "crm cluster init fdsf -y" on "hanode1"
    Then    Expected "Invalid stage: fdsf(available stages: ssh, firewalld, csync2, corosync, sbd, cluster, ocfs2, gfs2, admin, qdevice)" in stderr
    When    Try "crm cluster join fdsf -y" on "hanode1"
    Then    Expected "Invalid stage: fdsf(available stages: ssh, firewalld, ssh_merge, cluster)" in stderr
    When    Try "crm cluster join ssh -y" on "hanode1"
    Then    Expected "Can't use stage(ssh) without specifying cluster node" in stderr

  @clean
  Scenario: Init whole cluster service on node "hanode1" using "--node" option
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y --node "hanode1 hanode2 hanode3"" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    And     Show cluster status on "hanode1"

    When    Try "crm cluster init cluster -y" on "hanode1"
    Then    Expected "Cluster is active, can't run 'cluster' stage" in stderr

  @clean
  Scenario: Bind specific network interface using "-i" option
    Given   Cluster service is "stopped" on "hanode1"
    And     IP "@hanode1.ip.1" is belong to "eth1"
    When    Run "crm cluster init -i eth1 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     IP "@hanode1.ip.1" is used by corosync on "hanode1"
    And     Show corosync ring status
 
  @clean
  Scenario: Validate "-i" option
    Given   Cluster service is "stopped" on "hanode1"
    When    Try "crm cluster init -t udpu -i eth0 -i eth1"
    Then    Except "ERROR: cluster.init: Only one link is allowed for the 'udpu' transport type"
    When    Try "crm cluster init -i eth0 -i eth1 -i eth2 -i eth3 -i eth4 -i eth5 -i eth6 -i eth7 -i eth8"
    Then    Except "ERROR: cluster.init: Maximum number of interfaces is 8"
    When    Try "crm cluster init -i eth11 -y"
    Then    Except "ERROR: cluster.init: Invalid value 'eth11' for -i/--interface option"

  @clean
  Scenario: Using multiple network interface using "-i" option
    Given   Cluster service is "stopped" on "hanode1"
    And     IP "@hanode1.ip.0" is belong to "eth0"
    And     IP "@hanode1.ip.1" is belong to "eth1"
    When    Run "crm cluster init -i eth0 -i eth1 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     IP "@hanode1.ip.0" is used by corosync on "hanode1"
    And     IP "@hanode1.ip.1" is used by corosync on "hanode1"
    And     Show corosync ring status

  @clean
  Scenario: Using "-i" option, mixing with IP and NIC name
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -i eth0 -i @hanode1.ip.1 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     IP "@hanode1.ip.0" is used by corosync on "hanode1"
    And     IP "@hanode1.ip.1" is used by corosync on "hanode1"
    When    Run "crm cluster join -c hanode1 -i eth0 -i @hanode2.ip.1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     IP "@hanode2.ip.0" is used by corosync on "hanode2"
    And     IP "@hanode2.ip.1" is used by corosync on "hanode2"

    When    Try "crm cluster join cluster -c hanode1 -y" on "hanode2"
    Then    Expected "Cluster is active, can't run 'cluster' stage" in stderr

  @clean
  Scenario: Using "-i" option with IP address
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -i @hanode1.ip.0 -i @hanode1.ip.1 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     IP "@hanode1.ip.0" is used by corosync on "hanode1"
    And     IP "@hanode1.ip.1" is used by corosync on "hanode1"
    When    Run "crm cluster join -c hanode1 -i @hanode2.ip.0 -i @hanode2.ip.1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     IP "@hanode2.ip.0" is used by corosync on "hanode2"
    And     IP "@hanode2.ip.1" is used by corosync on "hanode2"

  @clean
  Scenario: Setup cluster name and virtual IP using "-A" option
    Given   Cluster service is "stopped" on "hanode1"
    When    Try "crm cluster init -A xxx -y"
    Then    Except "ERROR: cluster.init: 'xxx' does not appear to be an IPv4 or IPv6 address"
    When    Try "crm cluster init -A @hanode1.ip.0 -y"
    Then    Except "ERROR: cluster.init: Address already in use: @hanode1.ip.0"
    When    Run "crm cluster init -n hatest -A @vip.0 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Cluster name is "hatest"
    And     Cluster virtual IP is "@vip.0"
    And     Show cluster status on "hanode1"

  @clean
  Scenario: Invalid virtual IP address wouldn't block cluster init
    Given   Cluster service is "stopped" on "hanode1"
    When    Run "crm cluster init -A 60.60.60.6 --qnetd-hostname qnetd-node -y" on "hanode1"
    Then    Expected "Time out waiting for resource "admin-ip" to start" in stderr
    Then    Service "corosync-qdevice" is "started" on "hanode1"
 
  @clean
  Scenario: Detect multi IP in the same NIC
    Given   Cluster service is "stopped" on "hanode1"
    When    Try "crm cluster init -i eth0 -i @hanode1.ip.0 -y"
    Then    Except "ERROR: cluster.init: Invalid input '@hanode1.ip.0': the IP in the same NIC already used"
    When    Try "crm cluster init -i @hanode1.ip.0 -i eth0 -y"
    Then    Except "ERROR: cluster.init: Invalid input 'eth0': The same NIC already used"

  @clean
  Scenario: Init cluster service with ipv6 using "-I" option
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -I -i eth0 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     IP "@hanode1.ip6.0" is used by corosync on "hanode1"
    When    Run "crm cluster join -c hanode1 -i eth0 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     IP "@hanode2.ip6.0" is used by corosync on "hanode2"

  @clean
  Scenario: Init cluster with -N option (bsc#1175863)
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -N hanode1 -N hanode2 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Cluster service is "started" on "hanode2"

  @clean
  Scenario: Setup cluster with udpu transport
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y -t udpu" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    Then    Cluster is using "udpu" transport mode

  @clean
  Scenario: Setup cluster with udp transport
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y -t udp" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    Then    Cluster is using "udp" transport mode

  @clean
  Scenario: Check if the join side provides the corresponding network interface
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -i eth0 -i eth1 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Try "crm cluster join -c hanode1 -i eth1 -y" on "hanode2"
    Then    Cluster service is "stopped" on "hanode2"
    And     Except "Node hanode1 has 2 links, but provided 1" in stderr
    When    Run "crm cluster join -c hanode1 -i eth0 -i eth1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
