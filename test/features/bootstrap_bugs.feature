@bootstrap
Feature: Regression test for bootstrap bugs

  Tag @clean means need to stop cluster service if the service is available
  Need nodes: hanode1 hanode2 hanode3

  @clean
  Scenario: Stages dependency (bsc#1175865)
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Try "crm cluster init cluster -y" on "hanode1"
    Then    Except "ERROR: cluster.init: Please run 'ssh' stage first"
    When    Run "crm cluster init ssh -y" on "hanode1"
    When    Try "crm cluster init cluster -y" on "hanode1"
    Then    Except "ERROR: cluster.init: Please run 'csync2' stage first"
    When    Run "crm cluster init csync2 -y" on "hanode1"
    When    Try "crm cluster init cluster -y" on "hanode1"
    Then    Except "ERROR: cluster.init: Please run 'corosync' stage first"
    When    Run "crm cluster init corosync -y" on "hanode1"
    When    Run "crm cluster init cluster -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"

    When    Try "crm cluster join cluster -c hanode1 -y" on "hanode2"
    Then    Except "ERROR: cluster.join: Please run 'ssh' stage first"
    When    Try "crm cluster join ssh -c hanode1 -y" on "hanode2"
    When    Try "crm cluster join cluster -c hanode1 -y" on "hanode2"
    Then    Except "ERROR: cluster.join: Please run 'csync2' stage first"
    When    Try "crm cluster join csync2 -c hanode1 -y" on "hanode2"
    When    Try "crm cluster join cluster -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"

  @clean
  Scenario: Set placement-strategy value as "default"(bsc#1129462)
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Show cluster status on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    And     Show cluster status on "hanode1"
    When    Run "crm configure get_property placement-strategy" on "hanode1"
    Then    Got output "default"

  @clean
  Scenario: Empty value not allowed for option(bsc#1141976)
    When    Try "crm -c ' '"
    Then    Except "ERROR: Empty value not allowed for dest "cib""
    When    Try "crm cluster init --name ' '"
    Then    Except "ERROR: cluster.init: Empty value not allowed for dest "cluster_name""
    When    Try "crm cluster join -c ' '"
    Then    Except "ERROR: cluster.join: Empty value not allowed for dest "cluster_node""
    When    Try "crm cluster remove -c ' '"
    Then    Except "ERROR: cluster.remove: Empty value not allowed for dest "cluster_node""
    When    Try "crm cluster geo_init -a ' '"
    Then    Except "ERROR: cluster.geo_init: Empty value not allowed for dest "arbitrator""
    When    Try "crm cluster geo_join -c ' '"
    Then    Except "ERROR: cluster.geo_join: Empty value not allowed for dest "cluster_node""
    When    Try "crm cluster geo_init_arbitrator -c ' '"
    Then    Except "ERROR: cluster.geo_init_arbitrator: Empty value not allowed for dest "cluster_node""

  @clean
  Scenario: Setup cluster with crossed network(udpu only)
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -u -i eth0 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Try "crm cluster join -c hanode1 -i eth1 -y" on "hanode2"
    Then    Cluster service is "stopped" on "hanode2"
    And     Except "Cannot see peer node "hanode1", please check the communication IP" in stderr
    When    Run "crm cluster join -c hanode1 -i eth0 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"

  @clean
  Scenario: Remove correspond nodelist in corosync.conf while remove(bsc#1165644)
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -u -i eth1 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -i eth1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    When    Run "crm corosync get nodelist.node.ring0_addr" on "hanode1"
    Then    Expected "@hanode2.ip.0" in stdout
    #And     Service "hawk.service" is "started" on "hanode2"
    When    Run "crm cluster remove hanode2 -y" on "hanode1"
    Then    Online nodes are "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    # verify bsc#1175708
    #And     Service "hawk.service" is "stopped" on "hanode2"
    When    Run "crm corosync get nodelist.node.ring0_addr" on "hanode1"
    Then    Expected "@hanode2.ip.0" not in stdout

  @clean
  Scenario: Multi nodes join in parallel(bsc#1175976)
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    And     Cluster service is "stopped" on "hanode3"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Show cluster status on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2,hanode3"
    Then    Cluster service is "started" on "hanode2"
    And     Cluster service is "started" on "hanode3"
    And     Online nodes are "hanode1 hanode2 hanode3"
    And     Show cluster status on "hanode1"
    And     File "/etc/corosync/corosync.conf" was synced in cluster

  @clean
  Scenario: Multi nodes join in parallel timed out(bsc#1175976)
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    And     Cluster service is "stopped" on "hanode3"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Show cluster status on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    # Try to simulate the join process hanging on hanode2 or hanode2 died
    # Just leave the lock directory unremoved
    When    Run "mkdir /run/.crmsh_lock_directory" on "hanode1"
    When    Try "crm cluster join -c hanode1 -y" on "hanode3"
    Then    Except "ERROR: cluster.join: Timed out after 120 seconds. Cannot continue since the lock directory exists at the node (hanode1:/run/.crmsh_lock_directory)"
    When    Run "rm -rf /run/.crmsh_lock_directory" on "hanode1"

  @clean
  Scenario: Change host name in /etc/hosts as alias(bsc#1183654)
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "echo '@hanode1.ip.0 HANODE1'|sudo tee -a /etc/hosts" on "hanode1"
    When    Run "echo '@hanode2.ip.0 HANODE2'|sudo tee -a /etc/hosts" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c HANODE1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    When    Run "crm cluster remove HANODE2 -y" on "hanode1"
    Then    Cluster service is "stopped" on "hanode2"
    And     Online nodes are "hanode1"

  @clean
  Scenario: Stop service quickly(bsc#1203601)
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    When    Run "crm cluster stop --all" on "hanode1"
    Then    Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster start --all;sudo crm cluster stop --all" on "hanode1"
    Then    Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "systemctl start corosync" on "hanode1"
    Then    Service "corosync" is "started" on "hanode1"
    When    Run "crm cluster stop" on "hanode1"
    Then    Service "corosync" is "stopped" on "hanode1"

  @clean
  Scenario: Can't start cluster with --all option if no cib(bsc#1219052)
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"

    When    Run "crm cluster stop --all" on "hanode1"
    Then    Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "rm -f /var/lib/pacemaker/cib/*" on "hanode1"
    When    Run "rm -f /var/lib/pacemaker/cib/*" on "hanode2"
    And     Run "crm cluster start --all" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    Then    Cluster service is "started" on "hanode2"

    When    Try "crm cluster start xxx"
    Then    Except "ERROR: cluster.start: Node 'xxx' is not a member of the cluster"

  @clean
  Scenario: Can't stop all nodes' cluster service when local node's service is down(bsc#1213889)
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    When    Wait for DC
    And     Run "crm cluster stop" on "hanode1"
    And     Run "crm cluster stop --all" on "hanode1"
    Then    Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"

  @skip_non_root
  @clean
  Scenario: crm cluster join default behavior change in ssh key handling (bsc#1210693)
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "rm -rf /home/alice/.ssh" on "hanode1"
    When    Run "rm -rf /home/alice/.ssh" on "hanode2"
    When    Run "su - alice -c "sudo crm cluster init -y"" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "su - alice -c "sudo crm cluster join -c hanode1 -y"" on "hanode2"
    Then    Cluster service is "started" on "hanode2"

  @skip_non_root
  @clean
  Scenario: Passwordless for root, not for sudoer(bsc#1209193)
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    When    Run "useradd -m -s /bin/bash xin" on "hanode1"
    When    Run "echo "xin ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/xin" on "hanode1"
    When    Run "rm -f /root/.config/crm/crm.conf" on "hanode1"
    When    Run "useradd -m -s /bin/bash xin" on "hanode2"
    When    Run "echo "xin ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/xin" on "hanode2"
    When    Run "rm -f /root/.config/crm/crm.conf" on "hanode2"
    When    Run "su xin -c "sudo crm cluster run 'touch /tmp/1209193'"" on "hanode1"
    And     Run "test -f /tmp/1209193" on "hanode1"
    And     Run "test -f /tmp/1209193" on "hanode2"

  @skip_non_root
  @clean
  Scenario: Missing public key
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    And     Run "rm -f /root/.ssh/id_rsa.pub" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"

  @skip_non_root
  @clean
  Scenario: Skip upgrade when preconditions are not satisfied
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    When    Run "rm -f /var/lib/crmsh/upgrade_seq" on "hanode1"
    And     Run "mv /root/.config/crm/crm.conf{,.bak}" on "hanode1"
    Then    Run "crm status" OK on "hanode1"
    When    Run "rm -f /var/lib/crmsh/upgrade_seq" on "hanode1"
    And     Run "mv /root/.config/crm/crm.conf{.bak,}" on "hanode1"
    And     Run "mv /root/.ssh{,.bak}" on "hanode1"
    Then    Run "crm status" OK on "hanode1"
    And     Run "rm -rf /root/.ssh && mv /root/.ssh{.bak,}" OK on "hanode1"

  # skip non-root as behave_agent is not able to run commands interactively with non-root sudoer
  @skip_non_root
  @clean
  Scenario: Owner and permssion of file authorized_keys (bsc#1217279)
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    # in a newly created cluster
    When    Run "crm cluster init -y" on "hanode1"
    And     Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Run "stat -c '%U:%G' ~hacluster/.ssh/authorized_keys" OK on "hanode1"
    And     Expected "hacluster:haclient" in stdout
    And     Run "stat -c '%U:%G' ~hacluster/.ssh/authorized_keys" OK on "hanode2"
    And     Expected "hacluster:haclient" in stdout
