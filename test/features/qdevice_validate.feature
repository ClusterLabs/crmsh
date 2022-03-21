@qdevice
Feature: corosync qdevice/qnetd options validate

  Tag @clean means need to stop cluster service if the service is available

  @clean
  Scenario: Option "--qnetd-hostname" use the same node
    When    Try "crm cluster init --qnetd-hostname=hanode1"
    Then    Except "ERROR: cluster.init: host for qnetd must be a remote one"

  @clean
  Scenario: Option "--qnetd-hostname" use hanode1's IP
    When    Try "crm cluster init --qnetd-hostname=10.10.10.2"
    Then    Except "ERROR: cluster.init: host for qnetd must be a remote one"

  @clean
  Scenario: Option "--qnetd-hostname" use unknown hostname
    When    Try "crm cluster init --qnetd-hostname=error-node"
    Then    Except "ERROR: cluster.init: host "error-node" is unreachable"

  @clean
  Scenario: Service ssh on qnetd node not available
    When    Try "crm cluster init --qnetd-hostname=node-without-ssh"
    Then    Except "ERROR: cluster.init: ssh service on "node-without-ssh" not available"

  @clean
  Scenario: Option "--qdevice-port" set wrong port
    When    Try "crm cluster init --qnetd-hostname=qnetd-node --qdevice-port=1"
    Then    Except "ERROR: cluster.init: invalid qdevice port range(1024 - 65535)"

  @clean
  Scenario: Option "--qdevice-tie-breaker" set wrong value
    When    Try "crm cluster init --qnetd-hostname=qnetd-node --qdevice-tie-breaker=wrongtiebreaker"
    Then    Except "ERROR: cluster.init: invalid qdevice tie_breaker(lowest/highest/valid_node_id)"

  @clean
  Scenario: Option "--qdevice-heuristics" set wrong value
    When    Try "crm cluster init --qnetd-hostname=qnetd-node --qdevice-heuristics='ls /opt'"
    Then    Except "ERROR: cluster.init: commands for heuristics should be absolute path"
    When    Try "crm cluster init --qnetd-hostname=qnetd-node --qdevice-heuristics='/bin/not_exist_cmd /opt'"
    Then    Except "ERROR: cluster.init: command /bin/not_exist_cmd not exist"

  @clean
  Scenario: Option "--qnetd-hostname" is required by other qdevice options
    When    Try "crm cluster init --qdevice-port=1234"
    Then    Except multiple lines
      """
      usage: init [options] [STAGE]
      crm: error: Option --qnetd-hostname is required if want to configure qdevice
      """

  @clean
  Scenario: Option --qdevice-heuristics is required if want to configure heuristics mode
    When    Try "crm cluster init --qnetd-hostname=qnetd-node --qdevice-heuristics-mode="on""
    Then    Except multiple lines
      """
      usage: init [options] [STAGE]
      crm: error: Option --qdevice-heuristics is required if want to configure heuristics mode
      """

  @clean
  Scenario: Node for qnetd not installed corosync-qnetd
    Given   Cluster service is "stopped" on "hanode2"
    When    Try "crm cluster init --qnetd-hostname=hanode2 -y"
    Then    Except multiple lines
      """
      ERROR: cluster.init: Package "corosync-qnetd" not installed on hanode2!
      Cluster service already successfully started on this node except qdevice service.
      If you still want to use qdevice, install "corosync-qnetd" on hanode2.
      Then run command "crm cluster init" with "qdevice" stage, like:
        crm cluster init qdevice qdevice_related_options
      That command will setup qdevice separately.
      """
    And     Cluster service is "started" on "hanode1"

  @clean
  Scenario: Raise error when adding qdevice stage with the same cluster name
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -n cluster1 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster init -n cluster1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    When    Try "crm cluster init qdevice --qnetd-hostname=qnetd-node -y" on "hanode1,hanode2"
    Then    Except "ERROR: cluster.init: Duplicated cluster name "cluster1"!"
    When    Run "crm cluster stop" on "hanode1"
    When    Run "crm cluster stop" on "hanode2"

  @clean
  Scenario: Raise error when the same cluster name already exists on qnetd
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Try "crm cluster init -n cluster1 --qnetd-hostname=qnetd-node -y" on "hanode2"
    When    Try "crm cluster init -n cluster1 --qnetd-hostname=qnetd-node -y"
    Then    Except multiple lines
      """
      ERROR: cluster.init: This cluster's name "cluster1" already exists on qnetd server!
      Cluster service already successfully started on this node except qdevice service.
      If you still want to use qdevice, consider to use the different cluster-name property.
      Then run command "crm cluster init" with "qdevice" stage, like:
        crm cluster init qdevice qdevice_related_options
      That command will setup qdevice separately.
      """
    And     Cluster service is "started" on "hanode1"
    And     Cluster service is "started" on "hanode2"

  @clean
  Scenario: Run qdevice stage on inactive cluster node
    Given   Cluster service is "stopped" on "hanode1"
    When    Try "crm cluster init qdevice --qnetd-hostname=qnetd-node"
    Then    Except "ERROR: cluster.init: Cluster is inactive - can't run qdevice stage"

  @clean
  Scenario: Run qdevice stage but miss "--qnetd-hostname" option
    Given   Cluster service is "stopped" on "hanode1"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Try "crm cluster init qdevice -y"
    Then    Except multiple lines
      """
      usage: init [options] [STAGE]
      crm: error: Option --qnetd-hostname is required if want to configure qdevice
      """

  @clean
  Scenario: Setup qdevice on a single node cluster with RA running(bsc#1181415)
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "corosync-qdevice" is "stopped" on "hanode1"
    When    Run "crm configure primitive d Dummy op monitor interval=3s" on "hanode1"
    When    Run "crm cluster init qdevice --qnetd-hostname=qnetd-node -y" on "hanode1"
    Then    Expected "WARNING: To use qdevice service, need to restart cluster service manually on each node" in stdout
    And     Service "corosync-qdevice" is "stopped" on "hanode1"
    When    Run "crm cluster restart" on "hanode1"
    Then    Service "corosync-qdevice" is "started" on "hanode1"

  @clean
  Scenario: Remove qdevice from a single node cluster(bsc#1181415)
    When    Run "crm cluster init --qnetd-hostname=qnetd-node -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "corosync-qdevice" is "started" on "hanode1"
    When    Run "crm cluster remove --qdevice -y" on "hanode1"
    Then    Expected "Restarting cluster service" in stdout
    Then    Cluster service is "started" on "hanode1"
    And     Service "corosync-qdevice" is "stopped" on "hanode1"

  @clean
  Scenario: Remove qdevice from a single node cluster which has RA running(bsc#1181415)
    When    Run "crm cluster init --qnetd-hostname=qnetd-node -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "corosync-qdevice" is "started" on "hanode1"
    When    Run "crm configure primitive d Dummy op monitor interval=3s" on "hanode1"
    When    Run "crm cluster remove --qdevice -y" on "hanode1"
    Then    Expected "WARNING: To remove qdevice service, need to restart cluster service manually on each node" in stdout
    Then    Cluster service is "started" on "hanode1"
    And     Service "corosync-qdevice" is "started" on "hanode1"
    When    Run "crm cluster restart" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "corosync-qdevice" is "stopped" on "hanode1"
