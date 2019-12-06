@qdevice
Feature: corosync qdevice/qnetd options validate

  Tag @clean means need to stop cluster service if the service is available

  @clean
  Scenario: Option "--qdevice" use the same node
    When    Try "crm cluster init --qdevice=hanode1"
    Then    Except "ERROR: cluster.init: host for qnetd must be a remote one"

  @clean
  Scenario: Option "--qdevice" use hanode1's IP
    When    Try "crm cluster init --qdevice=10.10.10.2"
    Then    Except "ERROR: cluster.init: host for qnetd must be a remote one"

  @clean
  Scenario: Option "--qdevice" use unknown hostname
    When    Try "crm cluster init --qdevice=error-node"
    Then    Except "ERROR: cluster.init: host "error-node" is unreachable"

  @clean
  Scenario: Service ssh on qnetd node not available
    When    Try "crm cluster init --qdevice=node-without-ssh"
    Then    Except "ERROR: cluster.init: ssh service on "node-without-ssh" not available"

  @clean
  Scenario: Option "--qdevice-port" set wrong port
    When    Try "crm cluster init --qdevice=qnetd-node --qdevice-port=1"
    Then    Except "ERROR: cluster.init: invalid qdevice port range(1024 - 65535)"

  @clean
  Scenario: Option "--qdevice-algo" set wrong value
    When    Try "crm cluster init --qdevice=qnetd-node --qdevice-algo=wrongalgo"
    Then    Except "ERROR: cluster.init: invalid qdevice algorithm(ffsplit/lms)"

  @clean
  Scenario: Option "--qdevice-tie-breaker" set wrong value
    When    Try "crm cluster init --qdevice=qnetd-node --qdevice-tie-breaker=wrongtiebreaker"
    Then    Except "ERROR: cluster.init: invalid qdevice tie_breaker(lowest/highest/valid_node_id)"

  @clean
  Scenario: Option "--qdevice-tls" set wrong value
    When    Try "crm cluster init --qdevice=qnetd-node --qdevice-tls=wrong"
    Then    Except "ERROR: cluster.init: invalid qdevice tls(on/off/required)"

  @clean
  Scenario: Option "--qdevice-heuristics" set wrong value
    When    Try "crm cluster init --qdevice=qnetd-node --qdevice-heuristics='ls /opt'"
    Then    Except "ERROR: cluster.init: commands for heuristics should be absolute path"
    When    Try "crm cluster init --qdevice=qnetd-node --qdevice-heuristics='/bin/not_exists_cmd /opt'"
    Then    Except "ERROR: cluster.init: command /bin/not_exists_cmd not exists"

  @clean
  Scenario: Node for qnetd is a cluster node
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y --no-overwrite-sshkey" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    When    Try "crm cluster init --qdevice=hanode2 -y --no-overwrite-sshkey"
    Then    Except "ERROR: cluster.init: host for qnetd must be a non-cluster node"

  @clean
  Scenario: Run qdevice stage on inactive cluster node
    Given   Cluster service is "stopped" on "hanode1"
    When    Try "crm cluster init qdevice --qdevice=qnetd-node"
    Then    Except "ERROR: cluster.init: Cluster is inactive - can't run qdevice stage"

  @clean
  Scenario: Run qdevice stage but miss "--qdevice" option
    Given   Cluster service is "stopped" on "hanode1"
    When    Run "crm cluster init -y --no-overwrite-sshkey" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Try "crm cluster init qdevice"
    Then    Except "ERROR: cluster.init: qdevice related options are missing (--qdevice option is mandatory, find for more information using --help)"
