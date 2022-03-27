@qdevice
Feature: corosync qdevice/qnetd options

  Test corosync qdevice/qnetd options:
      "--qdevice-algo":        QNetd decision ALGORITHM(ffsplit/lms, default:ffsplit)
      "--qdevice-ti-breaker":  QNetd TIE_BREAKER(lowest/highest/valid_node_id, default:lowest)
      "--qdevice-tls":         Whether using TLS on QDevice/QNetd(on/off/required, default:on)
      "--qdevice-heuristics":  COMMAND to run with absolute path. For multiple commands, use ";" to separate
  Tag @clean means need to stop cluster service if the service is available
  Need nodes: hanode1 hanode2 qnetd-node

  @clean
  Scenario: Use "--qdevice-algo" to change qnetd decision algorithm to "lms"
    Given   Cluster service is "stopped" on "hanode1"
    And     Service "corosync-qdevice" is "stopped" on "hanode1"
    When    Run "crm cluster init --qnetd-hostname=qnetd-node --qdevice-algo=lms -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "corosync-qdevice" is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    And     Service "corosync-qdevice" is "started" on "hanode2"
    And     Show corosync qdevice configuration

  @clean
  Scenario: Use "--qdevice-tie-breaker" to change qnetd tie_breaker to "highest"
    Given   Cluster service is "stopped" on "hanode1"
    And     Service "corosync-qdevice" is "stopped" on "hanode1"
    When    Run "crm cluster init --qnetd-hostname=qnetd-node --qdevice-tie-breaker=highest -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "corosync-qdevice" is "started" on "hanode1"
    And     Show corosync qdevice configuration

  @clean
  Scenario: Use "--qdevice-tls" to turn off TLS certification
    Given   Cluster service is "stopped" on "hanode1"
    And     Service "corosync-qdevice" is "stopped" on "hanode1"
    When    Run "crm cluster init --qnetd-hostname=qnetd-node --qdevice-tls=off -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "corosync-qdevice" is "started" on "hanode1"
    And     Show corosync qdevice configuration

  @clean
  Scenario: Use "--qdevice-heuristics" to configure heuristics
    Given   Cluster service is "stopped" on "hanode1"
    And     Service "corosync-qdevice" is "stopped" on "hanode1"
    When    Run "crm cluster init --qnetd-hostname=qnetd-node --qdevice-heuristics='/usr/bin/test -f /tmp/file_exists;/usr/bin/which pacemaker' -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "corosync-qdevice" is "started" on "hanode1"
    And     Show corosync qdevice configuration
