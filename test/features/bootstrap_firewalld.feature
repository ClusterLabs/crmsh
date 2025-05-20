@bootstrap
Feature: Test deployment of high-availability firewalld service

  Need nodes: hanode1 hanode2 qnetd-node

  Scenario: The high-availability service is available
    Given   The "high-availability" firewalld service is available on "hanode1"
    And     The "high-availability" firewalld service is available on "hanode2"

  Scenario: The high-availability service is added after setup cluster while firewalld is offline
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    And     Service "firewalld" is "stopped" on "hanode1"
    And     Service "firewalld" is "stopped" on "hanode2"
    And     The "high-availability" firewalld service is not added on "hanode1"
    And     The "high-availability" firewalld service is not added on "hanode2"

    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    Then    The "high-availability" firewalld service is added on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    Then    The "high-availability" firewalld service is added on "hanode2"

    When    Run "crm cluster remove hanode2 -y" on "hanode1"
    Then    Cluster service is "stopped" on "hanode2"
    Then    The "high-availability" firewalld service is not added on "hanode2"
    When    Run "crm cluster remove hanode1 -y --force" on "hanode1"
    Then    Cluster service is "stopped" on "hanode1"
    Then    The "high-availability" firewalld service is not added on "hanode1"

  Scenario: The high-availability service is added after setup cluster while firewalld is running
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    And     Service "firewalld" is "stopped" on "hanode1"
    And     Service "firewalld" is "stopped" on "hanode2"
    And     The "high-availability" firewalld service is not added on "hanode1"
    And     The "high-availability" firewalld service is not added on "hanode2"
    # open behave agent port
    When    Run "firewall-offline-cmd --add-port=1122/tcp" on "hanode1"
    When    Run "firewall-offline-cmd --add-port=1122/tcp" on "hanode2"
    When    Run "systemctl start firewalld" on "hanode2"
    When    Run "systemctl start firewalld" on "hanode1"
    Then    Service "firewalld" is "started" on "hanode2"
    Then    Service "firewalld" is "started" on "hanode1"

    When    Run "crm cluster init -y -N hanode2" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    Then    Cluster service is "started" on "hanode2"
    Then    The "high-availability" firewalld service is added on "hanode1"
    Then    The "high-availability" firewalld service is added on "hanode2"

    When    Run "firewall-cmd --permanent --remove-service=high-availability; firewall-cmd --reload" on "hanode1"
    Then    The "high-availability" firewalld service is not added on "hanode1"
    When    Run "firewall-cmd --permanent --remove-service=high-availability; firewall-cmd --reload" on "hanode2"
    Then    The "high-availability" firewalld service is not added on "hanode2"
    When    Run "crm cluster init firewalld -y" on "hanode1"
    Then    The "high-availability" firewalld service is added on "hanode1"
    Then    The "high-availability" firewalld service is added on "hanode2"

  Scenario: Verify qnetd server port
    Given   Cluster service is "started" on "hanode1"
    And     Cluster service is "started" on "hanode2"
    And     Service "firewalld" is "stopped" on "qnetd-node"
    When    Run "firewall-offline-cmd --add-port=1122/tcp" on "qnetd-node"
    When    Run "systemctl start firewalld" on "qnetd-node"
    Then    Service "firewalld" is "started" on "qnetd-node"
    When    Run "crm cluster init qdevice --qnetd-hostname=qnetd-node -y" on "hanode1"
    Then    Service "corosync-qdevice" is "started" on "hanode1"
    Then    Service "corosync-qdevice" is "started" on "hanode2"
    Then    Service "corosync-qnetd" is "started" on "qnetd-node"
    Then    Port "5403" protocol "tcp" is opened on "qnetd-node"
