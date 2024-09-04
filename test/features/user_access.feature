@user
Feature: Functional test for user access

  Need nodes: hanode1

  Scenario: User in haclient group
    Given   Cluster service is "stopped" on "hanode1"
    When    Run "useradd -m -s /bin/bash -N -g haclient xin1" on "hanode1"
    When    Run "echo 'export PATH=$PATH:/usr/sbin/' >> ~xin1/.bashrc" on "hanode1"
    When    Run "echo "xin1 ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/xin1" on "hanode1"
    When    Run "su - xin1 -c 'sudo crm cluster init -y'" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Run "su - hacluster -c 'crm script run health'" OK on "hanode1"
    When    Run "su - xin1 -c 'crm node standby hanode1'" on "hanode1"
    Then    Node "hanode1" is standby

  @clean
  Scenario: User in sudoer
    Given   Cluster service is "stopped" on "hanode1"
    When    Run "useradd -m -s /bin/bash xin3" on "hanode1"
    When    Run "echo 'export PATH=$PATH:/usr/sbin/' >> ~xin3/.bashrc" on "hanode1"
    And     Run "echo "xin3 ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/xin3" on "hanode1"
    When    Try "su - xin3 -c 'crm cluster init -y'"
    Then    Except multiple lines
      """
      WARNING: Failed to open log file: [Errno 13] Permission denied: '/var/log/crmsh/crmsh.log'
      ERROR: Please run this command starting with "sudo"
      """
    When    Run "su - xin3 -c 'sudo crm cluster init -y'" on "hanode1"
    Then    Cluster service is "started" on "hanode1"

    When    Try "su - xin3 -c 'crm node standby hanode1'"
    Then    Except multiple lines
      """
      WARNING: Failed to open log file: [Errno 13] Permission denied: '/var/log/crmsh/crmsh.log'
      ERROR: Please run this command starting with "sudo"
      """
    When    Run "su - xin3 -c 'sudo crm node standby hanode1'" on "hanode1"
    Then    Node "hanode1" is standby

  @clean
  Scenario: Normal user access
    Given   Cluster service is "stopped" on "hanode1"
    When    Run "useradd -m -s /bin/bash user1" on "hanode1"
    When    Run "echo 'export PATH=$PATH:/usr/sbin/' >> ~user1/.bashrc" on "hanode1"
    When    Try "su - user1 -c 'crm cluster init -y'"
    Then    Except multiple lines
      """
      WARNING: Failed to open log file: [Errno 13] Permission denied: '/var/log/crmsh/crmsh.log'
      ERROR: Operation is denied. The current user lacks the necessary privilege.
      """
    When    Run "echo "user1 ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/user1" on "hanode1"
    When    Try "su - user1 -c 'crm cluster init -y'"
    Then    Except multiple lines
      """
      WARNING: Failed to open log file: [Errno 13] Permission denied: '/var/log/crmsh/crmsh.log'
      ERROR: Please run this command starting with "sudo"
      """
    When    Run "su - user1 -c 'sudo crm cluster init -y'" on "hanode1"
    Then    Cluster service is "started" on "hanode1"

    When    Run "useradd -m -s /bin/bash user2" on "hanode1"
    When    Run "echo 'export PATH=$PATH:/usr/sbin/' >> ~user2/.bashrc" on "hanode1"
    When    Try "su - user2 -c 'crm node standby hanode1'"
    Then    Except multiple lines
      """
      WARNING: Failed to open log file: [Errno 13] Permission denied: '/var/log/crmsh/crmsh.log'
      ERROR: Operation is denied. The current user lacks the necessary privilege.
      """
    When    Run "usermod -g haclient user2" on "hanode1"
    When    Run "su - user2 -c 'crm node standby hanode1'" on "hanode1"
    Then    Node "hanode1" is standby

    When    Run "useradd -m -s /bin/bash user3" on "hanode1"
    When    Run "echo 'export PATH=$PATH:/usr/sbin/' >> ~user3/.bashrc" on "hanode1"
    When    Try "su - user3 -c 'crm node online hanode1'"
    Then    Except multiple lines
      """
      WARNING: Failed to open log file: [Errno 13] Permission denied: '/var/log/crmsh/crmsh.log'
      ERROR: Operation is denied. The current user lacks the necessary privilege.
      """
    When    Run "echo "user3 ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/user3" on "hanode1"
    When    Try "su - user3 -c 'crm node online hanode1'"
    Then    Except multiple lines
      """
      WARNING: Failed to open log file: [Errno 13] Permission denied: '/var/log/crmsh/crmsh.log'
      ERROR: Please run this command starting with "sudo"
      """
    When    Run "su - user3 -c 'sudo crm node online hanode1'" on "hanode1"
    Then    Node "hanode1" is online
