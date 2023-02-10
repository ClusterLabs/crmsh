@user
Feature: Functional test for user access

  Need nodes: hanode1

  Scenario: User in haclient group
    Given   Cluster service is "stopped" on "hanode1"
    When    Run "useradd -m -s /bin/bash -N -g 90 xin1" on "hanode1"
    When    Try "su xin1 -c 'crm cluster init -y'"
    Then    Except multiple lines
      """
      ERROR: Please run this command starting with "sudo".
      Currently, this command needs to use sudo to escalate itself as root.
      Please consider to add "xin1" as sudoer. For example:
        sudo bash -c 'echo "xin1 ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/xin1'
      """
    When    Run "echo "xin1 ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/xin1" on "hanode1"
    When    Try "su xin1 -c 'crm cluster init -y'"
    Then    Except multiple lines
      """
      ERROR: Please run this command starting with "sudo"
      """
    When    Run "su xin1 -c 'sudo crm cluster init -y'" on "hanode1"
    Then    Cluster service is "started" on "hanode1"

    When    Run "useradd -m -s /bin/bash -N -g 90 xin2" on "hanode1"
    When    Run "su xin2 -c 'crm node standby hanode1'" on "hanode1"
    Then    Node "hanode1" is standby

  @clean
  Scenario: User in sudoer
    Given   Cluster service is "stopped" on "hanode1"
    When    Run "useradd -m -s /bin/bash xin3" on "hanode1"
    And     Run "echo "xin3 ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/xin3" on "hanode1"
    When    Try "su xin3 -c 'crm cluster init -y'"
    Then    Except multiple lines
      """
      WARNING: Failed to open log file: [Errno 13] Permission denied: '/var/log/crmsh/crmsh.log'
      ERROR: Please run this command starting with "sudo"
      """
    When    Run "su xin3 -c 'sudo crm cluster init -y'" on "hanode1"
    Then    Cluster service is "started" on "hanode1"

    When    Try "su xin3 -c 'crm node standby hanode1'"
    Then    Except multiple lines
      """
      WARNING: Failed to open log file: [Errno 13] Permission denied: '/var/log/crmsh/crmsh.log'
      ERROR: Please run this command starting with "sudo"
      """
    When    Run "su xin3 -c 'sudo crm node standby hanode1'" on "hanode1"
    Then    Node "hanode1" is standby

  @clean
  Scenario: Normal user access
    Given   Cluster service is "stopped" on "hanode1"
    When    Run "useradd -m -s /bin/bash user1" on "hanode1"
    When    Try "su user1 -c 'crm cluster init -y'"
    Then    Except multiple lines
      """
      WARNING: Failed to open log file: [Errno 13] Permission denied: '/var/log/crmsh/crmsh.log'
      ERROR: Please run this command starting with "sudo".
      Currently, this command needs to use sudo to escalate itself as root.
      Please consider to add "user1" as sudoer. For example:
        sudo bash -c 'echo "user1 ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/user1'
      """
    When    Run "echo "user1 ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/user1" on "hanode1"
    When    Try "su user1 -c 'crm cluster init -y'"
    Then    Except multiple lines
      """
      WARNING: Failed to open log file: [Errno 13] Permission denied: '/var/log/crmsh/crmsh.log'
      ERROR: Please run this command starting with "sudo"
      """
    When    Run "su user1 -c 'sudo crm cluster init -y'" on "hanode1"
    Then    Cluster service is "started" on "hanode1"

    When    Run "useradd -m -s /bin/bash user2" on "hanode1"
    When    Try "su user2 -c 'crm node standby hanode1'"
    Then    Except multiple lines
      """
      WARNING: Failed to open log file: [Errno 13] Permission denied: '/var/log/crmsh/crmsh.log'
      ERROR: This command needs higher privilege.
      Option 1) Please consider to add "user2" as sudoer. For example:
        sudo bash -c 'echo "user2 ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/user2'
      Option 2) Add "user2" to the haclient group. For example:
        sudo usermod -g haclient user2
      """
    When    Run "usermod -g haclient user2" on "hanode1"
    When    Run "su user2 -c 'crm node standby hanode1'" on "hanode1"
    Then    Node "hanode1" is standby

    When    Run "useradd -m -s /bin/bash user3" on "hanode1"
    When    Try "su user3 -c 'crm node online hanode1'"
    Then    Except multiple lines
      """
      WARNING: Failed to open log file: [Errno 13] Permission denied: '/var/log/crmsh/crmsh.log'
      ERROR: This command needs higher privilege.
      Option 1) Please consider to add "user3" as sudoer. For example:
        sudo bash -c 'echo "user3 ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/user3'
      Option 2) Add "user3" to the haclient group. For example:
        sudo usermod -g haclient user3
      """
    When    Run "echo "user3 ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/user3" on "hanode1"
    When    Try "su user3 -c 'crm node online hanode1'"
    Then    Except multiple lines
      """
      WARNING: Failed to open log file: [Errno 13] Permission denied: '/var/log/crmsh/crmsh.log'
      ERROR: Please run this command starting with "sudo"
      """
    When    Run "su user3 -c 'sudo crm node online hanode1'" on "hanode1"
    Then    Node "hanode1" is online
