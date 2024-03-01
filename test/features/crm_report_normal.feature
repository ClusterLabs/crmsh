@crm_report
Feature: crm report functional test for common cases

  Tag @clean means need to stop cluster service if the service is available
  Need nodes: hanode1 hanode2 hanode3

  Background: Setup a two nodes cluster
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Show cluster status on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    And     Show cluster status on "hanode1"

  @clean
  Scenario: crm report collect trace ra log
    When    Run "crm configure primitive d Dummy" on "hanode1"
    And     Run "crm configure primitive d2 Dummy" on "hanode1"
    Then    Resource "d" is started on "hanode1"
    And     Resource "d2" is started on "hanode2"
    When    Run "crm resource trace d monitor" on "hanode1"
    Then    Expected "Trace for d:monitor is written to /var/lib/heartbeat/trace_ra/Dummy" in stdout
    When    Wait "10" seconds
    And     Run "crm resource untrace d" on "hanode1"
    And     Run "crm resource trace d2 monitor /trace_d" on "hanode1"
    Then    Expected "Trace for d2:monitor is written to /trace_d/Dummy" in stdout
    When    Wait "10" seconds
    And     Run "crm resource untrace d2" on "hanode1"
    And     Run "crm report report" on "hanode1"
    Then    No crmsh tracebacks
    Then    Directory "trace_ra" in "report.tar.bz2"
    And     Directory "trace_d" in "report.tar.bz2"
    When    Run "rm -rf report.tar.bz2 report" on "hanode1"

  @clean
  Scenario: Run history and script
    When    Run "crm history info" on "hanode1"
    When    Run "crm history refresh" on "hanode1"
    When    Try "crm history peinputs|grep "pengine/pe-input-0""
    Then    Expected return code is "0"
    When    Try "crm history info|grep "Nodes: hanode1 hanode2""
    Then    Expected return code is "0"
    When    Run "crm configure primitive d100 Dummy" on "hanode1"
    When    Run "crm history refresh force" on "hanode1"
    When    Try "crm history info|grep "Resources: d100""
    Then    Expected return code is "0"
    Given   Cluster service is "stopped" on "hanode3"
    When    Run "crm cluster join -c hanode1 -y" on "hanode3"
    Then    Cluster service is "started" on "hanode3"
    When    Run "crm history refresh force" on "hanode1"
    When    Try "crm history info|grep "Nodes: hanode1 hanode2 hanode3""
    Then    Expected return code is "0"
    When    Run "crm script run health" on "hanode1"
    When    Run "crm script run virtual-ip id=vip_x ip=@vip.0" on "hanode1"
    Then    Resource "vip_x" type "IPaddr2" is "Started"

  @clean
  Scenario: Common tests
    When    Run "crm report -h" on "hanode1"

    When    Try "crm report "*s"" on "hanode1"
    Then    Expected "*s is invalid file name" in stderr

    When    Try "crm report /fsf/report" on "hanode1"
    Then    Expected "Directory /fsf does not exist" in stderr

    When    Try "crm report -n fs" on "hanode1"
    Then    Expected "host "fs" is unreachable:" in stderr

    When    Try "crm report -f xxxx" on "hanode1"
    Then    Expected "Invalid time string 'xxxx'" in stderr

    When    Try "crm report -f 1d -t 2d" on "hanode1"
    Then    Expected "The start time must be before the finish time" in stderr

    When    Run "crm -d report -S -d /tmp/report" on "hanode1"
    Then    Directory "/tmp/report/hanode1" created
    Then    Directory "/tmp/report/hanode2" not created
    When    Run "rm -rf /tmp/report" on "hanode1"

    When    Run "crm report -vv" on "hanode1"
    Then    Default crm_report tar file created
    When    Remove default crm_report tar file

    When    Run "crm report -d /tmp/report" on "hanode1"
    Then    Directory "/tmp/report" created
    When    Try "crm report -d /tmp/report" on "hanode1"
    Then    Expected "Destination directory /tmp/report exists, please cleanup or use -Z option" in stderr
    When    Run "crm report -d -Z /tmp/report" on "hanode1"
    Then    Directory "/tmp/report" created

    When    Run "mv /etc/corosync/corosync.conf /etc/corosync/corosync.bak" on "hanode1"
    When    Try "crm report" on "hanode1"
    Then    Expected "File /etc/corosync/corosync.conf does not exist" in stderr
    When    Run "mv /etc/corosync/corosync.bak /etc/corosync/corosync.conf" on "hanode1"

    When    Run "mv /var/lib/pacemaker/pengine /var/lib/pacemaker/pengine_bak" on "hanode1"
    When    Try "crm report" on "hanode1"
    Then    Expected "Cannot find PE directory" in stderr
    When    Run "mv /var/lib/pacemaker/pengine_bak /var/lib/pacemaker/pengine" on "hanode1"

    When    Run "crm cluster stop --all" on "hanode1"
    When    Run "rm -f /var/lib/pacemaker/cib/cib*" on "hanode1"
    When    Run "rm -f /var/lib/pacemaker/cib/cib*" on "hanode2"
    When    Run "crm report" OK
