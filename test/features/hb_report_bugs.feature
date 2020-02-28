@hb_report
Feature: Verify hb_report bugs

  Tag @clean means need to stop cluster service if the service is available

  Background: Setup a two nodes cluster
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y --no-overwrite-sshkey" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"

  @clean
  Scenario: Collect corosync's log correctly (bsc#1148874)
    When    Run "hb_report report1" on "hanode1"
    Then    File "corosync.log" not in "report1.tar.bz2"
    When    Run "rm -f report1.tar.bz2" on "hanode1"
    And     Run "crm cluster stop" on "hanode1"
    And     Run "crm corosync set logging.to_logfile yes" on "hanode1"
    And     Run "crm cluster start; sleep 60" on "hanode1"
    And     Run "hb_report report1" on "hanode1"
    Then    File "corosync.log" in "report1.tar.bz2"
    When    Run "rm -f report1.tar.bz2" on "hanode1"

  @clean
  Scenario: Collect /var/log/messages correctly (bsc#1148873)
    When    Run "hb_report report1" on "hanode1"
    Then    File "messages" not in "report1.tar.bz2"
    When    Run "rm -f report1.tar.bz2" on "hanode1"
    And     Write multi lines to file "/var/log/messages"
      """
      Feb 01 10:32:31 node1 line1
      Feb 05 12:00:27 node1 line2
      Feb 10 13:09:00 node1 line3
      """
    And     Run "hb_report -f Feb01 -t Feb11 report1" on "hanode1"
    Then    File "messages" in "report1.tar.bz2"
    When    Run "rm -f report1.tar.bz2" on "hanode1"

  @clean
  Scenario: crm report doesn't run if corosync.conf doesn't exist (bsc#1067456)
    When    Run "rm -f /etc/corosync/corosync.conf" on "hanode1"
    And     Run "rm -f /etc/corosync/corosync.conf" on "hanode2"
    And     Run "hb_report" on "hanode1"
    Then    Default hb_report tar file created
    When    Remove default hb_report tar file

  @clean
  Scenario: Unknown string format cause warnings (bsc#1077553)
    When    Write multi lines to file "/var/log/irregular_file"
      """
      test fsdfsd node1 line1
      tesfsdjlljfdsjfakjf node1 line2
      sfadhafdj node1 line3
      """
    And     Run "hb_report -E /var/log/irregular_file report1" on "hanode1"
    Then    Expected multiple lines not in output
      """
      ERROR: parse_time /var/log/messages: Unknown string format
      ERROR: parse_time /var/log/messages: Unknown string format
      ERROR: parse_time /var/log/messages: Unknown string format
      """
    Then    File "irregular_file" in "report1.tar.bz2"
    When    Run "rm -f report1.tar.gz" on "hanode1"

  @clean
  Scenario: Get node's status flag file correctly (bsc#1106052)
    When    Run "hb_report report1" on "hanode1"
    Then    File "STOPPED" not in "report1.tar.bz2"
    And     File "RUNNING" in "report1.tar.bz2"
    When    Run "rm -f report1.tar.gz" on "hanode1"
    And     Run "crm cluster stop" on "hanode1"
    And     Run "crm cluster stop" on "hanode2"
    When    Run "hb_report report1" on "hanode1"
    Then    File "STOPPED" in "report1.tar.bz2"
    And     File "RUNNING" not in "report1.tar.bz2"
    When    Run "rm -f report1.tar.gz" on "hanode1"

  @clean
  Scenario: analysis.txt should include warning/error/critical messages (bsc#1135696)
    When    Run "hb_report report1" on "hanode1"
    Then    File "analysis.txt" in "report1.tar.bz2"
    When    Run "tar jxf report1.tar.bz2" on "hanode1"
    And     Try "grep -E " warning:| error:| critical:" report1/analysis.txt"
    Then    Expected return code is "0"
    When    Run "rm -rf report1.tar.gz report1" on "hanode1"

  @clean
  Scenario: Verify hb_report handle files contain non-utf-8 characters (bsc#1130715)
    When    Run "echo 'abc#$%%^' | iconv -f UTF-8 -t UTF-16 > /opt/text_non_utf8" on "hanode1"
    And     Run "hb_report -E /opt/text_non_utf8 report1" on "hanode1"
    Then    File "text_non_utf8" in "report1.tar.bz2"
    When    Run "rm -f report1.tar.bz2" on "hanode1"

  @clean
  Scenario: Verify hb_report replace sensitive info (bsc#1163581)
    When    Run "crm configure primitive id=d Dummy meta passwd="sdfgtie49382xxx"" on "hanode1"
    And     Run "hb_report report" on "hanode1"
    Then    Expected multiple lines in output
      """
      WARNING: hanode1#Collector: Some PE/CIB/log files contain possibly sensitive data
      WARNING: hanode1#Collector: Using "-s" option can replace sensitive data
      """
    When    Run "tar jxf report.tar.bz2" on "hanode1"
    And     Try "grep -R "sdfgtie49382xx" report"
    Then    Expected return code is "0"

    When    Run "rm -rf report.tar.bz2 report" on "hanode1"
    And     Run "hb_report -s report" on "hanode1"
    Then    Expected multiple lines not in output
      """
      WARNING: hanode1#Collector: Some PE/CIB/log files contain possibly sensitive data
      WARNING: hanode1#Collector: Using "-s" option can replace sensitive data
      """
    When    Run "tar jxf report.tar.bz2" on "hanode1"
    And     Try "grep -R "sdfgtie49382xx" report"
    Then    Expected return code is "1"
    When    Run "rm -rf report.tar.bz2 report" on "hanode1"
