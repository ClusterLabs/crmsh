@hb_report
Feature: hb_report functional test

  Tag @clean means need to stop cluster service if the service is available

  @clean
  Scenario: Verify hb_report options
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"

    When    Run "hb_report" on "hanode1"
    Then    Default hb_report tar file created
    When    Remove default hb_report tar file

    @clean
    Scenario: Include archived logs(bsc#1148873)
    When    Write multi lines to file "/var/log/log1"
      """
      Sep 08 08:36:34 node1 log message line1
      Sep 08 08:37:01 node1 log message line2
      Sep 08 08:37:02 node1 log message line3
      """
    And     Run "xz /var/log/log1" on "hanode1"
    When    Write multi lines to file "/var/log/log1"
      """
      Sep 08 09:37:02 node1 log message line4
      Sep 08 09:37:12 node1 log message line5
      """
    And     Run "hb_report -f 20200901 -E /var/log/log1 report1" on "hanode1"
    Then    File "log1" in "report1.tar.bz2"
    When    Run "tar jxf report1.tar.bz2" on "hanode1"
    And     Run "cat report1/hanode1/log1" on "hanode1"
    Then    Expected multiple lines in output
      """
      Sep 08 08:36:34 node1 log message line1
      Sep 08 08:37:01 node1 log message line2
      Sep 08 08:37:02 node1 log message line3
      Sep 08 09:37:02 node1 log message line4
      Sep 08 09:37:12 node1 log message line5
      """
    When    Run "rm -rf report1.tar.gz report1" on "hanode1"
