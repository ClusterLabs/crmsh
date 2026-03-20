@sbd
Feature: Deprecated terms check and translate

  Need nodes: hanode1 hanode2

  Scenario: Give warnings when query/set with deprecated properties
    Given   Has disk "/dev/sda5" on "hanode1"
    Given   Has disk "/dev/sda5" on "hanode2"
    Given   Nodes ["hanode1", "hanode2"] are cleaned up
    And     Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Online nodes are "hanode1 hanode2"
    And     Show cluster status on "hanode1"
    When    Run "crm cluster init sbd -s /dev/sda5 -y" on "hanode1"
    Then    Service "sbd" is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode2"
    And     Resource "fencing-sbd" type "fence_sbd" is "Started"
    Then    Cluster property "fencing-timeout" is "71"
    And     Cluster property "stonith-timeout" is not configured

    # query deprecated property when only the new property is configured
    When    Run "crm configure get_property stonith-timeout" on "hanode1"
    Then    Expected ""stonith-timeout" is deprecated and not configured but "fencing-timeout" is; Cluster now is using the new property, instead of the default value of "stonith-timeout"" in stderr
    # set deprecated property when only the new property is configured
    When    Run "crm configure property stonith-timeout=80" on "hanode1"
    Then    Expected ""fencing-timeout" is configured; "stonith-timeout" is deprecated and ignored" in stderr
    # query deprecated property when both the new and the deprecated properties are configured
    When    Run "crm configure get_property stonith-timeout" on "hanode1"
    Then    Expected ""fencing-timeout" is configured; "stonith-timeout" is deprecated and ignored" in stderr
    # query deprecated property when only the deprecated property is configured
    When    Delete property "fencing-timeout" from cluster
    When    Run "crm configure get_property stonith-timeout" on "hanode1"
    Then    Expected ""stonith-timeout" is deprecated, please consider using "fencing-timeout"" in stderr
    # query new property when only the deprecated property is configured
    When    Run "crm configure get_property fencing-timeout" on "hanode1"
    Then    Expected ""fencing-timeout" is not configured but deprecated "stonith-timeout" is; Cluster now is using the deprecated property, instead of the default value of "fencing-timeout"" in stderr
    # set deprecated property which don't have replacement
    When    Run "crm configure property enable-startup-probes=true" on "hanode1"
    Then    Expected ""enable-startup-probes" is deprecated, please consider removing it" in stderr
    When    Delete property "enable-startup-probes" from cluster

  Scenario: Deprecated property during `crm cluster health sbd --fix`
    Then    Cluster property "stonith-timeout" is "80"
    And     Cluster property "fencing-timeout" is not configured

    # when configured value of stonith-timeout is not the expected value
    When    Run "crm cluster health sbd" on "hanode1"
    Then    Expected multiple lines in stderr
      """
      It's recommended that stonith-timeout is set to 71, now is 80
      "stonith-timeout" is deprecated, please consider using "fencing-timeout"
      """
    # --fix still keep stonith-timeout name after fixed
    When    Run "crm cluster health sbd --fix" on "hanode1"
    Then    Expected multiple lines in stderr
      """
      "stonith-timeout" in crm_config is set to 71, it was 80
      "stonith-timeout" is deprecated, please consider using "fencing-timeout"
      """
    Then    Cluster property "stonith-timeout" is "71"
    And     Cluster property "fencing-timeout" is not configured

    When    Run "crm configure show" on "hanode1"
    Then    Expected ""stonith-timeout" is deprecated, please consider using "fencing-timeout" in stderr

  Scenario: SBD purge
    When    Run "crm configure property fencing-timeout=80" on "hanode1"
    Then    Cluster property "fencing-timeout" is "80"
    When    Run "crm sbd purge" on "hanode1"
    Then    Expected multiple lines in output
      """
      Delete cluster property "stonith-timeout" in crm_config
      Delete cluster property "fencing-timeout" in crm_config
      """
    And     Cluster property "stonith-timeout" is not configured
    And     Cluster property "fencing-timeout" is not configured
