## What is preflight check?
Preflight check tool set provides many generic tests to verify some key configuration before you move your cluster into production. It tries to provide suggestion for the suspicious configuration based on each check, even help to change the configuration if the end user agree so.

It standardizes some complex tests, ie, to simulate cluster failures. They are carefully designed since the methods can be different and could be incorrect and go wild. They intend to not change any persistent configuration to harm the cluster without the confirmation from users.

## How to use it?
#### Help information
```Shell
# crm analyze preflight_check -h
usage: preflight_check [-c]
                       [--kill-sbd | --kill-corosync | --kill-pacemakerd | --fence-node NODE | --split-brain-iptables]
                       [-l] [-y] [-h]

Cluster preflight check tool set

optional arguments:
  -c, --check-conf        Validate the configurations
  --kill-sbd              Kill sbd daemon
  --kill-corosync         Kill corosync daemon
  --kill-pacemakerd       Kill pacemakerd daemon
  --fence-node NODE       Fence specific node
  --split-brain-iptables  Make split brain by blocking corosync ports
  -l, --kill-loop         Kill process in loop

other options:
  -y, --yes               Answer "yes" if asked to run the test
  -h, --help              Show this help message and exit

Log: /var/log/crmsh/preflight_check.log
Json results: /var/lib/crmsh/preflight_check/preflight_check.json
For each --kill-* testcase, report directory: /var/lib/crmsh/preflight_check
```
#### Basic status checking
```Shell
# crm analyze preflight_check 

============ Checking cluster state ============
[2021/03/09 13:49:51]INFO: Checking cluster service [Pass]
  INFO: pacemaker.service is enabled
  INFO: corosync.service is running
  INFO: pacemaker.service is running
[2021/03/09 13:49:51]INFO: Checking STONITH/Fence [Pass]
  INFO: stonith is enabled
  INFO: stonith resource stonith-sbd(external/sbd) is configured
  INFO: stonith resource stonith-sbd(external/sbd) is Started
  INFO: sbd service is running
[2021/03/09 13:49:52]INFO: Checking nodes [Pass]
  INFO: DC node: node1
  INFO: Cluster have quorum
  INFO: Online nodes: [ node1 node2 ]
[2021/03/09 13:49:52]INFO: Checking resources [Pass]
  INFO: Started resources: stonith-sbd,vip
```
* Planned check item collections
- [x] Checking cluster service status
- [x] Checking STONITH/Fence status
- [x] Checking nodes
- [x] Checking resources
- [ ] Check nic's MTU used by corosync, should large than totem.netmtu(1500)
- [ ] Check rrp mode is passive
- [ ] Check whether using non-exist IP
- [ ] Check sbd device have the same UUID between nodes
- [ ] Validate corosync.conf
- [ ] Should warning if two corosync communicate IPs are in the same NIC
- [ ] Check if sbd service between nodes are all enabled

#### Kill process
```Shell
# crm analyze preflight_check --kill-sbd

==============================================
Testcase:          Force kill sbd
Looping Kill:      False
Expected State:    a) sbd process restarted
                   b) Or, this node fenced.

Run (y/n)? y
(Report: /var/lib/crmsh/preflight_check/preflight_check-20210309-1615269167.report)
[2021/03/09 13:52:48]INFO: Process sbd(2289) is running...
[2021/03/09 13:52:48]INFO: Trying to run "killall -9 sbd"
[2021/03/09 13:52:50]INFO: Process sbd(3212) is restarted!
```
#### Fence node
```Shell
# crm analyze preflight_check --fence-node node2

==============================================
Testcase:          Fence node node2
Fence action:      reboot
Fence timeout:     60

Run (y/n)? y
[2021/03/09 13:54:17]INFO: Trying to fence node "node2"
[2021/03/09 13:54:17]INFO: Waiting 60s for node "node2" reboot...
[2021/03/09 13:54:17]INFO: Node "node2" will be fenced by "node2"!
[2021/03/09 13:54:32]INFO: Node "node2" was successfully fenced by "node2"
```
#### Make split brain
```Shell
# crm analyze preflight_check --split-brain-iptables

==============================================
Testcase:          Simulate split brain by blocking corosync ports
Expected Result:   One of nodes get fenced
Fence action:      reboot
Fence timeout:     60

Run (y/n)? y
[2021/03/09 13:55:30]INFO: Trying to temporarily block node2 communication ip
[2021/03/09 13:55:43]INFO: Node "node2" will be fenced by "node1"!
[2021/03/09 13:56:08]INFO: Node "node2" was successfully fenced by "node1"
[2021/03/09 13:56:08]INFO: Trying to recover node2 communication ip
```
#### Good unit test coverage
```
/home/runner/work/crmsh/crmsh/preflight_check/__init__.py                                         0      0   100%
/home/runner/work/crmsh/crmsh/preflight_check/check.py                                          189      3    98%
/home/runner/work/crmsh/crmsh/preflight_check/config.py                                           8      0   100%
/home/runner/work/crmsh/crmsh/preflight_check/explain.py                                          6      0   100%
/home/runner/work/crmsh/crmsh/preflight_check/main.py                                           129      1    99%
/home/runner/work/crmsh/crmsh/preflight_check/task.py                                           366      2    99%
/home/runner/work/crmsh/crmsh/preflight_check/utils.py                                          171      9    95%
```
## RPM link
https://build.opensuse.org/package/show/network:ha-clustering:Factory/crmsh
