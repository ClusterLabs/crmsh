#Descriptions
This directory include hb_report all the codes(implement with python). There are three classed, one environment variable configure and one lib. The following documents explain these files.

#Explainations
##master.py

The defination of master class, when user use the hb_report command, in the crm report script, some secure things is done, then crm script call master_node run function. Master do all things  master node should do, like decide to which log is collected, check ssh connections and so on.
### class master
####MEMBER VARABLES
* PIDS: master create new processes to collect logs, master should wait those processes exit. PIDS stores those processes' pid
####MEMBER FUNCTIONS
* version: print hb_report version information
* usage: print help message
* analyzed_argvment: analyze parameters user input
* cts_findlogseg: base on CTS time to find log segment
* analyzed: analyzed logs are collected
* start_slave_collect: ssh to collector node and excute hb_report script
* event:
* check_if_log_empty: master check logs that is collected is empty
* final_word: print final work
* send_env: master get environment and logs name need to be collected, create xmlfile, then call send_env scp xmlfile to collector /tmp.
* get_user_node_cts: TODO
* get_cts_log: TODO
* is_member: find user node is cluster member or not
##collector.py
The defination of collector class, this is a simple class, do collect log things and send the resule to master node.
###class collector
##node.py
The defination of node class, it is the father class of master and slave class, abstract some common features about the subclass.
###class node
##envir.py
This is environment variable configure file, all the  variable is needed during the hb_report run.Kind of important
###ENVIRONMENT VERABLES
##utillib.py
This is functions library.
###FUNCTIONS
##corosync_conf_support.py
This is the corosync cluster support script, this script implement some unique function for corosync cluster
###FUNCTIIONS
##ha_cf_support.py
This script just like corosync_conf_support.py, but this script for heartbeat cluster
###FUNCTIONS
##hb_report
This is hb_report entry script.
