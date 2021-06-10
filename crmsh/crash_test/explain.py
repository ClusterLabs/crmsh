contents = {}

contents["sbd"]= '''On {nodeA}, once the sbd process get killed, there are two situations:
  a) sbd process restarted
     Systemd will restart sbd service immediately.
     Restarting sbd service will also lead to restart corosync and pacemaker services because of the pre-defined dependencies among the systemd unit files.

  b) {nodeA} experience the watchdog fencing
     There is the race condition with the watchdog timer. Watchdog might reset {nodeA}, just before the sbd service get restarted and not tickle the watchdog timer in time.'''

contents["sbd-l"] = '''On {nodeA}, the sbd service is killed consistantly all the time. 
Very quickly, systemd will hit the start limit to restart sbd service. 
Basically, in the end, systemd stops restarting anymore, marks the sbd service as failure.
{nodeB} sbd cluster health check marks it as "UNHEALTHY".
{nodeB} treats {nodeA} as a node lost, and fences it in the end.'''

contents["corosync"] = '''On {nodeA}, once the corosync process get killed, systemd will restart corosync service immediately. There are two situations:
  a) corosync process restarts
     {nodeA} corosync process get restarted and rejoins to the existent membership quickly enough.
     Basically, it happens before {nodeB} treats it as a node lost.
     In the end, the cluster looks like nothing happened to the user. RA stays safe and sound.

  b) {nodeA} gets fenced
     {nodeA} gets fenced since {nodeB} corosync just ran out of timeout and treat it as a node lost and forms a new membership.
     The decision making process of {nodeB}, pengine(aka. schedulerd in Pacemaker 2), will initiate fence action against {nodeA}. '''

contents["corosync-l"] = '''The corosync service is killed consistantly all the time.
Very quickly, systemd will hit the start limit to restart corosync service.
Basically, in the end, systemd stops restarting anymore, marks the corosync service as failure. {nodeB} treats {nodeA} as a node lost, marks it as "unclean", and fence it in the end.'''

contents["pacemakerd"] = '''The pacemakerd process gets restarted by systemd. All RAs must stay intact.'''
