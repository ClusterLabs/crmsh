# Copyright (C) 2016 Shiwen Zhang <szhang@suse.de>
# See COPYING for license information.

import	os
import	datetime
import	sys
import	getopt
import	envir
import	socket
import	utillib
import	subprocess
import	collector
import	paramiko
import	tempfile
import	tarfile

from crmsh	import logtime
from crmsh	import utils
from crmsh	import logparser
from node	import node
from multiprocessing import Process

class master(node):
	SUDO = ''
	LOCAL_SUDO = ''
	COLLECTOR_PIDS =[]

	def version(self):
		print "crmsh: 2.2.0+git.1464769043.9e4df55"
		sys.exit

	def usage(self,msg = ''):
		print '''usage: report -f {time|"cts:"testnum} [-t time]
       [-u user] [-X ssh-options] [-l file] [-n nodes] [-E files]
       [-p patt] [-L patt] [-e prog] [-MSDZAQVsvhd] [dest]

	-f time: time to start from or a CTS test number
	-t time: time to finish at (dflt: now)
	-s	   : do sanitize
	-d     : don't compress, but leave result in a directory
	-n nodes: node names for this cluster; this option is additive
			 (use either -n "a b" or -n a -n b)
	         if you run report on the loghost or use autojoin,
	         it is highly recommended to set this option
	-u user: ssh user to access other nodes (dflt: empty, root, hacluster)
	-X ssh-options: extra ssh(1) options
	-l file: log file
	-E file: extra logs to collect; this option is additive
	         (dflt: /var/log/messages)
	-s     : sanitize the PE and CIB files
	-p patt: regular expression to match variables containing sensitive data;
	         this option is additive (dflt: "passw.*")
	-L patt: regular expression to match in log files for analysis;
	         this option is additive (dflt: $LOG_PATTERNS)
	-e prog: your favourite editor
	-Q     : don't run resource intensive operations (speed up)
	-M     : don't collect extra logs (/var/log/messages)
	-D     : don't invoke editor to write description
	-Z     : if destination directories exist, remove them instead of exiting
	         (this is default for CTS)
	-S     : single node operation; don't try to start report
	         collectors on other nodes
	-v     : increase verbosity
	-V     : print version
	dest   : report name (may include path where to store the report)
		'''
		if msg != "short":
			print '''

	. the multifile output is stored in a tarball {dest}.tar.bz2
	. the time specification is as in either Date::Parse or
	  Date::Manip, whatever you have installed; Date::Parse is
	  preferred
	. we try to figure where is the logfile; if we can't, please
	  clue us in ('-l')
	. we collect only one logfile and /var/log/messages; if you
	  have more than one logfile, then use '-E' option to supply
	  as many as you want ('-M' empties the list)

	Examples

	  report -f 2pm report_1
	  report -f "2007/9/5 12:30" -t "2007/9/5 14:00" report_2
	  report -f 1:00 -t 3:00 -l /var/log/cluster/ha-debug report_3
	  report -f "09sep07 2:00" -u hbadmin report_4
	  report -f 18:00 -p "usern.*" -p "admin.*" report_5
	  report -f cts:133 ctstest_133

	. WARNING . WARNING . WARNING . WARNING . WARNING . WARNING .

	  We won't sanitize the CIB and the peinputs files, because
	  that would make them useless when trying to reproduce the
	  PE behaviour. You may still choose to obliterate sensitive
	  information if you use the -s and -p options, but in that
	  case the support may be lacking as well. The logs and the
	  crm_mon, ccm_tool, and crm_verify output are *not* sanitized.

	  Additional system logs (/var/log/messages) are collected in
	  order to have a more complete report. If you don't want that
	  specify -M.

	  IT IS YOUR RESPONSIBILITY TO PROTECT THE DATA FROM EXPOSURE!

			'''
		sys.exit(1)


	def analyzed_argvment(self,argv):
#		if len(argv) < 2:
#			self.usage()
		if  '-f' not in argv:
			self.usage('short')

		try:
			opt,arg = getopt.getopt(sys.argv[1:],"hsQSDCZMAvdf:t:n:u:X:l:e:p:L:E:")
			if(len(arg)>1):
				self.usage("short")
				sys.exit()

			if(len(arg) == 1):
				envir.DEST = arg
			for args,option in opt:
				if (args == '-f'):
					envir.FROM_TIME = self.change_to_timestamp(option)
				if (args == '-t'):
					envir.TO_TIME  = self.change_to_timestamp(option)
				if (args == '-n'):
					envir.NODE_SOURCE = 'user'
					for i in option.split(' '):
						envir.USER_NODES.append(i)
				if (args == '-h'):
					self.usage()
				if (args == '-u'):
					envir.SSH_USER.append(option)
				if (args == '-X'):
					envir.SSH_OPTS = envir.SSH_OPTS+option
				if (args == '-l'):
					envir.HA_LOG = option
				if(args == '-e'):
					envir.EDITOR = option
				if(args == '-p'):
					envir.SANITIZE.append(option)
				if(args == '-s'):
					envir.DO_SANITIZE = 1
				if(args == '-Q'):
					envir.SKIP_LVL = envir.SKIP_LVL + 1
				if(args == '-L'):
					envir.LOG_PATTERNS.append(option)
				if(args == '-S'):
					envir.NO_SSH = 1
				if(args == '-D'):
					envir.NO_DESCRIPTION = 1
				if(args == '-C'):
					pass
				if(args == '-Z'):
					envir.FORCE_REMOVE_DEST = 1
				if(args == '-M'):
					envir.EXTRA_LOGS = []
				if(args == '-E'):
					envir.EXTRA_LOGS.append(option)
#				if(args == '-A'):
#					envir.USER_CLUSTER_TYPE = 'openais'
				if(args == '-v'):
					envir.VERBOSITY = envir.VERBOSITY+1
				if(args == '-d'):
					envir.COMPRSS = 0
		except getopt.GetoptError:
			self.usage("short")
			envir.SSH_USER.append("root")
			envir.SSH_USER.append("hacluster")

	def cts_findlogseg(self):
		'''
		'''
		#TODO
		return 'test message'
		utillib.debug('This is cts find log function, need to be finished later!:)')
	def is_node(self):
		pass

	def find_ssh_user(self):
		pass

#	def change_to_timestamp(self,time):
#		ds = utils.parse_to_timestamp(time)
#		return ds

	def analyzed(self):
		pass

	
	def create_collector_dir(self):
		pass

	def start_slave_collector(self,nodes,port=22,username='root'):

		utillib.debug('running class collector function run to collect log on '+nodes)

		paramiko.util.log_to_file('/tmp/paramiko.log')
		client = paramiko.SSHClient()
		client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		client.connect(nodes,port,username)

		path = os.path.join(envir.CRM_PATH,'collector.py')
		utillib.debug(nodes+' collector script path :'+path)

		#need to finish the hb_report path
		stdin,stdout,stderr = client.exec_command('python ~/hb_report/hb_report __slave')
		
		print nodes,' output :',stdout.read()


	def events(self):
		pass

	def check_if_log_is_empty(self):
		pass

	def final_word(self):
		pass

	def send_env(self,nodes):
		'''
		Send envir.xml to slave node
		'''
		if not utillib.do_which('scp'):
			utillib.fatal('Cannot find scp, does it is intalled?')
		if nodes != self.WE:
			command = 'scp '+os.path.join(envir.XML_PATH,envir.XML_NAME)+' root@'+nodes+':/tmp &>/dev/null'
			ret = os.system(command)
			if ret:
				utillib.fatal(nodes+' :scp envitonment file failed, please check cluster node can ssh or not')

	def get_user_node_cts(self,ctslog):
		#TODO
		print 'This need to get cts user nodes'

	
	def get_cts_log(self):
		ctslog = utillib.findmsg('CTS: Stack:')
		debug_msg = 'Using CTS control file :'+ctslog
		utillib.debug(debug_msg)
		#TODO
#		envir.USER_NODES = self.get_user_node_cts(ctslog)
		envir.NODES_SOURCE = 'user'
		
	def is_member(self):
		'''
		Check node from node list is member or not
		need to improve 
		if func can know user input the node do not belong to cluster 
		the hb_report can output the message then exit
		envir.NODE_SOURCE can tell the func where did hv_report get node
		only from user need to check
		'''
		if envir.NODE_SOURCE != 'user':
			return 
		NODECNT = len(envir.NODE)
		if not NODECNT:
			utillib.fatal('could not figure out a list of nodes; is this a cluster node?')

	def is_node(self):
		if THIS_IS_NODE:
			return True
		return False
	
	def testsshconn(self,user):
		ret = 1
		opts = envir.SSH_OPTS
		
		command = ['ssh']
		command.extend(opts)
		command.append('-T')
		command.append('-o Batchmode=yes')
		command.append(user)
		command.append('true')

		ret = subprocess.call(command)
		if not ret:
			return True

		return False


	def findsshuser(self):
		'''
		If user not provide ssh users, then hb_report find ssh user by it self
		'''
		rc = 0

		ssh_user = '__undef'
		if not len(envir.SSH_USER):
			try_user_list = '__default '+' '.join(envir.TRY_SSH)
		else:
			try_user_list = ' '.join(envir.SSH_USER)

		#debug message
		utillib.debug('FROM FINDSSHUSER: node name is '+' '.join(envir.USER_NODES))

		for n in envir.USER_NODES:
			rc = 1
			if n == self.WE:
			# Ahh, It' me, will break!
				continue
			for u in try_user_list.split(' '):
				if u != '__default':
					ssh_s = u+'@'+n
				else:
					ssh_s = n

				if self.testsshconn(ssh_s):
					utillib.debug('ssh '+ssh_s+' OK')
					ssh_user = u
					try_ssh_list = u
					rc = 0
					break
				else:
					utillib.debug('ssh '+ssh_s+' failed')

			if rc:
				envir.SSH_PASSWD_NODES = envir.SSH_PASSWD_NODES+n

		if len(envir.SSH_PASSWD_NODES):
			utillib.warn('passwordless ssh to node(s) '+envir.SSH_PASSWD_NODES+' does not work')
		
		if ssh_user == '__undef':
			return 1
		if ssh_user != '__default':
			envir.SSH_USER = ssh_user			
			#ssh user is default
			
		return 0


def run():
	'''
	This method do most of the job that master node should do
	'''

	
	utillib.check_user()
	utillib.setvarsanddefaults()
	utillib.get_ocf_directories()

	mtr = master()
	envir.__TMPFLIST = tempfile.mkstemp()[1]
	mtr.analyzed_argvment(sys.argv)

	#who am i
	mtr.WE= socket.gethostname()
	
	#get WORKDIR
	mtr.WORKDIR = mtr.mktemp(envir.DEST)
	mtr.WORKDIR = os.path.join(mtr.WORKDIR,envir.DEST)
	envir.MASTER_WORKDIR = mtr.WORKDIR
	mtr.compabitility_pcmk()
	mtr.cluster_type()
	support=__import__(mtr.import_support())
	
	if len(envir.CTS):
		support.get_log_var()
		utillib.debug('log setting :facility = '+envir.HA_LOGFACILITY+' logfile = '+envir.HA_LOGFILE+' debug file = '+envir.HA_DEBUGFILE)
	else:
		mtr.get_cts_log()

#
#part 1:get nodes
#
	utillib.get_nodes()
	utillib.debug('nodes: '+' '.join(envir.USER_NODES))
	mtr.is_member()

	#this is node

	for n in envir.USER_NODES:
		if n == mtr.WE:
			THIS_IS_NODE = 1

	if not mtr.is_node and envir.NODE_SOUECE != 'user':
		utillib.warn('this is not a node and you didn\'t specify a list of nodes using -n')
	
#
#part 2: ssh business
#
	#find out id ssh works
	if not envir.NO_SSH:
		mtr.findsshuser()
		if len(envir.SSH_USER):
			envir.SSH_OPTS = envir.SSH_OPTS.append('-o User='+envir.SSH_USER)
#
#part 3: root things
#
	SUDO = ''
	euid = os.geteuid()
	if not len(envir.SSH_USER) and euid != 0:
		utillib.debug('ssh user other than root, use sudo')
		SUDO = 'sudo -u root'

	LOCAL_SUDO = ''
	if not euid:
		utillib.debug('local user ither than root, use sudo')
		LOCAL_SUDO = 'sudo -u root'
	
#
#part 4: find the logs and cut out the segment for the period
#
	if THIS_IS_NODE:
		mtr.getlog()
	
	#create xml before collect
	utillib.creat_xml()
	
	#then scp the file to collector
	for n in envir.USER_NODES:

		p = Process(target=mtr.send_env,args=(n,))
		p.start()

	if not envir.NO_SSH:
		mtr.collect_for_nodes(envir.USER_NODES)
	elif is_node:
		mtr.collecct_for_nodes([mtr.WE])

#
#part 5: endgame:
#		 slaves  tar their result to stdout, the master wait
#		 for them, analyses result, asks the user to edit the
#		 problem description template, and print final words
#

	p = Process()
	print 'master workdir is ',mtr.WORKDIR

#try:
run()
#except OSError as msg:
#	print 'Get an Error',msg
#	if os.geteuid():
#		print 'Please use root'
