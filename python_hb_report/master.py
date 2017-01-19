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
import	time
import	shutil
import	stat

from crmsh	import logtime
from crmsh	import utils
from crmsh	import logparser
from node	import node
from multiprocessing import Process

class master(node):
#	SUDO = ''
#	LOCAL_SUDO = ''
	PIDS =[]

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

	def diffcheck(self,file1,file2,outfd):
		'''
		if file1 not as same as file2, return True
		else return False
		'''
		dir1 = os.path.dirname(file1)
		dir2 = os.path.dirname(file2)

		outf = os.path.join(self.WORKDIR,envir.ANALYSIS_F)
		if not os.path.isfile(file1):
			utillib.writefile(outf,file1+' does not exist')
			return False

		if not os.path.isfile(file2):
			utillib.writefile(outf,file1+' does not exist')
			return False

		base = os.path.basename(file1)

		if base == envir.CIB_F:
			if (os.path.isfile(os.path.join(dir1,'RUNNING')) and os.path.isfile(os.path.join(dir2,'RUNNING'))) or (os.path.isfile(os.path.join(dir1,'STOPPED')) and os.path.isfile(os.path.join(dir2,'STOPPED'))):
				msg = utillib.do_command(['crm_diff','-c','-n',file1,'-o',file2])
				outfd.write(msg)
			else:
				outfd.write('cannot compare cibs from running and stop systems')
		
		#confdiff
		#elif base == envir.B_CONF:

		else:
			msg = utillib.do_command(['diff','-bBu',file1,file2])
			outfd.write(msg)

		return len(msg)

	def analyze_one(self,files,outfd):
		'''
		if collector return different file then return True
		else return False
		'''
		#RC -- repeat counter
		RC = 0
		nodes = ''
		for n in envir.USER_NODES:
			if len(nodes):
				if not self.diffcheck(os.path.join(self.WORKDIR,nodes,files),os.path.join(self.WORKDIR,n,files),outfd):
					RC += 1
			else:
				nodes = n

		return RC

	
	def check_files(self,outf,files):
		'''
		If path exists and is a socket
		write warning message and path content to analyzed.txt
		'''
		for l in LOG_NODES:
			if utillib.is_socket(os.path.join(self.WORKDIR,l,files)):
				fd = open(os.path.join(self.WORKDIR,l,files))
				outf.write('WARN:'+files[0:len(files)-4]+'reported warnings at '+l)
				outf.write(fd.readlines())
				fd.close()

	def check_backtrace(self,outf):
		for l in LOG_NODES:
			if utillib.is_socket(os.path.join(self.WORKDIR,l,envir.BT_F)):
				fd = open(os.path.join(self.WORKDIR,l,envir.BT_F))
				outf.write('WARN: coredumps found at '+l+':')
				outf.write(fd.readlines())
				fd.close()

	def check_logs(self,outf):
		logs = []
		
		#change EXTRA_LOGS
		envir.EXTRA_LOGS.append(envir.HALOG_F)

		outf.write('Log patterns:\n')

		for f in envir.EXTRA_LOGS:
			if os.path.isfile(os.path.join(self.WORKDIR,os.path.basename(f))):
				logs.append(os.path.join(self.WORKDIR,os.path.basename(f)))
			for l in LOG_NODES:
				if os.path.isfile(os.path.join(self.WORKDIR,l,os.path.basename(f))):
					logs.append(os.path.join(self.WORKDIR,l,os.path.basename(f)))

		if not len(logs):
			return
		for l in logs:
			fd = open(l,'r')
			line = fd.readline()
			while line:
				for patt in envir.LOG_PATTERNS:
					if line.find(patt) != -1:
						outf.write(line)
					line = fd.readline()
		#change back
		envir.EXTRA_LOGS.remove(envir.HALOG_F)

	def consolidate(self,files):
		'''
		Remove same file,create symbolic link instead
		'''
		try:
			for l in LOG_NODES:
				if os.path.isfile(os.path.join(self.WORKDIR,files)):
					os.remove(os.path.join(self.WORKDIR,l,files))
				else:
					shutil.move(os.path.join(self.WORKDIR,l,files),os.path.join(self.WORKDIR,files))
				os.symlink(os.path.join(self.WORKDIR,files),os.path.join(self.WORKDIR,l,files))

		except IOError:
			#if no such file 
			#do not need to remove this file
			return 

	def analyze(self):
		'''
		Check every logs we need are collected
		'''
		outf = os.path.join(self.WORKDIR,envir.ANALYSIS_F)
		fd = open(outf,'w')
		ana_msg = ''
		flist = [envir.HOSTCACHE,envir.MEMBERSHIP_F,envir.CIB_F,envir.CRM_MON_F,envir.B_CONF,envir.SYSINFO_F,'logd.cf']
		dirs = LOG_NODES

		for f in flist:
			fd.write('Diff '+f+'...\n')
			for d in dirs:
				if f not in os.listdir(os.path.join(self.WORKDIR,d)):
					fd.write('\t\tno '+f+' on '+d+':/\n')
			
			#analyze_one return 0 if file do not exists or all node have this file 
			#if all node have same file and this file exists
			#then call consolidate remove extra file

			if self.analyze_one(f,fd) == len(LOG_NODES)-1 and os.path.isfile(os.path.join(self.WORKDIR,dirs[0],f)): 
				fd.write('OK\n')
				if f != envir.CIB_F:
					self.consolidate(f)

		self.check_files(fd,envir.CRM_VERIFY_F)
		self.check_backtrace(fd)
		self.check_files(fd,envir.PERMISSIONS_F)
		self.check_logs(fd)
		fd.close()
	
	def start_slave_collector(self,nodes,port=22,username='root'):
		
		fdout = open(os.path.join(self.WORKDIR,'output.txt'),'a')
		fderr = open(os.path.join(self.WORKDIR,'error.txt'),'a')
		utillib.debug('running class collector function run to collect log on '+nodes)

		paramiko.util.log_to_file('/tmp/paramiko.log')
		client = paramiko.SSHClient()
		client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		client.connect(nodes,port,username)

		path = os.path.join(envir.CRM_PATH,'collector.py')
		utillib.debug(nodes+' collector script path :'+path)

		command= 'python '+envir.EXCUTE_PATH+'/hb_report __slave'
		stdin,stdout,stderr = client.exec_command(command)
		
		outmsg = nodes+ ' output :'+stdout.read()
		fdout.write(outmsg)
		fdout.close()
		errmsg = nodes+ ' error: '+stderr.read()
		fderr.write(errmsg)
		fderr.close()

	def events_all(self,logf,outf):
		epatt= []
		logfd = open(logf,'r')
		lines = logfd.readlines()
		print lines

		for patt in envir.EVENT_PATTERNS:
			epatt.append(patt.split()[1])

		for patt in epatt:
			for l in lines:
				if l.find(patt) != -1:
					outf.write(l)

	def events(self):
		logf = os.path.join(self.WORKDIR,envir.HALOG_F)
		outf = os.path.join(self.WORKDIR,'events.txt')
		outfd = open(outf,'w')

		if os.path.isfile(logf):
			self.events_all(logf,outfd)
		
		for l in LOG_NODES:
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
			command = 'scp '+os.path.join(envir.XML_PATH,envir.XML_NAME)+' root@'+nodes+':'+envir.XML_PATH+' &>/dev/null'
			ret = os.system(command)
			if ret:
				utillib.fatal(nodes+' :scp envitonment file failed, please check cluster node can ssh or not')

	def get_user_node_cts(self,ctslog):
		#TODO
		utillib.debug('need to finish later')
	
	def get_cts_log(self):
		#TODO
		utillib.debug('need to finish later')
		
	def is_member(self):
		'''
		Check node from node list is member or not
		need to improve 
		if func can know user input the node do not belong to cluster 
		the hb_report can output the message then exit
		envir.NODE_SOURCE can tell the func where did hv_report get node
		only from user need to check
		'''
		#TODO
		if envir.NODE_SOURCE != 'user':
			return 
		NODECNT = len(envir.USER_NODES)
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
		If user not provide ssh users, find ssh user by itself
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
			utillib.warning('passwordless ssh to node(s) '+envir.SSH_PASSWD_NODES+' does not work')
		
		if ssh_user == '__undef':
			return 1
		if ssh_user != '__default':
			envir.SSH_USER = ssh_user			
			#ssh user is default
			
		return 0

	def get_result(self):

#		for p in self.PIDS:
#			pid, status = os.waitpid(p.pid,0)	
		global LOG_NODES
		LOG_NODES = []
		for n in envir.USER_NODES:
			if n+'.tar' not in os.listdir(self.WORKDIR):
				utillib.warning('NOTICE: '+n+' not return logs!')
			else:
				LOG_NODES.append(n)	
				tar = tarfile.open(os.path.join(self.WORKDIR,n+'.tar'),'r:')
				tar.extractall(path=self.WORKDIR)
				tar.close()
				self.RM_FILES.append(os.path.join(self.WORKDIR,n+'.tar'))


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
	envir.MASTER = mtr.WE

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
			mtr.THIS_IS_NODE = 1

	if not mtr.is_node and envir.NODE_SOUECE != 'user':
		utillib.warning('this is not a node and you didn\'t specify a list of nodes using -n')
	
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
	if mtr.THIS_IS_NODE:
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
#part 5:
#		 slaves  tar their result to stdout, send it to master,
#		 then master analyses result, asks the user to edit the
#		 problem description template, and print final words
#

	mtr.get_result()
	Process(target = mtr.analyze).start()
	Process(target = mtr.events).start()


#
#part 6: endgame: 
#		 remove tmpfiles and logs we do not need


	utillib.remove_files(mtr)


#try:
run()
#except OSError as msg:
#	print 'Get an Error',msg
#	if os.geteuid():
#		print 'Please use root'
