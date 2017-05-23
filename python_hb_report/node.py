#!/usr/bin/python3.5
# _*_ coding: utf-8 _*_
# File Name: node.py
# mail: wenshizhang555@hoxmail.com
# Created Time: Thu 27 Oct 2016 11:11:28 AM CST
# Description:
#########################################################################
import	os
import	re
import	sys
import	time
import	sys
import	tempfile
import	envir
import	utillib
import	corosync_conf_support
import	ha_cf_support
import	datetime
import	subprocess

from StringIO import StringIO
from crmsh import config
from crmsh	import utils
from crmsh	import logparser
from multiprocessing import Process

class node:
	SSH_PASSWD = ''
	WE = ''
	WORKDIR = ''
	THIS_IS_NODE = 0
	RM_FILES = []

	def skip_lvl(self,level):
		if envir.SKIP_LVL >= level:
			return True
		return False

	def mktemp(self,dest=''):
		tmpdir = tempfile.mkdtemp()
		if len(dest):
			print tmpdir,dest
			path = os.path.join(tmpdir,dest)
			os.mkdir(path)
		return tmpdir

	def get_crm_daemon_dir(self):
		'''
		Get envir.CRM_DARMON_DIR
		'''
		libdir = os.path.dirname(envir.HA_BIN)
		for p in ['/pacemaker','/heartbeat']:
			if os.access(libdir+p+'/crmd',os.X_OK):
				utillib.debug("setting CRM_DAEMON_DIR to"+libdir+p)
				envir.CRM_DAEMON_DIR = libdir+p
				return 0

		return 1

	def get_crm_daemon_dir2(self):
		'''
		Get_crm_daemon_dir function failed
		'''
		for p in ['/usr','/usr/local','/opt']:
			for d in ['libexec','lib64','lib']:
				for d2 in ['pacemaker','heartbeat']:
					if os.access(p+'/'+d+'/'+d2+'/crmd',os.X_OK):
						utillib.debug("setting CRM_DAEMON_CRM to"+p+'/'+d+'/'+d2+'/crmd')
						envir.CRM_DAEMON_DIR = p+'/'+d+'/'+d2+'/crmd'
						break
	
	def collect_journal(self,workdir):
		'''
		Collect Journal from Systemd, then write the result to file journal.log 
		'''
		global outf
		from_time = str(int(envir.FROM_TIME))
		to_time = str(int(envir.TO_TIME))
		outf = os.path.join(workdir,envir.JOURNAL_F)
		if utillib.do_which('journalctl'):
			if from_time.isdigit() and from_time != '0':
				from_t = datetime.datetime.fromtimestamp(int(from_time)).strftime("+%Y-%m-%d %H:%M")
			#do not know from_time in which cases
			elif from_time.isdigit():
				from_t = datetime.datetime.fromtimestamp(int(from_time)).strftime("+%Y-%m-%d %H:%M")

			#to_time
			if to_time.isdigit() and to_time != '0':
				to_t = datetime.datetime.fromtimestamp(int(to_time)).strftime("+%Y-%m-%d %H:%M")
			#do not know from_time in which cases
			elif to_time.isdigit():
				to_t = datetime.datetime.fromtimestamp(int(to_time)).strftime("+%Y-%m-%d %H:%M")

			if os.path.isfile(outf):
				utillib.warning(outf+' already exists')
			
			fd = open(outf,"w")
			fd.write('journalctl from: '+from_time+' until: '+to_time+' from_time '+from_t+' to_time: '+to_time+'\n')

			#use journalctl to get log messages
			cmd1 = ['journalctl','-o','short-iso','--since',from_t[1:],'--until',to_t[1:],'--no-pager']
			cmd2 = ['tail','-n','+2']
			jnl_process = subprocess.Popen(cmd1,stdout = subprocess.PIPE,stderr=subprocess.STDOUT)
			grep_process = subprocess.Popen(cmd2,stdin = jnl_process.stdout,stdout=subprocess.PIPE)
			output = grep_process.communicate()[0]
			fd.write(output)
			fd.close()

	def findlog(self):
		'''
		First try syslog files, if none found then use the
		logfile/debugfile settings
		'''
		logf = ''

		if  len(envir.HA_LOGFACILITY):
			logf = utillib.findmsg()

		if os.path.isfile(logf):
			return logf

		if len(envir.EXTRA_LOGS):
			for l in envir.EXTRA_LOGS:
				if os.path.isfile(l) and l != envir.PCMK_LOG:
					return l
		if os.path.isfile(os.path.join(self.WORKDIR,envir.JOURNAL_F)):
			return os.path.join(self.WORKDIR,envir.JOURNAL_F)

		if os.path.isfile(envir.PCMK_LOG):
			return envir.PCMK_LOG

		if len(envir.HA_DEBUGFILE):
			snd_logf = envir.HA_DEBUGFILE
			return envir.HA_DEBUGFILE
		else:
			snd_logf = envir.HA_LOGFILE
			return envir.HA_LOGFILE

		if len(snd_logf):
			utillib.debug('will try with '+snd_logf)
	def find_decompressor(self,logf):
		'''
		if system log is compressed , we need find uncompress command
		'''
		if logf.endswith('bz2'):
			return 'bzip2 -dc'
		elif logf.endswith('gz'):
			return 'gzip -dc'
		elif logf.endswith('xz'):
			return 'xz -dc'
		elif os.path.isfile(logf):
			return 'cat'
		else:
			return 'echo'

	def get_ts(self,line):
		ts = 0
		if len(line):
			func_getstamp = getattr(utillib,getstampproc)
			ts = int(self.change_to_timestamp(func_getstamp(line)))

		return ts


	def find_first_ts(self,message):
		for l in message.split('\n'):
			if not len(l):
				break
			ts = self.get_ts(l)
			if ts:
				return ts
			utillib.warning('cannot extract time: |'+l+'|; will try the next one')

	def is_our_log(self,logf,from_time,to_time):
		'''
		check if log contains a piece of our segment
		'''
		cat = self.find_decompressor(logf).split()
		cat.append(logf)

		head_msg = utillib.do_command(['head','-10'],utillib.do_command(cat))
		first_time = self.find_first_ts(head_msg)

		tail_msg = utillib.do_command(['tail','-10'],utillib.do_command(cat))
		tail_msg = utillib.do_command(['tac'],tail_msg)
		last_time = self.find_first_ts(tail_msg)

		if from_time > last_time:
			#we're pass good logs; exit
			return 2

		elif from_time >= first_time:
			#this is last good log
			return 3
		elif to_time == 0 or to_time >= first_time:
			#have to go further back
			#include this log
			return 1
		else:
			#donot include this log
			return 0

	def arch_logs(self,logf,from_time, to_time):
		next_log = []
		return_log = []

		#look for the file such as: ha-log-20090308 or 
		#ha-log-20090308.gz(.ba2) or ha-log.0,etc
		#the date need to match user input or today

		if not os.path.isdir(logf):
			next_log = os.listdir(os.path.dirname(logf))
			dirname = os.path.dirname(logf)
		else:
			next_log = os.listdir(logf)
			dirname = logf

		for n in next_log:
			ret = -1
			if re.search('^'+os.path.basename(logf)+'[0-9]*.*',n):
				if re.search('\d+',n):
					if n.find(envir.DATE) != -1:
						ret = self.is_our_log(n,from_time,to_time)
				else:
					 ret = self.is_our_log(os.path.join(dirname,n),from_time,to_time)
			if ret == 0:
				pass
			elif ret ==1:
				utillib.debug('found log '+next_log)
				return_log.append(os.path.join(dirs,n))
			elif ret == 2:
				#do not have to go to older logs
				break;
			elif ret == 3:
				return_log.append(os.path.join(dirname,n))

		return return_log

	def find_logseg(self,logf,from_time,to_time):
		logseg_path = os.path.join(envir.HA_NOARCHBIN,'print_logseg')
		if os.access(logseg_path,os.F_OK) and os.access(logsef_path,os.X_OK):
			utillib.do_command([logseg_path,logf,from_time,to_time])

		cat = self.find_decompressor(logf).split()
		cat.append(logf)
		source = utillib.do_command(cat).split('\n')

		if from_time == 0:
			FROM_LINE = 0
		else:
			FROM_LINE = utillib.findln_by_time(source,from_time)

	def dumplogset(self):
		'''
		find log/set of logs which are interesting for us
		'''
		logf = envir.HA_LOG
		from_time = int(envir.FROM_TIME)
		to_time = int(envir.TO_TIME)

		logf_set = self.arch_logs(logf,from_time,to_time)
		if not len(logf_set):
			return ''

		oldest = logf_set[len(logf_set)-1]
		newest = logf_set[0]
		if len(logf_set)>2:
			logf_set.remove(oldest)
			logf_set.remove(newest)
			mid_logfiles = logf_set
		else:
			mid_logfiles = []

		if len(logf_set) == 1:
			self.find_logseg(newest,from_time,to_time)
		else:
			self.find_logseg(oldest,from_time,0)
			for f in mid_logfiles:
				self.find_log(f)
				utillib.debug('including complete '+f+' logfile')
			self.find_logseg(newest,0,to_time)

		return ''
	def dumplogset():
		#TODO
		pass
	
	def getlog(self):
		'''
		Get Specify Logs
		'''
		global getstampproc
		outf = os.path.join(self.WORKDIR,envir.HALOG_F)
		outfd = open(outf,'w')

		#collect journal from systemd
		self.collect_journal(self.WORKDIR)
		
		if len(envir.HA_LOG):
			if not os.path.isfile(envir.HA_LOG):
				utillib.warning(envir.HA_LOG+' not found; We will try to find log ourselves')
			envir.HA_LOG = ''
		if not len(envir.HA_LOG):
			envir.HA_LOG = self.findlog()

		if not len(envir.HA_LOG) or not os.path.isfile(envir.HA_LOG):
			if len(envir.CTS):
				#argvment is envir.CTS
				msg = self.cts_findlogseg()
				outfd.write(msg)
			else:
				utillib.warning('no log at'+self.WE)
				return 
		if not envir.FROM_TIME:
			utillib.warning("a log found; but we cannot slice it")
			utillib.warning("please check the from time you input")
		
		elif len(envir.CTS):
			#argvment is envir.CTS and envir.HA_LOG
			msg = self.cts_findlogseg()
			outfd.write(msg)

		else:
			getstampproc = utillib.find_getstampproc(self)
			if len(getstampproc):
				msg = self.dumplogset()
				print msg
				outfd.write(msg)
			else:
				utillib.warning('could not figure out the log format of '+envir.HA_LOG)

	def node_need_pwd(self,nodes):
		pass

	def cts_findlogseg(self):
		'''
		'''
		#TODO
		return ''
		utillib.debug('This is cts find log function, need to be finished later!:)')

	def collect_for_nodes(self,nodes):
		'''
		Start slave collectors
		nodes is list
		'''
		for n in nodes:
			if self.node_need_pwd(n):
				utillib.info('Please provide password for '+utillib.say_ssh_user+' at '+n)
				utiilib.info('Note that collecting data will take a while.')
			
			p = Process(target=self.start_slave_collector,args=(n,))
			p.start()

			self.PIDS.append(p)

		#need sure child process run before parent process
		for p in self.PIDS:
			p.join()

	def get_pe_state_dir(self):
		'''
		Get PE_STATE_DIR from crmsh/config/path.pe_state_dir
		'''
		envir.PE_STATE_DIR = config.path.pe_state_dir
		return len(envir.PE_STATE_DIR)
	
	def get_pe_state_dir2(self):
		'''
		Failed to get PE_STATE_DIR from crmsh
		'''
		localstatedir = os.path.dirname(envir.HA_VARLIB)
		found = utillib.find_dir("pengine","/var/lib")
		files = os.listdir(found)
		for i in files:
			if i.find(".last") != -1:
				lastf = os.path.join(found,i)

		if os.path.isfile(lastf):
			envir.PE_STATE_DIR = os.path.dirname(lastf)

		else:
			for p in ['pacemaker/pengine','pengine','heartbeat/pengine']:
				if os.path.isdir(localstatedir+'/'+p):
					utillib.debug("setting PE_STATE_DIR to "+localstatedir+'/'+p)
					envir.PE_STATE_DIR = localstatedir+'/'+p
					break

	def get_cib_dir(self):
		'''
		Get CIB_DIR from crmsh/config.path.crm_config
		'''	
		envir.CIB_DIR = config.path.crm_config
		return len(envir.CIB_DIR)
	
	def get_cib_dir2(self):
		'''
		Failed to get CIB_DIR from crmsh
		HA_VARKIB is nornally set to {localstatedir}/heartbeat
		'''
		localstatedir = os.path.dirname(envir.HA_VARLIB)
		
		for p in ['pacemaker/cib','heartbeat/crm']:
			if os.path.isfile(localstatedir+'/'+p+'/cib.xml'):
				utillib.debug("setting CIB_DIR to localstatedir+'/'+p")
				envir.CIB_DIR = localstatedir+'/'+p
				break

	def echo_ptest_tool(self):
		ptest_progs = ['crm_simulate','ptest']

		for f in ptest_progs:
			if utillib.which(f):
				return os.path.basename(utillib.which(f))


	def compabitility_pcmk(self):				
		if self.get_crm_daemon_dir():				#have not tested carefully
			self.get_crm_daemon_dir2()

		if not len(envir.CRM_DAEMON_DIR):
			utillib.fatal("cannot find pacemaker daemon directory!")

		if self.get_pe_state_dir():
			self.get_pe_state_dir2()

		if self.get_cib_dir():
			self.get_cib_dir2()

		utillib.debug("setting PCMK_LIB to `dirname $CIB_DIR`")
		envir.PCMK_LIB = os.path.dirname(envir.CIB_DIR)

		envir.PTEST = self.echo_ptest_tool()

	def get_cluster_type(self):
		'''
		User do not input cluster type 
		We figure out it with ourselves
		'''
		if utillib.ps_grep("corosync"):
			if not os.path.isfile('/etc/corosync/corosync.conf') or os.path.isfile(envir.HA_CF):
				utillib.debug("this is Heartbeat cluster stack")
				envir.USER_CLUSTER_TYPE = 'heartbeat'
			else:
				utillib.debug("this is Corosync cluster stack")
				envir.USER_CLUSTER_TYPE = 'corosync'

		else:
			utillib.debug("this is Corosync cluster stack")
			envir.USER_CLUSTER_TYPE = 'corosync'

	def cluster_type(self):
		'''
		Get clustetr type 
		'''
		if not len(envir.USER_CLUSTER_TYPE):
			self.get_cluster_type()

		self.get_another_dirs()
			

	def get_another_dirs(self):
		'''
		Get some dirs
		'''
		#first get CORE_DIRS and PACKAGES
		if envir.HA_VARLIB != envir.PCMK_LIB:
			envir.CORES_DIRS.append(envir.HA_VARLIB+"/cores")
			envir.CORES_DIRS.append(envir.PCMK_LIB+'/cores')
		else:
			envir.CORES_DIRS.append(envir.HA_VARLIB+'/cores')

		packages = 'pacemaker libpacemaker3 pacemaker-pygui pacemaker-pymgmt pymgmt-client openais libopenais2 libopenais3 corosync libcorosync4 resource-agents cluster-glue libglue2 ldirectord libqb0 heartbeat heartbeat-common heartbeat-resources libheartbeat2 booth ocfs2-tools ocfs2-tools-o2cb ocfs2console ocfs2-kmp-default ocfs2-kmp-pae ocfs2-kmp-xen ocfs2-kmp-debug ocfs2-kmp-trace drbd drbd-kmp-xen drbd-kmp-pae drbd-kmp-default drbd-kmp-debug drbd-kmp-trace drbd-heartbeat drbd-pacemaker drbd-utils drbd-bash-completion drbd-xen lvm2 lvm2-clvm cmirrord libdlm libdlm2 libdlm3 hawk ruby lighttpd kernel-default kernel-pae kernel-xen glibc'
		envir.PACKAGES = packages.split(" ")

		event_patterns = '''membership crmd.*(NEW|LOST)|pmck.*(lost|memb|LOST|MEMB):
quorum crmd.*Updating.quorum.status|crmd.*quorum.(lost|ac?quir)
pause Process.pause.detected
resources lrmd.*(start|stop)
stonith crmd.*Exec|stonith-ng.*log_oper.*reboot|stonithd.*(requests|(Succeeded|Failed).to.STONITH|result=)
start_stop Configuration.validated..Starting.heartbeat|Corosync.Cluster.Engine|Executive.Service.RELEASE|Requesting.shutdown|Shutdown.complete'''
		envir.EVENT_PATTERNS = event_patterns.split('\n')

		if envir.USER_CLUSTER_TYPE == 'corosync':
			envir.CONF = '/etc/corosync/corosync.conf'
			envir.CORES_DIRS.append('/var/lib/corosync')
			envir.CF_SUPPORT = envir.HA_NOARCHBIN+'/openais_conf_support.sh'
			envir.MEMBERSHIP_TOOL_OPTS = ''

		else:
			envir.CONF = envir.HA_CF
			envir.CF_SUPPORT = envir.HA_NOARCHBIN+'/ha_cf_support.sh'
			envir.MEMBERSHIP_TOOL_OPTS = '-H'

		envir.B_CONF = os.path.basename(envir.CONF)
		
		if not os.path.isfile(envir.CF_SUPPORT):
			utillib.fatal('no stack specific support:'+envir.CF_SUPPORT)
	
	def get_log_var(self):
		'''
		Get log variable
		'''
		if not len(envir.HA_LOGFACILITY):
			envir.HA_LOGFACILITY = envir.DEFAULT_HA_LOGFACILITY

		envir.HA_DEBUGLEVEL = 'info'
		if envir.USER_CLUSTER_TYPE == 'heartbeat':
			cfdebug = ha_cf_support.getcfvar('debug')
		else:
			if corosync_conf_support.iscfvartrue('debug'):
				HA_LOGDEVEL = 'debug'
		if corosync_conf_support.uselogd():
			if not os.path.isfile(envir.LOGD_CF):
				#no configurations: use default
				return 
			else:
				utillib.debug('reading log settings from '+envir.LOGD_CF)
				corosync.get_logd_logvars()
	
	def change_to_timestamp(self,times):
		if not len(envir.DATE):
			if len(times.split()) > 1:
				date_string = times.split()[0]
				date = ''.join(re.findall(r'\d+',date_string))
			else:
				date =  time.strftime("%Y%m%d")
			
			envir.DATE = date

		try:
			ds = utils.parse_to_timestamp(times)
			return ds
		except:
			return 0

	def import_support(self):
		global support
		if envir.USER_CLUSTER_TYPE == 'corosync':
			#import corosync_conf_support as support
			return "corosync_conf_support"
		else:
			return "ha_conf_support"
			#import ha_conf_support as support
			
	def conf(self):
		pass


	def mktar(self):
		pass



