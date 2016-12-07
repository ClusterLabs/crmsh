#!/usr/bin/python3.5
# _*_ coding: utf-8 _*_
# File Name: node.py
# mail: wenshizhang555@hoxmail.com
# Created Time: Thu 27 Oct 2016 11:11:28 AM CST
# Description:
#########################################################################
import	os
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

	def skip_lvl(self,level):
		if envir.SKIP_LVL >= level:
			return True
		return False

	def mktemp(self,dest=''):
		tmpdir = tempfile.mkdtemp()
		if len(dest):
			path = os.path.join(tmpdir,dest)
			os.mkdir(path)
		return tmpdir

	def get_crm_daemon_dir(self):
		'''
		Get envir.CRM_DARMON_DIR
		'''
		libdir = utillib.dirname(envir.HA_BIN)
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

	def dumplogset():
		#TODO
		pass
	
	def getlog(self):
		'''
		Get Specify Logs
		'''
		outf = os.path.join(self.WORKDIR,envir.HALOG_F)

		#collect journal firm systemd
		self.collect_journal(self.WORKDIR)
		
		if len(envir.HA_LOG):
			if not os.path.isfile(envir.HA_LOG):
				utillib.warn(envir.HA_LOG+' not found; We will try to find log ourselves')
			envir.HA_LOG = ''
		
		if envir.HA_LOG == '':
			envir.HA_LOG = self.findlog()

		if len(envir.HA_LOG) or not os.path.isfile(envir.HA_LOG):
			if len(envir.CTS):
				#argvment is envir.CTS
				msg = self.cts_findlogseg()

				fd = open(outf,"a")
				fd.write(msg)
				fd.close()
			else:
				utillib.warning('no log at'+self.WE)
				return 
		if not envir.FROM_TIME:
			utillib.warning("a log found; but we cannot slice it")
			utillib.warning("please check the time you input")
		elif len(envir.CTS):
			#argvment is envir.CTS and envir.HA_LOG
			msg = self.cts_findlogseg()

			fd = open(outf,"a")
			fd.write(msg)
			fd.close()

		else:
			global getstamproc
			getstampproc = utillib.find_getstampproc()
			if len(getstampproc):
				msg = self.dumplogset()
				f = open(outf,'a')
				if not f.write(msg):
					utillib.fatal('disk full')
			else:
				utillib.warning('could not figure out the log format of '+envir.HA_LOG)


	def node_need_pwd(self,nodes):
		pass

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
		localstatedir = utillib.dirname(envir.HA_VARLIB)
		found = utillib.find_dir("pengine","/var/lib")
		files = os.listdir(found)
		for i in files:
			if i.find(".last") != -1:
				lastf = os.path.join(found,i)

		if os.path.isfile(lastf):
			envir.PE_STATE_DIR = utillib.dirname(lastf)

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
		localstatedir = utillib.dirname(envir.HA_VARLIB)
		
		for p in ['pacemaker/cib','heartbeat/crm']:
			if os.path.isfile(localstatedir+'/'+p+'/cib.xml'):
				utillib.debug("setting CIB_DIR to localstatedir+'/'+p")
				envir.CIB_DIR = localstatedir+'/'+p
				break

	def echo_ptest_tool(self):
		ptest_progs = ['crm_simulate','ptest']

		for f in ptest_progs:
			if utillib.which(f):
				return utillib.basename(utillib.which(f))


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
		envir.PCMK_LIB = utillib.dirname(envir.CIB_DIR)

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

		if envir.USER_CLUSTER_TYPE == 'corosync':
			envir.CONF = '/etc/corosync/corosync.conf'
			envir.CORES_DIRS.append('/var/lib/corosync')
			envir.CF_SUPPORT = envir.HA_NOARCHBIN+'/openais_conf_support.sh'
			envir.MEMBERSHIP_TOOL_OPTS = ''

		else:
			envir.CONF = envir.HA_CF
			envir.CF_SUPPORT = envir.HA_NOARCHBIN+'/ha_cf_support.sh'
			envir.MEMBERSHIP_TOOL_OPTS = '-H'

		envir.B_CONF = utillib.basename(envir.CONF)
		
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
	
	def change_to_timestamp(self,time):
		ds = utils.parse_to_timestamp(time)
		return ds

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

	def check_this_is_node(self):
		pass


	def mktar(self):
		pass



