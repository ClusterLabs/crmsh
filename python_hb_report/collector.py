#!/usr/bin/python3.5

import	os
import	envir
import	sys
import	socket
import	utillib
import	subprocess
import	platform
import	threading
import	shutil
import	tempfile
import	tarfile
import  time
import StringIO

from node import node

class collector(node):

	def debug_info(self):
		if(envir.VERBOSITY > 1):
			utillib.info("high debug level, please read debug.out")

	def sys_info(self,filename):
		'''
		create file WORKDIR/sysinfo.txt
		'''
		msg = ''
		f = open(filename,'w')
		support = __import__(self.import_support())
		cluster_version = support.cluster_info()
		msg = cluster_version

		hbrp_ver = utillib.do_command([envir.HA_NOARCHBIN+'/hb_report','-V'])
		msg = msg+hbrp_ver

		rsag_ver = utillib.do_grep_file('/usr/lib/ocf/lib/heartbeat/ocf-shellfuncs','Build version:')
		rsag_ver = 'resource-agents: '+rsag_ver
		msg = msg + rsag_ver

		crm_version = utillib.crm_info()
		msg = msg+crm_version

		booth_info = utillib.do_command(['booth','--version'])
		msg = msg+booth_info
		
		pkg_info = utillib.pkg_version()
		msg = msg + pkg_info
		f.write(pkg_info)
		
		if envir.SKIP_LVL >= 1:
			vrf_info = utillib.verify_packages()
			msg = msg + vrf_info

		sys_name = 'Platform: '+ platform.system()+'\n'
		msg = msg+sys_name

		knl_name = 'Kernel release: '+platform.release()+'\n'
		msg = msg+knl_name
		
		arch_name = 'Architecture: '+platform.machine()+'\n'
		msg = msg+arch_name

		if platform.system() == 'Linux':
			dist_name = utillib.distro()+'\n'
			msg = msg + dist_name
		f.write(msg)
		f.close()

	def sys_stats(self):
		
		msg = ''

		f = open(os.path.join(self.WORKDIR,envir.SYSSTATS_F),'w')

		msg = msg + self.WE+'\n'

		uptime = utillib.do_command(['uptime'])
		msg = msg+uptime

		ps_info = utillib.do_command(['ps','axf'])
		msg = msg+ps_info
	
		ps_info = utillib.do_command(['ps','auxw'])
		msg = msg + ps_info

		top_info = utillib.do_command(['top','-b','-n','1'])
		msg = msg + top_info

		ip_info = utillib.do_command(['ip','addr'])
		msg = msg+'\n'+ip_info

		net_info = utillib.do_command(['netstat','-i'])
		msg = msg +'\n'+net_info

		arp_info = utillib.do_command(['arp','-an'])
		msg = msg + '\n' + arp_info

		if os.path.isdir('/proc'):
			cpu_f =open('/proc/cpuinfo','r')
			cpu_info = cpu_f.readline()
			while len(cpu_info):
				msg = msg + cpu_info
				cpu_info = cpu_f.readline()

		scsi_info = utillib.do_command(['lsscsi'])
		msg = msg +'\n'+ scsi_info

		pci_info = utillib.do_command(['lspci'])
		msg = msg +'\n'+ pci_info

		mount_info = utillib.do_command(['mount'])
		msg = msg +'\n' + mount_info

		#df can block, run in background, allow for 5 seconds
		df_pro = subprocess.Popen(['df'],stderr = subprocess.STDOUT,stdout = subprocess.PIPE)
		timer = threading.Timer(5.0,df_pro.kill)
		timer.start()
		df_info = df_pro.communicate()[0]
		if timer.is_alive():
			#df exited naturally, cancel timer
			timer.cancel()
		msg = msg +'\n'+df_info

		f.write(msg)
		f.close()

	def pe2dot(self,path):
		pef = utillib.basename(path)
		if pef.endswith('.bz2'):
			dotf = pef[0:len(pef)-4]

		if not len(envir.PTEST):
			return False
		try:
			msg = utillib.do_command([envir.PTEST,'-D','dotf','-x',pef])
		except:
			utillib.debug(envir.PTEST+' faild! ')
			return

	def dlm_dump(self):
		output = os.path.join(self.WORKDIR,envir.DLM_DUMP_F)
		if not utillib.do_which('dlm_tool'):
			return 
		dlm_file_info = 'NOTICE - Lockspace overview:\n'	
		dlm_file_info = dlm_file_info + utillib.do_command(['dlm_tool','ls'])

		dlm_pro = subprocess.Popen(['dlm_tool','ls'],stdout = subprocess.PIPE,stderr = subprocess.STDOUT)
		grep_pro = subprocess.Popen(['grep','name'],stdin = dlm_pro.stdout,stdout = subprocess.PIPE,stderr = subprocess.STDOUT)

		dlm_list = grep_pro.communicate()[0].split('\n')

		for d in dlm_list:
			strd = d.split()
			for X,N in strd:
				dlm_file_info = dlm_file_info+'\n'+'NOTICE - Lockspace '+N
				dlm_file_info = dlm_file_info +utillib.do_command(['dlm_tool','lock_dump',N])

		dlm_file_info = dlm_file_info +'\nNOTICE - Lockspace histoty:\n'
		dlm_file_info = dlm_file_info +utillib.do_command(['dlm_tool','dump'])

		utillib.writefile(output,dlm_file_info)




	def getpeinputs(self,workdir):
		i = 0

		utillib.debug('looking for PE files in'+envir.PE_STATE_DIR)
		flist = utillib.find_files(envir.PE_STATE_DIR.split())
		grep_pro = subprocess.Popen(['grep','-v',"[.]last$"],stdin = subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
		flist = grep_pro.communicate(' '.join(flist))[0].split()
		
		if len(flist):
			filename = utillib.basename(envir.PE_STATE_DIR)
			pengine_dir = os.path.join(workdir,filename)
			os.mkdir(pengine_dir)
			for f in flist:
#				os.symlink(f,os.path.join(pengine_dir,utillib.basename(f)))
				os.symlink(f,pengine_dir)
				utillib.do_command(['ln','-s',f,pengine_dir])
				i = i + 1
			utillib.debug('found '+str(i)+' pengine input files in '+envir.PE_STATE_DIR)

		if i >= 20:
			for f in flist:
				if not self.skip_lvl(1):
					path = os.path.join(workdir,utillib.basename(envir.PE_STATE_DIR))
					path = os.path.join(path,utillib.basename(f))
					self.pe2dot(path)
		else:
			utillib.debug('too many PE inputs to create dot files')

	def touch_DC_if_dc(self):
		dc = utillib.do_command(['crmadmin','-D'])
		dc = dc.split()[len(dc.split()) - 1]
		if self.WE == dc:
			utillib.writefile(os.path.join(self.WORKDIR,'DC'),'')

	def getbacktraces(self):
		flist = []
		bt_files = utillib.find_files(envir.CORES_DIRS)
		for f in bt_files:
			bf = utillib.basename(f)
			bf_num  = utillib.do_command(['expr','match',bf,'core'])
			if bf_num > 0:
				flist.append(f)
		if len(flist):
			utillib.getbt(flist,os.path.join(self.WORKDIR,envir.BT_F))
			utillib.debug('found basktraces: '+' '.join(flist))

	def getconfigurations(self):
		dest = self.WORKDIR	

		for conf in envir.CONFIGURATIONS:
			if os.path.isfile(conf):
				shutil.copyfile(conf,os.path.join(dest,utillib.basename(conf)))
			elif os.path.isdir(conf):
				files = os.listdir(conf)
				dst = os.path.join(self.WORKDIR,utillib.basename(conf))
				os.mkdir(dst)
				for f in files:
					src = os.path.join(conf,f)
					shutil.copyfile(src,os.path.join(dst,f))

	def time_status(self):
		output = os.path.join(self.WORKDIR,envir.TIME_F)

		time_info = utillib.do_command(['date'])
		time_info = time_info + utillib.do_command(['ntpdc','-pn'])
		utillib.writefile(output,time_info)

	def corosync_blackbox(self):
		outf = os.path.join(self.WORKDIR,envir.COROSYNC_RECORDER_F)
		from_time = envir.FROM_TIME
		to_time = envir.TO_TIME

		inpf = utillib.find_files(['/var/lib/corosync'])

		if os.path.isfile(' '.join(inpf)):
			blkbox_info = utillib.do_command(['corosync-blackbox'])
			utillib.writefile(outf,blkbox_info)
			utillib.do_command(['touch','-r',inpf,outf])

	def getratraces(self):
		i = 0
		trace_dir = os.path.join(envir.HA_VARLIB,'trace_ra')
		
		if not os.path.isdir(trace_dir):
			return False

		utillib.debug('looking for RA trace files in '+trace_dir)
		sed_pro = subprocess.Popen(['sed',"s,"+utillib.dirname(trace_dir)+"/,,g"],stdin = subprocess.PIPE,stdout = subprocess.PIPE)
		flist = sed_pro.communicate(' '.join(utillib.find_file(trace_dir)))[0].split('\n')

		if len(flist):
			for f in flist:
				shutil.copyfile(f,self.WORKDIR)
				i = i+1
			utillib.debug('found '+str(i)+' trace files in '+trace_dir)

	def sanitize(self):
		'''
		Replace sensitive info with ****
		'''
		need_replace_files = []
		for f in os.path.join(self.WORKDIR,envir.B_CONF).split():
			if os.path.isfile(f):
				utillib.sanitize_one(f)
		rc = 0

		try:
			dirs = os.path.join(self.WORKDIR,envir.CIB_F).split()
		except OSError:
			pass
		else:
			need_replace_files.extend(dirs)

		try:
			dirs = os.listdir(os.path.join(self.WORKDIR,'pengine'))
		except OSError:
			pass
		else:
			need_replace_files.extend(dirs)


		for n in need_replace_files:
			if os.path.isfile(n):
				if envir.DO_SANITIZE:
					utillib.sanitize_one(n)
				else:
					if utillib.test_sensitive_one(n):
						utillib.warning('some PE or CIB file contain possibly sensitive data')
						utillib.warning('you may not want to send this report to a public mailing list')

	def mvenv(self):
		env_src_path = os.path.join(envir.XML_PATH,envir.XML_NAME)
		env_dst_path = os.path.join(self.WORKDIR,envir.XML_NAME)
#		shutil.copyfile(env_src_path,self.WORKDIR)
		shutil.move(env_src_path,self.WORKDIR)
		return 

	def collect_info(self):
		getstampproc = ''

		self.sys_info(os.path.join(self.WORKDIR,envir.SYSINFO_F))
		self.sys_stats()
		utillib.getconfig(self.WORKDIR)
		self.getpeinputs(self.WORKDIR)
		utillib.crmconfig(self.WORKDIR)
		if not self.skip_lvl(1):
			self.touch_DC_if_dc()
		self.getbacktraces()
		self.getconfigurations()
		utillib.check_perms(os.path.join(self.WORKDIR,envir.PERMISSIONS_F),self)
		self.dlm_dump()
		self.time_status()
		self.getlog()
		self.corosync_blackbox()
		self.getratraces()
		if not self.skip_lvl(1):
			self.sanitize()

		for l in envir.EXTRA_LOGS:
			if not os.path.isfile(l):
				continue

			if l == envir.HA_LOG and l != envir.HALOG_F:
				os.symlink(envir.HALOG_F,os.path.join(self.WORKDIR,utillib.basename(l)))
				continue

	def return_result(self):
		'''
		Return logs to master through scp
		create tarfile in WORKDIR
		'''
		tarname = self.WE+'.tar'
		tarpath = os.path.join(self.WORKDIR,tarname)
		start=time.time()
		tar = tarfile.open(tarpath, 'w')

		curr_dir = os.getcwd()
		os.chdir(utillib.dirname(self.WORKDIR))
		tar.add(utillib.basename(self.WORKDIR))
		tar.close()
		
		os.chdir(curr_dir)

		command = ['scp',tarpath,'root@'+envir.MASTER+':'+envir.MASTER_WORKDIR]
		print command

		msg = utillib.do_command(command)
		print msg

		self.RM_FILES.append(self.WORKDIR)
		self.RM_FILES.append(tarpath)



def run(master_flag):

	sla = collector()

	#if this is master node, then flag THIS_IS_NDOE is 1, else case it is 0
	sla.THIS_IS_NODE = master_flag
	
	#init_tempfiles
	envir.__TMPFLIST = tempfile.mkstemp()[1]

	#who am i
	sla.WE = socket.gethostname()
	print 'start collector on ',sla.WE

	utillib.parse_xml()
	
	#get WORKDIR
	sla.WORKDIR = sla.mktemp(sla.WE)
	sla.WORKDIR = sla.WORKDIR+"/"+sla.WE
	sla.compabitility_pcmk()
	sla.cluster_type()
	support = __import__(sla.import_support())

	support.get_log_var()
	utillib.debug('log setting :facility = '+envir.HA_LOGFACILITY+' logfile = '+envir.HA_LOGFILE+' debug file = '+envir.HA_DEBUGFILE)
	

	#In order to avoid master node delete envirenv file before scp it to another node
	#Then master node donot need to delete here, it will be deleted before master node end of run
	try:
		if not sla.THIS_IS_NODE:
			if not utillib.do_rm(sla.WE,os.path.join(envir.XML_PATH,envir.XML_NAME)):
				raise IOError('NO Such file or directory')
	except IOError as msg:
		print msg
		sys.exit(1)

	sla.collect_info()
	sla.return_result()

#
#part 4: endgames:
#		 remove tmpfile and logs we do not need
#
#	utillib.remove_files(sla)

