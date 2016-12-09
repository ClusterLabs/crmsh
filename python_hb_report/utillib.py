import os
import datetime
import sys
import socket
import re
import envir
import time
import StringIO
import subprocess
import shutil
import tempfile
import stat

import xml.etree.ElementTree as ET
from xml.dom import minidom

from crmsh	import utils


#set variables default
def setvarsanddefaults():
	'''
	do some environment variable initial 
	'''
	now = datetime.datetime.now()
	now_string = now.strftime("%Y-%m-%d %H:%M:%S.%f")
	now_t = utils.parse_to_timestamp(now_string)
	envir.UNIQUE_MSG="Mark:HB_REPORT:"+str(int(now_t))
	NOW = now

	envir.TO_TIME = utils.parse_to_timestamp(now_string)
	date = datetime.datetime.date(now).strftime("%a-%d-%m-%Y")
	envir.DEST = "hb_report-"+date
	envir.SANITIZE.append("passw.*")
	envir.SSH_OPTS = ['-o StrictHostKeyChecking=no','-o EscapeChar=none','-o ConnectTimeout=15']
	envir.LOG_PATTERNS.append("CRIT:")
	envir.LOG_PATTERNS.append("ERROR:")

def debug(msg):
	if (envir.VERBOSITY >0):
		print >> sys.stderr,socket.gethostname(),"DEBUG:",msg
		return 0

def fatal(msg):
	print >> sys.stderr,socket.gethostname(),"ERROR:",msg
	sys.exit(1)

def warning(msg):
	print >>sys.stderr,socket.gethostname(),"WARN:",msg

def info(msg):
	print >> sys.stderr,socket.gethostname(),"INFO:",msg

def get_value(line):
	'''
	Base on parameter key to search and get the value in string line
	'''

	value = line.split("=")
	
	#only want right part of =
	value = str(value[1])

	#cut off the '}\n'
	value = value[0:len(value)-2]
	
	#if some variable's value composed of other variable
	#then replace it
	m = re.search('([A-Z]+_){0,}[A-Z]{1,}',value)
	if m:
		value = re.sub('\$([A-Z]+_){0,}[A-Z]{1,}',getattr(envir,m.group()),value)
	return value

def get_ocf_directories():
	'''
	Get some critical variable that store at osc-directories 
	'''
	f = open("/usr/lib/ocf/lib/heartbeat/ocf-directories","r");
	line = f.readline()
	while len(line) >0:
		if line.find("HA_DIR:=") != -1:
			envir.HA_DIR = get_value(line)
		#TODO
		# ha_cf not right
		if line.find("HA_CF:=") != -1:
			envir.HA_CF = get_value(line)
		
		if line.find("HA_VARLIB:=") != -1:
			envir.HA_VARLIB = get_value(line)

		if line.find("HA_BIN:=") != -1:
			envir.HA_BIN = get_value(line)
		line = f.readline()

def logd_getcfvar(pattern):
	'''
	'''
	#TODO
	f = open(envir.LOGD_CF)
	for line in f:
		if line.startswith('#'):
			continue
		if line.startwith(pattern):
			pass

def get_logd_logvars():
	'''
	unless logfacility is set to none, heartbeat/ha_logd are
	going to log through syslog
	TODO
	'''
	envir.HA_LOGFACILITY = logd_getcfvar('logfacility')

def find_dir(name,path):
	result = []
	for root,dirs,files in os.walk(path):
		
		if name in dirs:
				result.append(os.path.join(root,name))
	
	result_string = ''.join(result)
	return result_string


def which(command):
	'''
	Implement of command which
	'''
	path = os.getenv("PATH")
	path_list = path.split(":")
	
	for p in path_list:
		if command in os.listdir(p):
			return os.path.join(p,command)

def ps_grep_pid(pid):
	'''
	Like function ps_grep, base on pid find matches
	'''
	dirs = os.listdir('/proc')
	
	for d in dirs:
		if re.match('\d+',d):
			if d == pid:
				return False

	return True

def ps_grep(proname):
	'''
	Ps and grep, if got match then return False, otherwise return True
	'''
	dirs = os.listdir("/proc")

	for d in dirs:
		if re.match("\d+",d):
			path = os.path.join('/proc',d+'/cmdline')
			f = open(path,'r')
			msg = f.readline()
			if msg.find(proname) != -1 and msg.find('grep') == -1:
				return False
	return True

def findmsg(mark):
	syslog = '/var/log /var/logs /var/syslog /var/adm /var/log/ha /var/log/cluster /var/log/pacemaker /var/log/heartbeat /var/log/crm /var/log/corosync'
	syslogdirs = syslog.split(' ')
	favourites = 'ha-*'
	log = []
	dirname = ''

	for d in syslogdirs:
		if not os.path.isdir(d):
			continue
		subdir = os.listdir(d)
		for s in subdir:
			if s.startswith('ha-'):
				if s.find(mark) != -1:
					log.append(s)
		if len(log):
			break
		for s in subdir:
			if s.find(mark) != -1:
				log.append(s)
		if len(log):
			break
	
	if len(log):
		dirs = os.listdir(log[0])
		dirsname = ' '.join(dirs)
		debug('found HA log at '+dirname)
	else:
		debug('no HA log found in '+syslog)
	
	return dirname

def iscrmrunning():
	'''
	Test whether crm is running
	if running return True, otherwise return False
	'''
	result = 0
	#if ps and grep find the crmd then return True
	if  not ps_grep('crmd'):
		return True
	pid = os.fork()
	if not pid:
		result = os.system('crmadmin -D >/dev/null 2>&1')
		if result:
			return True
		return False
	else:
		for i in range(100):
			try:
				os.waitpid(pid,0)
			except:
				break;
			time.sleep(1)
		if not ps_grep_pid(pid):
			os.kill(pid,signal.SIGKILL)

def get_crm_nodes():
	'''
	Use crm to get all node in current cluster
	Before call this function, must ensure crm is running, otherwise will get exception
	'''
	rc = 0
	from crmsh import ui_context
	from crmsh import ui_root
	from crmsh import msg
	from crmsh import options
	ui = ui_root.Root()
	context = ui_context.Context(ui)

	if len(envir.USER_NODES):
		return rc
	try:
		oldout = sys.stdout
		sys.stdout = myout= StringIO.StringIO()

		if not context.run('node server'):
			rc = 1
		sys.stdout = oldout
		nodes = myout.getvalue()
		nodes = nodes.rstrip()
		envir.USER_NODES = nodes.split('\n')
		debug('Get CRM node list: '+' '.join(envir.USER_NODES))
	except ValueError as msg:
		rc = 1
		msg.common_err(msg)
	
	return rc


def get_nodes():
	# 1. set by user
	if len(envir.USER_NODES):
		print envir.USER_NODES
	# 2. running crm
	elif iscrmrunning():
		debug('querying CRM for nodes')
		get_crm_nodes()
		envir.NODE_SOURCE = 'crm'
	# 3. hostcache
	elif os.path.isfile(envir.HA_VARLIB+'/hostcache'):
		utillib.debug('reading nodes from '+envir.HA_VARLIB+'/hostcache')
		get_hostcache_node()
		envir.NODE_SOURCE = 'hostcache'
	# 4. ha.cf
	elif envir.USER_CLUSTER_TYPE == 'heartbeat':
		utillib.debug('reading node from ha.cf')
		getcfvar('node')
		envir.NODE_SOURCE = 'ha.cf'
	# 5.of the cluster's stopped, try the CIB
	elif os.path.isfile(envir.CIB_DIR+'/'+envir.CIB_F):
		utillib.debug('reading node from the archived'+envir.CIB_DIR+'/'+envir.CIB_F)
		CIB_file = os.path.join(envir.CIB_DIR,envir.CIB_F)
		get_crm_node()
		envir.NODE_SOURCE = 'crm'

def do_which(command):
	path = []
	path = os.environ['PATH'].split(':')

	for n in path:
		dirlist = os.listdir(n)
		if command in dirlist:
			return True
	
	return False

def do_greple(dirs,form):
	'''
	In dirs directoriy find file text  match form
	Like grep -l -e, return the match name when get the first match 
	'''
	files = os.listdir(dirs)
	log = ''
	
	for f in files:
		#pass directires
		if not os.path.isfile(f):			
			continue

		if f.find("ha-") != -1:
			fd = open(f,'r')
			txt = fd.readline()
			#hit the targrt
			while txt:
				if txt.find(form) != -1:
					return f
				txt = fd.readline()
			fd.close()

	for f in files:

		if not os.path.isfile(f):
			continue

		fd = open(f,'r')
		txt = fd.readline()
		#hit the targrt
		while txt:
			if txt.find(form) != -1:
				return f
			txt = fd.readline()
		fd.close()
		
	return log

def do_grep_file(files,form):
	'''
	In dirs directoriy find file text  match form
	Like grep -l -e, return the match name when get the first match 
	'''
	log = ''
		
	if not os.path.isfile(files):
		fatal(files+' is not exits')

	fd = open(files,'r')
	txt = fd.readline()
	#hit the targrt
	while txt:
		if txt.find(form) != -1:
			return txt
		txt = fd.readline()
	fd.close()

	return ''
		

def findmsg():
	'''
	Found HA Log
	'''
	dirs="/var/log /var/logs /var/syslog /var/adm /var/log/ha /var/log/cluster /var/log/pacemaker /var/log/heartbeat /var/log/crm /var/log/corosync /var/log/openais"
	syslogdirs = dirs.split()
	favourites ='ha-*'
	mark = envir.UNIQUE_MSG
	log = []

	for f in syslogdirs:
		#grep pass directries
		if not os.path.isdir(f):
			continue
		log = do_greple(f,mark)
	
	if not len(log):
		debug('no HA log found in '+dirs)
	else:
		debug('found HA log at'+' '.join(log))
	
	return log

def creat_xml():
	root = ET.Element('root')

	ET.SubElement(root,'DEST').text = envir.DEST
	ET.SubElement(root,'FROM_TIME').text = str(int(envir.FROM_TIME))
	ET.SubElement(root,'TO_TIME').text = str(int(envir.TO_TIME))
	ET.SubElement(root,'USER_NODES').text = '$'.join(envir.USER_NODES)
	ET.SubElement(root,'HA_LOG').text = envir.HA_LOG
	ET.SubElement(root,'UNIQUE_MSG').text = envir.UNIQUE_MSG
	ET.SubElement(root,'SANITIZE').text = '$'.join(envir.SANITIZE)
	ET.SubElement(root,'DO_SANITIZE').text = str(envir.DO_SANITIZE)
	ET.SubElement(root,'SKIP_LVL').text = str(envir.SKIP_LVL)
	ET.SubElement(root,'EXTRA_LOGS').text = '$'.join(envir.EXTRA_LOGS)
	ET.SubElement(root,'PCMK_LOG').text = envir.PCMK_LOG
	ET.SubElement(root,'USER_CLUSTER_TYPE').text = envir.USER_CLUSTER_TYPE
	ET.SubElement(root,'CONF').text = envir.CONF
	ET.SubElement(root,'B_CONF').text = envir.B_CONF
	ET.SubElement(root,'PACKAGES').text = '$'.join(envir.PACKAGES)
	ET.SubElement(root,'CORES_DIRS').text = '$'.join(envir.CORES_DIRS)
	ET.SubElement(root,'VERBOSITY').text = str(envir.VERBOSITY)
	ET.SubElement(root,'XML_PATH').text = str(envir.XML_PATH)
	ET.SubElement(root,'XML_NAME').text = str(envir.XML_NAME)
	ET.SubElement(root,'HA_BIN').text = str(envir.HA_BIN)
	ET.SubElement(root,'MASTER_WORKDIR').text = str(envir.MASTER_WORKDIR)
	ET.SubElement(root,'MASTER').text = str(envir.MASTER)



	tree = ET.tostring(root,'UTF-8')
	tree = minidom.parseString(tree).toprettyxml(indent="\t")

	path = os.path.join(envir.XML_PATH,envir.XML_NAME)

	f = open(path,'w')
	f.write(tree)
	f.close()

def parse_xml():
	'''
	Parse envir.xml file
	'''
	path= os.path.join(envir.XML_PATH,envir.XML_NAME)
	root = ET.parse(path).getroot()

	for t in root:
		if t.tag == 'DEST':
			envir.DEST = t.text
		if t.tag == 'FROM_TIME':
			envir.FROM_TIME = int(t.text )
		if t.tag == 'TO_TIME':
			envir.TO_TIME = int(t.text)
		if t.tag == 'USER_NODES':
			envir.USER_NODES = t.text.split('$')
		if t.tag == 'HA_LOG':
			envir.HA_LOG = t.text
		if t.tag == 'UNIQUE_MSG':
			envir.UNIQUE_MSG = t.text
		if t.tag == 'SANITIZE':
			envir.SANITIZE = t.text.split('$')
		if t.tag == 'DO_SANITIZE':
			envir.DO_SANIZITE = int(t.text)
		if t.tag == 'SKIP_LVL':
			envir.SKIP_LVL = int(t.text)
		if t.tag == 'EXTRA_LOGS':
			envir.EXTRA_LOGS = t.text.split('$')
		if t.tag == 'PCMK_LOG':
			envir.PCMK_LOG = t.text
		if t.tag == 'USER_CLUSTER_TYPE':
			envir.USER_CLUSTER_TYPE = t.text
		if t.tag == 'CONF':
			envir.CONF = t.text
		if t.tag == 'B_CONF':
			envir.B_CONF = t.text
		if t.tag == 'PACKAGES':
			envir.PACKAGES = t.text.split('$')
		if t.tag == 'CORES_DIRS':
			envir.CORES_DIRS = t.text.split('$')
		if t.tag == 'VERBOSITY':
			envir.VERBOSITY = int(t.text)
		if t.tag == 'XML_NAME':
			envir.XML_NAME = t.text
		if t.tag == 'XML_PATH':
			envir.XML_PATH = t.text
		if t.tag == 'HA_BIN':
			envir.HA_BIN = t.text
		if t.tag == 'MASTER_WORKDIR':
			envir.MASTER_WORKDIR = t.text
		if t.tag == 'MASTER':
			envir.MASTER = t.text

def check_user():
	'''
	hb_report force user run as root
	so run it, the user shoule be check
	'''
	euid = os.geteuid()
	if euid:
		fatal('Please run hb_report as root!')
	
def do_rm(nodes,filepath):
	'''
	Remove file base on path absolute path filepath
	'''
	if not os.path.isfile(filepath):
		debug(nodes+': '+filepath+'is not exits')
		return False
	os.remove(filepath)
	debug(nodes+' remove file :'+filepath)
	return True

def crm_info():
	'''
	Get crmd version
	'''
	crm_pro = subprocess.Popen([envir.CRM_DAEMON_DIR+'/crmd','version'],stdout = subprocess.PIPE,stderr = subprocess.STDOUT)
	return crm_pro.communicate()[0]


def do_command(argv):
	'''
	call subprocess do 
	'''
	command = argv[0]
	comm_list = argv

	if not do_which(command):
		debug(command+' is not found')
		msg = command+' : command not found'
		return msg

	com_pro = subprocess.Popen(comm_list,stdout = subprocess.PIPE,stderr = subprocess.STDOUT)

	msg = com_pro.communicate()[0]
	return msg

def pkg_ver_deb():
	argv = ['dpkg-query','-f',"${Name} ${Version}",'-W']
	argv.extend(envir.PACKAGES)

	msg = do_command(argv)

	return msg

def pkg_ver_pkg_info():
	#TODO
	pass
def pkg_ver_pkginfo():
	#TODO
	pass

def pkg_ver_rpm():
	argv = ['rpm','-q','--qf',"%{name} %{version}-%{release} - %{distribution} %{arch}\n"]
	argv.extend(envir.PACKAGES)

	rpm_pro = subprocess.Popen(argv,stdout = subprocess.PIPE,stderr = subprocess.STDOUT)
	grep_pro = subprocess.Popen(['grep','-v',"not installed"],stdin = rpm_pro.stdout,stdout = subprocess.PIPE)

	pkg_info = grep_pro.communicate()[0]

	return pkg_info

def pkg_version():
	pkg_mgr = get_pkg_mgr()

	if not len(pkg_mgr):
		debug('pkg_mgr not found')
		return

	debug('the package manager is '+pkg_mgr)

	func = globals()['pkg_ver_'+pkg_mgr]
	pkg_info = func()

	return pkg_info

def get_pkg_mgr():
	
	if do_which('dpkg'):
		pkg_mgr = 'deb'
	elif do_which('rpm'):
		pkg_mgr = 'rpm'
	elif do_which('pkg_info'):
		pkg_mgr = 'pkg_info'
	elif do_which('pkginfo'):
		pkg_mgr ='pkginfo'
	else:
		warning('Unknown package manager!')
		return

	return pkg_mgr

def verify_rpm():
	argv = ['rpm','--verify']
	argv.extend(envir.PACKAGES)

	rpm_pro = subprocess.Popen(argv,stdout = subprocess.PIPE,stderr = subprocess.STDOUT)
	grep_pro = subprocess.Popen(['grep','-v',"not installed"],stdin = rpm_pro.stdout,stdout = subprocess.PIPE,stderr = subprocess.STDOUT)

	rpm_msg = grep_pro.communicate()[0]
	return rpm_msg

def verify_deb():
	argv = ['debsums','-s']
	argv.extend(envir.PACKAGES)

	deb_info = do_command(argv)

	return deb_info

def verify_pkg_info():
	'''
	Do not need to get
	'''
	pass

def verify_pkginfo():
	'''
	Do not need to get
	'''
	pass

def verify_packages():
	pkg_mgr = get_pkg_mgr()

	if not len(pkg_mgr):
		return
	func = globals()['verify_'+pkg_mgr]
	vrf_info = func()

	return vrf_info

def distro():
	distro_msg = do_command(['lsb_release','-d'])

	if len(distro_msg):
		debug('using lsb_release for distribution info')
		return distro_msg

	if os.path.isdir('/etc/debain_version/'):
		relf = do_command(['ls','/etc/debain_version/'])
	elif os.path.isdir('/etc/slackware-version'):
		relf = do_command(['ls','/etc/slackware-version'])
	else:
		relf = do_command(['ls','-d','/etc/*-release'])
	
	if len(relf):
		for f in relf.split():
			msg = do_command(['ls',f])
			msg = msg + do_command(['cat',f])
			return msg
	
	warning('no lsb_release, no /etc/*-release, no /etc/debain_version: no distro information')

def writefile(path,msg):
	try:
		f = open(path,'w')
		f.write(msg)
		f.close()
	except IOError as msg:
		fatal(msg)
	except:
		faral('Can not collect file :'+path+'on '+socket.gethostname())

def get_membership_tool():
	mem_tool = ['ccm_tool','crm_node']

	for m in mem_tool:
		if do_which(m):
			return m

def dumpstate(workdir):
	crm_pro = subprocess.Popen(['crm_mon','-1'],stdout = subprocess.PIPE,stderr = subprocess.STDOUT)
	grep_pro = subprocess.Popen(['grep','-v',"^Last upd"],stdin = crm_pro.stdout,stderr = subprocess.STDOUT,stdout = subprocess.PIPE)

	crm_info = grep_pro.communicate()[0]

	writefile(os.path.join(workdir,envir.CRM_MON_F),crm_info)

	cib_info = do_command(['cibadmin','-Ql'])
	writefile(os.path.join(workdir,envir.CIB_F),cib_info)
	
	mem_tool = get_membership_tool()
	mbsp_info = do_command([mem_tool,envir.MEMBERSHIP_TOOL_OPTS,'-p'])
	writefile(os.path.join(workdir,envir.MEMBERSHIP_F),mbsp_info)

def getconfig(workdir):
	if os.path.isfile(envir.CONF):
		shutil.copyfile(envir.CONF,os.path.join(workdir,os.path.basename(envir.CONF)))
	
	if os.path.isfile(envir.LOGD_CF):
		shutil.copyfile(envir.LOGD_CF,os.path.join(workdir,os.path.basename(envir.LOGD_CF)))

	if iscrmrunning():
		dumpstate(workdir)
		writefile(os.path.join(workdir,'RUNNING'),'')
	else:
		shutil.copyfile(os.path.join(envir.CIB_DIR,envir.CIB_F),os.path.join(workdir,envir.CIB_F))
		writefile(os.path.join(workdir,'STOPPED'),'')

	if len(envir.HOSTCACHE):
		if os.path.isfile(os.path.join(envir.HA_VARLIB,'hostcache')):
			shutil.copyfile(os.path.join(envir.HA_VARLIB,'hostcache'),os.path.join(workdir,envir.HOSTCACHE))

	if len(envir.HB_UUID_F):
		crm_uuid_info = do_command(['crm_uuid','-r'])
		writefile(os.path.join(workdir,envir.HB_UUID_F),crm_uuid_info)

	if os.path.isfile(os.path.join(workdir,envir.CIB_F)):
		verify_info = do_command(['crm_verify','-V','-x',os.path.join(workdir,envir.CIB_F)])
		writefile(os.path.join(workdir,envir.CRM_VERIFY_F),verify_info)

def touchfile(time):
	tmp = tempfile.mkstemp()[1]
	os.utime(tmp,(time,time))

	return tmp

def add_tmpfiles(files):
	if not os.path.isfile(envir.__TMPFLIST):
		return
	f = open(envir.__TMPFLIST,'a')
	f.write(files)
	f.close


def find_files(dirs):
	from_time = envir.FROM_TIME
	to_time = envir.TO_TIME

	if from_time <= 0:
		warning('sorry, can\'t find files based on time if you don\'t supply time')
		return
	from_stamp = touchfile(from_time)

	if not len(from_stamp):
		warning("Can't create temporary files")
		return
	add_tmpfiles(from_stamp)
	findexp = '-newer '+from_stamp

	if to_time > 0:
		to_stamp = touchfile(to_time)
		
		if not len(to_stamp):
			warning("Can't create temporary files")
			return
		add_tmpfiles(to_stamp)

		findexp = findexp + ' ! -newer '+to_stamp
		command = ['find']
		command.extend(dirs)
		command.append('-type')
		command.append('f')
		command.extend(findexp.split())
		msg = do_command(command)

		return msg.split('\n')

def crmconfig(workdir):
	if os.path.isfile(os.path.join(workdir,envir.CIB_F)):
		if do_which('crm'):
			CIB_file = os.path.join(workdir,envir.CIB_F)
			cibconfig_info = do_command(['crm','configure','show'])
			writefile(os.path.join(workdir,envir.CIB_TXT_F),cibconfig_info)

def getbt(flist,output):
	corefile = ''

	if not do_which('gdb'):
		warning('please install gdb to get backtraces')
		return
	#TODO
	#utillib.sh getbt

def num_id(passwd,uid):
	get_pro = subprocess.Popen(['getent',passwd,uid],stdout = subprocess.PIPE,stderr = subprocess.STDOUT)
	awk_pro = subprocess.Popen(['awk','-F:',"{print $3}"],stdin = get_pro.stdout,stdout = subprocess.PIPE)
	n_uid = awk_pro.communicate()[0]
	return n_uid 

def chk_id(ids,n_id):
	if n_id != 0:
		return False
	print ids,'is not found'
	return True
	

def check_perms(output,sla):
	msg = ''
	support =  __import__(sla.import_support())
	file_info = support.essential_files()
	
	for types,f,p,uid,gid in file_info:
		if types == 'f':
			if not os.path.isfile(f):
				utillib.debug(f+' wrong type or doesn\'t exist')
				continue
		else:
			if not os.path.isdir(f):
				utillib.debug(f+" wrong type or doesn't exist")
				continue

		n_uid = num_id('passwd',uid)
		if  chk_id(uid,n_uid):
			continue

		n_gid = num_id('group',gid)
		if chk_id(gid,n_gid):
			continue
		
		if not pl_checkperms(f,p,n_uid,n_gid):
			msg = msg+'wrong permissions or ownership for '+f
			ls_info = do_command(['ls','-ld',f])
			msg = msg+'\n'+str(ls_info)

	writefile(output,msg)

def pl_checkperms(filename,perms,in_uid,in_gid):
	mode = os.stat(filename).st_mode
	uid = os.stat(filename).st_uid
	gid  = os.stat(filename).st_gid
	
	if oct((mode & 07777)) != perms:
		return False

	try:
		if int(uid) != int(in_uid):
			print int(uid),int(in_uid)
			return False

		if int(gid) != int(in_gid):
			print int(gid),int(in_gid)
			return False
	except ValueError:
		#uid or gid aren't numeric
		return False

	return True

def is_sensitive_xml(files):
	
	for patt in envir.SANITIZE:
		ret = do_command(['egrep','-s','name="'+patt+'"',files])
		if len(ret):
			return True
	
	return False

def test_sensitive_one(files):
	'''
	Unsupport files are compressed, just like sentive_one 
	'''
	return is_sensitive_xml(files)


def sanitize_hacf():
	print 'call function sanitize_hacf from utillib module'

def sanitize_xml_attr(files):
	'''
	Unsupport files are compressed, line gzip ang  bzip2
	Need to be finished
	'''
	source = open(files,'r')
	lines = source.readlines()
	source.close()

	source = open(files,'w')
	
	for msg in lines:
		for patt in envir.SANITIZE:
			if re.search('name="'+patt+'"',msg):
				msg = re.sub('value="[^"]*"','value="****"',msg)

		source.write(msg)

def sanitize_one(files):

	if os.path.basename(files) == 'ha.cf':
		sanitize_hacf()
	else:
		sanitize_xml_attr(files)

def getstamp_syslog(message):
	return ''.join(message.split()[0:2])

def find_getstampproc(sla,filepath):
	'''
	Now  we do not need to get log from /var/log/messages and /var/log/pacemaker.log
	'''
	pass

def remove_files(nodes):
	for f in nodes.RM_FILES:
		if os.path.isfile(f):
			os.remove(f)
		elif os.path.isdir(f):
			shutil.rmtree(f)

def is_socket(path):
	'''
	True if path exists and is socket
	'''
	if os.path.exists(path):
		mode = os.stat(path).st_mode
		if stat.S_ISSOCK(mode):
			return True
	return False

