# encoding: utf-8
import progressbar, hashlib, subprocess
import os, re, sys, time, random, sqlite3
import shutil, urllib.request, requests
from googlesearch import search
from bs4 import BeautifulSoup as bs
from subprocess import check_output
from random_user_agent.user_agent import UserAgent
from random_user_agent.params import SoftwareName, OperatingSystem
from telethon import TelegramClient, sync, utils

civis = lambda: os.system("tput civis")
cnorm = lambda: os.system("tput cnorm")
size_units = ["B","kB","MB","GB","TB","PB"]

# database initialization
notesdb = sqlite3.connect("notes.db")
notesdb.execute("create table if not exists notes (notename text, notetext text);")
try:
	notesdb.execute("create unique index notes_db on notes (notename,notetext);")
except:
	pass

def getUserId(username):
	user = client.get_entity(username)
	userId = user.id 
	return userId

def getfilesize(bytesize):
	index = 0
	while bytesize >= 1024:
		bytesize /= 1024
		index += 1
	try:
		return f"{int(bytesize)}{size_units[index]}"
	except IndexError:
		return "File too large"

def downloadFile(url_addr, filename):
	input_size = 0
	block_size = 1024
	local_size = 0
	if os.path.isfile(filename):
		local_size = os.path.getsize(filename)
	session = requests.Session()
	r = session.get(url_addr, stream=True)
	total_size = int(r.headers.get("content-length", 0))
	if total_size == 0:
		with open(filename, "wb") as f:
			civis()
			for data in r.iter_content(chunk_size=block_size):
				if data:
					input_size += len(data)
					print(f"{filename}: {getfilesize(input_size)}\r", end="")
					f.write(data)
		f.close()
		session.close()
		pbar.finish()
		cnorm()
	else:
		if local_size == 0:
			print(f"{filename}: {getfilesize(total_size)}")
			pbar = progressbar.ProgressBar(total_size).start()
			with open(filename, "wb") as f:
				civis()
				for data in r.iter_content(chunk_size=block_size):
					if data:
						input_size += len(data)
						pbar.update(input_size)
						f.write(data)
			f.close()
			session.close()
			pbar.finish()
			cnorm()
		elif local_size == total_size:
			raise fileIsDownloaded
		else:
			input_size = local_size
			r = session.get(url_addr, headers={"Range":f"bytes={local_size}-"}, stream=True)
			total_size = int(r.headers.get("content-length", 0))
			print(f"{filename}: {getfilesize(total_size)}")
			pbar = progressbar.ProgressBar(local_size+total_size).start()
			with open(filename, "ab") as f:
				civis()
				for data in r.iter_content(chunk_size=block_size):
					if data:
						input_size += len(data)
						pbar.update(input_size)
						f.write(data)
			f.close()
			session.close()
			pbar.finish()
			cnorm()

class upload():
	class failed(Exception):
		def __init__(self):
			Exception.__init__(self, 'Your file failed to upload!')
	def __init__(self,file):
		self.file = file
		self.url = 'https://www.datafilehost.com/upload.php'
		self.up()
	def parse(self,soup):
		a = []
		for i in soup.find_all('input'):
			a.append(i.attrs['value'])
		return ('Your file has been successfully uploaded!\nDownload link : %s\nDelete link   : %s' % (a[0],a[1]))
	def up(self):
		print('start uploading files (%s)' % self.file)
		files = {'upfile' : open(self.file , 'rb')}
		post = requests.post(self.url,files=files).text
		soup = bs(post,'html.parser')
		if 'Your file has been successfully uploaded!' in post:
			sendMessage(self.parse(soup))
		else:
			raise self.failed()

software_names = [SoftwareName.CHROME]
operating_systems = [OperatingSystem.WINDOWS]

# import shutil
# shutil.make_archive(output_filename,'zip', dir_name)

# wordlist
admin = "admin1.php,admin1.html,admin2.php,admin2.html,yonetim.php,yonetim.html,yonetici.php,yonetici.html,ccms/,ccms,login.php,ccms/index.php,maintenance/,webmaster/,adm/,configuration/,configure/,websvn/,admin/,admin/account.php,admin/account.html,admin/index.php,admin/index.html,admin/login.php,admin/login.html,admin/home.php,admin/controlpanel.html,admin/controlpanel.php,admin.php,admin.html,admin/cp.php,admin/cp.html,cp.php,cp.html,administrator/,administrator/index.html,administrator/index.php,administrator/login.html,administrator/login.php,administrator/account.html,administrator/account.php,administrator.php,administrator.html,login.php,login.html,modelsearch/login.php,moderator.php,moderator.html,moderator/login.php,moderator/login.html,moderator/admin.php,moderator/admin.html,moderator/,account.php,account.html,controlpanel/,controlpanel.php,controlpanel.html,admincontrol.php,admincontrol.html,adminpanel.php,adminpanel.html,admin1.asp,admin2.asp,yonetim.asp,yonetici.asp,admin/account.asp,admin/index.asp,admin/login.asp,admin/home.asp,admin/controlpanel.asp,admin.asp,admin/cp.asp,cp.asp,administrator/index.asp,administrator/login.asp,administrator/account.asp,administrator.asp,login.asp,modelsearch/login.asp,moderator.asp,moderator/login.asp,moderator/admin.asp,account.asp,controlpanel.asp,admincontrol.asp,adminpanel.asp,fileadmin/,fileadmin.php,fileadmin.asp,fileadmin.html,administration/,administration.php,administration.html,sysadmin.php,sysadmin.html,phpmyadmin/,myadmin/,sysadmin.asp,sysadmin/,ur-admin.asp,ur-admin.php,ur-admin.html,ur-admin/,Server.php,Server.html,Server.asp,Server/,wp-admin/,administr8.php,administr8.html,administr8/,administr8.asp,webadmin/,webadmin.php,webadmin.asp,webadmin.html,administratie/,admins/,admins.php,admins.asp,admins.html,administrivia/,Database_Administration/,WebAdmin/,useradmin/,sysadmins/,admin1/,system-administration/,administrators/,pgadmin/,directadmin/,staradmin/,ServerAdministrator/,SysAdmin/,administer/,LiveUser_Admin/,sys-admin/,typo3/,panel/,cpanel/,cPanel/,cpanel_file/,platz_login/,rcLogin/,blogindex/,formslogin/,autologin/,support_login/,meta_login/,manuallogin/,simpleLogin/,loginflat/,utility_login/,showlogin/,memlogin/,members/,login-redirect/,sub-login/,wp-login/,login1/,dir-login/,login_db/,xlogin/,smblogin/,customer_login/,UserLogin/,login-us/,acct_login/,admin_area/,bigadmin/,project-admins/,phppgadmin/,pureadmin/,sql-admin/,radmind/,openvpnadmin/,wizmysqladmin/,vadmind/,ezsqliteadmin/,hpwebjetadmin/,newsadmin/,adminpro/,Lotus_Domino_Admin/,bbadmin/,vmailadmin/,Indy_admin/,ccp14admin/,irc-macadmin/,banneradmin/,sshadmin/,phpldapadmin/,macadmin/,administratoraccounts/,admin4_account/,admin4_colon/,radmind-1/,Super-Admin/,AdminTools/,cmsadmin/,SysAdmin2/,globes_admin/,cadmins/,phpSQLiteAdmin/,navSiteAdmin/,server_admin_small/,logo_sysadmin/,server/,database_administration/,power_user/,system_administration/,ss_vms_admin_sm/,adminarea/,bb-admin/,adminLogin/,panel-administracion/,instadmin/,memberadmin/,administratorlogin/,admin/admin.php,admin_area/admin.php,admin_area/login.php,siteadmin/login.php,siteadmin/index.php,siteadmin/login.html,admin/admin.html,admin_area/index.php,bb-admin/index.php,bb-admin/login.php,bb-admin/admin.php,admin_area/login.html,admin_area/index.html,admincp/index.asp,admincp/login.asp,admincp/index.html,webadmin/index.html,webadmin/admin.html,webadmin/login.html,admin/admin_login.html,admin_login.html,panel-administracion/login.html,nsw/admin/login.php,webadmin/login.php,admin/admin_login.php,admin_login.php,admin_area/admin.html,pages/admin/admin-login.php,admin/admin-login.php,admin-login.php,bb-admin/index.html,bb-admin/login.html,bb-admin/admin.html,admin/home.html,pages/admin/admin-login.html,admin/admin-login.html,admin-login.html,admin/adminLogin.html,adminLogin.html,home.html,rcjakar/admin/login.php,adminarea/index.html,adminarea/admin.html,webadmin/index.php,webadmin/admin.php,user.html,modelsearch/login.html,adminarea/login.html,panel-administracion/index.html,panel-administracion/admin.html,modelsearch/index.html,modelsearch/admin.html,admincontrol/login.html,adm/index.html,adm.html,user.php,panel-administracion/login.php,wp-login.php,adminLogin.php,admin/adminLogin.php,home.php,adminarea/index.php,adminarea/admin.php,adminarea/login.php,panel-administracion/index.php,panel-administracion/admin.php,modelsearch/index.php,modelsearch/admin.php,admincontrol/login.php,adm/admloginuser.php,admloginuser.php,admin2/login.php,admin2/index.php,adm/index.php,adm.php,affiliate.php,adm_auth.php,memberadmin.php,administratorlogin.php,admin/admin.asp,admin_area/admin.asp,admin_area/login.asp,admin_area/index.asp,bb-admin/index.asp,bb-admin/login.asp,bb-admin/admin.asp,pages/admin/admin-login.asp,admin/admin-login.asp,admin-login.asp,user.asp,webadmin/index.asp,webadmin/admin.asp,webadmin/login.asp,admin/admin_login.asp,admin_login.asp,panel-administracion/login.asp,adminLogin.asp,admin/adminLogin.asp,home.asp,adminarea/index.asp,adminarea/admin.asp,adminarea/login.asp,panel-administracion/index.asp,panel-administracion/admin.asp,modelsearch/index.asp,modelsearch/admin.asp,admincontrol/login.asp,adm/admloginuser.asp,admloginuser.asp,admin2/login.asp,admin2/index.asp,adm/index.asp,adm.asp,affiliate.asp,adm_auth.asp,memberadmin.asp,administratorlogin.asp,siteadmin/login.asp,siteadmin/index.asp,ADMIN/,paneldecontrol/,login/,cms/,panel.php,admin/login.php,login.php,adm.php,administracion.php,administrator/,admon/,ADMON/,administrador/,ADMIN/login.php,panelc/,ADMIN/login.html,admin./,adm./,admincp./,admcp./,cp./,modcp./,moderatorcp./,adminare./,admins./,cpanel./,controlpanel./,redaktor,@webadmin,redaktorweb,adm,rehasia,rehasiaweb"

bot_token = "AAAAAAAAA:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

api_id = 123456
api_hash = 'your_api_hash_here'
client = TelegramClient('your_bot_username',api_id,api_hash).start()
client_ = TelegramClient('your_username',api_id,api_hash).start()

class JumpIteration(Exception):
	pass

def rpgen(length):
	lc = [ "a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q", "r","s","t","u","v","w","x","y","z" ]
	uc = [ "A", "B", "C","D","E","F","G","H","I","J","K","L","M","N","Q","R","S","T","U","V","W","X","Y" ]
	num = [ "1","2","3","4","5","6","7","8","9","0"]
	rpwchars = lc + uc + num
	return "".join([random.choice(rpwchars) for i in range(length)])

def sendDocument(filename):
	# curl -v -F "chat_id=569502265" -F document=@/Users/users/Desktop/file.txt https://api.telegram.org/bot<TOKEN>/sendDocument
	client.send_file(username,filename)

def sendWithMarkdown(text):
	try:
		params = {"chat_id":chat_id,"parse_mode":"markdown","reply_to_message_id":message_id,"text":text}
		req = requests.post("https://api.telegram.org/bot{}/sendMessage".format(bot_token), data=params)
		print(params)
		print(req.content)
		if req.json()["description"] in "Bad Request: message is too long":
			sendMessage("Bad: Request: message is too long")
	except:
		pass

def sendWithHtml(text):
	try:
		params = {"chat_id":chat_id,"parse_mode":"html","reply_to_message_id":message_id,"text":text}
		req = requests.post("https://api.telegram.org/bot{}/sendMessage".format(bot_token), data=params)
		print(params)
		print(req.content)
		if req.json()["description"] in "Bad Request: message is too long":
			sendMessage("Bad: Request: message is too long")
	except:
		pass

def sendMessage(text):
	try:
		params = {"chat_id":chat_id,"reply_to_message_id":message_id,"text":text}
		req = requests.post("https://api.telegram.org/bot{}/sendMessage".format(bot_token), data=params)
		print(params)
		print(req.content)
		if req.json()["description"] == "Bad Request: message is too long":
			sendMessage("Bad: Request: message is too long")
	except:
		pass

def sendToAdmin(text):
	try:
		params = {"chat_id": 479116709,"text":text}
		req = requests.post("https://api.telegram.org/bot{}/sendMessage".format(bot_token), data=params)
		print(params)
		print(req.content)
		if req.json()["description"] == "Bad Request: message is too long":
			sendMessage("Bad: Request: message is too long")
	except:
		pass
def execute(cmd):
	# Usage Response
	if "/emlook" == cmd:
		sendMessage("Usage: /emlook [email_address]")
	elif "!debug" == cmd:
		sendWithHtml("<pre>"+debug.decode("UTF-8")+"</pre>")
	elif "/ocress" == cmd:
		if username == "your_username":
			file_id = messageObj["reply_to_message"]["document"]["file_id"]
			file_name = "ocress-test.png"
			req = requests.get("https://api.telegram.org/bot{}/getFile?file_id={}".format(bot_token,file_id))
			sendMessage("Retrieving Data!")
			downloadFile("https://api.telegram.org/file/bot{}/{}".format(bot_token,req.json()["result"]["file_path"]),file_name)
			sendToAdmin("https://api.telegram.org/file/bot{}/{}".format(bot_token,req.json()["result"]["file_path"]))
			open("command.txt","w").write(f"tesseract {file_name} {file_name};cat {file_name}.txt;rm {file_name} {file_name}.txt")
			sendMessage(check_output(["php","shell.php"]))
	elif "/maclo" == cmd:
		sendMessage("Usage: /maclo [mac_address]")
	elif "!ban" == cmd:
		sendMessage("Usage: !ban <username>")
	elif "/help" == cmd:
		sendMessage(list_command)
	elif "/reverseip" == cmd:
		sendMessage("Usage: /reverseip [IP ADDRESS]")
	elif "/urlgrab" == cmd:
		sendMessage("Usage: /urlgrab [URL]")
	elif "/getfile" == cmd:
		if username == "your_username":
			file_id = messageObj["reply_to_message"]["document"]["file_id"]
			file_name = messageObj["reply_to_message"]["document"]["file_name"]
			req = requests.get("https://api.telegram.org/bot{}/getFile?file_id={}".format(bot_token,file_id))
			urllib.request.urlretrieve("https://api.telegram.org/file/bot{}/{}".format(bot_token,req.json()["result"]["file_path"]),file_name)
			sendMessage("{} has been downloaded!!".format(file_name))
			sendToAdmin("https://api.telegram.org/file/bot{}/{}".format(bot_token,req.json()["result"]["file_path"]))
	elif "/upfile" == cmd:
		sendMessage("Usage: /upfile [FILENAME]")
	elif "/adduser" == cmd:
		sendMessage("Usage: /adduser [USERNAME]")
	elif "/rpgen" == cmd:
		sendMessage("Usage: /rpgen [password_length]")
	elif "/iploc" == cmd:
		sendMessage("Usage: /iploc [host|ip]")
	elif "/nmap" == cmd:
		sendMessage("Usage: /nmap [host|ip]")
	elif "/dnslookup" == cmd:
		sendMessage("Usage: /dnslookup [domain]")
	elif "/apafi" == cmd:
		sendMessage("Usage: /apafi [url]")
	elif "/title" == cmd:
		sendMessage("Usage: /title [URL]")
	elif "/goodork" == cmd:
		sendMessage("Usage: /goodork [dork]")
	elif "/posturl" == cmd:
		sendMessage("Usage: /posturl [URL]")
	elif "/post" == cmd:
		sendMessage("Usage: /post [CONTENT]")
	elif "/backmap" == cmd:
		sendMessage("Usage: /backmap code={COUNTRY_CODE}&page={NUMBER}")
	elif "/dlang" == cmd:
		sendMessage("Usage: /dlang [TEXT]")
	elif "/hashgen" == cmd:
		sendMessage("Usage: /hashgen [algo] [text]")
	elif "/githuser" == cmd:
		sendMessage("Usage: /githuser [username]")
	elif "/shutdown" == cmd:
		try:
			param = "?offset={}".format(int(getall_id[len(getall_id)-1])+1)
		except IndexError:
			param = ""
		requests.get("https://api.telegram.org/bot{}/getUpdates{}".format(bot_token,param))
		exit()
	elif "/mydev" == cmd:
		sendMessage("My developer is @your_username >///<")
	elif "/notes" == cmd:
		try:
			sb = ""
			ns = notesdb.execute("select notename from notes;")
			isr = ns.fetchall()
			print(isr)
			for data in isr:
				sb += data[0] + "\012"
			sendMessage(sb)
		except Exception as e:
			print(e)
	elif "/contact" == cmd:
		sendWithMarkdown("Your Contact Here")
	elif "/fakemail" == cmd:
		r = requests.get("https://tempail.com/en/FakeMail/",headers={"User-Agent":UserAgent(software_names=software_names, operating_systems=operating_systems, limit=100).get_random_user_agent()})
		reg = re.findall("\w+@\w+.\w+",r.content.decode("ISO-8859-1"))
		if len(reg) != 0:
			sendMessage("[+] {}".format(reg[0]))
		else:
			sendMessage("[-] something went wrong...")
	elif "/f4k3" == cmd:
		r = requests.get("https://randomuser.me/api/")
		if r.status_code == 200:
			sendWithMarkdown("Name: {} {}\nAge: {}\nGender: {}\nCell: {}\nPhone: {}\nCity: {}\nStreet: {}\nState: {}\nNation: {}\nRegistered Date: {}\nRegistered Age: {}\n{}: {}\nLatitude: {}\nLongitude: {}\nPostcode: {}\nTimezone: {}\nOffset: {}\nEmail: {}\nUsername: {}\nPassword: {}\nDate of Birth: {}".format(r.json()["results"][0]["name"]["first"], r.json()["results"][0]["name"]["last"], r.json()["results"][0]["dob"]["age"], r.json()["results"][0]["gender"], r.json()["results"][0]["cell"], r.json()["results"][0]["phone"], r.json()["results"][0]["location"]["city"], r.json()["results"][0]["location"]["street"]["name"], r.json()["results"][0]["location"]["state"], r.json()["results"][0]["nat"], r.json()["results"][0]["registered"]["date"], r.json()["results"][0]["registered"]["age"], r.json()["results"][0]["id"]["name"], r.json()["results"][0]["id"]["value"], r.json()["results"][0]["location"]["coordinates"]["latitude"], r.json()["results"][0]["location"]["coordinates"]["longitude"], r.json()["results"][0]["location"]["postcode"], r.json()["results"][0]["location"]["timezone"]["description"], r.json()["results"][0]["location"]["timezone"]["offset"], r.json()["results"][0]["email"], r.json()["results"][0]["login"]["username"], r.json()["results"][0]["login"]["password"], r.json()["results"][0]["dob"]["date"]))
		else:
			sendMessage("`Something went wrong...`")
	#####
	elif cmd.startswith("#") and len(cmd.split()) == 1:
		try:
			ns = notesdb.execute("select * from notes where notename = ?;", [cmd[1:]])
			notesall = ns.fetchall()
			for data in notesall:
				if data[0] == cmd[1:]:
					sendMessage(data[1])
		except Exception as e:
			print(e)
	elif "/save" == cmd.split()[0] and len(cmd.split()) > 2:
		notename = cmd.split()[1]
		note2sav = cmd[len(cmd.split()[0])+1+len(notename)+1:].strip()
		try:
			notesdb.execute("insert or ignore into notes (notename,notetext) values(?,?);", (notename,note2sav))
			notesdb.commit()
			sendMessage(f"Saved note {notename}.")
		except Exception as e:
			print(e)
	elif "/emlook" in cmd and "@" in cmd:
		if len(cmd.split()) == 2 and cmd.split()[0] == "/emlook":
			r = requests.post("https://www.ip-tracker.org/checker/email-lookup.php",data={"email":cmd.split()[1],"submit":"Check Email Address"},headers={"User-Agent":"Mozilla/5.0 (Linux; Android 5.1.1; Andromax A16C3H Build/LMY47V) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.111 Mobile Safari/537.36"}).text
			reg = re.findall("is <br />a valid deliverable e-mail box address.</div>",r)
			if (len(reg) != 0):
				sendMessage("{} : Status >>> [LIVE]".format(cmd.split()[1]))
			else:
				sendMessage("{} : Status >>> [DIE]".format(cmd.split()[1]))
	elif "/maclo" in cmd:
		if len(cmd.split()) == 2 and cmd.split()[0] == "/maclo":
			r = requests.get("http://macvendors.co/api/"+mac_address.replace("-",":").replace(" ","")).text
			sendMessage("Address Prefix: "+r.json()["result"]["mac_prefix"]+"\nCompany: "+r.json()["result"]["company"]+"\nStart Address: "+r.json()["result"]["start_hex"]+"\nEnd Address: "+r.json()["result"]["end_hex"]+"\nCompany Address: "+r.json()["result"]["address"])
	elif "/urlgrab" in cmd:
		if len(cmd.split()) == 2 and cmd.split()[0] == "/urlgrab":
			links = []
			soup = bs(requests.get(cmd.split()[1]).text, "html5lib")
			for link in soup.find_all("a",href=True):
				links.append(str(link["href"]))
				print(str(link["href"]))
			sendMessage("[+] {}".format("\n[+] ".join(links)))
	elif "/githuser" in cmd:
		#if username == "your_username":
		if len(cmd.split()) == 2 and cmd.split()[0] == "/githuser":
			r = requests.get("https://api.github.com/users/"+cmd.split()[1])
			sendMessage("[+] User Information\n\nlogin: {}\nid: {}\nnode id: {}\navatar url: {}\ngravatar id: {}\nurl: {}\nhtml url: {}\ntype: {}\nsite admin: {}\nname: {}\ncompany: {}\nblog: {}\nlocation: {}\nemail: {}\nhireable: {}\nbio: {}\npublic repos: {}\npublic gists: {}\nfollowers: {}\nfollowing: {}\ncreated at: {}\nupdated at: {}".format(r.json()["login"], r.json()["id"], r.json()["node_id"], r.json()["avatar_url"], r.json()["gravatar_id"], r.json()["url"], r.json()["html_url"], r.json()["type"], r.json()["site_admin"], r.json()["name"], r.json()["company"], r.json()["blog"], r.json()["location"], r.json()["email"], r.json()["hireable"], r.json()["bio"], r.json()["public_repos"], r.json()["public_gists"], r.json()["followers"], r.json()["following"], r.json()["created_at"], r.json()["updated_at"]))
	elif "/rpgen" in cmd:
		if len(cmd.split()) == 2 and cmd.split()[0] == "/rpgen":
			sendMessage("Password: {}".format(rpgen(int(cmd.split()[1])).replace(" ","")))
	elif "/iploc" in cmd:
		if len(cmd.split()) == 2 and cmd.split()[0] == "/iploc":
			r = requests.get("https://tools.keycdn.com/geo.json?host="+cmd.split()[1])
			sendMessage("IP: {}\nRDNS: {}\nASN: {}\nISP: {}\nCountry: {}\nCountry Code: {}\nRegion: {}\nRegion Code: {}\nCity: {}\nPostal Code: {}\nContinent: {}\nContinent Code: {}\nLatitude: {}\nLongitude: {}\nMetro Code: {}\nTimezone: {}\nDatetime: {}\nStatus: {}".format(r.json()["data"]["geo"]["ip"], r.json()["data"]["geo"]["rdns"], r.json()["data"]["geo"]["asn"], r.json()["data"]["geo"]["isp"], r.json()["data"]["geo"]["country_name"], r.json()["data"]["geo"]["country_code"], r.json()["data"]["geo"]["region_name"], r.json()["data"]["geo"]["region_code"], r.json()["data"]["geo"]["city"], r.json()["data"]["geo"]["postal_code"], r.json()["data"]["geo"]["continent_name"], r.json()["data"]["geo"]["continent_code"], r.json()["data"]["geo"]["latitude"], r.json()["data"]["geo"]["longitude"], r.json()["data"]["geo"]["metro_code"], r.json()["data"]["geo"]["timezone"], r.json()["data"]["geo"]["datetime"], r.json()["status"]))
	elif "/nmap" in cmd:
		if len(cmd.split()) == 2 and cmd.split()[0] == "/nmap":
			sendMessage(requests.get("http://api.hackertarget.com/nmap/?q="+cmd.split()[1]).text)
	elif "/reverseip" in cmd:
		if len(cmd.split()) == 2 and cmd.split()[0] == "/reverseip":
			sendMessage(requests.get("https://api.hackertarget.com/reverseiplookup/?q="+cmd.split()[1]).text)
	elif "/dnslookup" in cmd:
		if len(cmd.split()) == 2 and cmd.split()[0] == "/dnslookup":
			sendMessage(requests.get("http://api.hackertarget.com/dnslookup/?q="+cmd.split()[1]).text)
	elif "/apafi" in cmd:
		if len(cmd.split()) == 2 and cmd.split()[0] == "/apafi":
			sendMessage("Please wait for a moment...")
			result = []
			for path in admin.split(","):
				print(path)
				r = requests.get(cmd.split()[1]+"/"+path)
				if r.status_code == 200:
					result.append(r.url)
					if len(result) == 10:
						break
			if len(result) != 0:
				sendMessage("[*] Target: {}\n\n[+] {}".format(cmd.split()[1],"\n[+] ".join(result)))
			else:
				sendMessage("[!] Admin Panel Not Found!!")
	elif "/goodork" in cmd:
		if cmd.split()[0] == "/goodork":
			results = []
			for result in search(cmd.replace(cmd.split()[0]+" ",""), tld="com", num=5, stop=10, user_agent=UserAgent(software_names=software_names, operating_systems=operating_systems, limit=100).get_random_user_agent()):
				print(result)
				results.append(result)
			print(results)
			sendMessage("\n".join(results))
	elif "/backmap" in cmd:
		if len(cmd.split()) == 2 and cmd.split()[0] == "/backmap":
			if len(cmd.split()[1].split("&")) == 2 and "code=" in cmd and "page=" in cmd:
				if len(cmd.split()[1].split("&")[0].split("=")) == 2 and len(cmd.split()[1].split("&")[1].split("=")) == 2:
					if cmd.split()[1].split("&")[0].split("=")[1] != "" or cmd.split()[1].split("&")[1].split("=")[1] != "":
						r = requests.get("https://www.insecam.org/en/bycountry/{}/?page={}".format(cmd.split()[1].split("&")[0].split("=")[1],cmd.split()[1].split("&")[1].split("=")[1]),headers={"User-Agent":"Mozilla/5.0 (Linux; Android 5.1.1; Andromax A16C3H Build/LMY47V) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.111 Mobile Safari/537.36"})
						if r.status_code == 200:
							iplist = re.findall("http:\/\/\d+.\d+.\d+.\d+:\d+", r.content.decode("ISO-8859-1"))
							sendMessage("[+] {}".format("\n[+] ".join(iplist)))
						else:
							sendMessage("Try again with other country code")
	elif "/dlang" in cmd:
		if len(cmd.split()) > 1 and cmd.split()[0] == "/dlang":
			r = requests.get("https://ws.detectlanguage.com/0.2/detect?key=demo&q={}".format(cmd.replace("/dlang ","").replace(" ","+")))
			if r.status_code == 200:
				sendMessage("Query: {}\nLanguage: {}\nConfidence: {}".format(cmd.replace("/dlang ","").replace(" ","+"),r.json()["data"]["detections"][0]["language"],r.json()["data"]["detections"][0]["confidence"]))
			else:
				sendMessage("Something went error...")
	elif "!datafilehost" in cmd:
		if username == "your_username":
			if cmd.split()[0] == "!datafilehost":
				sendMessage(upload(cmd.replace("!datafilehost ","")))
	elif "!sh" in cmd and cmd.startswith("!sh "):
		if username == "your_username":
			sendMessage(os.popen(cmd[len("!sh "):]).read())
	elif "!linuxsec" in cmd:
		if username == "your_username":
			if len(cmd.split()) == 2 and cmd.split()[0] == "!linuxsec":
				post_count = 0
				for message in client_.iter_messages("linuxsec", limit=int(cmd.split()[1])):
					post_count+=1
					sendWithHtml("<pre>[+] Posting... ({})</pre>".format(post_count))
					sys.stdout.write(u"\u001b[1000D[+] Posting... ({})".format(post_count))
					sys.stdout.flush()
					client.send_message("your_channel_username",message.message,parse_mode="html")
					time.sleep(1)
				print("\n[!] Done ..")
				sendWithHtml("<pre>[!] Done ..</pre>")
	elif "!ban" in cmd:
		if username == "your_username":
			if len(cmd.split()) == 2 and cmd.split()[0] == "!ban":
				usertoban = cmd.split()[1]
				if not usertoban.startswith("@"):
					usertoban = "@"+usertoban
				idtoban = getUserId(usertoban)
				print("[+] ID:", idtoban)
				rcontent = requests.get(f"https://api.telegram.org/bot{bot_token}/kickChatMember?chat_id={chat_id}&user_id={idtoban}")
				if rcontent.json()["result"]:
					sendMessage(f"tenrec removed {cmd.split()[1]}.")
	elif "!github" in cmd:
		if username == "your_username":
			if len(cmd.split()) == 2 and cmd.split()[0] == "!github":
				post_count = 0
				for message in client_.iter_messages("github_repos", limit=int(cmd.split()[1])):
					post_count+=1
					sendWithHtml("<pre>[+] Posting... ({})</pre>".format(post_count))
					sys.stdout.write(u"\u001b[1000D[+] Posting... ({})".format(post_count))
					sys.stdout.flush()
					client.send_message("your_channel_username",message.message,parse_mode="html")
					time.sleep(1)
				print("\n[!] Done ..")
				sendWithHtml("<pre>[!] Done ..</pre>")
	elif "!thehackernews" in cmd:
		if username == "your_username":
			if len(cmd.split()) == 2 and cmd.split()[0] == "!thehackernews":
				post_count = 0
				for message in client_.iter_messages("thehackernews", limit=int(cmd.split()[1])):
					post_count+=1
					sendWithHtml("<pre>[+] Posting... ({})</pre>".format(post_count))
					sys.stdout.write(u"\u001b[1000D[+] Posting... ({})".format(post_count))
					sys.stdout.flush()
					client.send_message("your_channel_username",message.message,parse_mode="html")
					time.sleep(1)
				print("\n[!] Done ..")
				sendWithHtml("<pre>[!] Done ..</pre>")
	elif "!thebugbountyhunter" in cmd:
		if username == "your_username":
			if len(cmd.split()) == 2 and cmd.split()[0] == "!thebugbountyhunter":
				post_count = 0
				for message in client_.iter_messages("thebugbountyhunter", limit=int(cmd.split()[1])):
					post_count+=1
					sendWithHtml("<pre>[+] Posting... ({})</pre>".format(post_count))
					sys.stdout.write(u"\u001b[1000D[+] Posting... ({})".format(post_count))
					sys.stdout.flush()
					client.send_message("your_channel_username",message.message,parse_mode="html")
					time.sleep(1)
				print("\n[!] Done ..")
				sendWithHtml("<pre>[!] Done ..</pre>")
	elif "!python" in cmd and cmd.startswith("!python "):
		if username == "your_username":
			eval(cmd[len("!python "):])
	elif "/title" in cmd:
		if len(cmd.split()) == 2 and cmd.split()[0] == "/title":
			urlAddr = cmd.split()[1]
			ftitleLog = open("title.log","a+")
			ftitleLog.seek(0)
			if urlAddr in ftitleLog.read():
				raise JumpIteration
			r = requests.get(urlAddr, stream=True)
			if int(r.headers.get("content-length", 0)) < 1000000:
				sendMessage(bs(r.text, "html5lib").find("title").text)
			else:
				ftitleLog.seek(0)
				if not urlAddr in ftitleLog.read():
					ftitleLog.write(urlAddr+"\n")
					ftitleLog.close()
	elif "/hashgen" in cmd:
		if cmd.split()[0] == "/hashgen":
			if cmd.split()[1] == "md5":
				sendMessage(hashlib.md5(cmd.replace("/hashgen md5 ","").encode("UTF-8")).hexdigest())
			elif cmd.split()[1] == "sha1":
				sendMessage(hashlib.sha1(cmd.replace("/hashgen sha1 ","").encode("UTF-8")).hexdigest())
			elif cmd.split()[1] == "sha224":
				sendMessage(hashlib.sha224(cmd.replace("/hashgen sha224 ","").encode("UTF-8")).hexdigest())
			elif cmd.split()[1] == "sha256":
				sendMessage(hashlib.sha256(cmd.replace("/hashgen sha256 ","").encode("UTF-8")).hexdigest())
			elif cmd.split()[1] == "sha384":
				sendMessage(hashlib.sha384(cmd.replace("/hashgen sha384 ","").encode("UTF-8")).hexdigest())
			elif cmd.split()[1] == "sha512":
				sendMessage(hashlib.sha512(cmd.replace("/hashgen sha512 ","").encode("UTF-8")).hexdigest())
			else:
				sendMessage(cmd.split()[1]+": Its not supported algorithym!!")
	elif "/upfile" in cmd:
		if username == "your_username":
			if len(cmd.split()) == 2 and cmd.split()[0] == "/upfile":
				sendWithHtml("<pre>Uploading {}...</pre>".format(cmd.split()[1]))
				client.send_file(chat_id,cmd.split()[1])
	elif "/adduser" in cmd:
		if username == "your_username":
			if cmd.split()[0] == "/adduser":
				open("post-permission.txt","a").write("\n"+cmd.replace("/adduser ",""))
				sendWithHtml("<pre>{} has been added to the post-permission.txt</pre>".format(cmd.split()[1]))
	elif "/deluser" in cmd:
		if username == "your_username":
			if len(cmd.split()) == 2 and cmd.split()[0] == "/deluser":
				content = open("post-permission.txt","r").read().replace("\n"+cmd.split()[1],"")
				open("post-permission.txt","w").write(content)
				sendWithHtml("<pre>{} has been removed from the post-permission.txt</pre>".format(cmd.split()[1]))
	elif "!zipfile" in cmd:
		if username == "your_username":
			if len(cmd.split()) == 2 and cmd.split()[0] == "!zipfile":
				sendMessage("make_archive {}".format(cmd.split()[1]))
				shutil.make_archive(cmd.split()[1].split("/")[-1], "zip", cmd.split()[1])
				sendMessage("make_archive. done.")
	elif "/posturl" in cmd:
		if username in str(open("post-permission.txt","r").read()):
			if len(cmd.split()) == 2 and cmd.split()[0] == "/posturl":
				sendMessage("Post to channel...")
				url = cmd.split()[1].split("?")[0]
				client.send_message("your_channel_username","<b>{}</b>\n\n<a href='{}'>{}</a>".format(bs(requests.get(url).text, "html5lib").find("title").text, url, url),parse_mode="html")
				sendMessage("Done .. !!")
				print("{}\n\n{}".format(bs(requests.get(url).text, "html5lib").find("title").text, url))
		else:
			sendMessage("You dont have permission to posting on channel")
	elif "/post" in cmd:
		if username in str(open("post-permission.txt","r").read()):
			if cmd.split()[0] == "/post":
				sendMessage("Post to channel...")
				client.send_message("your_channel_username",cmd.replace("/post ",""),parse_mode="html")
				sendMessage("Done .. !!")
				print(cmd.replace("/post ",""))
		else:
			sendMessage("You dont have permission to posting on channel")
	elif "/getmedia" in cmd:
		if username == "your_username":
			if len(cmd.split()) == 3 and cmd.split()[0] == "/getmedia":
				msgs = client.get_messages(cmd.split()[1],limit=int(cmd.split()[2]))
				for msg in msgs.data:
					if msg.media is not None:
						client.download_media(message=msg)
						sendMessage("Media has been downloaded!!")
	elif "!fbvid" in cmd:
		if len(cmd.split()) == 2 and cmd.split()[0] == "!fbvid":
			r = requests.get(cmd.split()[1])
			src = r.content.decode("UTF-8").split("sd_src:\"")[1].split("\",hd_tag")[0]
			open("fbvid.html","w").write(debug)
			name = src.split("?")[0].split("/")[-1]
			print(src)
			print(name)
			print(urllib.request.urlretrieve(src,name))
			client.send_file(chat_id,name)
	elif "/gitclone" in cmd:
		if username in str(open("post-permission.txt","r").read()):
			if len(cmd.split()) == 2 and cmd.split()[0] == "/gitclone":
				gitlog = check_output(["git","clone",cmd.split()[1]])
				sendMessage(gitlog)
				if os.path.isdir(cmd.split()[1].split("/")[-1]):
					shutil.make_archive(cmd.split()[1].split("/")[-1], 'zip', cmd.split()[1].split("/")[-1])
					sendMessage("Uploading...")
					client.send_file(chat_id,cmd.split()[1].split("/")[-1]+".zip")
					if os.path.isfile(cmd.split("/")[-1]+".zip"): os.remove(cmd.split("/")[-1]+".zip")
					os.system("rm -rf {}".format(cmd.split("/")[-1]))
				else:
					sendMessage("Repository not found")
	else:
		pass

print("[+] Tenrec Bot")
print("Starting...")
"""
List of command
---------------
adduser - Add User to Post-Permission
apafi - Admin Panel Finder
backmap - Network Live IP Video Cameras
contact - Contact the Developer
deluser - Delete User from Post-Permission
dlang - Detect Language
dnslookup - DNS Lookup
emlook - Email Validation
f4k3 - Fake User Data Generator
fakemail - Temp Mail Generator
getfile - Download File
getmedia - Download Media
gitclone - Clone Repository
githuser - (GitHub) Get User Information
goodork - Google Dork
hashgen - Hash Generator
help - Show list command
iploc - IPGeolocation
maclo - MAC Lookup
mydev - Who is my developer?
nmap - Port Scanner
post - POST to BHS Channel
posturl - POST URL to BHS Channel
reverseip - Reverse IP Lookup
rpgen - Password Generator
title - Get Title
upfile - Upload File
urlgrab - URL Grabber
"""
list_command = """
List of command
---------------
/adduser - Add User of Post-Permission
/apafi - Admin Panel Finder
/backmap - Network Live IP Video Cameras
/contact - Contact the Developer
/deluser - Delete User from Post-Permission
/dlang - Detect Language
/dnslookup - DNS Lookup
/emlook - Email Validation
/f4k3 - Fake User Data Generator
/fakemail - Temp Mail Generator
/getfile - Download File
/getmedia - Download Media
/gitclone - Clone Repository
/githuser - (GitHub) Get User Information
/goodork - Google Dork
/hashgen - Hash Generator
/help - Show list command
/iploc - IPGeolocation
/maclo - MAC Lookup
/mydev - Who is my developer?
/nmap - Port Scanner
/post - POST to BHS Channel
/posturl - POST URL to BHS Channel
/reverseip - Reverse IP Lookup
/rpgen - Password Generator
/title - Get Title
/upfile - Upload File
/urlgrab - URL Grabber
"""
param = ""
message_id = ""
username = ""
max_char = 4096
debug = ""
chat_id = "-1001377057401"

sc_cache = open(sys.argv[0], "r").read()
while True:
	getall_id = []
	r = requests.get("https://api.telegram.org/bot{}/getUpdates{}".format(bot_token,param))
	debug = r.content
	print(r.content)
	for i in r.json()["result"]:
		getall_id.append(i["update_id"])
		try:
			print("[+] {}: {}".format(i["message"]["from"]["username"],i["message"]["text"]))
			chat_id = i["message"]["chat"]["id"]
			message_id = i["message"]["message_id"]
			messageObj = i["message"]
			username = i["message"]["from"]["username"]
			execute(i["message"]["text"])
		except Exception as e:
			print(e)
	try:
		param = "?offset={}".format(int(getall_id[len(getall_id)-1])+1)
	except IndexError:
		param = ""
	if not sc_cache == open(sys.argv[0], "r").read():
		break
	time.sleep(2)
