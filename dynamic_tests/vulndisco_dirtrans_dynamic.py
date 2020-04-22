import sys
import re
import time
sys.path.append("/home/udev/analysis-tools/mercury-a4594e9/client")
from merc.lib.common import Session

#todo add whitelist
#todo add search for all content providers referenced
#todo add report description
class MyClass():
	def __init__(self):
		print "dynamic vulndisco directory transversal script loaded"


	def merc_connect(self, adb):
		avd_name = adb.check_devices()[0]
		while adb.check_process(avd_name, "com.mwr.mercury"):
			print "\tprocess found (mercury), killing"
			adb.kill_process(avd_name, "com.mwr.mercury")

		adb.run_cmd(avd_name, " forward tcp:31415 tcp:31415")
		while "".join(adb.run_cmd(avd_name, " shell dumpsys activity | grep '* Recent #0: TaskRecord{'")).find("com.mwr.mercury") < 0:
			adb.run_cmd(avd_name, " shell am start com.mwr.mercury/.Main")
			time.sleep(3)
		sessionip = "127.0.0.1"
		sessionport = 31415

		newsession = Session(sessionip, sessionport, "bind")

		# Check if connection can be established
		if newsession.executeCommand("core", "ping", None).data == "pong":
			return newsession

		adb.run_cmd(avd_name, " shell input keyevent 19")
		adb.run_cmd(avd_name, " shell input keyevent 66")
		newsession = Session(sessionip, sessionport, "bind")
	
		# Check if connection can be established
		if newsession.executeCommand("core", "ping", None).data == "pong":
			#print "CONNECTED TO MERCURY!!"
			return newsession

		adb.run_cmd(avd_name, " shell input keyevent 66")
		newsession = Session(sessionip, sessionport, "bind")
	
		# Check if connection can be established
		if newsession.executeCommand("core", "ping", None).data == "pong":
			return newsession
		return None

	def main(self, apk):
		db = apk.db
		idx = db.getindex('name')
		s_test_result = db.getrow(db.curs, db.table_name, idx, "vulndisco_dirtrans_static")[db.getindex('test_result')].split(" ")
		dbdata = [""] * len(db.scheme)
		dbdata[db.getindex('name')] = 'vulndisco_dirtrans_dynamic'
		dbdata[db.getindex('is_file_from_apk')] = 0
		dbdata[db.getindex('is_binary')] = 0
		dbdata[db.getindex('is_test')] = 1
		dbdata[db.getindex('is_running')] = 0
		dbdata[db.getindex('category')] = "dynamic vulnerability test"

		if "".join(s_test_result).find("Not Vulnerable") > -1:
			print "NO TEST RESULT\n"
			dbdata[db.getindex('test_result')] = "Not Vulnerable"
			db.addrow(db.curs, db.table_name, dbdata)
			return 0

		session = self.merc_connect(apk.adb)
		if not session:
			dbdata[db.getindex('test_result')] = "Not Vulnerable"
			db.addrow(db.curs, db.table_name, dbdata)
			print "NO SESSION\n"
			return 0

		session.executeCommand("shell", "executeSingleCommand", {"args":"echo testing > /data/data/com.mwr.mercury/traverse"}).getPaddedErrorOrData()
		
		# Get all authorities
		info = session.executeCommand("provider", "info", None).getPaddedErrorOrData()
		auths = re.findall('(?<=Authority: ).+', info)
		
		vuln = []
		for a in auths:
			for r in s_test_result:
				#print a, r
				if a.find(r) < 0:
					continue
				#print("Checking " + a)
				request = {'Uri': "content://" + a + "/../../../../../../../../../../../../../../../../data/data/com.mwr.mercury/traverse"}
		
				response = session.executeCommand("provider", "read", request)

				if not ((response.isError() or len(response.data) == 0)):
					#print session.color.red(a + " is vulnerable to directory traversal!")
					vuln.append(a)

		if len(vuln) > 0:
			dbdata[db.getindex('test_result')] = ";".join(vuln)
		else:
			dbdata[db.getindex('test_result')] = "Not Vulnerable"
		db.addrow(db.curs, db.table_name, dbdata)
		print "dynamic vulndisco directory transversal script execution complete\n"
		return len(vuln)
		
		

