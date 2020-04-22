import sys
import re
import time
sys.path.append("/home/udev/analysis-tools/mercury-a4594e9/client")
from merc.lib.common import Session

#todo: add known issues content provider whitelist
#todo add report description
class MyClass():
	def __init__(self):
		print "dynamic SQL Injection script loaded"


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
		s_test_result = db.getrow(db.curs, db.table_name, idx, "vulndisco_sqli_static")[db.getindex('test_result')].split(" ")
		manifest = db.getrow(db.curs, db.table_name, idx, "manifest.xml")[db.getindex('test_result')].replace("\\n", "\n")
		part = manifest[manifest.find('package="')+9:]
		pname = part[:part.find('"')]

		dbdata = [""] * len(db.scheme)
		dbdata[db.getindex('name')] = 'vulndisco_sqli_dynamic'
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
		queryList = []
		projectionList = []
		selectionList = []
		
		#print "\n[*] Getting a list of all content uri's to query..."
		#print "\t- Fetching authorities..."
		
		# Get list of all authorities and make content uri's out of them
		providerinfo = session.executeCommand("provider", "info", {}).getPaddedErrorOrData()
		authorities = re.findall('(?<=Authority: ).+', providerinfo)
		for authority in authorities:
			for s in s_test_result:
				if authority.find(s) > -1:
					queryList.append("content://" + authority)
        
		# Get list of all packages
		packagesinfo = session.executeCommand("packages", "info", {}).getPaddedErrorOrData()
		packages = re.findall('(?<=Package name: ).+', packagesinfo)
		for package in packages:
			if package.find(pname) < 0:
				continue
			path = session.executeCommand("packages", "path", {'packageName':package}).data
			
			# Iterate through paths returned
			for line in path.split():
			
				if (".apk" in line):
					if session.executeCommand("core", "unzip", {'filename':'classes.dex', 'path':line, 'destination':'/data/data/com.mwr.mercury/'}).isError():
						pass
					else:
					
						strings = session.executeCommand("provider", "finduri", {'path':'/data/data/com.mwr.mercury/classes.dex'}).data
						
						for string in strings.split():
							if (("CONTENT://" in string.upper()) and ("CONTENT://" != string.upper())):
								queryList.append(string[string.upper().find("CONTENT"):]) 
						
						# Delete classes.dex
						session.executeCommand("core", "delete", {'path':'/data/data/com.mwr.mercury/classes.dex'})
					
				if (".odex" in line):
					strings = session.executeCommand("provider", "finduri", {'path':line}).data
	
					for string in strings.split():
						if (("CONTENT://" in string.upper()) and ("CONTENT://" != string.upper())):
							queryList.append(string[string.upper().find("CONTENT"):])
                    
                    
		#print "[*] Checking for SQL injection...\n"
		
		# Check all found URI's for injection in projection and selection
		for uri in queryList:
			#print "Checking: ", uri
			projectioninject = session.executeCommand("provider", "query", {"Uri":uri, "projection":"'"})
			selectioninject = session.executeCommand("provider", "query", {"Uri":uri, "selection":"'"})
            
			if "unrecognized token" in projectioninject.error:
				#print "Injection point:", session.color.red("projection") + " - " + uri

				if uri not in projectionList:
					projectionList.append(uri)
			else:
				if "unrecognized token:" in selectioninject.error:
					#print "Injection point:", session.color.yellow("selection") + " - " + uri
					
					if uri not in selectionList:
						selectionList.append(uri)
                        
		# Generate a summary
		#print session.color.blue('\n[*] Summary\n    -------')
		#print session.color.red("\nInjection in projection:")
		#for uri in projectionList:
		#	print uri
		#
		#print session.color.red("\nInjection in selection:")
		#for uri in selectionList:
		#	print uri
		#print ""

		if len(projectionList) + len(selectionList) > 0:
			dbdata[db.getindex('test_result')] = " ".join(projectionList) + " ".join(selectionList)
		else:
			dbdata[db.getindex('test_result')] = "Not Vulnerable"
		db.addrow(db.curs, db.table_name, dbdata)
		print "dynamic SQL Injection script execution complete\n"
		return len(projectionList) + len(selectionList)
