#!/usr/bin/python

import imp
import os
import sys
import traceback
import time
from APKHelper import APKHelper
from adb import ADB
from emulator import Emulator

BUSYBOX = '/home/udev/android-sdk-linux/platform-tools/fuzz/intent_fuzzer/tools/busybox'
MERCURY_SERVER = "/home/udev/analysis-tools/mercury-a4594e9/server/bin/mercury-server.apk"
EMULATOR_PATH = "/home/udev/android-sdk-linux/tools/"
NUM_EMULATORS = 1
API_LEVEL = "android-15"
SDCARD = True
ADB_PATH = "/home/udev/android-sdk-linux/platform-tools/"
emu = Emulator(EMULATOR_PATH)
adb = ADB(ADB_PATH)
'''
todo: add write sdcard static test
todo: add write sdcard dynamic test
todo: add sqli static test 				done
todo: add sqli dynamic test				done
todo: add ssl dynamic test
todo: add privacy static tests 			done
todo: fix occasional adb.check_devices NoneType bug	
todo: fix occasional hang on app install		done
'''

def load_from_file(filepath):
	class_inst = None
	py_mod = None
	expected_class = 'MyClass'

	mod_name,file_ext = os.path.splitext(os.path.split(filepath)[-1])

	if file_ext.lower() == '.py':
		py_mod = imp.load_source(mod_name, filepath)
	
	if hasattr(py_mod, expected_class):
		class_inst = py_mod.MyClass() 
	
	return class_inst

def load_from_dir(folder):
	found = 0
	mydir = os.path.dirname(os.path.realpath(__file__)) + folder
	for filepath in os.listdir(mydir):
		tmp = load_from_file(mydir+filepath)
		if tmp:
			try:
				found += tmp.main(apk)
			except Exception:
				traceback.print_exc(Exception)
				print "\nScript execution failed... moving to next\n"
				pass
	return found

def startup():
	avds = []
	#delete all emulator instances
	print "killing all emulator instances..."
	avd_dic =  emu.check_avd()
	for k, v in avd_dic.iteritems():
		emu.kill_emulator(k)
		emu.delete_avd(k)

	#create new emulator instances
	print "creating new emulator instances..."
	for i in range(0, NUM_EMULATORS):
		emu.create_avd("fuzz_%d" % i, API_LEVEL)
		avds.append("fuzz_%d" % i)

	#create an sdcard for each emulator
	sdcards = []	
	if SDCARD:
		print "creating new sdcards for each emulator..."
		for i in range(0, NUM_EMULATORS):
			#emu.delete_sdcard("sdcard_%d" %i)
			emu.make_sdcard(512, "sdcard_%d" % i)
			sdcards.append("sdcard_%d" % i)

	#start um up
	print "starting up emulator instances..."
	for i in range(0, len(avds)):
		if SDCARD:
			emu.start_avd(avds[i], " -cpu-delay 0 -no-boot-anim -memory 2048 -partition-size 512 -sdcard %s" % sdcards[i])
		else:
			emu.start_avd(avds[i])

def wait_for_device(name=""):
	adb.stop_adb()
	print "\n"
	adb.start_adb()
	print "\n"
	print "waiting for emulator instances to come online..."
	time.sleep(10)
	while True:
		devices = adb.check_devices()
		if devices == None:
			time.sleep(1)
			continue
		if len(devices) < NUM_EMULATORS:
			time.sleep(1)
			continue
		tmp = ""
		for d in devices:
			if d == name:
				tmp = d
		if tmp.find("offline") > -1:
			time.sleep(1)
			continue
		else:
			break
#move to emulator.py
def stop():
	#kills everything nicely
	avd_dic =  emu.check_avd()
	for k, v in avd_dic.iteritems():
		print "killing avd:", k
		emu.kill_emulator(k)
		#emu.delete_avd(k)

def install_busybox(avd_name):
	print "Installing BusyBox"
	adb.run_cmd(avd_name, " remount")
	adb.run_cmd(avd_name, " push %s /system/xbin/" % BUSYBOX)
	adb.run_cmd(avd_name, " shell chmod 770 /system/xbin/busybox")
	adb.run_cmd(avd_name, " shell /system/xbin/busybox --install /system/xbin/")
	

def startup_emu():
	print "Starting Emulator"
	startup()
	avd_name = adb.check_devices()[0]
	wait_for_device(avd_name)
	avd_name = adb.check_devices()[0]
	time.sleep(10)
	install_busybox(avd_name)
	adb.unlock_screen(avd_name)
	adb.run_cmd(avd_name, " push %s /data/local/tmp" % MERCURY_SERVER)
	result = adb.run_cmd(avd_name, " shell pm install /data/local/tmp/%s" % MERCURY_SERVER.split("/")[-1])
	while not(str(result).find("INSTALL_FAILED_ALREADY_EXISTS") > -1):
		print "Waiting for Package Manager to come online"
		time.sleep(10)
		if "".join(adb.run_cmd(avd_name, " shell ls /data/data/ | grep com.mwr.mercury")).find('com.mwr.mercury') > -1:
			break
		result = adb.run_cmd(avd_name, " shell pm install /data/local/tmp/%s" % MERCURY_SERVER.split("/")[-1])
	print "Mercury server installed"
	return 1
	
#move to adb.py
def install_apk(infile, apk):
	db = apk.db
	idx = db.getindex('name')
	manifest = db.getrow(db.curs, db.table_name, idx, "manifest.xml")[db.getindex('test_result')].replace("\\n", "\n")
	part = manifest[manifest.find('package="')+9:]
	pname = part[:part.find('"')]

	avd_name = adb.check_devices()[0]
	adb.run_cmd(avd_name, " push %s /data/local/tmp/tmp.apk" % infile)
	result = adb.run_cmd(avd_name, " shell pm install /data/local/tmp/tmp.apk")
	count = 0
	while not(str(result).find("INSTALL_FAILED_ALREADY_EXISTS") > -1):
		print "Waiting for Package Manager to come online", count
		time.sleep(10)
		#check /data/data/ for package name 
		if "".join(adb.run_cmd(avd_name, " shell ls /data/data/ | grep %s" % pname)).find(pname) > -1:
			break
		if "".join(adb.run_cmd(avd_name, " shell ls /data/local/tmp | grep tmp.apk")).find("tmp.apk") < 0:
			adb.run_cmd(avd_name, " push %s /data/local/tmp/tmp.apk" % infile)
		result = adb.run_cmd(avd_name, " shell pm install /data/local/tmp/tmp.apk")
		if str(result).find("INSTALL_FAILED_MISSING_SHARED_LIBRARY") > -1:
			return False
		if str(result).find("INSTALL_FAILED_INVALID_URI") > -1:
			return False
		if count > 9:
			return False
		count =+ 1
	print "Installed: ", infile
	return True

#move to adb.py
def uninstall_apk(apk):
	db = apk.db
	idx = db.getindex('name')
	manifest = db.getrow(db.curs, db.table_name, idx, "manifest.xml")[db.getindex('test_result')].replace("\\n", "\n")
	part = manifest[manifest.find('package="')+9:]
	pname = part[:part.find('"')]
	avd_name = adb.check_devices()[0]
	while "".join(adb.run_cmd(avd_name, " shell ls /data/data/ | grep %s" % pname)).find(pname) > -1:
		adb.run_cmd(avd_name, " shell pm uninstall %s" % pname)
		time.sleep(10)
	adb.run_cmd(avd_name, " shell rm /data/local/tmp/tmp.apk")

def help():
	print 'driver.py /path/to/apk/directory/'

if __name__ == "__main__":
	start = time.time()
	if len(sys.argv) != 2:
		help()
		sys.exit()
	dirlist = os.listdir(sys.argv[-1])
	emu_started = startup_emu()
	count = 1
	failed = []
	processed = []
	for f in dirlist:
		infile = sys.argv[-1] + f
		print "Processing file: %d/%d" % (count, len(dirlist))
		count += 1
		print "Loading file into database: ", infile
		try:
			apk = APKHelper(infile)
		except Exception:
			traceback.print_exc(Exception)
			failed.append(infile)
			continue
		print 'Loaded\n'
		load_from_dir("/analysis/")
		if load_from_dir("/static_tests/"):
			if not emu_started:
				emu_started = startup_emu()
			apk.emu = emu
			apk.adb = adb
			adb.unlock_screen(adb.check_devices()[0])
			if install_apk(infile, apk):
				load_from_dir("/dynamic_tests/")
				uninstall_apk(apk)
				print "Dynamic tests complete"
			else:
				print "Failed to install"
				failed.append(infile)
				continue
		processed.append(infile)

	print "Done!"
	print "Failed: %d" % len(failed)
	print "Processed: %d" % len(processed)
	print "Time: ", time.time() - start

