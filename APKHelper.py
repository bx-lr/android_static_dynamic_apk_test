#!/usr/bin/python

'''
Load APK into Database
'''

from DatabaseHelper import DBHelper
from StringIO import StringIO
import zipfile
import base64
import os
import traceback

class APKHelper():
	def __init__(self, path):
		self.path = path
		self.db = None
		self.emu = None
		self.adb = None
		self.load()

	def load(self):
		fd = open(self.path, 'rb')
		apk = fd.read()
		fd.close()

		zipdata = StringIO()
		zipdata.write(apk)
		myzipfile = zipfile.ZipFile(zipdata)
		self.db = DBHelper(db_name = 'output/%s.db' % self.path.split("/")[-1])
		data = [""] * len(self.db.scheme)
	    	
		data[0] = "apk"
		data[1] = 0
		data[2] = base64.encodestring(apk)
		data[3] = 1
		data[4] = 1
		self.db.addrow(self.db.curs, self.db.table_name, data)
		data[4] = 0
		for name in myzipfile.namelist():
			data[0] = "".join(name).decode('utf-8').encode('ascii').replace("'", "")
			data[1] = 1
			data[2] = base64.encodestring(myzipfile.open(name).read())
			data[3] = 1
			try:
				self.db.addrow(self.db.curs, self.db.table_name, data)
			except Exception:
				os.remove('output/%s.db' % self.path.split("/")[-1])
				traceback.print_exc(Exception)
				raise Exception
if __name__ == "__main__":
	APKHelper('/home/udev/analysis/amazon/mShop/com.amazon.mShop.android-1.apk')
