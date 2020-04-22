'''
Generate decoded AndroidManifest.xml
scheme ["name text", "is_file_from_apk int", "file_data text", "is_binary int", "is_test int", "is_running int", "test_result text"]
'''
import base64
from androguard.core.bytecodes import apk as androApk

class MyClass():
	def __init__(self):
		print "AndroidMainifest.xml decoder script loaded"
		
	def main(self, apk):
		db = apk.db
		idx = db.getindex('name')
		data = db.getrow(db.curs, db.table_name, idx, "AndroidManifest.xml")
		
		idx = db.getindex('is_binary')
		if data[idx]:
			b_manifest = data[db.getindex('file_data')]
			b_manifest = base64.decodestring(b_manifest.replace('\\n', ""))
		buff = androApk.AXMLPrinter(b_manifest).getBuff()
		data = [""] * len(db.scheme)
		data[db.getindex('name')] = 'manifest.xml'
		data[db.getindex('is_file_from_apk')] = 0
		data[db.getindex('is_binary')] = 0
		data[db.getindex('is_test')] = 1
		data[db.getindex('is_running')] = 0
		data[db.getindex('test_result')] = "%s" % buff
		data[db.getindex('category')] = "Analysis"
		db.addrow(db.curs, db.table_name, data)
		print "AndroidMainifest.xml decoder script execution complete\n"
		return 0
		
