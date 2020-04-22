'''
check for debug flag in mainifest

'''

from xml.dom.minidom import parseString
#todo add report description
class MyClass():
	def __init__(self):
		print "static pcp debuggable flag script loaded"

	def check_flag(self, data):
		dom = parseString(data)
		tags =  dom.getElementsByTagName('application')
		providers = []
		for tag in tags:
			tag_items = tag.attributes.items()
			for ttag in tag_items:
				if ttag[0].find("android:debuggable") > -1:
					if ttag[1].find("true") > -1:
						return True
		return False
		
	def main(self, apk):
		result = 0
		db = apk.db
		idx = db.getindex('name')
		manifest = db.getrow(db.curs, db.table_name, idx, "manifest.xml")[db.getindex('test_result')].replace("\\n", "\n")

		data = [""] * len(db.scheme)
		data[db.getindex('name')] = 'pcp_debugflag_static'
		data[db.getindex('is_file_from_apk')] = 0
		data[db.getindex('is_binary')] = 0
		data[db.getindex('is_test')] = 1
		data[db.getindex('is_running')] = 0
		data[db.getindex('category')] = "static pcp test"

		if self.check_flag(manifest):
			data[db.getindex('test_result')] = "True"
		else:
			data[db.getindex('test_result')] = "False"
		db.addrow(db.curs, db.table_name, data)
		print "static pcp debuggable flag script execution complete\n"
		return result

