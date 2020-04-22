'''
check for potential SQL Injection vulnerabilities
'''

from xml.dom.minidom import parseString
'''
ensure no:
	android:readPermission
	android:writePermission
	android:Permission
	android:exported=false
	android:enabled=flase

look for:
	provider name and java/lang/String
then:
	SQLiteDatabase;.rawQuery:(
	SQLiteDatabase;.insert:(
	SQLiteDatabase;.update:(
before:
	return-object
	return-void
	return
'''

#todo: add owasp description
#todo: add known issues content provider whitelist

class MyClass():
	def __init__(self):
		print "static vulndisco SQL Injection script loaded"

	def get_valid_providers(self, data):
		dom = parseString(data)
		tags =  dom.getElementsByTagName('provider')
		providers = []
		for tag in tags:
			tag_items = tag.attributes.items()
			for ttag in tag_items:
				if ttag[0].find("android:name") > -1:
					#print ttag[1]
					providers.append(ttag[1])
				if ttag[0].find("android:readPermission") > -1:
					#print "\t requires readPermission"
					providers.pop()
					continue
				if ttag[0].find("android:writePermission") > -1:
					#print "\t requires writePermission"
					providers.pop()
					continue
				if ttag[0].find("android:Permission") > -1:
					#print "\t requires custom permission"
					providers.pop()
					continue
				if ttag[0].find("android:enabled") > -1:
					if ttag[1].find("false") > -1:
						#print "\t not enabled"
						providers.pop()
						continue
				if ttag[0].find("android:exported") > -1:
					if ttag[1].find("false") > -1:
						#print "\t not exported"
						providers.pop()
						continue
		return providers

	def main(self, apk):

		db = apk.db
		idx = db.getindex('name')

		classes_data = db.getrow(db.curs, db.table_name, idx, "classes.dex.dump")[db.getindex('test_result')].split("\\n")
		manifest_data = db.getrow(db.curs, db.table_name, idx, "manifest.xml")[db.getindex('test_result')].replace("\\n", "\n")

		valid_providers = self.get_valid_providers(manifest_data)

		data = [""] * len(db.scheme)
		data[db.getindex('name')] = 'vulndisco_sqli_static'
		data[db.getindex('is_file_from_apk')] = 0
		data[db.getindex('is_binary')] = 0
		data[db.getindex('is_test')] = 1
		data[db.getindex('is_running')] = 0
		data[db.getindex('category')] = "static vulnerability test"

		if len(valid_providers) < 1:
			data[db.getindex('test_result')] = "Not Vulnerable"
			db.addrow(db.curs, db.table_name, data)
			print "static vulndisco SQL Injection script execution complete\n"
			return 0
	
		tmp = []
		queries = ["SQLiteDatabase;.rawQuery:(","SQLiteDatabase;.insert:(","SQLiteDatabase;.update:("]
		ends = ["      catches       :"]
		for provider in valid_providers:
			for i in xrange(0, len(classes_data)):
				if classes_data[i].find(str(provider)) > -1 and classes_data[i].find("java/lang/String;") > -1:
					next = 0
					for j in xrange(i, len(classes_data)):
						if next > 0:
							break
						for q in queries:
							if classes_data[j].find(q) > -1:
								print classes_data[j]
								tmp.append(provider)
								next = 1
								break
						for e in ends:
							if classes_data[j].find(e) > -1:
								next = 1
								break
		tmp = set(tmp)
		if len(tmp) > 0:
			data[db.getindex('test_result')] = " ".join(tmp).decode('utf-8').encode('ascii')
		else:
			data[db.getindex('test_result')] = "Not Vulnerable"
		db.addrow(db.curs, db.table_name, data)
		print "static vulndisco SQL Injection script execution complete\n"
		return len(tmp)
		
