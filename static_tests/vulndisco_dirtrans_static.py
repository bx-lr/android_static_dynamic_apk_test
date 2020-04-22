'''
check for potential directory transversal vulnerabilities

'''

from xml.dom.minidom import parseString
'''
todo add line information to test... so we can report the disassembly line where we are interested
todo try/catch on different search methods
todo add check for all content:// providers referenced
todo add whitelist
todo add report description
'''
class MyClass():
	def __init__(self):
		print "static vulndisco directory transversal script loaded"

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
				if ttag[0].find("android:Permission") > -1:
					#print "\t requires custom permission"
					providers.pop()
					continue
				if ttag[0].find("android:exported") > -1:
					if ttag[1].find("false") > -1:
						#print "\t not exported"
						providers.pop()
						continue
		return providers
		
	def main(self, apk):
		result = 0
		db = apk.db
		idx = db.getindex('name')
#		dex = db.getrow(db.curs, db.table_name, idx, "classes.dex.androguard.dump")[db.getindex('test_result')].split("\\n\\t\\t")
		dex = db.getrow(db.curs, db.table_name, idx, "classes.dex.dump")[db.getindex('test_result')].split("\\n")
		manifest = db.getrow(db.curs, db.table_name, idx, "manifest.xml")[db.getindex('test_result')].replace("\\n", "\n")

		data = [""] * len(db.scheme)
		data[db.getindex('name')] = 'vulndisco_dirtrans_static'
		data[db.getindex('is_file_from_apk')] = 0
		data[db.getindex('is_binary')] = 0
		data[db.getindex('is_test')] = 1
		data[db.getindex('is_running')] = 0
		data[db.getindex('category')] = "static vulnerability test"

		valid_providers = self.get_valid_providers(manifest)
		if len(valid_providers) < 1:
			#print "\nNo valid content providers were found, bye..."
			data[db.getindex('test_result')] = "Not Vulnerable"
			db.addrow(db.curs, db.table_name, data)
			print "static vulndisco directory transversal script execution complete\n"
			return result
	
		tmp = []
		for provider in valid_providers:
			p = provider 
			p += ".openFile:"

			for line in dex:
				if line.find(p) > -1: #dexdump tool syntax
					print line
					tmp.append(provider)
#			p = provider
#			p = p.replace(".", "/")
#			p += "; openFile (L"
#			for line in dex:
#				if line.find(p) > -1: #androguard disasm syntax
#					tmp.append(provider)
		tmp = set(tmp)
		if len(tmp) > 0:
			result += 1
			data[db.getindex('test_result')] = " ".join(tmp).decode('utf-8').encode('ascii')
		else:
			data[db.getindex('test_result')] = "Not Vulnerable"
		db.addrow(db.curs, db.table_name, data)
		print "static vulndisco directory transversal script execution complete\n"
		return result

