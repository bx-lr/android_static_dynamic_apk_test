'''
breaks out app components and various info:

*activities <activity android:name="
*services <service android:name="
*receivers <receiver android:name="
*providers <provider android:name"<uses-sdk
*permissions <uses-permission android:name="
*custom_permission <permission android:name="
*features <uses-feature android:name="
*sdk_version_min <uses-sdk android:minSdkVersion="
*sdk_version_target <uses-sdk android:targetSdkVersion="
package_name  package="com.blah.blah.blah
install_location android:installLocation="
'''

from xml.dom.minidom import parseString
#todo add report description
class MyClass():
	def __init__(self):
		print "static component script loaded"

	def check_flag(self, data, k, v):
		dom = parseString(data)
		tags =  dom.getElementsByTagName(k)
		items = []
		for tag in tags:
			tag_items = tag.attributes.items()
			#print k, v, tag_items
			for ttag in tag_items:
				if ttag[0].find(v) > -1:
					items.append(ttag[1])
		return items
		
	def update_db(self, db, k, v, result):
		data = [""] * len(db.scheme)
		data[db.getindex('name')] = k+' '+v
		data[db.getindex('is_file_from_apk')] = 0
		data[db.getindex('is_binary')] = 0
		data[db.getindex('is_test')] = 1
		data[db.getindex('is_running')] = 0
		data[db.getindex('category')] = "static component test"
		data[db.getindex('test_result')] = " ".join(result).decode('utf-8').encode('ascii')
		db.addrow(db.curs, db.table_name, data)

	def main(self, apk):
		db = apk.db
		idx = db.getindex('name')
		manifest = db.getrow(db.curs, db.table_name, idx, "manifest.xml")[db.getindex('test_result')].replace("\\n", "\n")
		components = {'permission':'android:name', 'uses-permission':'android:name', 'provider':'android:name', \
 'receiver':'android:name', 'service':'android:name', 'activity':'android:name', 'uses-feature': 'android:name', \
 'uses-sdk':'android:minSdkVersion', 'manifest':'package', 'manifest':'android:installLocation'}
		for k, v in components.iteritems():
			items = self.check_flag(manifest, k, v)		
			self.update_db(db, k, v, items)
		print "static component script execution complete\n"
		return 0

if __name__ == "__main__":
	mc = MyClass()
	#data = open('/home/udev/analysis/ama/wmss/manifest.xml', 'rb').read()
	data = open('/home/udev/analysis/amazon/mShop/manifest.xml', 'rb').read()
	components = {'permission':'android:name', 'uses-permission':'android:name', 'provider':'android:name', \
 'receiver':'android:name', 'service':'android:name', 'activity':'android:name', 'uses-feature': 'android:name', \
 'uses-sdk':'android:minSdkVersion', 'manifest':'package', 'manifest':'android:installLocation'}
	for k, v in components.iteritems():
		items = mc.check_flag(data, k, v)
		print k, items

