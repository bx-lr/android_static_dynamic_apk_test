
'''
dex:
org/apache/http/conn/ssl/SSLSocketFactory;.ALLOW_ALL_HOSTNAME_VERIFIER
org/apache/http/conn/ssl/AllowAllHostnameVerifier;.<init>:()V

org.apache.http.conn.ssl.TrustSelfSignedStrategy.isTrusted:([Ljava/security/cert/X509Certificate;Ljava/lang/String;)Z

xml:
<uses-permission android:name="android.permission.INTERNET"> </uses-permission>
'''

from xml.dom.minidom import parseString

report = """Top 10 Mobile Risks, Release Candidate v1.0
M3: Insufficient Transport Layer Protection
Remove all code after the development cycle that may allow the application to accept all certificates such as org.apache.http.conn.ssl.AllowAllHostnameVerifier or SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER. This is equivalent to trusting all certificates.
"""

#todo add report description

class MyClass():
	def __init__(self):
		print "static vulndisco SSL error script loaded"

	def get_permissions(self, data):
		dom = parseString(data)
		tags = dom.getElementsByTagName('uses-permission')
		for tag in tags:
			tag_items = tag.attributes.items()
			for ttag in tag_items:
				if ttag[1].find("INTERNET") > -1:
					return True
		return False

	def main(self, apk):
		result = 0
		db = apk.db
		idx = db.getindex('name')
#		dex = db.getrow(db.curs, db.table_name, idx, "classes.dex.androguard.dump")[db.getindex('test_result')].split("\\n\\t\\t")
		dex = db.getrow(db.curs, db.table_name, idx, "classes.dex.dump")[db.getindex('test_result')].split("\\n")
		manifest = db.getrow(db.curs, db.table_name, idx, "manifest.xml")[db.getindex('test_result')].replace("\\n", "\n")

		data = [""] * len(db.scheme)
		data[db.getindex('name')] = 'vulndisco_ssl_static'
		data[db.getindex('is_file_from_apk')] = 0
		data[db.getindex('is_binary')] = 0
		data[db.getindex('is_test')] = 1
		data[db.getindex('is_running')] = 0
		data[db.getindex('category')] = "static vulnerability test"
		data[db.getindex('report')] = report

		ALL_HOSTNAME_VERIFIER = ""
		SELF_SIGNED_CERTS = ""

		if self.get_permissions(manifest):
	
			for i in xrange(0, len(dex)):
				line = dex[i]
			
				if line.find("org/apache/http/conn/ssl/SSLSocketFactory;.ALLOW_ALL_HOSTNAME_VERIFIER") > -1:
					print line
					ALL_HOSTNAME_VERIFIER = "ALL_HOSTNAME_VERIFIER"
 					result += 1
				if line.find("org/apache/http/conn/ssl/AllowAllHostnameVerifier;.<init>:()V") > -1:
					print line
					ALL_HOSTNAME_VERIFIER = "ALL_HOSTNAME_VERIFIER"
 					result += 1				
				if line.find("org.apache.http.conn.ssl.TrustSelfSignedStrategy.isTrusted:([Ljava/security/cert/X509Certificate;Ljava/lang/String;)Z") > -1:
					print line
					SELF_SIGNED_CERTS = "SELF_SIGNED_CERTIFICATE"
 					result += 1
		if result > 0:
			data[db.getindex('test_result')] = "%s %s" % (ALL_HOSTNAME_VERIFIER, SELF_SIGNED_CERTS)
		else:
			data[db.getindex('test_result')] = "Not Vulnerable"
		db.addrow(db.curs, db.table_name, data)
		print "static vulndisco SSL error script execution complete\n"
		return result

