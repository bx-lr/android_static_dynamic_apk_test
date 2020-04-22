'''
Generate disassembled classes.dex
scheme ["name text", "is_file_from_apk int", "file_data text", "is_binary int", "is_test int", "is_running int", "test_result text"]
'''

import base64
import os
import subprocess
from androguard.core.androgen import AndroguardS
from androguard.core.analysis import analysis

'''
todo add try/catch arround different disassembly methods
'''

class MyClass():
	def __init__(self):
		print "classes.dex disassembly script loaded"
		self.DEXDUMP = '/home/udev/android-sdk-linux/platform-tools/dexdump'
		
	def main(self, apk):
		db = apk.db
		idx = db.getindex('name')
		data = db.getrow(db.curs, db.table_name, idx, "classes.dex")
		
		idx = db.getindex('is_binary')
		if data[idx]:
			b_classes = data[db.getindex('file_data')]
			b_classes = base64.decodestring(b_classes.replace('\\n', ""))
		
		fd = open("tmp.dex", "wb")
		fd.write(b_classes)
		fd.close()
		path = os.path.abspath("tmp.dex")
		proc = subprocess.Popen([self.DEXDUMP,'-d', path],stdout=subprocess.PIPE)
		disasm = []
		while True:
			line = proc.stdout.readline()
			if line != '':
				disasm.append(line)
			else:
				break
		
		disasm = "".join(disasm)
		data = [""] * len(db.scheme)
		data[db.getindex('name')] = 'classes.dex.dump'
		data[db.getindex('is_file_from_apk')] = 0
		data[db.getindex('is_binary')] = 0
		data[db.getindex('is_test')] = 1
		data[db.getindex('is_running')] = 0
		data[db.getindex('test_result')] = disasm.replace("'", "\"")
		data[db.getindex('category')] = "Analysis"
		db.addrow(db.curs, db.table_name, data)
		print "classes.dex disassembly script execution complete\n"

#generate androguard dump
#throw this into a different file
#		a = AndroguardS( "tmp.dex" )
#		x = analysis.VMAnalysis( a.get_vm() )
		os.remove("tmp.dex")
#		
#		disasm = ""
#		for method in a.get_methods() :
#			g = x.hmethods[ method ]
#			
#			if method.get_code() == None :
#				continue
#			
#			disasm += "%s %s %s %s %s\n" % (method.get_class_name(), method.get_name(), method.get_descriptor(), method.get_code().get_length(), method.get_code().registers_size)
#			
#			idx = 0
#			for i in g.basic_blocks.get() :
#
#				disasm += "\t %s %x %x [ CHILDS = %s ] [ FATHERS = %s ]\n" % (i.name, i.start, i.end, ', '.join( "%x-%x-%s" % (j[0], j[1], j[2].get_name()) for j in i.childs ), ', '.join( j[2].get_name() for j in i.fathers ) )
#				
#				for ins in i.get_instructions() :
#					disasm += "\t\t %x %s %s\n" % (idx, ins.get_name(), ins.get_output())
#					idx += ins.get_length()
#			disasm += "\n"
#		data = [""] * len(db.scheme)
#		data[db.getindex('name')] = 'classes.dex.androguard.dump'
#		data[db.getindex('is_file_from_apk')] = 0
#		data[db.getindex('is_binary')] = 0
#		data[db.getindex('is_test')] = 1
#		data[db.getindex('is_running')] = 0
#		data[db.getindex('test_result')] = disasm.replace("'", "\"")
#		db.addrow(db.curs, db.table_name, data)
#		print "\t generated androguard dexdump"
#		print "classes.dex disassembly script execution complete\n"
		return 0


