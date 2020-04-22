'''
run yara rules

'''
import subprocess
import Queue
import threading
import os

from xml.dom.minidom import parseString
#todo add report description

DEBUG = False

class YARA():
	def __init__(self):
		pass

	def queue_stdout(self, out, queue):
		if DEBUG:
			print "[YARA] queue_stdout"
		tmp = out.readlines()
		if DEBUG:
			print "\t queue_stdout returned", tmp
		queue.put(tmp)
		out.close()

	def queue_stderr(self, err, queue):
		if DEBUG:
			print "[YARA] queue_stderr"
		tmp = err.readlines()
		if DEBUG:
			print "\t queue_stderr returned", tmp
		queue.put(tmp)
		err.close()

	def run_yara(self, cmd):
		p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

		queue = Queue.Queue()

		t1 = threading.Thread(target=self.queue_stdout, args=(p.stdout, queue))
		t1.daemon = True
		t1.start()
		
		t2 = threading.Thread(target=self.queue_stderr, args=(p.stderr, queue))
		t2.daemon = True
		t2.start()

		line = []

		try:
			line.append("".join(queue.get(timeout=10)))
			line.append("".join(queue.get(timeout=10)))
		except:
			if DEBUG:
				print "\t run_yara exception reading queue"
			pass

		if DEBUG:
			print "\t run_yara returned: ", line
		p.kill()
		return line



class MyClass():
	def __init__(self):
		print "static privacy yara script loaded"

	def do_yara(self, data):
		fd = open('tmp.dex', 'wb')
		fd.writelines(data)
		fd.close()
		y = YARA()
		result = y.run_yara('yara -m static_tests/updatedscores_privacyrules.yara tmp.dex'.split(" "))
		#print result
		os.remove('tmp.dex')
		return result
		
	def main(self, apk):
		db = apk.db
		idx = db.getindex('name')
		dex = db.getrow(db.curs, db.table_name, idx, "classes.dex.dump")[db.getindex('test_result')].replace('\\n', '\n')
		data = [""] * len(db.scheme)
		data[db.getindex('name')] = 'privacy_yara_static'
		data[db.getindex('is_file_from_apk')] = 0
		data[db.getindex('is_binary')] = 0
		data[db.getindex('is_test')] = 1
		data[db.getindex('is_running')] = 0
		data[db.getindex('category')] = "static privacy test"
		result = self.do_yara(dex)
		data[db.getindex('test_result')] = " ".join(result)
		db.addrow(db.curs, db.table_name, data)
		print "static privacy yara script execution complete\n"
		return 0

if __name__ == "__main__":
	y = YARA()
	result = y.run_yara('yara -m /home/udev/android-sdk-linux/platform-tools/fuzz/intent_fuzzer/static_tests/updatedscores_privacyrules.yara /home/udev/analysis/ama/wmss/classes.dex.dump'.split(" "))
	print result





