#!/usr/bin/python
import os
import sys
import sqlite3 as lite

def showformat(recs, sept = ('-' * 40)):
	print len(recs), 'records'
	print sept
	for rec in recs:
		maxkey = max(len(key) for key in recs)
		for key in rec:
			print '%-*s => %s' % (maxkey, key, rec[key])
		print sept

def makedicts(cursor, query, params=()):
	cursor.execute(query, params)
	colnames = [desc[0] for desc in cursor.description]
	rowdicts = [dict(zip(colnames, row)) for row in cursor.fetchall()]
	return rowdicts


def dumpdb(cursor, table, format=True):
	if not format:
		cursor.execute('select * from ' + table)
		while True:
			rec = cursor.fetchone()
			if not rec:
				break
			print rec
	else:
		recs = makedicts(cursor, 'select * from ' + table)
		showformat(recs)

def help():
	print 'stats.py /path/to/database/directory/'

if __name__ == "__main__":

	if len(sys.argv) != 2:
		help()
		sys.exit()
	dirlist = os.listdir(sys.argv[-1])
	vulndb = []
	dfound = 0
	sfound = 0
	checkdb = 0 
	pcpdb = []
	for f in dirlist:
		if not f.endswith('db'):
			continue
		checkdb += 1
		conn = lite.Connection(sys.argv[-1]+f)
		curs = conn.cursor()
		recs = makedicts(curs, 'select * from apk_table')
		a = sys.argv[-1]+f
		do_report = 0
		for rec in recs:
			if rec['is_test'] == 1:
				if rec['category'].find('vulnerability test') > -1:
					if not rec['test_result'].find('Not Vulnerable') > -1:
						if rec['name'].find('vulndisco') > -1 and rec['name'].find('dynamic') > -1:
							dfound += 1
						if rec['name'].find('vulndisco') > -1 and rec['name'].find('static') > -1:
							sfound += 1
						if a:
							vulndb.append(a)
							print "\n", a
							print '\t' + rec['name'] + ' ' + rec['test_result']
							a = None
							do_report = 1
						else:
							do_report = 1
							print '\t' + rec['name'] + ' ' + rec['test_result']
				if rec['category'].find('pcp test') > -1:
					if rec['test_result'] == "True":
						do_report = 1
						pcpdb.append(sys.argv[-1]+f)
						if a:
							print "\n", a
							print '\t' + rec['name'] + ' ' + rec['test_result']
							a = None
						else:
							print '\t' + rec['name'] + ' ' + rec['test_result']
				if rec['name'].find('privacy_yara_static') > -1 and do_report:
					v = 0.0
					tmp = rec['test_result'].split('\\n')
					for t in tmp:
						p = t[t.find("weight=\""):]
						p = p.split(",")[0].replace("weight=\"", "").replace("\"", "")
						if len(p) > 1:
							v += float(p)
					print "\tPrivacy Score:", v


	print "\nFound %d vulnerable apk's out of %d successfully parsed files" % (len(vulndb)+1, checkdb)
	print "\tConfirmed: %d" % (dfound)
	print "\tUnconfirmed: %d" % (sfound - dfound)
	print "\nFound %d apk's with Poor Coding Pracitces" % (len(pcpdb))
	





