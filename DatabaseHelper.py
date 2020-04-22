#!/usr/bin/python

'''
Database Helper Class
'''

import sqlite3 as lite


class DBHelper():

	def __init__(self, db_name="output/test.db", empty_on_startup=True, table_name="apk_table", scheme = ["name text", "is_file_from_apk int", "file_data text", "is_binary int", "is_apk int", "is_test int", "is_running int", "test_result text", "category text", "report text"]):
		self.db_name = db_name
		self.table_name = table_name
		self.empty_on_startup = empty_on_startup
		self.scheme = scheme
		self.conn = lite.Connection(self.db_name)
		self.curs = self.conn.cursor()
		#make the table empty on startup
		try:
			if self.empty_on_startup:
				self.curs.execute("drop table " + self.table_name)
		except:
			pass
		self.curs.execute('create table %s (%s)' % (self.table_name, ",".join(self.scheme))) 
		self.conn.commit()

	def getindex(self, col_name):
		for i in range(0, len(self.scheme)):
			if self.scheme[i].split(" ")[0] == col_name:
				return i
		return None

	def getrow(self, cursor, table, column, value):
		cursor.execute('select * from ' + table)
		rows = cursor.fetchall()
		for row in rows:
			if row[column] == value:
				return row
		return None

	def addrow(self, cursor, table, data, debug=False):
		cursor.execute('select * from ' + table)
		if debug:
			print 'insert into %s values (%s)' % (table, str(data).rstrip("]").lstrip("["))
		cursor.execute('insert into %s values (%s)' % (table, str(data).rstrip("]").lstrip("[")))
		self.conn.commit()
		
	def updaterow(self, cursor, table, fieldname, data, key, value):
		cursor.execute('select * from ' + table)
		cursor.execute('update %s set %s = "%s" where %s = "%s"' % (table, fieldname, data, key, value))
		self.conn.commit()

	def deleterow(self, cursor, table, condition):
		cursor.execute('delete from %s where %s' % (table, condition))
		self.conn.commit()
		
	def makedicts(self, cursor, query, params=()):
		cursor.execute(query, params)
		colnames = [desc[0] for desc in cursor.description]
		rowdicts = [dict(zip(colnames, row)) for row in cursor.fetchall()]
		return rowdicts

	def showformat(self, recs, sept = ('-' * 40)):
		print len(recs), 'records'
		print sept
		for rec in recs:
			maxkey = max(len(key) for key in recs)
			for key in rec:
				print '%-*s => %s' % (maxkey, key, rec[key])
			print sept

	def dumpdb(self, cursor, table, format=True):
		if not format:
			cursor.execute('select * from ' + table)
			while True:
				rec = cursor.fetchone()
				if not rec:
					break
				print rec
		else:
			recs = self.makedicts(cursor, 'select * from ' + table)
			self.showformat(recs)


if __name__ == "__main__":
	tmp = DBHelper()
	tmp.dumpdb(tmp.curs, tmp.table_name)
	data = [""] * len(tmp.scheme)

	data[0] = "asdf"
	tmp.addrow(tmp.curs, tmp.table_name, data)

	data[0] = "qwer"
	tmp.addrow(tmp.curs, tmp.table_name, data)
	tmp.dumpdb(tmp.curs, tmp.table_name)

	fname = tmp.scheme[-1].split(" ")[0] 	#name of row field to update
	fdata = "test test test"		#new data
	key = tmp.scheme[0].split(" ")[0]	#search on row field
	value = data[0]				#value of row field to update
	tmp.updaterow(tmp.curs, tmp.table_name, fname, fdata, key, value)
	tmp.dumpdb(tmp.curs, tmp.table_name)

	tmp.deleterow(tmp.curs, tmp.table_name, "name = 'asdf'")
	tmp.dumpdb(tmp.curs, tmp.table_name)
		
		



	
