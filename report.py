#!/usr/bin/python
import os
import sys
import sqlite3 as lite
from fpdf import FPDF, HTMLMixin
 
class MyFPDF(FPDF, HTMLMixin):
	def footer(self):                
		#Position at 1.5 cm from bottom
		self.set_y(-15)
		#Arial italic 8
		self.set_font('Arial','I',8)
		#Text color in gray
		self.set_text_color(128)
		#Page number
		self.cell(0,10,'Page '+str(self.page_no()),0,0,'C')


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


def getTitle(title, sample):
	html = '''
<table align="center" width="100%">
<tr>
<td width="100%" align="center">
<h1>
Analysis Report For:
</h1>
<h3>
{0}
</h3>
</td>
</tr>
</table>'''

#	html += """<H1 align="center"> %s </H1>""" % (title)
#	html += """<h2 align="center">%s</h2>""" % sample
	return html.format(sample)

def getTOC():

	html = '''<br><h2><b><u>Contents:</u></b></h2>
<ol>
<li><b>Summary</b></li>
<li><b>General Information</b></li>
<li><b>Privacy Analysis</b></li>
<li><b>Vulnerability Analysis</b></li>
<li><b>Quality Analysis</b></li>
</ol>
'''
	return html
	

def getToc(pdf):

	html = '''<br><h2><b><u>Table of Contents</u></b></h2>
<ol>
<li><b>General Information</b></li>
<li><b>Static Analysis Report</b></li>
<ol><li>Activities</li>
<li>Services</li>
<li>Broadcast Receivers</li>
<li>Required Permissions</li>
<li>Used Permissions</li>
<li>Features</li>
<li>Urls</li></ol>
<li><b>Dynamic Analysis Report</b></li>
<ol><li>File Operations</li>
<li>Network Operations</li>
<li>Started Services</li>
<li>Data Leaks</li></ol>
</ol>
'''
	# Begin with regular font
	pdf.write_html(html)
	l = pdf.add_link()
	pdf.set_link(l)


	html = """<H2 align="center" id="general-info" name="general-info"> Table of Contents 2</H2>
<ul><li>Title</li>
<li>Table of Contents</li>
<li>Summary</li>
<li>Privacy</li>
<li>Vulnerabilities</li>
<li>Poor Coding Practices</li></ul>
<br><br><h2>General Information</h2>
"""
	pdf.write_html(html)
	pdf.write(5,'www.fpdf.org',l)
	return pdf


def getSummary(summary, curs):
	html = """<H2 align="center"> Summary </H2>"""
	html += """<p>%s: this is a place holder, we will put information describing the table and what the colors mean</p>""" % (summary)
	html += """<table border="1" align="center" width="90%">
<thead>
<tr>
<th width="30%">Privacy</th>
<th width="30%">Vulnerability</th>
<th width="30%">Quality</th>
</tr>
</thead>
<tbody>
<tr>
<td bgcolor="{0}"> </td>
<td bgcolor="{1}"> </td>
<td bgcolor="{2}"> </td>
</tr>
</tbody>
</table>"""
	cat1 = getPrivacyScore(curs)
	cat2 = getVulnerabilityScore(curs)
	cat3 = getPcpScore(curs)
	return html.format(cat1, cat2, cat3)


def getVulnerabilityReport(curs):
	recs = makedicts(curs, 'select * from apk_table')
	tmp = []
	rpts = []
	for rec in recs:
		if rec['is_test'] == 1:
			if rec['category'].find('vulnerability test') > -1:
				if not rec['test_result'].find('Not Vulnerable') > -1:
					tmp.append(rec['name'] + ' ' + rec['test_result'])
					try:
						rpts.append(str(rec['report']).replace("\\n", "\n"))
					except:
						rpts.append("")
						pass
	html = """<H2 align="center"> Vulnerability </H2>"""
	html += """<p>Test Results Place Holder</p>"""
	for a in range(0, len(tmp)):
		s = tmp[a].split(" ")
		html += "<ul><li>%s</li>" % s[0]
		for i in range(1, len(s)):
			if len(s[i]) > 1:
				html += "<ul><li>" + s[i] + "</li></ul>"
		if len(rpts[a]) > 1:
			html += "<ul><li>" + rpts[a] + "</li></ul>" 
		html += "</ul>"
	return html

def getPcpReport(curs):
	recs = makedicts(curs, 'select * from apk_table')
	tmp = []
	for rec in recs:
		if rec['is_test'] == 1:
			if rec['category'].find('pcp test') > -1:
				if rec['test_result'].find('True') > -1:
					tmp.append(rec['name'] + ' ' + rec['test_result'])

	html = """<H2 align="center"> Privacy </H2>"""
	html += """<p>this is a place holder</p>"""
	for t in tmp:
		s = t.split(" ")
		html += "<ul><li>%s</li>" % s[0]
		for i in range(1, len(s)):	
			html += "<ul><li>" + s[i] + "</li></ul>"
		html += "</ul>"
	return html

def getPrivacyScore(curs):
	recs = makedicts(curs, 'select * from apk_table')
	v = 0.0
	for rec in recs:
		if rec['name'].find('privacy_yara_static') > -1:
			tmp = rec['test_result'].split('\\n')
			for t in tmp:
				p = t[t.find("weight=\""):]
				p = p.split(",")[0].replace("weight=\"", "").replace("\"", "")
				if len(p) > 1:
					v += float(p)
				
	if v < 1.0:
		score = "#00FF00"
	elif v > 5.0 and v < 10.0:
		score = "#FFFF00"
	else:
		score = "#FF0000"
	return score

def getVulnerabilityScore(curs):
	score = "#00FF00"
	recs = makedicts(curs, 'select * from apk_table')
	scount = 0
	for rec in recs:
		if rec['is_test'] == 1:
			if rec['category'].find('dynamic vulnerability test') > -1:
				if not rec['test_result'].find('Not Vulnerable') > -1:
					return  "#FF0000"
			if rec['category'].find('static vulnerability test') > -1:
				if not rec['test_result'].find('Not Vulnerable') > -1:
					scount += 1
	if scount > 1:
		score = "#FFFF00"
	return score

def getPcpScore(curs):
	recs = makedicts(curs, 'select * from apk_table')
	for rec in recs:
		if rec['is_test'] == 1:
			if rec['category'].find('pcp test') > -1:
				if rec['test_result'].find('True') > -1:
					return  "#FF0000"
	return "#00FF00"

def getGeneralInfo(curs):
	html = """<H2 align="center"> General Information </H2>"""
	html += """<p>Various general information about the apk</p><br></br>"""
	
	recs = makedicts(curs, 'select * from apk_table')
	for rec in recs:
		if rec['is_test'] == 1:
			if rec['category'].find('static component test') > -1:
				#print rec['name'], rec['test_result']
				html += """<p>{0}</p><h4>{1}</h4>""".format(rec['name'], rec['test_result'])
	return html

def getPrivacyReport(curs):
	html = """<H2 align="center"> Privacy </H2>"""
	html += """<p>Privacy rules that hit on the apk</p><br></br>"""
	
	recs = makedicts(curs, 'select * from apk_table')
	for rec in recs:
		if rec['name'].find('privacy_yara_static') > -1:
			tmp = rec['test_result'].split('\\n')
			for t in tmp:
				t = t.replace("tmp.dex", "")
				t = t.lstrip(" ")
				n = t.split(" ")[0]
				r = t.replace(n, "")
				html += "<p>{0}</p><h4>{1}</h4>".format(n, r) 
	return html

def getVulnReport(curs):
	html = """<H2 align="center"> Vulnerability </H2>"""
	html += """<p>Static and dynamic vulnerability rules that hit on the apk</p><br></br>"""
	
	recs = makedicts(curs, 'select * from apk_table')
	for rec in recs:
		if rec['category'].find('static vulnerability test') > -1 or  rec['category'].find('dynamic vulnerability test')> -1:
			html += "<p>{0}</p><h4>{1}</h4>".format(rec['name'], rec['test_result']) 
			if len(rec['report']) > 1 and rec['test_result'].find('Not Vulnerable') == -1:
				html += "<h5>{0}</h5></h4>".format(rec['report'].replace("\\n", "\n"))
	return html

def getQualityReport(curs):
	html = """<H2 align="center"> Quality </H2>"""
	html += """<p>Quality rules that hit on the apk</p><br></br>"""
	
	recs = makedicts(curs, 'select * from apk_table')
	for rec in recs:
		if rec['category'].find('static pcp test') > -1:
			html += "<p>{0}</p><h4>{1}</h4>".format(rec['name'], rec['test_result']) 
	return html


def help():
	print 'report.py /path/to/database/file.db /output/file'

if __name__ == "__main__":

	if len(sys.argv) != 3:
		help()
		sys.exit()
	print 'Input Database: ', sys.argv[-2]
	print 'Output PDF: ', sys.argv[-1]

	conn = lite.Connection(sys.argv[-2])
	curs = conn.cursor()

	#pdf.set_title(title)
	#pdf.set_author('AMA Research')

	title = "AMA Security Research Report: "
	sample = (sys.argv[-2].split('/')[-1].rstrip('.db'))
	pdf=MyFPDF()	
	pdf.add_page()
	html = getTitle(title, sample)
	pdf.write_html(html)

	pdf.add_page()
	html = getTOC()
	pdf.write_html(html)
	
	pdf.add_page()
	html = getSummary('Summary', curs)
	pdf.write_html(html)

	pdf.add_page()
	html = getGeneralInfo(curs)
	pdf.write_html(html)
	
	pdf.add_page()
	html = getPrivacyReport(curs)
	pdf.write_html(html)

	pdf.add_page()
	html = getVulnReport(curs)
	pdf.write_html(html)

	pdf.add_page()
	html = getQualityReport(curs)
	pdf.write_html(html)

	pdf.output(sys.argv[-1],'F')

