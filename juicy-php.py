#!/usr/bin/env python
#
# 
#
# juicy-php.py - Finding paths to phpinfo for aws keys or xdebug rce
#
# By @RandomRobbieBF
# 
#

import requests
import sys
import argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
session = requests.Session()


parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url", required=True ,default="http://localhost",help="URL to test")
parser.add_argument("-p", "--proxy",required=False, help="Proxy for debugging")

args = parser.parse_args()
url = args.url
if args.proxy:
	proxy = args.proxy
else:
	proxy = ""




http_proxy = proxy
proxyDict = { 
              "http"  : http_proxy, 
              "https" : http_proxy, 
              "ftp"   : http_proxy
            }
            
            



def test_url(url,urlpath):
	newurl = ""+url+"/"+urlpath+""
	headers = {"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0","Connection":"close","Accept":"*/*",}
	try:
		response = session.get(newurl, headers=headers,verify=False, proxies=proxyDict,timeout=30)
		if response.status_code == 200:
			if "$_SERVER['SCRIPT_NAME']" in response.text:
				print("[+] Found PHPinfo for "+newurl+" [+]")
					if 'xdebug.remote_connect_back</td><td class="v">On</td>' in response.text:
						print("[+] Xdebug Enabled Possible RCE [+]")
						text_file = open("xdebug.txt", "a")
						text_file.write(""+newurl+"\n")
						text_file.close()
						return True
					if 'AWS_SECRET' in response.text:
						print("[+] AWS Keys Exposed [+]")
						text_file = open("aws.txt", "a")
						text_file.write(""+newurl+"\n")
						text_file.close()
						return True
					if "nginx" and "FPM/FastCGI" and "PHP Version 7." in response.text:
						print("[+] Nginx / FPM - Look at possible rce https://github.com/neex/phuip-fpizdam [+]")
						text_file = open("fpm-rce.txt", "a")
						text_file.write(""+newurl+"\n")
						text_file.close()
						return True	
						
					if 'ImageMagick release date </td><td class="v">2016' in response.text:
						print("[+] Check Out CVE-2016-3714 RCE might be possible if you can upload an image. [+]")
						text_file = open("imagetrick.txt", "a")
						text_file.write(""+newurl+"\n")
						text_file.close()
						return True				
			else:
				print("[-] No Luck for "+urlpath+" [-]")
		else:
			print("[-] No Luck for "+urlpath+" [-]")
	except:
		print ("[-] Check Url might have Issues [-]")
		sys.exit(0)
			
			
def grab_paths(url):
	headers = {"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0","Connection":"close","Accept-Language":"en-US,en;q=0.5","Accept-Encoding":"gzip, deflate"}
	try:
		response = session.get("https://gist.githubusercontent.com/RandomRobbieBF/ea5b4bb307fa6f73bb4714841883bfbe/raw/phpinfo.txt", headers=headers,verify=False, proxies=proxyDict)
		lines = response.text.strip().split('\n')
		for urlpath in lines:
			loop = test_url(url,urlpath)
			if loop:
				break
	except:
		print("[-] Failed to obtain paths file [-]")
		sys.exit(0)
				
	
grab_paths(url)
