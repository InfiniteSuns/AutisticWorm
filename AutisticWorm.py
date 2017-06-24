#!/usr/local/bin/python3
# coding: utf8

import argparse    # for getting those command line arguments
from bs4 import BeautifulSoup    # for parsing what they respond
import os    # for os path stuff
import re    # for validating those addresses
import requests    # for making those http requests
import sys    # for stopping gracefully
from termcolor import colored    # because why not?
import traceback    # for when it shits its pants and doesn't stop gracefully

from requests.packages.urllib3.exceptions import InsecureRequestWarning    # for bypassing annoying warning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)    # yea, that one

autistic = """
  ___        _   _     _   _      
 / _ \      | | (_)   | | (_)     
/ /_\ \_   _| |_ _ ___| |_ _  ___ 
|  _  | | | | __| / __| __| |/ __|
| | | | |_| | |_| \__ | |_| | (__ 
\_| |_/\__,_|\__|_|___/\__|_|\___|
"""

worm = """
 _    _                           
| |  | |                          
| |  | | ___  _ __ _ __ ___       
| |/\| |/ _ \| '__| '_ ` _ \      
\  /\  | (_) | |  | | | | | |     
 \/  \/ \___/|_|  |_| |_| |_|
"""

print(colored(autistic, "yellow", attrs=['bold']))
print(colored(worm, "yellow", attrs=['bold']))

print(colored("HTTP title fetch machine, AutisticWorm 0.8.0alpha", "yellow", attrs=['bold']))

print("Brought to you by Dmitry Kireev (@InfiniteSuns)\n")

verbosity = False
timeoutsec = float(3)
ipfile = None    # variable to hold path to ip file
ippattern = re.compile("^([1][0-9][0-9].|^[2][5][0-5].|^[2][0-4][0-9]."
                       "|^[1][0-9][0-9].|^[0-9][0-9].|^[0-9].)([1][0-9][0-9]."
                       "|[2][5][0-5].|[2][0-4][0-9].|[1][0-9][0-9].|[0-9][0-9].|[0-9].)"
                       "([1][0-9][0-9].|[2][5][0-5].|[2][0-4][0-9].|[1][0-9][0-9]."
                       "|[0-9][0-9].|[0-9].)([1][0-9][0-9]|[2][5][0-5]|[2][0-4][0-9]|"
                       "[1][0-9][0-9]|[0-9][0-9]|[0-9])$")    # looks stupid, but works

argparser = argparse.ArgumentParser()
argparser.add_argument('-i', '--ipfile', help="i.e. /root/ipfile.txt", required=True)
argparser.add_argument('-t', '--timeout', help="connection timeout (default is 3 seconds)", required=False)
argparser.add_argument('-v', '--verbose', help="switch to verbose mode", required=False)
args = argparser.parse_args()

if args.ipfile:
    print("[i] IP file received as argument")
    if os.path.exists(args.ipfile):
        print("[+] IP file seems legit\n")
        ipfile = args.ipfile
    else:
        print("[-] IP file seems not legit\n")
        sys.exit(1)
if args.timeout:
    print("[i] Timeout received as argument")
    try:
        timeoutsec = float(int(args.timeout))
        print("[+] Timeout set to " + str(int(timeoutsec)) + " second(s)\n")
    except Exception:
        print("[-] Timeout seems invalid, ignored\n")
if args.verbose:
    verbosity = True

logfile = os.getcwd() + "/AutisticWorm.log"

print("[~] Checking if logfile exists")
if os.path.exists(logfile):
    print("[i] Logfile already exists\n")
else:
    try:
        logfileptr = open(logfile, "w")
        logfileptr.close()
        print("[i] Logfile was created\n")
    except Exception:
        print(colored("[!] Had hard time creating logfile and failed!",
                      "red"))
        traceback.print_exc(file=sys.stdout)
        sys.exit(1)

ports = [('http', '80'), ('http', '8080'), ('https', '443'), ('https', '8443')]    # list of popular http(s) ports

try:
    with open(ipfile) as inputfile:
        iplist = inputfile.readlines()
except Exception:
    print(colored("[!] Had hard time reading ipfile and failed!",
                  "red"))
    traceback.print_exc(file=sys.stdout)
    sys.exit(1)

try:
    for ip in iplist:
        ip = str(ip.rstrip())
        if ippattern.match(ip):
            for port in ports:
                try:
                    ipstring = ip + ":" + port[1]
                    req = requests.get(port[0] + '://' + ipstring, stream=True, verify=False,
                                       timeout=timeoutsec, allow_redirects=True)
                    req.raise_for_status()

                    content = req.content
                    soup = BeautifulSoup(content, 'html.parser')
                    title = soup.find("title")
                    if title is not None:
                        titlestring = str(title.text.encode('utf-8'))
                        print(colored("[+] " + ipstring, color="green", attrs=['bold']))
                        print(titlestring)

                        logfileptr = open(logfile, "a")
                        logfileptr.write(ipstring + " " + titlestring + "\n")
                        logfileptr.close()
                    else:
                        print(colored("[i] Port looks open, but title is somehow empty @ " + ipstring, "yellow"))

                except requests.exceptions.ConnectionError as err:
                    if verbosity:
                        print(colored("[!] Connection error @ " + ip + ":" + port[1], "red"))
                    pass
                except requests.exceptions.HTTPError as err:
                    statuscode = re.search('[0-9]+', str(err.response)).group()
                    print(colored("[i] HTTP error " + statuscode + " @ " + ip + ":" + port[1], "yellow"))
                    pass
                except requests.exceptions.ReadTimeout as err:
                    if verbosity:
                        print(colored("[!] Tired waiting @ " + ip + ":" + port[1], "red"))
                    pass
        else:
            print("[!] " + ip + " seems to be invalid, skipping it")
            pass

except KeyboardInterrupt:
    print(colored("[i] Ctrl+C caught, stopping gracefully",
                  "red"))
