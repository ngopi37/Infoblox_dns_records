#!/bin/python3

#import pydig
import argparse
import requests
import re
import sys,socket
from infoblox_client import connector
from infoblox_client import objects
from infoblox_client import utils
import dns
from dns import resolver
from dns import reversename
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from profanity import profanity
from datetime import datetime
import time
import getpass 
import logging
from csv import reader
from os import path


now = datetime.now()
date_time = now.strftime("%m%d%Y")
log_file="dns_create_delete"+date_time
logging.basicConfig(filename="/tmp/"+log_file,format='%(asctime)s %(message)s',filemode='a+')
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
host = "x.x.x.x"

main_parser = argparse.ArgumentParser(add_help=False)
main_parser.add_argument('--view',
                    help='DNS view',
                    choices=["Internal-Production", "External-Production"],
                    default="Internal-Production")
#main_parser.add_argument('--username',
#                    help='Username to connect Infoblox',required=True)
#main_parser.add_argument('--password',
#                    help='password to connect Infoblox',required=True)
parser = argparse.ArgumentParser(prog="DNS_Host",description="DNS Host Create/Delete program",conflict_handler='resolve',formatter_class=argparse.RawTextHelpFormatter,usage="DNS_Host [-h] {create_host_record and delete_host_record} ...")

subparsers = parser.add_subparsers(dest='command',
                                   title="Options")
subparsers.required = True

subparser = subparsers.add_parser('create_a_record', parents=[main_parser],                                                                  
                                  help="(example \"Dns_Host create_a_record 10.1.1.1 abc.server1.com --username admin --password  password --view(optional) Default Internal-Production\")")
subparser.add_argument('ip',
                       help='IPv4 address for the record')
subparser.add_argument('fqdn',
                       help='fqdn name for ip address')
subparser.add_argument('--ttl',
                       type=int,
                       help='TTL for TXT record')
#subparser.add_argument('--ea', type=json.loads,
#                       help='External Atrributes of host to create example \"{\"Ticket_number\" : \"RITM111123\"}\"')

subparser = subparsers.add_parser('delete_a_record',parents=[main_parser],
                                  help='(example \"DNS_Host delete_a_record abc.server1.com --username admin --password  password \")') 
subparser.add_argument('ip',
                       help='IPv4 address for the record')
subparser.add_argument('fqdn',
                       help='fqdn name for ip address')

subparser = subparsers.add_parser('bulk_upload',parents=[main_parser],
                                  help='(example DNS_Host bulk_upload --view(option) Internal -i \"/tmp/dns_input.csv\"') 

subparser.add_argument('-i','--input_file',help='input csv file')

args = parser.parse_args(None if sys.argv[1:] else ['-h'])

#username = getpass.getuser() 
username = input("Username:")
password = getpass.getpass()
ticket_number = input("Ticket Number:")
hostname=socket.gethostname()
os_user = getpass.getuser()

opts = {'host': host, 'username': username, 'password': password}

ib_api_connect = connector.Connector(opts)

def is_valid_hostname(hostname): 
    regex = re.compile('[@!#$%^&*()<>?/\|}{~:+=]')

    if(regex.search(hostname) == None): 
        if profanity.contains_profanity(hostname):
           print("Hostname contains bad words")
           logger.error("DNS Addition performed by %s: Hostname contains bad words",os_user)
           return False
        else:
          return True 
    else: 
        return False 
    
def resolve_ip(ip,quiet=False):
    rev_name=reversename.from_address(ip)
    try:
        answer = resolver.query(rev_name,'ptr')
        if not quiet:
            print("[+] " + str(ip) + " : " + str(answer[0]))
        return 1, str(answer[0])
    except resolver.NXDOMAIN:
        #if not quiet:
            #print(str(ip) +" is available for creation...")
        return 2, None
    except resolver.NoNameservers:
        if not quiet:
            print("[-] Answer refused for " + str(ip))
        return 3, None
    except resolver.NoAnswer:
        if not quiet:
            print("[-] No answer section for " + str(ip))
        return 4, None
    except dns.exception.Timeout:
        if not quiet:
            print("[-] Timeout")
        return 5, None

def dig_hostname(hostname,ip):
    hr = 0
    result = dns.resolver.resolve(hostname, 'A',raise_on_no_answer=False)
    if result.rrset is not None:
       hr=1
       for rdata in result:
           print('A:', rdata.to_text())
    resolved_ip = resolve_ip(ip)
    if(resolved_ip[1] != None):
        if(resolved_ip[1] == hostname):
          hr=1
 #return False
        r_ip = 1
    else:
        r_ip = 0
    if(hr == 1 and r_ip == 1):
        print("{0} and {1} are in use".format(hostname,ip))
        logger.error("DNS Addition performed by %s: %s and %s are in use",os_user,hostname,ip)
        return False
    if(hr == 1 and r_ip == 0):
        print("{0} is in use and {1} is free to use".format(hostname,ip))    
        logger.error("DNS Addition performed by %s: %s is attached and %s free to use",os_user,hostname,ip)
        return False
    if(hr == 0 and r_ip == 1):
        logger.error("DNS Addition performed by %s: %s is free to use and %s is attached to %s",os_user,hostname,ip,resolved_ip[1])
        print("{0} is free to use and {1} is assigned to {2}".format(hostname,ip,resolved_ip[1]))
        return False
    if(hr== 0 and r_ip == 0):
         print("{0} and {1} are free to use".format(hostname,ip))
         return True
     
def post_validation(ip):
    rev_name=reversename.from_address(ip)
    answer = resolver.query(rev_name,'ptr')
    if str(answer[0]) is not None:
       print(str(ip) + " assigned to " + str(answer[0]))

class host_create:
          
    def create_a_record(self,conn,fqdn,ip,view ):
        hr_exists = 0
        ipr_exists = 0
        resolved_ip = []
        z_name = '.'.join(fqdn.split('.')[1:]).rstrip()
        try:
           find_zone_name = objects.DNSZone.search(conn, fqdn=z_name,view=view)
           if(find_zone_name == None):
             print("error --- "+ z_name +' This is not a valid zone name......Please Check')
             sys.exit()
           if(is_valid_hostname(fqdn) == False):
               sys.exit("{0} Not a valid hostname".format(fqdn))
           if(utils.is_valid_ip(ip) == False):
                 sys.exit("{0} Not a valid ip address".format(ip))
           if(dig_hostname(fqdn,ip)):
               find_record = objects.ARecord.search(conn, name=fqdn,view=view)
               if find_record :
                  resolved_ip = resolve_ip(ip)
                  if(resolved_ip[1] != None):
                     r_ip=resolved_ip[1] 
                     print("Host {0} is already in use and associated with {1}".format(fqdn,r_ip))
                  else:
                     print("Host {0} is already in use".format(fqdn))    
               else:
                    #print("Both {0} and {1} are available and free to use".format(fqdn,ip))
                  ea = objects.EA({ "Ticket Number" : ticket_number})
                    #my_ip = objects.IP.create(ip,view=view)
                  result = objects.ARecord.create(conn,check_if_exists=True,name=fqdn,ipv4addr=ip,view=view,extattrs=ea)
                  print(fqdn +" record created successfully")
                  logger.info("%s %s: DNS addition performed by %s: %s :%s view:%s",hostname,os_user,username,fqdn,ip,view)
                  print("Post record creation and validation is in progress .....")
                  time.sleep(1)
                  post_validation(ip)
        except Exception as e:
               print(e)
               
    def delete_a_record(self,conn,fqdn,ip,view):
        try:
            find_arecord = objects.ARecord.search(conn,name=fqdn,view=view)
            if(find_arecord):
               delete_arecord=find_arecord.delete()
               if delete_arecord == None:
                  print("A record {0} deleted sucessfully".format(fqdn))
                  #logger.info("Ticket Number :%s",ticket_number)
                  logger.info("%s %s: DNS deletion  performed by %s: %s :%rs view:%s",hostname,os_user,username,fqdn,ip,view) 

            else:
                print(fqdn +" not available")
        except Exception as e:
            logger.error("%s %s: DNS deletion  performed by %s: error : %s",hostname,os_user,e)
            print(e)
                    
        
host_create = host_create()
command = args.command
view = args.view
if(command == "create_a_record"):
    host_create.create_a_record(ib_api_connect,args.fqdn,args.ip,args.view)
if(command == "delete_a_record"):
    host_create.delete_a_record(ib_api_connect,args.fqdn,args.ip,args.view)
if(command == "bulk_upload"):
    input_file=args.input_file
    if (str(path.exists(input_file))):
       with open(input_file) as csv_file:
        #reader = csv.DictReader(csv_file)
            csv_reader = reader(csv_file)
            for row in csv_reader:
                task_type = row[0]
                fqdn = row[1]
                ip = row[2]
                action = row[3]
                if(task_type == "A"):
                   print("A record : ")
                if(action == "add"):
                   print("A record creation ....")
                   host_create.create_a_record(ib_api_connect, fqdn,ip,view)
                if(action == "delete"):
                   print("A record deletion ....")
                   host_create.delete_a_record(ib_api_connect, fqdn,ip,view)
# remove used arguments
#del(args.command)
# call subcommand
#getattr(host_create, command)(ib_api_connect, args)
