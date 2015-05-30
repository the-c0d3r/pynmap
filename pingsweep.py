#!/usr/bin/env python

# nmap is for nmap scanning of course.
import nmap
import re
import os
import threading
import fcntl
import struct
import socket
import time

global keeptime
keeptime = False


class bcolors:
	# This module is just for beautifying output
	# bcolors.ENDC should be followed after using each
	# of the variables to revert back to original color

    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class IP():

	def __init__(self):
		# get localip/LANip
		self.localip = self.getlocalip()
		# Generate ip address list with range
		self.iptoscan = self.generateipaddress(self.localip)
		#print self.iptoscan
		
		# Start multithreading
		self.multithread(self.iptoscan)

	def multithread(self,ip):
		if keeptime: 
			starttime = time.time()
		threads = []
		for i in ip:
			t = threading.Thread(target=self.scan,args=(i,))
			threads.append(t)
			t.start()
		
		if keeptime:
			while t.isAlive():
				time.sleep(0.005)
			else:
				if keeptime:
					endtime = time.time()
					print "[+] Scan done in %d Seconds" % (endtime - starttime)

	def scan(self,ip):
		try:
			nm = nmap.PortScanner()
			nm.scan(hosts=ip, arguments='-sP')
			result = nm[ip].state()
		except KeyError:
			pass
		else:
			if result == 'up':
				
				hostname = (nm[ip].hostname() if nm[ip].hostname() else 'unknown')

				print str("[+] "+bcolors.OKBLUE+"%s"+bcolors.ENDC+" : "+ bcolors.OKGREEN + \
					"%s"+ bcolors.ENDC) % (ip, hostname)#, nm[ip].vendor()) "%s" + bcolors.ENDC

	def getlocalip(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

		if 'ifname' not in vars(): # Check if the variable ifname is already defined
			ifname = 'wlan0'
		return socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s',ifname[:15]))[20:24])


	def generateipaddress(self,ip):
		''' Generate IP Address for scanning
		Returns list'''
		octets = ip.split('.')
		# got 4 octets now
		# get first 3 octets, combine them with '.'
		# and iterate from 0 to 255 for the last octet
		first3 = str(octets[0]+"."+octets[1]+"."+octets[2]+".")
		# get 3 octets and combine them with 1 to 255
		iplist = [first3+str(i) for i in range(0,256)]
		return iplist

def main():

	app = IP()

if __name__ == '__main__':
	from sys import platform
	if 'linux' not in platform:
		print "[!] Sorry, Only " + bcolors.OKGREEN + " Linux operation system" + bcolors.ENDC +" is supported"
	else:
		main()


'''
to do
=====
check for root permission
and if not root
ask to execute itself with sudo

os.system('sudo python pingsweep.py')'''