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
		starttime = time.time()
		threads = []
		for i in ip:
			t = threading.Thread(target=self.scan,args=(i,))
			threads.append(t)
			t.start()
		while t.isAlive(): # Check if there is alive threads, if the threads are still running
			time.sleep(0.05)
		else:
			endtime = time.time()
			print "Scan done in %d Seconds" % (endtime - starttime)

	def scan(self,ip):
		try:
			nm = nmap.PortScanner()
			nm.scan(hosts=ip, arguments='-sP')
			result = nm[ip].state()
		except KeyError:
			pass
		else:
			if result == 'up':
				print "%s is alive" % ip

	def getlocalip(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
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
	main()
