#!/usr/bin/env python


import nmap
import threading
import Queue
import fcntl
import struct
import socket
import time
import os

global alive_ipaddress
alive_ipaddress = []

"""
Program Flow:

    Main()
        PingScan()
            scanThread()
                scanPing()
        osScan()
            scanThread()
                scanOS()
To implement more functions:
    1. create a control function which generates multiple scanThreads
    2. Add scantype to the scanThread arguments
    3. create the job function which scans for a particular ip
"""

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

class scanThread(threading.Thread):
    """
    This is the main control thread
    Which calls 2 functions 
    scanPing & scanOS
    """
    def __init__(self,q,scan_type):
        threading.Thread.__init__(self)
        self.q = q
        self.scan_type = scan_type

    def run(self):
        if self.scan_type == "ping":
            scanPing(self.q)
        elif self.scan_type == "os":
            scanOS(self.q)

def scanPing(q):
    try:
        queueLock.acquire()
        ip = q.get()
        queueLock.release()
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, arguments='-sP')
        result = nm[ip].state()
    except KeyError:
        pass
    except nmap.PortScannerError:
        pass
    else:
        if result == 'up':
            queueLock.acquire()
            alive_ipaddress.append(str(ip))
            print str("[+] "+bcolors.OKBLUE+"%s"+bcolors.ENDC) % (ip)
            queueLock.release()

def scanOS(q):
    try:
        queueLock.acquire()
        ip = q.get()
        #print "[+] Scanning : %s" % ip
        queueLock.release()
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, arguments='-O')
        osname = nm[ip]["osmatch"][0]["name"]
        accuracy = nm[ip]["osmatch"][0]["accuracy"]
    except KeyError:
        queueLock.acquire()
        print str("[!] "+bcolors.OKBLUE+"%s"+bcolors.ENDC+" : "+ bcolors.WARNING + "No Response"+ bcolors.ENDC) % (ip)
        queueLock.release()
    except KeyboardInterrupt:
        print "\n[+] Program Terminated!"
        exit()
    except nmap.PortScannerError:
        pass
    else:
        if osname:
            queueLock.acquire()
            print str("[+] "+bcolors.OKBLUE+"%s"+bcolors.ENDC+" : "+ bcolors.OKGREEN + \
                "%s [%s%%]"+ bcolors.ENDC) % (ip, osname,accuracy)#, nm[ip].vendor()) "%s" + bcolors.ENDC
            queueLock.release()

def getlocalip():
    """
    This function will return the Local IP Address of the wlan0 interface
    Please change ifname to 'eth0' or whatever your interface name is, if it's not 'wlan0'
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if 'ifname' not in vars(): # Check if the variable ifname is already defined
            ifname = 'wlan0'
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s',ifname[:15]))[20:24])
    except IOError:
        print "{}[!] Error, unable to detect local ip address.\n[!] Check your connection to network{}".format(bcolors.FAIL,bcolors.ENDC)
        exit()

def generateipaddress(ip):
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

def pingScan():
    """
    This function controls the generation of scanThreads
    """
    starttime = time.time()
    works = generateipaddress(getlocalip())
    global queueLock
    queueLock = threading.Lock()
    # set max-size of queue to be the length of works
    workQueue = Queue.Queue(len(works))

    # Add the ips into Queue
    queueLock.acquire()
    for work in works:
        workQueue.put(work)
    queueLock.release()

    thread_count = len(works)
    threads = []

    for i in range(thread_count):
        thread = scanThread(workQueue,"ping")
        thread.start()
        threads.append(thread)

    # Wait for threads to finish
    for thread in threads:
        thread.join()

    print "\n[+] Alive ip addresses : %s" % len(alive_ipaddress)
    endtime = time.time()
    print "[!] Scan Done in : %.2f seconds" % float(endtime-starttime)

def osScan():
    """
    This function will control the generation of scanThreads
    which in turn calls the scanOS() function
    """
    starttime = time.time()
    works = alive_ipaddress
    global queueLock
    queueLock = threading.Lock()
    # set max-size of queue to be the length of works
    workQueue = Queue.Queue(len(works))

    # Add the ips into Queue
    queueLock.acquire()
    for work in works:
        workQueue.put(work)
    queueLock.release()

    thread_count = len(works)
    threads = []

    for i in range(thread_count):
        thread = scanThread(workQueue,"os")
        thread.start()
        threads.append(thread)

    # Wait for threads to finish
    for thread in threads:
        thread.join()

    endtime = time.time()
    print "[!] Scan Done in : %.2f seconds" % float(endtime-starttime)

def main():
    try:
        fpath = os.path.realpath(__file__)
        r00t = root()
        if not r00t:
            print "[+] Getting {}r00t{} privilege".format(bcolors.FAIL,bcolors.ENDC)
            os.system("sudo python %s" % fpath)
            exit()

        pingScan()

        if len(alive_ipaddress) >= 2:
            print "\n[+] Press enter to go to next phase of the scan"
            print "[+] OS Detection (Might take time) --- Ctrl + C to exit"
            response = raw_input("> ")
            if response == "":
                osScan()
            else:
                exit()

    except KeyboardInterrupt:
        print "\n[+] Ctrl + C Detected!"
        print "[+] Terminating..."
        exit()

def root():
    return True if os.getuid() == 0 else False

if __name__ == '__main__':
    from sys import platform
    if 'linux' not in platform:
        print "[!] Sorry, Only " + bcolors.OKGREEN + " Linux operation system" + bcolors.ENDC +" is supported"
    else:
        main()