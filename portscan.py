import threading
import socket
from optparse import OptionParser

class ip():

	def __init__(self,ipaddr):
		self.ip = ipaddr
		port_range = [i for i in range(19,300)]
		self.multithread(ipaddr,port_range)
		

	def scan(self,ipaddr,port):
		s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		status = s.connect_ex((ipaddr,port))
		if (status == 0):
			print "[+] =[%s]= Port Open" % port
		else:
			pass

	def multithread(self,ipaddr,ports):
		threads = []
		for i in ports:
			t = threading.Thread(target=self.scan,args=(ipaddr,i,))
			threads.append(t)
			t.start()

	def bannergrab(self,ipaddr,port):
		s = socket.socket()
		s.connect_ex((ipaddr,port))
		s.send('hello')
		response = s.recv(1024)
		print "[Banner Information]\n%s" % response

def parseArgs():

	parser = OptionParser()

	parser.add_option("-t","--target",dest="target",
	help="IP Address to scan within quote",metavar='"127.0.0.1"')

	return parser

def main():
	parser = parseArgs()
	(option, args) = parser.parse_args()

	if option.target != None:
		app = ip(option.target)

	elif option.target == None:
		app = ip('127.0.0.1')

if __name__ == '__main__':
	main()