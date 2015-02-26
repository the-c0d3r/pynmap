import threading
import socket
from optparse import OptionParser

class ip():

	def __init__(self):
		self.initialize_variable()

		self.multithread(self.ipaddr,self.portrange)
		
	def initialize_variable(self):
		# This function is for initializing the necessary command arguments and automate default values when one is empty
		# For target argument, the default value is 'Localhost' ('127.0.0.1')
		# As for port range, I think it's just necessary to scan from port 20 to 1024
		
		# Generate a list and assign it to self.portrange

		if option.target:
			self.ipaddr = option.target
		elif not option.target:
			print("\n[!] --target argument is not supplied, default value (localhost) is taken\n")
			self.ipaddr = '127.0.0.1'
		if option.portrange:
			self.highrange = int(option.portrange.split('-')[0])
			self.lowrange = int(option.portrange.split('-')[1])
			self.portrange = [i for i in range((self.lowrange-1),self.highrange)]
			
		elif not option.portrange:
			print("\n[!] --portrange argument is not supplied, default value (20-1024) is taken\n")
			self.highrange = 1024
			self.lowrange = 20
			self.portrange = [i for i in range((self.lowrange-1),self.highrange)]

		

	def scan(self,ipaddr,port):
		# Accepts ipaddress parameter, and port to scan is accepted as port(type=int)
		# Only prints when the port is OPEN
		# Or set your own error message to display with "else" code block

		s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		status = s.connect_ex((ipaddr,port))
		if (status == 0):
			print "[+] =[%s]= Port Open" % port
		else:
			pass

	def multithread(self,ipaddr,ports):
		# Handles port scanning operation with multi-threading
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
	
	parser.add_option("-p","--port range",dest="portrange",
	help="Port Range to scan separated with -",metavar="5-300")

	return parser

def main():
	global option

	parser = parseArgs()
	(option, args) = parser.parse_args()
	# Just assign the class function to do the rest
	app = ip()
#	if option.target != None:
#		app = ip(option.target)
#
#	elif option.target == None:
#		print "[+] Using 'LocalHost' as default target"
#		app = ip('127.0.0.1')

if __name__ == '__main__':
	main()
