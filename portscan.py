import threading
import socket
from optparse import OptionParser
import nmap
import time

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    ENDC = '\033[0m' # Add this color for reseting back the color.

banner = r"""{}{}
 ____   __   ____  ____        ____   ___   __   __ _ 
(  _ \ /  \ (  _ \(_  _)      / ___) / __) / _\ (  ( \
 ) __/(  O ) )   /  )(        \___ \( (__ /    \/    /
(__)   \__/ (__\_) (__)       (____/ \___)\_/\_/\_)__)
============================{}Written by the-c0d3r{}{}======
""".format(bcolors.OKGREEN,bcolors.BOLD,bcolors.WARNING,bcolors.OKBLUE,bcolors.ENDC)


class ip():

    def __init__(self):
        self.initialize_variable()

        self.multithread(self.ipaddr,self.portrange)
        
    def initialize_variable(self):

        self.verbose = False
        # This switch is to be used when the port number is defined. 
        # to display if the designated port is closed or not. 


        print banner
        # This function is for initializing the necessary command arguments and automate default values when one is empty
        # For target argument, the default value is 'Localhost' ('127.0.0.1')
        # As for port range, I think it's just necessary to scan from port 20 to 1024
        
        # Generate a list and assign it to self.portrange

        if option.target:
            if option.target[0].isdigit():
                self.ipaddr = option.target
            elif option.target[0].isalpha():
                addr = (option.target)
                if 'http://' in addr: addr = addr.strip('http://')
                self.ipaddr = self.resolve(addr)

        elif not option.target:
            print("\n[!] --target argument is not supplied, default value (localhost) is taken")
            self.ipaddr = '127.0.0.1'

        if option.portrange:
            if '-' in option.portrange:
                self.highrange = int(option.portrange.split('-')[1])
                self.lowrange = int(option.portrange.split('-')[0])
                self.portrange = [i for i in range(self.lowrange,(self.highrange+1))]
            else:
                self.portrange = [option.portrange]
                self.verbose = True

        elif not option.portrange:
            print("[!] --portrange argument is not supplied, default value (20-1024) is taken\n")
            self.highrange = 1024
            self.lowrange = 20
            self.portrange = [i for i in range(self.lowrange,self.highrange)]

    def resolve(self, host):
        # Get website and translate it to IP address
        # Using very low level socket module
        print("[+] Target argument received website address")
        print("[+] Resolving website address to ip address")
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            print(bcolors.WARNING+"[!] Error resolving website to ip, please get ip address manually"+bcolors.ENDC)
            exit()
        else:
            #print((bcolors.OKBLUE+"[+] %s = %s"+bcolors.ENDC) % (host, ip))
            print("{}[+] {} = {}".format(bcolors.OKBLUE,host,ip,bcolors.ENDC))
            return ip

    def scan(self,ipaddr,port):
        # Accepts ipaddress parameter, and port to scan is accepted as port(type=int)
        # Only prints when the port is OPEN
        # Or set your own error message to display with "else" code block
        #print("[.] Scanning %s : %s" % (ipaddr,port))
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        status = s.connect_ex((ipaddr,port))
        if (status == 0):
            # print("[+] =[\033[91m%s\033[0m]= Port Open"  % port)
            print("[+] =[\033[91m{:^6}\033[0m]= Port Open".format(port))
        else:
            if self.verbose:
                print("{}[+]=[{}]= Port closed{}".format(bcolors.FAIL, port, bcolors.ENDC))
            elif not self.verbose:
                pass

    def online(self,ip):
        """ Check if target is online using nmap -sP probe """
        # -sP probe could be blocked. Check for common ports. 
        # there could be solution with socket module. 
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=ip, arguments='-sP')
            result = nm[ip].state()
        except KeyError:
            pass
        else:
            if result == 'up':
                return True
            else:
                return False

    def multithread(self,ipaddr,ports):
        # Handles port scanning operation with multi-threading
        try:
            # Check if the target is online or offline first.
            if self.online(ipaddr):
                print("[~] Target : "+bcolors.HEADER+"%s"%ipaddr+bcolors.ENDC)
                if len(ports) > 1:
                    for i in ports:
                        t = threading.Thread(target=self.scan,args=(ipaddr,int(i),)).start()
                else:
                    t = threading.Thread(target=self.scan,args=(ipaddr,int(ports[0]))).start()

                #self.bannergrab(ipaddr,80)

            elif not self.online(ipaddr):
                print("[!] Target IP is offline, or blocking nmap -sP probe")

        except KeyboardInterrupt:
            print("[~] Process stopped as TERMINATE Signal received")

    def bannergrab(self,ipaddr,port):
        s = socket.socket()
        s.connect_ex((ipaddr,port))
        s.send('GET HTTP/1.1 \r\n')
        
        response = s.recv(1024)
        time.sleep(3)
        if response:
            pass
        print "[Banner Information]\n%s" % response

def parseArgs():

    parser = OptionParser()

    parser.add_option("-t","--target",dest="target",
    help="IP Address to scan",metavar="127.0.0.1")
    
    parser.add_option("-p","--port range",dest="portrange",
    help="Port Range to scan separated with -",metavar="5-300 or 80")

    return parser

def main():
    global option

    parser = parseArgs()
    (option, args) = parser.parse_args()
    # Just assign the class function to do the rest
    app = ip()
#   if option.target != None:
#       app = ip(option.target)
#
#   elif option.target == None:
#       print "[+] Using 'LocalHost' as default target"
#       app = ip('127.0.0.1')

if __name__ == '__main__':
    main()
