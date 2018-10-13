"""
This module is responsible for manipulating the ip addresses
"""

import sys
import socket
import struct
import fcntl
import ipaddress
from typing import List

from lib.colors import Colors


class IPV4Network:
    def __init__(self, CIDR: str) -> None:
        """Accepts CIDR format ip address"""
        self.ipList = [ip for ip in ipaddress.ip_network(CIDR)]

    def getIPs(self) -> List[str]:
        """Returns all the ip address in the CIDR range"""
        return [str(ip) for ip in self.ipList]


def ip2int(row) -> int:
    """converts ip to int"""
    return int(ipaddress.IPv4Address(row[0]))


def getLocalip(interface: str = "wlan0") -> str:
    """This function will return the Local IP Address of the interface"""
    if "nux" in sys.platform:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            return socket.inet_ntoa(
                fcntl.ioctl(
                    s.fileno(), 0x8915, struct.pack('256s',interface[:15])
                )[20:24]
            )
        except IOError:
            print("{}[!] Error, unable to detect local ip address.".format(Colors.FAIL))
            print("[!] Check your connection to network {}".format(Colors.ENDC))
            exit()
    elif "darwin" in sys.platform:
        return [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][0]
