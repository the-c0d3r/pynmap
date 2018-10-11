"""
This module is responsible for scanning using nmap module
"""
from typing import Any
import lib.nmap


class Scanner:
    nmap = lib.nmap.PortScanner()

    def __init__(self) -> None:
        pass

    def scan(self, ip: str, arguments: Any) -> str:
        try:
            self.nmap.scan(hosts=ip, arguments=arguments)
            return self.nmap[ip]
        except KeyError:
            # this KeyError will trigger on invalid ips such as 192.168.1.0
            pass
