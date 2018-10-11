#!/usr/bin/env python

"""
This is the new ping sweeper to sweep the whole network
"""
from terminaltables import SingleTable
import concurrent.futures
from lib.ip import IPV4Network, ip2int
from lib.scanner import Scanner



def tableprinter(data):
    """Accepts a list of sorted and preformatted data array"""
    sort = sorted(data, key=ip2int)
    data = [("IP", "HOSTNAME")] + sort
    table = SingleTable(data)
    print(table.table)


def main():
    ipList = IPV4Network("192.168.1.0/24").getIPs()
    scanner = Scanner()

    scanResult = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scanner.scan, ip, "-sP"): ip for ip in ipList}

    for future in concurrent.futures.as_completed(futures):
        result = future.result()
        if result:
            host = futures[future]
            hostname = result['hostname']
            scanResult.append((host, hostname))

    tableprinter(scanResult)

main()

