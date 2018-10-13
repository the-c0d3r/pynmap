#!/usr/bin/env python

"""
This is the new ping sweeper to sweep the whole network
"""
import argparse
import time
import concurrent.futures
from terminaltables import SingleTable

from lib.ip import IPV4Network, ip2int
from lib.scanner import Scanner


def tableprinter(data: [(str, str)]) -> None:
    """Accepts a list of sorted and preformatted data array"""
    sort = sorted(data, key=ip2int)
    data = [("IP", "HOSTNAME")] + sort
    table = SingleTable(data)
    print(table.table)


def build_parser() -> argparse.ArgumentParser:
    """Configures a parser and return it"""
    parser = argparse.ArgumentParser(prog="pingsweeper", description="Multithreaded ping sweeper")
    parser.add_argument("-t", "--target", help="Target network in CIDR format eg. 192.168.1.0/24")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.target is None:
        parser.print_help()
        print("[-] -t target parameter required")
        exit()

    starttime = int(time.time())
    ipList = IPV4Network(args.target).getIPs()
    scanner = Scanner()
    print("Scanning {} network".format(args.target))

    scanResult = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=254) as executor:
        futures = {executor.submit(scanner.scan, ip, "-sP"): ip for ip in ipList}

    for future in concurrent.futures.as_completed(futures):
        result = future.result()
        if result:
            host = futures[future]
            hostname = result['hostname']
            scanResult.append((host, hostname))

    tableprinter(scanResult)
    endtime = int(time.time())
    print("Elasped : {} seconds".format(endtime - starttime))

main()

