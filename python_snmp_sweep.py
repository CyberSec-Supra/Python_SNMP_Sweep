#!/usr/bin/env python3

from pysnmp.hlapi import *
import ipaddress
import argparse
import sys

def snmp_walk(ip, community='public', depth=3, output_handle=None):
    header = f"\n[+] SNMP on {ip}:\n"
    print(header.strip())
    if output_handle:
        output_handle.write(header)

    root_oid = ObjectIdentity('1.3')
    visited = set()

    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),  # SNMPv2c
        UdpTransportTarget((str(ip), 161), timeout=1.0, retries=1),
        ContextData(),
        ObjectType(root_oid),
        lexicographicMode=True
    ):
        if errorIndication or errorStatus:
            error_msg = f"    [!] SNMP Error on {ip}: {errorIndication or errorStatus.prettyPrint()}\n"
            print(error_msg.strip())
            if output_handle:
                output_handle.write(error_msg)
            return

        for varBind in varBinds:
            oid, value = varBind
            if oid.prettyPrint() in visited:
                continue
            visited.add(oid.prettyPrint())

            oid_levels = oid.prettyPrint().split('.')
            base_depth = len(ObjectIdentity('1.3').resolveWithMib(MibViewController(MibBuilder())).getOid().asTuple())
            current_depth = len(oid_levels) - base_depth

            if current_depth > depth:
                return

            indent = "  " * current_depth
            line = f"{indent}{oid.prettyPrint()} = {value.prettyPrint()}\n"
            print(line.strip())
            if output_handle:
                output_handle.write(line)

def get_targets(target):
    try:
        return list(ipaddress.ip_network(target, strict=False).hosts())
    except ValueError as e:
        print(f"[!] Invalid target format: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="SNMP Sweep and print 3 levels deep")
    parser.add_argument("target", help="IP/Subnet/range (e.g. 192.168.1.0/24)")
    parser.add_argument("-c", "--community", default="public", help="SNMP community string (default: public)")
    parser.add_argument("-o", "--output", help="Output filename to save results (e.g. snmp_results.txt)")
    args = parser.parse_args()

    targets = get_targets(args.target)
    print(f"[*] Starting SNMP sweep on {len(targets)} hosts...")

    output_handle = open(args.output, 'w') if args.output else None

    for ip in targets:
        snmp_walk(ip, args.community, depth=3, output_handle=output_handle)

    if output_handle:
        output_handle.close()
        print(f"\n[+] SNMP results saved to: {args.output}")

if __name__ == "__main__":
    main()
