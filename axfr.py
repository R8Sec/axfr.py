#!/usr/bin/env python3
import argparse
import dns.query as dq
import dns.rdataclass
import dns.rdatatype
import dns.resolver as dr
import dns.zone as dz
import sys

# Function to find name servers
def find_nameservers(domain):
    # Find name nameserver for the target domain which will be used for zone transfer
    try:
        nameservers_found = [ns.to_text() for ns in dr.resolve(domain, 'NS')]
    except Exception as error:
        print(error)
        sys.exit(1)

    print(f'[*] Found {len(nameservers_found)} nameservers for {domain}')
    print('[+] Nameservers:')

    # Find IP addresses of the nameservers and print them
    nameserver_ips = []    # List to store nameserver IPs
    for ns in nameservers_found:
        # Resolve the IP address of the nameserver
        host = [ip.to_text() for ip in dr.resolve(ns, 'A')]
        nameserver_ips += host # Add IP address to the list of nameserver IPs
        print(f'{ns} {host[0]}')  # Print nameserver and its IP address

    # Ask user if it is ok to proceed with zone transfer on the found nameservers
    proceed = input("Attempt zone transfer on each of them? (Y/n): ")
    if proceed.lower() in ("y", ""):  # Empty string defaults to "Y"
        return nameserver_ips
    else:  # Ask user to enter nameserver IPs manually
        user_input = input("Enter comma-separated list of nameserver IPs: ")
        nameserver_ips = [ip.strip() for ip in user_input.split(',')] 
        return nameserver_ips

# Make the output more readable
def print_zone_data(zone_data):
    for record in sorted(zone_data):
        print(record)

def zone_transfer(domain, nameserver, timeout):
    try:    # Try zone transfer
        zone = dz.from_xfr(dq.xfr(nameserver, domain, lifetime=timeout))
        zone_data = set()   # Set to store zone data
        for name, node in zone.nodes.items():   # Iterate over the nodes in the zone
            for rdataset in node.rdatasets: # Iterate over the rdatasets in the node
                for rdata in rdataset:
                    record = f"{name}.{zone.origin} {rdataset.ttl} {dns.rdataclass.to_text(rdataset.rdclass)} {dns.rdatatype.to_text(rdataset.rdtype)} {rdata}"
                    zone_data.add(record)
        print(f'[+] Successful zone transfer from {nameserver}')
        return zone_data

    # Print error if zone transfer fails and exit
    except Exception as error:
        print(f'[-] Zone transfer failed from {nameserver}.\nError: {error}')
        sys.exit(1)

def setup_nameservers(nameservers, domain):
    try:
        if nameservers:
            return [ip.strip() for ip in nameservers.split(',')]
        else:
            return find_nameservers(domain)
    except Exception as error:
        print(error)
        sys.exit(1)

# Main
def main():
    parser = argparse.ArgumentParser(description='DNS Zone Transfer', usage='dnsenum.py -d <domain>')
    parser.add_argument('-d', '--domain', help='Target domain', required=True)
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Timeout for DNS queries (default: 10)')
    parser.add_argument(
        '-n',
        '--nameservers',
        required=False,
        default=None,
        help='List of nameserver IPs (e.g., "8.8.8.8, 8.8.4.4, 1.1.1.1")',
    )
    args = parser.parse_args()

    # Initialise dns.resolver.Resolver class
    r = dr.Resolver()

    # define variables
    domain = args.domain   # Target domain
    timeout = args.timeout  # Timeout for DNS queries
    nameservers = args.nameservers  # Nameserver IPs

    # Setup nameservers
    r.nameservers = setup_nameservers(nameservers, domain)

    # Try zone transfer
    all_zone_data = []
    for nameserver in r.nameservers:
        zone_data = zone_transfer(domain, nameserver, timeout)
        all_zone_data.append(zone_data)

    unique_zone_data = list(set(frozenset(zone) for zone in all_zone_data))
    print("Zone Transfer Results:\n")
    for i, zone_data in enumerate(unique_zone_data):
        print(f"Zone transfer from {r.nameservers[i]}:\n")
        print_zone_data(zone_data)
        print("\n")

    if len(unique_zone_data) > 1:
        print("Differences between zone transfer results found:\n")
        base_data = unique_zone_data[0]
        for other_data in unique_zone_data[1:]:
            differences = base_data.symmetric_difference(other_data)
            if differences:
                print("Differences found:\n")
                print_zone_data(differences)
                print("\n")

if __name__=='__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Exiting program")