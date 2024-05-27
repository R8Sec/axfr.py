#!/usr/bin/env python3
import dns.zone as dz
import dns.query as dq
import dns.resolver as dr
import dns.rdataclass
import dns.rdatatype
import argparse
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
def print_zone_data(zone):
    # Print zone data
    for name, node in zone.nodes.items():   # Iterate over the nodes in the zone
        print(f'\n{name}:')   # Print the name of the node
        for rdataset in node.rdatasets: # Iterate over the rdatasets in the node
            # Print the rdataset details
            print(f"{name}.{zone.origin} {rdataset.ttl} {dns.rdataclass.to_text(rdataset.rdclass)} {dns.rdatatype.to_text(rdataset.rdtype)}")
            for rdata in rdataset:
                print(f' --> {rdata}')

# Gather found subdomains after successful zone transfer
def get_subdomains(axfr, domain):
    subdomains = []   # List to store tuple containing subdomain and ip address
    for record in axfr:
        subdomains.append(f'{record.to_text()}.{domain}')

    return subdomains

def zone_transfer(domain, nameserver, timeout):
    try:    # Try zone transfer
        zone = dz.from_xfr(dq.xfr(nameserver, domain, lifetime=timeout))

    # Print error if zone transfer fails and exit
    except Exception as error:
        print(f'[-] Zone transfer failed from {nameserver}.\nError: {error}')
        sys.exit(1)

    print(f'\n[*] Successful zone transfer from {nameserver}')
    return zone

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
    parser.add_argument('-s',
        '--subdomains',
        action='store_true',
        required=False,
        help='Output only the found subdomains. Don\'t show details',
    )
    args = parser.parse_args()

    # Initialise dns.resolver.Resolver class
    r = dr.Resolver()

    # define variables
    domain = args.domain   # Target domain
    timeout = args.timeout  # Timeout for DNS queries
    nameservers = args.nameservers  # Nameserver IPs

    # Setup name servers
    try:
        if not nameservers:
            r.nameservers = find_nameservers(domain)
        else:
            r.nameservers = [ip.strip() for ip in nameservers.split(',')]
    except Exception as error:
        print(error)
        sys.exit(1)

    # Try zone transfer
    subdomains = []
    for nameserver in r.nameservers:
        axfr = zone_transfer(domain, nameserver, timeout)
        if args.subdomains:
            subdomains += get_subdomains(axfr, domain)
        else:
            print_zone_data(axfr)

    if args.subdomains:
        unique_subdomains = set(subdomains)
        [print(subdomain) for subdomain in unique_subdomains]

if __name__=='__main__':
    main()