#!/usr/bin/env python3
import dns.zone as dz
import dns.query as dq
import dns.resolver as dr
import argparse

TIMEOUT = 10    # Set timeout for DNS queries

# Function to find name servers
def find_nameservers(domain):
    try:
        # Find name nameserver for the target domain which will be used for zone transfer
        nameservers_found = [ns.to_text() for ns in dr.resolve(domain, 'NS')]
    except Exception as error:
        print(error)
        return

    print(f'[*] Found {len(nameservers_found)} nameservers for {domain}')
    print('[+] Nameservers:')

    # Find IP addresses of the nameservers and print them
    nameservers = []    # List to store nameserver IPs
    for ns in nameservers_found:
        nameserver_host = [ip.to_text() for ip in dr.resolve(ns, 'A')]
        nameservers += nameserver_host
        print(f'{ns} ({nameserver_host})')

    proceed = input("Attempt zone transfer on each of them? (Y/n): ")
    if proceed.lower() in ("y", ""):  # Empty string defaults to "Y"
        return nameservers
    else:
        # Let user input nameserver IPs manually
        nameservers = input("Enter comma-separated list of nameserver IPs: ")
        return [ip.strip() for ip in nameservers.split(',')]

def zone_transfer(domain, nameserver):
    try:    # Try zone transfer
        axfr = dz.from_xfr(dq.xfr(nameserver, domain, lifetime=TIMMEOUT))

    # Print error if zone transfer fails and return
    except Exception as error:
        print(f'[-] Zone transfer failed from {nameserver}.\nError: {error}')
        return

    # Add found subdomains after successful zone transfer
    subdomains = []   # List to store found subdomains
    for record in axfr:
        subdomains.append(f'{record.to_text()}.{domain}')

    print(f'[*] Successful zone transfer from {nameserver}')
    print('[+] Found subdomains:')
    for subdomain in subdomains:    # Output found subdomains
        print(f'{subdomain}')

# Main
def main():
    parser = argparse.ArgumentParser(description='DNS Zone Transfer', usage='dnsenum.py -d <domain>')
    parser.add_argument('-d', '--domain', help='Target domain', required=True)
    parser.add_argument(
        '-n',
        '--nameservers',
        required=False,
        help='List of nameserver IPs (e.g., "8.8.8.8, 8.8.4.4, 1.1.1.1")',
    )
    args = parser.parse_args()

    # Initialise dns.resolver.Resolver class
    r = dr.Resolver()

    # Target domain
    domain = args.domain

    # Set name servers
    try:
        if not args.nameservers:
            r.nameservers = find_nameservers(domain)
        else:
            r.nameservers = [ip.strip() for ip in args.nameservers.split(',')]
    except Exception as error:
        print(error)
        return

    # Try zone transfer
    [zone_transfer(domain, nameserver) for nameserver in r.nameservers]

if __name__=='__main__':
    main()
