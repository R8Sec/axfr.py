# DNS Zone Transfer Tool

## Description
This is a simple tool for performing DNS zone transfers. It uses the `dnspython` library to perform the required queries.

## Requirements
- dnspython: `pip install dnspython`

## Usage
```
usage: dnsenum.py -d <domain>

DNS Zone Transfer

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Target domain
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout for DNS queries (default: 10)
  -n NAMESERVERS, --nameservers NAMESERVERS
                        List of nameserver IPs (e.g., "8.8.8.8, 8.8.4.4, 1.1.1.1")
```

## Functionality
The script does the following:
1. It queries NS records for the target domain if nameservers are not provided with the `-n` flag.
2. If you are ok with performing a zone transfer on the found nameservers (you will be prompted to proceed), the tool will attempt an AXFR query on each of the found nameservers.
3. You can choose not to use the found nameservers and provide them yourself. In this case you'll have to type a comma-separated list of nameservers IPs (e.g., 8.8.8.8, 8.8.4.4, 1.1.1.1, 216.239.38.10).
4. Attempts to perform a zone transfer on the chosen nameservers and prints out the results.

### Errors
The script will display errors if:
- The provided nameserver IPs are not valid.
- The AXFR query fails. This can happen for several reasons, e.g., lack of support for zone transfer, timing out, authentication required, etc.

### Example
```
./axfr.py -d zonetransfer.me
```