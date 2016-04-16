#!/usr/bin/env python3
try: import simplejson as json
except ImportError: import json
import xmlrpc.client
import subprocess

## update DNS entries served by gandi to reflect changes in the WAN-side IP address.
## requires an API key that you can find somewhere on the gandi website.
## if the names do not already exist then it will error out. currently expects 
## both an A and an AAAA record, and sets them both to the WAN IP.
## based on https://wuffleton.com/code/gandi-openwrt/

## Configuration
api = xmlrpc.client.ServerProxy('https://rpc.gandi.net/xmlrpc/', verbose=False, use_builtin_types=True)
#api = xmlrpc.client.ServerProxy('https://rpc.ote.gandi.net/xmlrpc/', verbose=False, use_builtin_types=True)
apikey = 'YOUR API KEY HERE'
domain = 'YOUR DOMAIN NAME HERE'
records = ['vpn']
ttl = 300 # 15 minutes
ip4netname = 'wan'
ip6netname = 'wan6'
# Note: Assignment of IPv6 Addresses/Suffixes to Records is configured below in main()

def main():
    # Ask Ubus for net interface info, then parse its json output
    netinfo = json.loads(subprocess.check_output("ubus call network.interface dump", shell=True, universal_newlines=True))['interface']

    # Store the json objects for our interfaces
    for netif in netinfo:
        if netif['interface'] == ip4netname:
            ip4netif = netif
        elif netif['interface'] == ip6netname:
            ip6netif = netif

    # Public IPv4 Address
    ip4addr = ip4netif['ipv4-address'][0]['address']

    # Delegated Prefix w/ CIDR Prefix length
    ip6prefix = ip6netif['ipv6-prefix'][0]['address'] + '/' + str(ip6netif['ipv6-prefix'][0]['mask'])

    ## IPv6 Configuration ##
    # Get prefixes for networks
    vpn = getip6prefix('lan', ip6netif)

    # IP6 Addresses; Indicies correspond to records
    ip6addrs = [vpn[0] + '1']

    # Prefix lengths for each record's address
    ip6prefixlens = [vpn[1]]
    ## End IPv6 Configuration ##

    # Get the Zone ID for given domain
    active_zone = api.domain.info(apikey, domain)['zone_id']

    # State storage setup
    numrecs = len(records)
    ip4changed = [False] * numrecs
    ip6changed = [False] * numrecs

    # Check IPs for all records
    for i in range(0, numrecs):
        # Did v4 Change?
        ip4changed[i] = ip_changed(records[i], 'A', ip4addr, active_zone)
        # Did v6 Change?
        ip6changed[i] = ip_changed(records[i], 'AAAA', ip6addrs[i], active_zone)

    # If any IP changed, create a new zone and update necessary records, otherwise we're done and will exit here
    if True in ip4changed + ip6changed:
        # Create new zone to save changes in
        new_zone = api.domain.zone.version.new(apikey, active_zone)
        # Apply changed IPs to new zone
        for i in range(0, numrecs):
            if ip4changed[i]:
                update_record(records[i], 'A', ip4addr, active_zone, new_zone)
                print("IPv4 Updated for " + records[i])
            if ip6changed[i]:
                update_record(records[i], 'AAAA', ip6addrs[i], active_zone, new_zone)
                print("IPv6 Updated for " + records[i])
        # Activate the new zone
        api.domain.zone.version.set(apikey, active_zone, new_zone)
    else:
        print('All records are already up-to-date.')

# Update a record on the server
# Takes a record name, the record type, the new value for the record
# The XMLXPC object for the current zone, and the XMLRPC object for the new zone
def update_record(record, rtype, value, active_zone, new_zone):
    # Delete Record
    records = api.domain.zone.record.delete(apikey, active_zone, new_zone, {"name": record, "type": rtype})
    # Add New Record
    api.domain.zone.record.add(apikey, active_zone, new_zone, {"name": record, "ttl": ttl, "type": rtype, "value": value})

# Check if the IP for given record changed
# Takes a record name, the record type, an ip to check against, and the XMLRPC object for the current zone
def ip_changed(record, rtype, ip, active_zone):
    recinfo = api.domain.zone.record.list(apikey, active_zone, 0, {"name": record, "type": rtype})[0]
    return not recinfo['value'] == ip

# Get assigned IPv6 Prefix for Given Interface
# Takes interface name and the json object with interface info
# Returns List with Address as 0, Prefix length as 1
def getip6prefix(interface, ip6netif):
    ifinfo = ip6netif['ipv6-prefix'][0]['assigned'][interface]
    return [ifinfo['address'], str(ifinfo['mask'])]

if __name__ == "__main__":
    main()
