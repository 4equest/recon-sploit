from censys.search import CensysHosts
import socket
from ipaddress import ip_address
import json

def get_ip_by_host(address):
    try:
        ip_address(address)
        return address
    except ValueError:
        return socket.gethostbyname(address)

def get_cpe_by_ip(ip, CENSYS_API_ID, CENSYS_API_SECRET):
    h = CensysHosts(api_id=CENSYS_API_ID, api_secret=CENSYS_API_SECRET)

    cpe_list = []

    try:
        results = h.search("ip:1.1.1.1")

        for result in results:
            print(json.dumps(result, indent=4))

    except Exception as e:
        print(e)

    return cpe_list

def get_cpe_by_censys(address, CENSYS_API_ID, CENSYS_API_SECRET):
    ip = get_ip_by_host(address)
    return get_cpe_by_ip(ip, CENSYS_API_ID, CENSYS_API_SECRET)