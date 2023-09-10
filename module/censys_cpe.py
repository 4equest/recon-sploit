from censys.search import CensysHosts
import socket
from ipaddress import ip_address

def get_ip_by_host(domain):
    try:
        ip_address(domain)
        return domain
    except ValueError:
        return socket.gethostbyname(domain)

def get_cpe_by_censys(domains, CENSYS_API_ID, CENSYS_API_SECRET):
    try:
        domain_to_cpes = {}
        h = CensysHosts(api_id=CENSYS_API_ID, api_secret=CENSYS_API_SECRET)
        domain_to_ip = {domain: get_ip_by_host(domain) for domain in domains}
        ips = list(domain_to_ip.values())
        results = h.bulk_view(ips)
        for domain, ip in domain_to_ip.items():
            result = results[ip]
            cpe_list = []
            for service in result["services"]:
                if "software" in service:
                    for software in service["software"]:
                        if "uniform_resource_identifier" in software:
                            cpe_list.append(software["uniform_resource_identifier"])
            domain_to_cpes[domain] = cpe_list
    except Exception as e:
        print(e)
    return domain_to_cpes