import requests
import json

def vulners_post_request(json_parameters):
    session = requests.Session()
    response = session.get("https://vulners.com/api/v3/burp/software/",params=json_parameters)
    return response.json()
    
def cpe_vulnerabilities(cpe_string):
    cpe_split = cpe_string.split(":")
    if len(cpe_split) <= 4:
        raise ValueError("Malformed CPE string. Please, refer to the https://cpe.mitre.org/specification/.")
    if cpe_split[1] == '2.3':
        version = cpe_split[5]
        cpe_split[5] = ""
    elif cpe_split[1] in '/a/o/h':
        version = cpe_split[4]
        cpe_split[4] = ""
    else:
        raise ValueError("Malformed CPE string. Please, refer to the https://cpe.mitre.org/specification/.")
    
    cpe_string=":".join(cpe_split[0:4])
    version = version.split("/")[0]
    
    data = vulners_post_request({"software":cpe_string, 'version':version, 'type':'cpe'})
    results = []
    if data['result'] == "OK":
        for item in data['data']['search']:
            source = item['_source']
            if (('sourceHref' in source) and source['sourceHref'] != ""):
                results.append([source['id'], source['title'], source['published'], source['type'], source['cvss']['score'], source['sourceHref']])
    return results
