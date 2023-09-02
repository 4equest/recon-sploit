# recon-sploit
Tool to list vulnerabilities that may be exploitable without access to the target (with shodan)

# Usage
```
usage: recon-sploit.py [-h] (-l DOMAIN_LIST | -d DOMAIN | --cpe CPE | --cve CVE) [--show-duplicate SHOW_DUPLICATE]

Run recon-sploit.py with arguments

optional arguments:
  -h, --help            show this help message and exit
  -l DOMAIN_LIST, --domain-list DOMAIN_LIST
                        specify target domain list file
  -d DOMAIN, --domain DOMAIN
                        specify single domain or IP
  --cpe CPE             specify single CPE
  --cve CVE             specify single CVE
  --show-duplicate SHOW_DUPLICATE
                        show duplicate exploits
```

## Example

### recon example.com
```
python3 recon-sploit.py -d example.com 
```

### recon example.com subdomains
```
assetfinder example.com | sort | uniq > domains.txt  
```
and
```
python3 recon-sploit.py -t domains.txt
``` 
![carbon](https://github.com/4equest/recon-sploit/assets/107108812/40e0306f-e5f4-4725-877e-a7a2684656ff)

# Features
* Get version information and vulnerability list from Shodan
* Search for exploit in Exploit-DB
* Search for exploit in Vulners
