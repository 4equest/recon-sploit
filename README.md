# recon-sploit
Tool to list vulnerabilities that may be exploitable without access to the target (with shodan)

# Usage
```
usage: recon-sploit.py [-h] (-t TARGETS | -d DOMAIN)

Run recon-sploit.py with arguments

optional arguments:
  -h, --help            show this help message and exit
  -t TARGETS, --targets TARGETS
                        specify target list file
  -d DOMAIN, --domain DOMAIN
                        specify single domain or IP
```

## Example
Recon example.com
```
python3 recon-sploit.py -d example.com 
```


recon example.com subdomains
```
assetfinder example.com | sort | uniq > domains.txt  
```
and
```
python3 recon-sploit.py -t domains.txt
``` 




