import argparse
import os
import re
import subprocess
import csv
import json
from colorama import Fore, Back, Style
import shutil
from module.vulners import cpe_vulnerabilities
import cve_searchsploit as CS

pdir = os.path.dirname(os.path.abspath(CS.__file__))
cve_map = {}

with open(pdir + "/exploitdb_mapping_cve.json") as data_file:
    cve_map = json.load(data_file)
    
def check_requirements():
    try:
        output = subprocess.check_output(['which', 'smap'])
        return True
    except subprocess.CalledProcessError:
        print('smap is not installed')
        return False

def install_smap():
    try:
        output = subprocess.check_output(['which', 'go'])
        print('go is already installed:', output.decode('utf-8').strip())
    except subprocess.CalledProcessError:
        print('go is not installed, installing go')
        os.system('sudo apt-get update')
        os.system('sudo apt-get install golang-go -y')
    print('Installing smap')
    os.system('go install -v github.com/s0md3v/smap/cmd/smap@latest')

def check_smap_command():
    try:
        output = subprocess.check_output(['smap'])
        print('smap installed successfully')
    except subprocess.CalledProcessError as e:
        print('Error running smap command:', e.output.decode('utf-8').strip())
        exit(1)

def run_smap_command(args):

    if os.path.exists('smap_output'):
        os.remove('smap_output')
        
    if args.targets:
        os.system(f'smap -iL {args.targets} -oS smap_output')
    elif args.domain:
        os.system(f'smap {args.domain} -oS smap_output')

def extract_cve_and_domains():
    cve_pattern = re.compile(r'CVE-\d{4}-\d+')
    domain_pattern = re.compile(r'^\+ \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} \((.+)\)', re.MULTILINE)
    cpe_pattern = re.compile(r'cpe:/.+')
    cve_to_domains = {}
    cpe_to_domains = {}
    with open('smap_output', 'r') as f:
        content = f.read()
        domain_matches = domain_pattern.findall(content)
        for domain in domain_matches:
            domains = domain.split(', ')
            start_index = content.index(domain) + len(domain)
            end_index = content.find('\n+', start_index)
            if end_index == -1:
                end_index = len(content)
            section = content[start_index:end_index]
            cve_matches = cve_pattern.findall(section)
            for cve in cve_matches:
                if cve not in cve_to_domains:
                    cve_to_domains[cve] = set()
                for d in domains:
                    cve_to_domains[cve].add(d)
            cpe_matches = cpe_pattern.findall(section)
            for cpe_line in cpe_matches:
                for cpe in cpe_line.split():
                    if len(cpe.split(':')) > 4:
                        if cpe not in cpe_to_domains:
                            cpe_to_domains[cpe] = set()
                        for d in domains:
                            cpe_to_domains[cpe].add(d)
    return cve_to_domains, cpe_to_domains

def search_cve_aux(cve):
    results = []
    files = open(pdir + "/exploitdb/files_exploits.csv")
    reader = csv.reader(files)
    next(reader)
    if cve in cve_map:
        for row in reader:
            edb, file, description, date, author, type, platform, port, date_added, date_updated, verified, codes, tags, aliases, screenshot_url, application_url, source_url = tuple(row)
            if edb in cve_map[cve]:
                results.append([edb, file, date, author, platform, type, port])
    files.close()
    return results

def display_cve_information(cve_to_domains):
    term_size = shutil.get_terminal_size()
    term_width = term_size.columns
    found = False
    for cve, domains in sorted(cve_to_domains.items()):
        results = search_cve_aux(cve)
        if results != []:
            print(f'+{"-" * int(term_width / 2)}')
            print(f'| CVE ID: {Fore.GREEN + Style.BRIGHT}{cve}{Style.RESET_ALL}')
            print(f'| Domains: {", ".join(sorted(domains))}')
            for result in results:
                edb, file, date, author, platform, type, port = result
                if edb:
                    print(f'+{"-" * int(term_width / 2)}')
                    print(f'| Exploit DB Id: {Fore.GREEN + Style.BRIGHT}{edb}{Style.RESET_ALL}')
                    print(f'| File: {pdir}/exploitdb/{file}')
                    print(f'| Date: {date}')
                    print(f'| Author: {author}')
                    print(f'| Platform: {platform}')
                    print(f'| Type: {type}')
                    found = True
            print(f'+{"-" * int(term_width / 2)}\n')
                    
    if not found:
        print('No Exploits found')

def display_cpe_information(cpe_to_domains):
    term_size = shutil.get_terminal_size()
    term_width = term_size.columns
    found = False
    for cpe, domains in sorted(cpe_to_domains.items()):
        results = cpe_vulnerabilities(cpe)
        if results != []:
            print(f'+{"-" * int(term_width / 2)}')
            print(f'| CPE: {Fore.GREEN + Style.BRIGHT}{cpe}{Style.RESET_ALL}')
            print(f'| Domains: {", ".join(sorted(domains))}')
            for result in results:
                id, title, published, type, cvss_score, source_href = result
                if id:
                    print(f'+{"-" * int(term_width / 2)}')
                    print(f'| Title: {Fore.GREEN + Style.BRIGHT}{title}{Style.RESET_ALL}')
                    print(f'| URL: {source_href}')
                    print(f'| Date: {published}')
                    print(f'| id: {id}')
                    print(f'| cvss_score: {cvss_score}')
                    print(f'| Type: {type}')
                    found = True
            print(f'+{"-" * int(term_width / 2)}\n')
                    
    if not found:
        print('No Exploits found')
        
        
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run recon-sploit.py with arguments')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-t', '--targets', type=str, help='specify target list file')
    group.add_argument('-d', '--domain', type=str, help='specify single domain or IP')
    args = parser.parse_args()
    
    print("Updating exploitdb. This may take a while for the first time")
    CS.update_db()
    if not check_requirements():
        user_input = input('Do you want to install smap? (y/n): ')
        if user_input.lower() == 'y':
            install_smap()
            check_smap_command()
    
    print("Gathering information...\n")
    run_smap_command(args)
    cve_to_domains, cpe_to_domains = extract_cve_and_domains()
    print(cpe_to_domains)
    display_cve_information(cve_to_domains)
    display_cpe_information(cpe_to_domains)

