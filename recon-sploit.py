import argparse
import os
import re
import subprocess
import csv
import json
from colorama import Fore, Back, Style
import shutil
from dotenv import load_dotenv
from module.vulners import cpe_vulnerabilities
from module.shodan import run_smap_command
from module.exploitdb import search_cve_aux, update_db, pdir
from collections import defaultdict
    
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

def extract_cve_and_domains():
    cve_pattern = re.compile(r'CVE-\d{4}-\d+')
    domain_pattern = re.compile(r'^\+ \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} \((.+)\)', re.MULTILINE)
    cpe_pattern = re.compile(r'cpe:/.+')
    cve_to_domains = defaultdict(set)
    cpe_to_domains = defaultdict(set)

    with open('smap_output', 'r') as f:
        content = f.read()
        domain_matches = domain_pattern.findall(content)

        for domain in domain_matches:
            domains = set(domain.split(', '))
            start_index = content.index(domain) + len(domain)
            end_index = content.find('\n+', start_index)
            if end_index == -1:
                end_index = len(content)
            section = content[start_index:end_index]
            cve_matches = cve_pattern.findall(section)

            for cve in cve_matches:
                cve_to_domains[cve] |= domains

            cpe_matches = cpe_pattern.findall(section)
            for cpe_line in cpe_matches:
                for cpe in cpe_line.split():
                    if len(cpe.split(':')) > 4:
                        cpe_to_domains[cpe] |= domains

    return dict(cve_to_domains), dict(cpe_to_domains)

def display_cve_information(cve_to_domains):
    term_size = shutil.get_terminal_size()
    term_width = term_size.columns
    found = False
    for cve, domains in sorted(cve_to_domains.items()):
        results = search_cve_aux(cve)
        if not results:
            continue
        line_separator = f'+{"-" * int(term_width / 2)}'
        print(line_separator)
        print(f'| CVE ID: {Fore.GREEN + Style.BRIGHT}{cve}{Style.RESET_ALL}')
        print(f'| Domains: {", ".join(sorted(domains))}')
        for result in results:
            if result['Exploit DB Id']:
                print(f'+{"-" * int(term_width / 2)}')
                for key, value in result.items():
                    print(f'| {key}: {Fore.GREEN + Style.BRIGHT}{value}{Style.RESET_ALL}')
                found = True
        print(line_separator)
        print()
                    
    if not found:
        print('No Exploits found in Exploit-DB')

def display_cpe_information(cpe_to_domains):
    term_size = shutil.get_terminal_size()
    term_width = term_size.columns
    found = False
    for cpe, domains in sorted(cpe_to_domains.items()):
        results = cpe_vulnerabilities(cpe)
        if not results:
            continue
        line_separator = f'+{"-" * int(term_width / 2)}'
        print(line_separator)
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
        print(line_separator)
        print()
                    
    if not found:
        print('No Exploits found in Vulners')
        
        
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run recon-sploit.py with arguments')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-l', '--domain-list', type=str, help='specify target domain list file')
    group.add_argument('-d', '--domain', type=str, help='specify single domain or IP')
    group.add_argument('--cpe', type=str, help='specify single CPE')
    group.add_argument('--cve', type=str, help='specify single CVE')
    parser.add_argument('--show-duplicate', type=bool, default=False, help='show duplicate exploits')
    args = parser.parse_args()

    load_dotenv()
    censys_api_id = None
    censys_api_secret = None
    if 'CENSYS_API_ID' in os.environ and 'CENSYS_API_SECRET' in os.environ:
        censys_api_id = os.environ['CENSYS_API_ID']
        censys_api_secret = os.environ['CENSYS_API_SECRET']
        
    update_db()
        
    if not check_requirements():
        user_input = input('Do you want to install smap? (y/n): ')
        if user_input.lower() == 'y':
            install_smap()
            check_smap_command()
    
    print("Gathering information...\n")
    run_smap_command(args)
    cve_to_domains, cpe_to_domains = extract_cve_and_domains()
    display_cve_information(cve_to_domains)
    display_cpe_information(cpe_to_domains)