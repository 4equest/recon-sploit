import os
import re
import subprocess
import csv
import json
import shutil
from colorama import Fore, Back, Style
from collections import defaultdict
from tqdm import tqdm
import argparse
from dotenv import load_dotenv
from module.vulners import cpe_vulnerabilities
from module.shodan import run_smap_command
from module.exploitdb import search_cve_aux, update_db, pdir
from module.censys_cpe import get_cpe_by_censys

    
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

def add_cpe_to_list(domains, cpe_to_domains, censys_api_id, censys_api_secret):
    for domain in tqdm(domains, desc="Searching CPEs by Censys"):
        cpe_list = get_cpe_by_censys(domain, censys_api_id, censys_api_secret)
        
        if cpe_list:
            for cpe in cpe_list:
                if cpe not in cpe_to_domains:
                    cpe_to_domains[cpe] = set()
                cpe_to_domains[cpe].add(domain)
            
    return cpe_to_domains


def display_information(id_type, id_to_domains, search_func):
    term_size = shutil.get_terminal_size()
    term_width = term_size.columns
    found = False
    for id, domains in sorted(id_to_domains.items()):
        results = search_func(id)
        if not results:
            continue
        line_separator = f'+{"-" * int(term_width / 2)}'
        print(line_separator)
        print(f'| {id_type}: {Fore.GREEN + Style.BRIGHT}{id}{Style.RESET_ALL}')
        print(f'| Domains: {", ".join(sorted(domains))}')
        for result in results:
            if result.get('Exploit DB Id') or result.get('id'):
                print(line_separator)
                for key, value in result.items():
                    print(f'| {key}: {Fore.GREEN + Style.BRIGHT}{value}{Style.RESET_ALL}')
                found = True
        print(line_separator)
        print()
        
    if not found:
        print(f'No Exploits found ({id_type})')

def display_cve_information(cve_to_domains):
    display_information('CVE', cve_to_domains, search_cve_aux)

def display_cpe_information(cpe_to_domains):
    display_information('CPE', cpe_to_domains, cpe_vulnerabilities)

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
    
    if args.cpe:
        display_cpe_information({args.cpe: ["single_search"]})
        exit()
        
    if args.cve:
        display_cve_information({args.cve: ["single_search"]})
        exit()
        
    if not check_requirements():
        user_input = input('Do you want to install smap? (y/n): ')
        if user_input.lower() == 'y':
            install_smap()
            check_smap_command()
            
    if args.domain:
        domains = [args.domain]
    elif args.domain_list:
        with open(args.domain_list, 'r') as f:
            domains = f.read().splitlines()
    
    print("Gathering information...\n")
    run_smap_command(args)
    cve_to_domains, cpe_to_domains = extract_cve_and_domains()
    cpe_to_domains = add_cpe_to_list(domains, cpe_to_domains, censys_api_id, censys_api_secret)
    display_cve_information(cve_to_domains)
    display_cpe_information(cpe_to_domains)