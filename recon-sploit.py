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
import configparser
from collections import defaultdict

pdir = os.path.dirname(os.path.abspath(CS.__file__))
cve_map = {}
config = configparser.ConfigParser()
config['DEFAULT'] = {'A': '', 'B': ''}

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


def search_cve_aux(cve):
    results = []
    with open(pdir + "/exploitdb/files_exploits.csv") as files:
        reader = csv.reader(files)
        next(reader)
        if cve in cve_map:
            for row in reader:
                edb, file, description, date, author, type, platform, port, date_added, date_updated, verified, codes, tags, aliases, screenshot_url, application_url, source_url = tuple(row)
                if edb in cve_map[cve]:
                    results.append([edb, file, date, author, platform, type, port])

    return results

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
    if not os.path.exists('config.cfg'):
        with open('config.cfg', 'w') as configfile:
            config.write(configfile)
    else:
        config.read('config.cfg')
        A = config.get('DEFAULT', 'A')
        B = config.get('DEFAULT', 'B')

    parser = argparse.ArgumentParser(description='Run recon-sploit.py with arguments')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-t', '--targets', type=str, help='specify target list file')
    group.add_argument('-d', '--domain', type=str, help='specify single domain or IP')
    group.add_argument('-c', '--cpe', type=str, help='specify single CPE')
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
    display_cve_information(cve_to_domains)
    display_cpe_information(cpe_to_domains)