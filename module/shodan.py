import os

def run_smap_command(args):
    if os.path.exists('smap_output'):
        os.remove('smap_output')
    if args.domain_list:
        os.system(f'smap -iL {args.domain_list} -oS smap_output')
    elif args.domain:
        os.system(f'smap {args.domain} -oS smap_output')
    
    return
