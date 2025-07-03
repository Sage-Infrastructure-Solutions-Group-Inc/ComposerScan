from datetime import datetime, timedelta
from platform import version

import requests
from argparse import ArgumentParser
import json
import logging
from time import sleep
from packaging.version import Version, InvalidVersion

API_URL = 'https://packagist.org/api/security-advisories/?packages[]='
RATE_LIMIT = 5

last_request = None

parser = ArgumentParser()
parser.add_argument('input', help='the input composer.lock file.')
parser.add_argument('output', help='the output resport file.')


args = parser.parse_args()

logging.basicConfig(level=logging.INFO)

vulns = {}

def add_vuln(package_name, vuln):
    if package_name not in vulns:
        vulns[package_name] = []
    vulns[package_name].append(vuln)

def cleanup_version(ver):
    import re
    ver = re.sub('[\<\>\=\-a-zA-Z]','', ver)
    return ver

def check_version_applicable(installed_ver: Version, min_ver=0, max_ver=0):
    min_ver = Version(cleanup_version(min_ver))
    max_ver = Version(cleanup_version(max_ver))
    if installed_ver > min_ver:
        if installed_ver == max_ver:
            return True
        if installed_ver < max_ver:
            return True
    else:
        return False

def get_vulns(package):
    name = package.get('name')
    version = package.get('version')
    try:
        installed_version = Version(cleanup_version(version))
    except InvalidVersion:
        return None
    # Be kind and don't be a jerk to the API
    while True:
        if last_request is None: break
        elif last_request + timedelta(seconds=RATE_LIMIT) > datetime.now():
            sleep(0.2)
        else: break
    results = requests.get(API_URL + name).json()
    try:
        for advisory in list(results['advisories'].values())[0]:
            impacted_versions = advisory['affectedVersions'].split('|')
            for version in impacted_versions:
                comma_split = version.split(',')
                if len(comma_split) == 2:
                    min_ver = comma_split[0]
                    max_ver = comma_split[1]
                    try:
                        if check_version_applicable(installed_version, min_ver, max_ver):
                            advisory['installedVersion'] = installed_version.__str__()
                            logging.info(f"Package {name} {installed_version} is vulnerable to: {advisory}")
                            add_vuln(name, advisory)
                    except InvalidVersion:
                        logging.warning(f"Package {name} {installed_version} or {min_ver} or {max_ver} is not a valid version.")
    except: pass



with open(args.input, 'r', encoding="utf-8") as f:
    data = json.load(f)

for package in data['packages']:
    get_vulns(package)

with open(args.output, 'w', encoding="utf-8") as f:
    json.dump(vulns, f, indent=4)
