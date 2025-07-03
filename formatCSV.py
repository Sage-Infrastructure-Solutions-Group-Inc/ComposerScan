import csv
from argparse import ArgumentParser
import json
from codecs import ignore_errors

parser = ArgumentParser()

parser.add_argument('input')
parser.add_argument('output')

args = parser.parse_args()

with open(args.input) as datafile:
    data = json.load(datafile)

with open(args.output, 'w', newline='') as outputfile:

    headers = ['package', 'cve', 'installedVersion', 'affectedVersions', 'title', 'link', 'sources', 'severity']
    writer = csv.DictWriter(outputfile, fieldnames=headers, extrasaction="ignore")
    writer.writeheader()
    for package, advisories in data.items():
        for advisory in advisories:
            advisory['package'] = package
            writer.writerow(advisory)

print('Completed CSV export')