# cidr_to_compact_regex.py
import ipaddress
import re
import argparse
from itertools import groupby
from operator import itemgetter

def ranges_to_regex(octet_values):
    ranges = []
    for k, g in groupby(enumerate(sorted(octet_values)), lambda x: x[0]-x[1]):
        group = list(map(itemgetter(1), g))
        if len(group) == 1:
            ranges.append(str(group[0]))
        else:
            ranges.append(f"{group[0]}-{group[-1]}")
    return '|'.join(ranges)

def compact_octet_regex(values):
    values = sorted(set(values))
    parts = []
    for k, g in groupby(enumerate(values), lambda x: x[0] - x[1]):
        group = list(map(itemgetter(1), g))
        if len(group) == 1:
            parts.append(str(group[0]))
        else:
            start, end = group[0], group[-1]
            if start == end:
                parts.append(str(start))
            elif start < 10 and end < 10:
                parts.append(f"{start}-{end}")
            elif start < 100 and end < 100:
                parts.append(f"{start:02}-{end:02}")
            else:
                parts.append(f"{start}-{end}")
    return '(?:' + '|'.join(parts) + ')'

def cidr_to_compact_regex(cidr):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return f"Invalid CIDR: {cidr}"

    if net.num_addresses > 1024:
        return f"CIDR too large for compression ({net.num_addresses} IPs)"

    octet_map = {}
    for ip in net.hosts():
        parts = str(ip).split('.')
        prefix = '.'.join(parts[:3])
        last_octet = int(parts[3])
        octet_map.setdefault(prefix, []).append(last_octet)

    regex_parts = []
    for prefix, last_octets in octet_map.items():
        regex = f"{re.escape(prefix)}\.{compact_octet_regex(last_octets)}"
        regex_parts.append(regex)

    return '(' + '|'.join(regex_parts) + ')'

def main():
    parser = argparse.ArgumentParser(description="Convert CIDR to compact regex pattern")
    parser.add_argument("cidr", nargs='+', help="CIDR block(s) (e.g. 192.168.0.0/24)")
    parser.add_argument("--out", help="Output file (e.g. output.txt)", default="output_regex.txt")
    args = parser.parse_args()

    with open(args.out, "w") as f:
        for cidr in args.cidr:
            regex = cidr_to_compact_regex(cidr)
            f.write(f"{cidr}:\n{regex}\n\n")
            print(f"Written regex for {cidr}")

if __name__ == "__main__":
    main()
