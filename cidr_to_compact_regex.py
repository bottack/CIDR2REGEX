
import ipaddress
import re
import argparse

def format_range(s, e):
    if s == e:
        return str(s)
    patterns = []
    if s <= 9:
        end = min(e, 9)
        patterns.append(f"[{s}-{end}]" if s != end else str(s))
        s = end + 1
        if s > e:
            return "|".join(patterns)
    if s <= 99:
        for tens in range(s // 10, e // 10 + 1):
            start = max(s, tens * 10)
            end = min(e, tens * 10 + 9)
            if start == end:
                patterns.append(str(start))
            elif start % 10 == 0 and end % 10 == 9:
                patterns.append(f"{tens}[0-9]")
            else:
                patterns.append(f"{tens}[{start%10}-{end%10}]")
        s = (e // 10 + 1) * 10
        if s > e:
            return "|".join(patterns)
    if s <= 255:
        for h in range(s // 100, e // 100 + 1):
            start = max(s, h * 100)
            end = min(e, h * 100 + 99)
            if start == end:
                patterns.append(str(start))
            else:
                sub = format_range(start % 100, end % 100)
                patterns.append(f"{h}(?:{sub})")
    return "|".join(patterns)

def range_to_regex_groups_fixed(start, end):
    return f"(?:{format_range(start, end)})"

def split_range(octets):
    octets.sort()
    ranges = []
    i = 0
    while i < len(octets):
        start = octets[i]
        j = i
        while j + 1 < len(octets) and octets[j + 1] == octets[j] + 1:
            j += 1
        end = octets[j]
        ranges.append((start, end))
        i = j + 1
    return ranges

def cidr_to_strict_regex_fixed(cidr):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return f"Invalid CIDR: {cidr}"
    if net.prefixlen == 32:
        return f"({re.escape(str(net.network_address))})"
    octet_map = {}
    for ip in net.hosts():
        parts = str(ip).split('.')
        prefix = '.'.join(parts[:3])
        last_octet = int(parts[3])
        octet_map.setdefault(prefix, []).append(last_octet)
    regex_parts = []
    for prefix, octets in octet_map.items():
        ranges = split_range(octets)
        compact = '|'.join(range_to_regex_groups_fixed(s, e) for s, e in ranges)
        regex_parts.append(f"{re.escape(prefix)}\.{compact}")
    return f"({'|'.join(regex_parts)})"

def main():
    parser = argparse.ArgumentParser(description="Convert CIDR to optimized regex pattern")
    parser.add_argument("cidr", nargs='+', help="CIDR block(s) (e.g. 192.168.0.0/24)")
    parser.add_argument("--out", help="Output file (e.g. output.txt)", default="output_regex.txt")
    args = parser.parse_args()
    with open(args.out, "w") as f:
        for cidr in args.cidr:
            regex = cidr_to_strict_regex_fixed(cidr)
            f.write(f"{cidr}:\n{regex}\n\n")
            print(f"Written regex for {cidr}")

if __name__ == "__main__":
    main()
