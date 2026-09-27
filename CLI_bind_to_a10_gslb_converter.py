#!/usr/bin/env python3
"""Convert forward and IPv4 reverse BIND9 zones into one A10 GSLB CLI.

The script scans only .zone files directly inside zones/ (no recursion),
auto-detects forward versus IPv4 reverse zones from $ORIGIN, and always writes
one combined CLI to output/combined_zones.cli. Set DEBUG_PER_ZONE_FILES to
True to also retain one CLI file per converted zone for debugging.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from collections import defaultdict
from datetime import datetime
from typing import List, Optional, Tuple
import csv
import datetime as dt
import ipaddress
import re
import shlex
import time

SCRIPT_DIR = Path(__file__).resolve().parent
INPUT_DIR = SCRIPT_DIR / "zones"
OUTPUT_DIR = SCRIPT_DIR / "output"
REPORT_DIR = SCRIPT_DIR / "reports"

CLASS_LIST = "GSLB_DOMAINS"
PARTITION_NAME = "DNS_AUTH"
SITE_NAME = "Site-1"
SITE_DEVICE = "adc6"
SITE_DEVICE_IP = "10.1.2.3"
DEVICE_NAME = SITE_DEVICE
DEVICE_IP = SITE_DEVICE_IP
SERVICE_PORT = 80
SERVICE_PROTO = "tcp"
POLICY_NAME = "GSLB_FORWARD"
REVERSE_POLICY_NAME = "GSLB_REVERSE"
DEFAULT_TTL = 7200
SERVICE_IP_PREFIX = "domain"
OUTPUT_MODE = "FULL"
DEBUG_PER_ZONE_FILES = False

def fqdn(owner,origin):
    origin = (origin or "").rstrip(".")
    if owner in ("","@"):
        return origin
    if owner.endswith("."):
        return owner[:-1]
    if owner == origin or owner.endswith("." + origin):
        return owner
    return f"{owner}.{origin}" if origin else owner


def parse_forward_zone(path):
    txt=path.read_text(errors="replace")
    origin=None
    default_ttl="3600"
    last_owner="@"
    records=[]
    logical=[]
    current=""
    current_indented=False
    depth=0
    for raw in txt.splitlines():
        # Strip comments only when the semicolon is outside quoted data.
        quoted=False
        escaped=False
        end=len(raw)
        for i,char in enumerate(raw):
            if escaped:
                escaped=False
            elif char == "\\" and quoted:
                escaped=True
            elif char == '"':
                quoted=not quoted
            elif char == ";" and not quoted:
                end=i
                break
        source=raw[:end]
        part=source.strip()
        if not part:
            continue
        if not current:
            current_indented=bool(source[:1].isspace())
        current=(current + " " + part).strip()
        depth += part.count("(") - part.count(")")
        if depth > 0:
            continue
        logical.append((current,current_indented))
        current=""
        current_indented=False
    if current:
        logical.append((current,current_indented))

    for line,indented in logical:
        line=line.strip().replace("("," ").replace(")"," ")
        if not line: continue
        if line.upper().startswith("$ORIGIN"):
            fields=line.split()
            if len(fields)>1: origin=fields[1].rstrip(".")
            continue
        if line.upper().startswith("$TTL"):
            fields=line.split()
            if len(fields)>1: default_ttl=fields[1]
            continue
        if line.startswith("$"): continue
        lexer=shlex.shlex(line, posix=True)
        lexer.whitespace_split=True
        lexer.commenters=""
        toks=list(lexer)
        if not toks: continue
        rr=None
        for i,t in enumerate(toks):
            if t.upper() in ("A","AAAA","CNAME","MX","TXT","SRV","NS","SOA","CAA","PTR"):
                rr=i; break
        if rr is None: continue
        owner=last_owner if indented else toks[0]
        ttl=default_ttl
        if not indented:
            last_owner=owner
        for t in toks[(0 if indented else 1):rr]:
            if t.upper() not in ("IN","CH","HS") and re.fullmatch(r"\d+[WDHMSwdhms]*",t):
                ttl=t
        rtype=toks[rr].upper()
        data=" ".join(toks[rr+1:])
        records.append({"owner":fqdn(owner,origin),"ttl":ttl,"type":rtype,"data":data})
    return origin,records


def obj_name(origin,ip):
    return f"{origin}_{ip.replace('.','_').replace(':','_')}"


def host_key(owner,origin):
    if owner==origin: return ""
    if owner==f"*.{origin}": return "*"
    if owner.endswith("."+origin): return owner[:-(len(origin)+1)]
    return owner


def generate(origin,records,config=None):
    config=config or {}
    class_list=config.get("class_list",CLASS_LIST)
    partition_name=config.get("partition_name",PARTITION_NAME)
    site_name=config.get("site_name",SITE_NAME)
    site_device=config.get("site_device",SITE_DEVICE)
    site_device_ip=config.get("site_device_ip",SITE_DEVICE_IP)
    service_port=int(config.get("service_port",SERVICE_PORT))
    service_proto=config.get("service_proto",SERVICE_PROTO)
    policy_name=config.get("policy_name",POLICY_NAME)
    lines=[]
    ips={}
    for r in records:
        if r["type"] in ("A","AAAA"):
            ips.setdefault(r["data"].split()[0],obj_name(origin,r["data"].split()[0]))
# Add domain to class_list    
    lines += ["!",f"active partition shared","!"]
    lines += ["!",f"class-list {class_list} dns"]
    lines += [f"dns contains {origin}","!"]
    lines += [f"write memory","!"]
    lines += ["!",f"active partition {partition_name}","!"]
        
# Create service-ip objects for each unique IP address
    for ip,name in sorted(ips.items()):
        lines += [
            f"gslb service-ip {name} {ip}",
            "  health-check-protocol-disable",
            "  health-check-disable",
            f"  port {service_port} {service_proto}",
            "    health-check-protocol-disable",
            "    health-check-disable",
            "!"
        ]
# Add site and zone configuration
    lines += [f"gslb site {site_name}",f"  slb-dev {site_device} {site_device_ip}"]
    for n in sorted(ips.values()):
        lines.append(f"    vip-server {n}")
    lines += ["!", f"gslb zone {origin}"]
    lines += [f"  policy {policy_name}"]
    
    services=defaultdict(list)
# Create the DNS records for each subdomain and group them into a single service block
    for r in records:
        h=host_key(r["owner"],origin)
        t=r["type"]
        if t in ("A","AAAA"):
            services[h].append(f"    dns-a-record {ips[r['data'].split()[0]]} static")
        elif t=="TXT":
            services[h].append(f"    dns-txt-record {r['owner']} {r['data']} ttl {r['ttl']}")
        elif t=="CNAME":
            services[h].append(f"    dns-cname-record {r['data']}")
        elif t=="MX":
            pr,host=r["data"].split(None,1)
            lines.append(f"  dns-mx-record {host} {pr} ttl {r['ttl']}")
        elif t=="NS":
            lines.append(f"  dns-ns-record {r['data']} ttl {r['ttl']}")
        elif t=="SOA":
            m=re.match(r"(\S+)\s+(\S+)\s+\(?\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)",r["data"])
            if m:
                ns,mb,serial,refresh,retry,expire,minimum=m.groups()
                lines.append(f"  dns-soa-record {ns} {mb} expire {expire} refresh {refresh} retry {retry} ttl {r['ttl']}")
            else:
                lines.append(f"! TODO SOA {r['data']}")
        elif t == "SRV":
            try:
                priority, weight, port, target = r["data"].split(None, 3)
                services[h].append(
                    f"    dns-srv-record {target} port {port} {priority} ttl {r['ttl']}"
                )
            except ValueError:
                lines.append(f"! TODO Invalid SRV {r['owner']} {r['data']}")
        else:
            lines.append(f"! TODO {t} {r['owner']} {r['data']}")    

    for svc in sorted(services):
        s=f"  service {service_port}"
        if svc: s+=f" {svc}"
        lines.append(s)
        lines.extend(services[svc])
    lines.append("!")
    return "\n".join(lines),len(ips)


@dataclass
class ParseResult:
    origin: str = ""
    zone_type: str = "unknown"
    soa_mname: str = ""
    soa_rname: str = ""
    soa_serial: int = 0
    soa_refresh: int = 0
    soa_retry: int = 0
    soa_expire: int = 0
    soa_minimum: int = 0
    ns_records: List[str] = field(default_factory=list)
    ptr_records: List[Tuple[str, int, str]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def zone_type_from_origin(origin: str) -> str:
    o = origin.lower().rstrip(".")
    if o.endswith("in-addr.arpa"):
        return "ipv4"
    if o.endswith("ip6.arpa"):
        return "ipv6"
    return "unknown"


def is_ipv4_reverse_zone(origin: str, filename: str = "") -> bool:
    """Return true only for IPv4 reverse zones handled by this converter."""
    candidates = (origin, filename)
    return any(value.lower().rstrip(".").endswith("in-addr.arpa") for value in candidates if value)


def normalize_fqdn(name: str) -> str:
    return name.rstrip(".") + "."


def service_name_from_ip(ip: str) -> str:
    """
    Generate a Service-IP name based only on the IP address.
    """
    ip_name = ip.replace(".", "_").replace(":", "_")
    return f"{SERVICE_IP_PREFIX}_{ip_name}"


def ipv4_from_reverse(origin: str, owner: str) -> str:
    origin = origin.lower().rstrip(".")
    owner = owner.strip().rstrip(".")
    suffix = origin.replace(".in-addr.arpa", "")
    parts = [p for p in suffix.split(".") if p]
    if not parts:
        raise ValueError(f"invalid IPv4 reverse origin: {origin}")
    # Reverse zone labels are ordered least-significant -> most-significant.
    # Example origin 23.163.102.in-addr.arpa + owner 135 => 102.163.23.135
    octets = list(reversed(parts))
    octets.append(owner)
    ip = ".".join(octets)
    ipaddress.IPv4Address(ip)  # validate
    return ip


def ipv6_from_reverse(origin: str, owner: str) -> str:
    origin = origin.lower().rstrip(".")
    owner = owner.strip().rstrip(".")
    suffix = origin.replace(".ip6.arpa", "")
    nibbles = [n for n in (owner + "." + suffix).split(".") if n]
    for n in nibbles:
        if not re.fullmatch(r"[0-9a-f]", n, re.I):
            raise ValueError(f"invalid IPv6 nibble: {n}")
    full_hex = "".join(reversed(nibbles))
    if len(full_hex) > 32:
        raise ValueError(f"IPv6 nibble sequence too long ({len(full_hex)} hex chars)")
    full_hex = full_hex.rjust(32, "0")
    addr = ipaddress.IPv6Address(int(full_hex, 16))
    return addr.compressed


def tokenize_record_line(line: str) -> List[str]:
    # Keep parentheses for later multiline assembly, but remove inline comments.
    line = line.split(";", 1)[0].strip()
    if not line:
        return []
    return line.split()


def split_records(text: str) -> List[Tuple[str, bool]]:
    """
    Returns a list of (record_text, owner_explicit) tuples.

    owner_explicit is False when the *first* physical line of the record
    starts with whitespace, which in BIND zone-file syntax means the owner
    name field was omitted and the record reuses the previous owner name.
    This must be detected before whitespace is stripped/joined, otherwise
    the following TTL/class tokens get mistaken for an owner name.
    """
    records: List[Tuple[str, bool]] = []
    current: List[str] = []
    balance = 0
    owner_explicit = True

    for raw in text.splitlines():
        line = raw.split(";", 1)[0].rstrip()
        if not line.strip():
            continue
        if not current:
            owner_explicit = line[:1] not in (" ", "\t")
        current.append(line.strip())
        balance += line.count("(") - line.count(")")
        if balance <= 0:
            records.append((" ".join(current).strip(), owner_explicit))
            current = []
            balance = 0
            owner_explicit = True

    if current:
        records.append((" ".join(current).strip(), owner_explicit))
    return records


def parse_reverse_zone(path: Path) -> ParseResult:
    result = ParseResult()
    ttl = DEFAULT_TTL
    current_owner: Optional[str] = None

    text = path.read_text(errors="replace")
    for record, owner_explicit in split_records(text):
        toks = record.replace("(", " ").replace(")", " ").split()
        if not toks:
            continue

        head = toks[0].upper()
        if head == "$ORIGIN" and len(toks) >= 2:
            result.origin = toks[1].rstrip(".")
            result.zone_type = zone_type_from_origin(result.origin)
            current_owner = None
            continue

        if head == "$TTL" and len(toks) >= 2 and toks[1].isdigit():
            ttl = int(toks[1])
            continue

        rr_idx = None
        rr_type = None
        for i, tok in enumerate(toks):
            up = tok.upper()
            if up in {"SOA", "NS", "PTR"}:
                rr_idx = i
                rr_type = up
                break

        if rr_idx is None or rr_type is None:
            continue

        pre = toks[:rr_idx]
        post = toks[rr_idx + 1 :]

        owner = None
        rr_ttl = None

        if owner_explicit and pre:
            owner = pre[0]
            ttl_class_toks = pre[1:]
        else:
            # Blank owner field: reuse the previous record's owner name.
            # Everything in `pre` here is TTL/class, not an owner name.
            owner = current_owner or "@"
            ttl_class_toks = pre

        for tok in ttl_class_toks:
            if tok.isdigit():
                rr_ttl = int(tok)

        current_owner = owner

        if rr_type == "SOA":
            if len(post) < 7:
                result.warnings.append(f"Incomplete SOA record: {record}")
                continue

            result.soa_mname = normalize_fqdn(post[0])
            result.soa_rname = normalize_fqdn(post[1])

            try:
                result.soa_serial = int(post[2])
                result.soa_refresh = int(post[3])
                result.soa_retry = int(post[4])
                result.soa_expire = int(post[5])
                result.soa_minimum = int(post[6])
            except ValueError:
                result.warnings.append(f"Invalid SOA numeric values: {record}")
            continue

        if rr_type == "NS":
            if not post:
                result.warnings.append(f"NS record missing target: {record}")
                continue
            result.ns_records.append(normalize_fqdn(post[0]))
            continue

        if rr_type == "PTR":
            if not post:
                result.warnings.append(f"PTR record missing target: {record}")
                continue
            target = normalize_fqdn(post[0])
            result.ptr_records.append((owner, rr_ttl or ttl, target))
            continue

    if not result.origin:
        # Fallback to file name without extension if origin is not present.
        result.origin = path.stem
        result.zone_type = zone_type_from_origin(result.origin)

    if not result.soa_mname:
        result.warnings.append("Missing SOA mname")
    if not result.soa_rname:
        result.warnings.append("Missing SOA rname")
    if not result.ns_records:
        result.warnings.append("No NS records found")
    if not result.ptr_records:
        result.warnings.append("No PTR records found")

    return result


def build_cli(zone: ParseResult, output_mode: str = OUTPUT_MODE) -> Tuple[List[str], List[str], List[str]]:
    warnings = list(zone.warnings)
    out: List[str] = []
    service_lines: List[str] = []

    # Resolve every PTR record to an IP, then group by IP. Multiple PTR
    # names can share the same IP (e.g. a blank-owner continuation line
    # that inherits the previous owner) - all of them get kept and emitted
    # as separate dns-ptr-record lines under the one shared service-ip,
    # instead of silently dropping all but the first.
    ip_groups: "dict[str, List[Tuple[int, str, str]]]" = {}
    ip_order: List[str] = []
    for owner, rr_ttl, target in zone.ptr_records:
        try:
            if zone.zone_type == "ipv6":
                ip = ipv6_from_reverse(zone.origin, owner)
            elif zone.zone_type == "ipv4":
                ip = ipv4_from_reverse(zone.origin, owner)
            else:
                raise ValueError(f"unsupported zone type for {zone.origin}")
        except Exception as exc:
            warnings.append(f"PTR owner {owner!r} skipped: {exc}")
            continue

        if ip not in ip_groups:
            ip_groups[ip] = []
            ip_order.append(ip)
        ip_groups[ip].append((rr_ttl, target, owner))

    # Build service-ips, sorted by IP for deterministic output. The first
    # PTR record seen for an IP determines the owner used for the ipv4
    # service reference; every PTR record for that IP gets its own
    # dns-ptr-record line.
    services = [(ip, ip_groups[ip][0][2]) for ip in sorted(ip_order)]

    # Add domain to class_list    
    out += ["!",f"active partition shared","!"]
    out += ["!",f"class-list {CLASS_LIST} dns"]
    out += [f"dns contains {zone.origin}","!"]
    out += [f"write memory","!"]
    out += ["!",f"active partition {PARTITION_NAME}","!"]
    
    # Add service-ip lines for each unique IP
    for ip, owner in services:
        sname = service_name_from_ip(ip)
        service_lines.extend(
            [
                f"gslb service-ip {sname} {ip}",
                "  health-check-protocol-disable",
                "  health-check-disable",
                "  port 80 tcp",
                "    health-check-protocol-disable",
                "    health-check-disable",
                "",
            ]
        )

    if output_mode != "ZONES_ONLY":
        out.extend(service_lines)
        out.extend(
        [
            f"gslb site {SITE_NAME}",
            f"  slb-dev {DEVICE_NAME} {DEVICE_IP}",
        ]
    )
        for ip, owner in services:
            out.append(f"    vip-server {service_name_from_ip(ip)}")
        out.append("!")
    out.extend(
        [
#            f"gslb policy {POLICY_NAME}",
#            "  metric-order health-check weighted-ip weighted-site capacity active-servers active-rdt geographic connection-load num-session admin-preference bw-cost least-response admin-ip connection-count-by-site",
#            "  dns server srv mx naptr ns auto-ns ptr txt any authoritative cname",
#            "!",
            f"gslb zone {zone.origin}",
            f"  policy {POLICY_NAME}",
        ]
    )

    if zone.soa_mname and zone.soa_rname:
        out.append(
            f"  dns-soa-record {zone.soa_mname} {zone.soa_rname} "
            f"expire {zone.soa_expire} "
            f"refresh {zone.soa_refresh} "
            f"retry {zone.soa_retry} "
            f"ttl {zone.soa_minimum} "
            f"serial {zone.soa_serial}"
        )

    for ns in sorted({n for n in zone.ns_records}):
        out.append(f"  dns-ns-record {ns}")

    for ip, owner in services:
        if zone.zone_type == "ipv4":
            service_ref = owner
        else:
            service_ref = service_name_from_ip(ip)
        out.append(f"  service 80 {service_ref}")
        for rr_ttl, target, _owner in ip_groups[ip]:
            out.append(f"    dns-ptr-record {target} ttl {rr_ttl}")

    out.append("!")
    return out, warnings, [service_name_from_ip(ip) for ip, _owner in services]



def extract_zone_section(cli_text: str) -> List[str]:
    """Remove per-zone shared/class-list setup from generated CLI text."""
    lines = cli_text.splitlines()
    marker = f"active partition {PARTITION_NAME}"
    try:
        return lines[lines.index(marker) + 2:]
    except ValueError:
        return lines


def merge_config_blocks(sections: List[List[str]]) -> List[str]:
    """Keep each GSLB object once and merge repeated site vip-server entries."""
    blocks = []
    current = []
    for section in sections:
        for line in section:
            stripped = line.strip()
            starts_object = stripped.startswith("gslb ") and not line[:1].isspace()
            if stripped == "!" or starts_object:
                if current:
                    blocks.append(current)
                    current = []
            if stripped and stripped != "!":
                current.append(line)
        if current:
            blocks.append(current)
            current = []
    merged = []
    positions = {}
    for block in blocks:
        first = block[0].strip()
        parts = first.split()
        key = tuple(parts[:3]) if len(parts) >= 3 else (first,)
        if key not in positions:
            positions[key] = len(merged)
            merged.append(list(block))
            continue
        existing = merged[positions[key]]
        for line in block[1:]:
            if line not in existing:
                existing.append(line)
    # A10 CLI imports depend on object type order across the whole file:
    # all service-IPs first, then sites, then zones.
    def object_order(block):
        first = block[0].strip().split()
        if len(first) >= 2 and first[:2] == ["gslb", "service-ip"]:
            return 0
        if len(first) >= 2 and first[:2] == ["gslb", "site"]:
            return 1
        if len(first) >= 2 and first[:2] == ["gslb", "zone"]:
            return 2
        return 3

    merged.sort(key=object_order)
    result = []
    for block in merged:
        result.extend(block)
        result.append("!")
    return result


def convert(input_dir=INPUT_DIR, output_dir=OUTPUT_DIR, report_dir=REPORT_DIR,
            debug_per_zone_files=DEBUG_PER_ZONE_FILES):
    input_dir, output_dir, report_dir = map(Path, (input_dir, output_dir, report_dir))
    files = sorted(input_dir.glob("*.zone"))
    if not files:
        raise FileNotFoundError(f"No .zone files found in {input_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    config = {"class_list": CLASS_LIST, "partition_name": PARTITION_NAME,
              "site_name": SITE_NAME, "site_device": SITE_DEVICE,
              "site_device_ip": SITE_DEVICE_IP, "service_port": SERVICE_PORT,
              "service_proto": SERVICE_PROTO, "policy_name": POLICY_NAME}
    start = time.time()
    class_entries = []
    sections = []
    summaries = []
    report = ["BIND -> A10 GSLB conversion report", f"Generated: {dt.datetime.now()}",
              f"Input Folder: {input_dir}", f"Output Folder: {output_dir}",
              f"Report Folder: {report_dir}", ""]
    converted = skipped = failed = 0

    for file in files:
        try:
            origin, records = parse_forward_zone(file)
            zone_name = (origin or file.stem).lower().rstrip(".")
            if not origin:
                raise ValueError("Zone file has no $ORIGIN directive")
            if zone_name.endswith("in-addr.arpa"):
                zone = parse_reverse_zone(file)
                if not is_ipv4_reverse_zone(zone.origin, file.stem):
                    skipped += 1
                    report.extend([file.name, "  Status: SKIPPED (not an in-addr.arpa zone)", ""])
                    continue
                per_zone, warnings, services = build_cli(zone, OUTPUT_MODE)
                record_count = len(zone.ptr_records)
                zone_kind = "IPv4 reverse"
                service_count = len(services)
                cli_text = "\n".join(per_zone)
            elif zone_name.endswith("ip6.arpa"):
                skipped += 1
                report.extend([file.name, "  Status: SKIPPED (IPv6 reverse zones are not supported)", ""])
                continue
            else:
                cli_text, service_count = generate(origin, records, config)
                per_zone = cli_text.splitlines()
                warnings = []
                record_count = len(records)
                zone_kind = "Forward"
            class_entry = f"dns contains {origin}"
            if class_entry not in class_entries:
                class_entries.append(class_entry)
            sections.append(extract_zone_section(cli_text))
            if debug_per_zone_files:
                (output_dir / f"{zone_name}.cli").write_text(cli_text.rstrip() + "\n", encoding="utf-8")
            summaries.append([file.name, origin, zone_kind, record_count, service_count, "SUCCESS"])
            report.extend([file.name, f"  Origin: {origin}", f"  Type: {zone_kind}",
                           f"  Records: {record_count}", f"  Service-IP objects: {service_count}",
                           f"  Warnings: {len(warnings)}"])
            report.extend(f"    WARNING: {w}" for w in warnings)
            report.append("")
            converted += 1
        except Exception as exc:
            failed += 1
            summaries.append([file.name, "", "ERROR", 0, 0, "FAILED"])
            report.extend([file.name, "  Status: FAILED", f"  Error: {exc}", ""])

    combined = ["! =====================================================",
                "! Combined BIND -> A10 GSLB Converter v0.1",
                f"! Generated: {datetime.now()}",
                "! =====================================================", ""]
    if class_entries:
        combined.extend(["! Shared class list", "active partition shared", "!",
                         f"class-list {CLASS_LIST} dns"])
        combined.extend(f"  {entry}" for entry in class_entries)
        combined.extend(["!", "write memory", "!", f"active partition {PARTITION_NAME}", "!"])
        combined.extend(merge_config_blocks(sections))
        combined.append("write memory")
    combined_path = output_dir / "combined_zones.cli"
    combined_path.write_text("\n".join(combined) + "\n", encoding="utf-8")

    with (report_dir / "conversion_summary.csv").open("w", newline="", encoding="utf-8") as fp:
        writer = csv.writer(fp)
        writer.writerow(["File", "Origin", "Type", "Records", "Service-IP objects", "Status"])
        writer.writerows(summaries)
    report.extend(["Totals", f"  Zones converted: {converted}", f"  Zones skipped: {skipped}",
                   f"  Zones failed: {failed}", f"  Elapsed: {time.time() - start:.2f}s", ""])
    (report_dir / "conversion_report.txt").write_text("\n".join(report), encoding="utf-8")
    return {"converted": converted, "skipped": skipped, "failed": failed,
            "combined_cli": combined_path, "output_dir": output_dir, "report_dir": report_dir}


def main():
    start = time.time()
    try:
        result = convert()
    except (OSError, ValueError) as exc:
        print(f"Conversion failed: {exc}")
        return 1
    print(f"Zones converted : {result['converted']}")
    print(f"Zones skipped   : {result['skipped']}")
    print(f"Zones failed    : {result['failed']}")
    print(f"Combined CLI    : {result['combined_cli']}")
    print(f"Output folder   : {result['output_dir']}")
    print(f"Reports folder  : {result['report_dir']}")
    print(f"Debug per-zone files: {DEBUG_PER_ZONE_FILES}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
