#!/usr/bin/env python3
"""
aws_hunter.py — Unified AWS Asset Hunter
Version : 1.0.0

Merges ELB CNAME-chain discovery (elbhunter) with AWS IP range
identification (aws_ip_ranger) into one tool.

Install : pip install dnspython rich requests pandas openpyxl tqdm
Requires: aws_shared.py in the same directory (for IP range lookup + Excel)

Usage:
  python aws_hunter.py -t targets.txt
  python aws_hunter.py -t targets.txt -o results.xlsx
  python aws_hunter.py -t targets.txt -o results.csv
  python aws_hunter.py -t targets.txt -w 100 --ptr
  python aws_hunter.py -t targets.txt -q | tee hits.txt   # pipeline mode

Per-target logic:
  Domain / URL → CNAME chain walk → ELB detection
                 --ptr catches Route53 Alias records that skip CNAME
  Bare IP      → AWS range lookup → service, region, CIDR
                 PTR reverse DNS  → compute hostname / ELB hostname
"""

import argparse
import csv
import ipaddress
import json
import random
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

# ── dependency check ──────────────────────────────────────────────────────────

try:
    import dns.exception
    import dns.resolver
    import dns.reversename
except ImportError:
    sys.exit("[-] dnspython not found.  pip install dnspython")

try:
    from rich import box
    from rich.align import Align
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import (BarColumn, MofNCompleteColumn, Progress,
                               SpinnerColumn, TaskProgressColumn,
                               TextColumn, TimeElapsedColumn)
    from rich.table import Table
except ImportError:
    sys.exit("[-] rich not found.  pip install rich")

# Optional aws_shared — provides IP range lookup + Excel output
try:
    from aws_shared import (
        build_prefix_networks,
        check_ip_in_networks,
        dedupe_prefix_matches,
        load_aws_ranges_cached,
        make_session,
        write_excel,
        COLOURS,
    )
    import pandas as pd
    HAS_AWS_SHARED = True
except ImportError:
    HAS_AWS_SHARED = False

# ── CONFIG ────────────────────────────────────────────────────────────────────

CONFIG = {
    "cache_file": Path(".aws_ip_ranges_cache.json"),
    "token_file": Path(".aws_ip_ranges_token.txt"),
}

VERSION = "1.1.0"
BANNER  = r"""
[bold red]  _____      ___  _   _            _            [/]
[bold red] |  _  |_ __|  _|| |_| |_  _ _ _ | |_ ___  _ _[/]
[bold red] | |_| | V  \__ \|   _| '_|| | ' \|  _/ -_)| '_|[/]
[bold red] |_____|\_/\_/___/ \__|_|   |_||_||_|\__\___||_|  [/]
[bold dim]  Unified AWS Asset Hunter  v{v}[/]
""".format(v=VERSION)

# ── patterns ──────────────────────────────────────────────────────────────────

ELB_RE    = re.compile(
    r'(?:'
    r'\.[a-z]{2}-(?:[a-z]+-)+\d+\.elb\.amazonaws\.com'        # standard: REGION.elb.amazonaws.com
    r'|'
    r'\.elb\.[a-z]{2}-(?:[a-z]+-)+\d+\.amazonaws\.com'        # older Classic: elb.REGION.amazonaws.com
    r'|'
    r'\.[a-z]{2}-(?:[a-z]+-)+\d+\.elb\.amazonaws\.com\.cn'    # China
    r')\.?$',
    re.IGNORECASE
)
REGION_RE = re.compile(
    r'([a-z]{2}-(?:[a-z]+-)+\d+)\.elb\.amazonaws\.com'        # standard + China
    r'|'
    r'\.elb\.([a-z]{2}-(?:[a-z]+-)+\d+)\.amazonaws\.com',     # older Classic
    re.IGNORECASE
)
EC2_PTR_RE  = re.compile(
    r'^ec2-[\d-]+\.([a-z]{2}-(?:[a-z]+-)+\d)\.compute\.amazonaws\.com\.?$', re.IGNORECASE)
EC2_PTR_RE1 = re.compile(
    r'^ec2-[\d-]+\.compute-1\.amazonaws\.com\.?$', re.IGNORECASE)  # us-east-1 quirk

DEFAULT_RESOLVERS: List[str] = [
    "1.1.1.1", "1.0.0.1",
    "8.8.8.8", "8.8.4.4",
    "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220",
]
DNS_RETRY_SLEEP = 0.1

console = Console(highlight=False)

# ── data model ────────────────────────────────────────────────────────────────

class Hit:
    """One result row — covers both domain (ELB) and IP (AWS range) paths."""

    __slots__ = (
        "target", "input_type",
        "elb_confirmed", "elb_hostname", "elb_type",
        "aws_confirmed", "aws_service", "aws_cidr",
        "region", "resolved_ips",
        "cname_chain", "ptr_hostname", "method", "ts",
    )

    def __init__(
        self,
        target:        str,
        input_type:    str,   # "DOMAIN" | "IP"
        elb_confirmed: bool,
        elb_hostname:  str,   # *.elb.amazonaws.com  or ""
        elb_type:      str,   # ALB/NLB / K8s NLB / Internal ELB / ""
        aws_confirmed: bool,
        aws_service:   str,   # EC2 / CLOUDFRONT / S3 / ELB / ""
        aws_cidr:      str,   # 52.48.0.0/14 or ""
        region:        str,
        resolved_ips:  List[str],
        cname_chain:   List[str],
        ptr_hostname:  str,   # EC2 PTR hostname for IP hits
        method:        str,   # CNAME / PTR / PTR-IP / RANGE
    ) -> None:
        self.target        = target
        self.input_type    = input_type
        self.elb_confirmed = elb_confirmed
        self.elb_hostname  = elb_hostname
        self.elb_type      = elb_type
        self.aws_confirmed = aws_confirmed
        self.aws_service   = aws_service
        self.aws_cidr      = aws_cidr
        self.region        = region
        self.resolved_ips  = resolved_ips
        self.cname_chain   = cname_chain
        self.ptr_hostname  = ptr_hostname
        self.method        = method
        self.ts            = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # status label used in output
    @property
    def status(self) -> str:
        if self.elb_confirmed:
            return "ELB"
        if self.aws_confirmed:
            return "AWS"
        return "-"

    # hostname column: ELB hostname for confirmed ELBs, PTR for IPs, chain for others
    @property
    def display_hostname(self) -> str:
        if self.elb_hostname:
            return self.elb_hostname
        if self.ptr_hostname:
            return self.ptr_hostname
        return "-"

    def to_dict(self) -> Dict:
        return {
            "target":        self.target,
            "input_type":    self.input_type,
            "status":        self.status,
            "elb_confirmed": "yes" if self.elb_confirmed else "no",
            "aws_confirmed": "yes" if self.aws_confirmed else "no",
            "elb_hostname":  self.elb_hostname or "-",
            "elb_type":      self.elb_type     or "-",
            "aws_service":   self.aws_service   or "-",
            "aws_cidr":      self.aws_cidr      or "-",
            "region":        self.region        or "-",
            "resolved_ips":  ", ".join(self.resolved_ips),
            "cname_chain":   " -> ".join(self.cname_chain),
            "ptr_hostname":  self.ptr_hostname  or "-",
            "method":        self.method,
            "timestamp":     self.ts,
        }

# ── ELB classification ────────────────────────────────────────────────────────

def is_elb(hostname: str) -> bool:
    return bool(ELB_RE.search(hostname))


def extract_region(hostname: str) -> str:
    m = REGION_RE.search(hostname)
    if not m:
        return "unknown"
    return m.group(1) or m.group(2) or "unknown"


def classify_elb(hostname: str) -> str:
    """
    Classify ELB type from hostname label.
    Handles:
      - dualstack.* prefix (IPv4/IPv6 dual-stack alias — strip before classifying)
      - internal-* → Internal ELB
      - k8s-*      → K8s NLB (provisioned by AWS Load Balancer Controller)
      - Numeric or hex suffix ≥8 chars → ALB/NLB
      - Everything else → Classic/ALB
    """
    # strip dualstack. prefix — it's a DNS alias layer, not part of the ELB name
    if hostname.lower().startswith("dualstack."):
        hostname = hostname[len("dualstack."):]

    label = hostname.split(".")[0].lower()

    if label.startswith("internal-"):
        return "Internal ELB"
    if label.startswith("k8s-"):
        return "K8s NLB"

    # Hash suffix: ALB uses numeric (e.g. 1170224139), NLB can use hex (e.g. 36253386bec48ce6)
    parts = label.rsplit("-", 1)
    if len(parts) == 2 and len(parts[-1]) >= 8:
        suffix = parts[-1]
        if suffix.isdigit() or re.match(r'^[0-9a-f]+$', suffix):
            return "ALB/NLB"

    return "Classic/ALB"


def region_from_ec2_ptr(hostname: str) -> str:
    m = EC2_PTR_RE.match(hostname)
    if m:
        return m.group(1)
    if EC2_PTR_RE1.match(hostname):
        return "us-east-1"
    return "unknown"


def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

# ── target normalisation ──────────────────────────────────────────────────────

def normalise_target(raw: str) -> Optional[str]:
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None
    if raw.startswith(("http://", "https://")):
        raw = urlparse(raw).hostname or ""
    else:
        raw = raw.split("/")[0]

    raw = raw.rstrip(".")
    if not raw:
        return None

    # bracketed IPv6: [::1]:port → ::1
    if raw.startswith("["):
        inner = raw.split("]")[0].lstrip("[")
        return inner if is_ip(inner) else None

    # bare IP check BEFORE port strip (IPv6 contains ":")
    if is_ip(raw):
        return raw

    raw = raw.split(":")[0].rstrip(".")
    return raw.lower() if raw else None


def load_targets(path: str) -> List[str]:
    seen:    set       = set()
    targets: List[str] = []
    with open(path, "r", errors="ignore") as fh:
        for line in fh:
            t = normalise_target(line)
            if t and t not in seen:
                seen.add(t)
                targets.append(t)
    return targets


def load_resolvers(path: Optional[str]) -> List[str]:
    if not path:
        return DEFAULT_RESOLVERS
    try:
        with open(path) as fh:
            ns = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        return ns if ns else DEFAULT_RESOLVERS
    except OSError as e:
        console.print(f"[yellow][!] Cannot read resolver file ({e}) — using built-in defaults[/]")
        return DEFAULT_RESOLVERS

# ── DNS layer (retry + TCP fallback) ─────────────────────────────────────────

def _make_resolver(ns: str, timeout: float) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [ns]
    r.timeout     = timeout
    r.lifetime    = timeout
    return r


def dns_query(hostname, rdtype: str, nameservers: List[str],
              timeout: float, max_retries: int = 2) -> Optional[dns.resolver.Answer]:
    """UDP with retry + TCP fallback. NXDOMAIN/NoAnswer returns None immediately."""
    last_ns = nameservers[0]           # safe default; overwritten in first iteration
    for attempt in range(max_retries + 1):
        ns      = random.choice(nameservers)
        last_ns = ns
        try:
            return _make_resolver(ns, timeout).resolve(hostname, rdtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None                # definitive negative — no retry
        except dns.exception.Timeout:
            if attempt < max_retries:
                time.sleep(DNS_RETRY_SLEEP)
                continue
            # All UDP attempts exhausted — one TCP retry on last resolver
            try:
                return _make_resolver(last_ns, timeout * 1.5).resolve(
                    hostname, rdtype, tcp=True)
            except Exception as e:     # TCP also failed
                return None
        except dns.resolver.NoNameservers:
            if attempt < max_retries:
                time.sleep(DNS_RETRY_SLEEP)
                continue
            return None
        except Exception as e:         # unexpected — abort cleanly
            return None
    return None


def resolve_ips(hostname: str, nameservers: List[str],
                timeout: float, max_retries: int) -> List[str]:
    ans = dns_query(hostname, "A", nameservers, timeout, max_retries)
    if ans is None:
        return []
    try:
        return [str(rr) for rr in ans]
    except Exception as e:
        return []


def ptr_query(ip: str, nameservers: List[str],
              timeout: float, max_retries: int) -> str:
    """Reverse DNS lookup. Returns hostname string or '' on failure."""
    try:
        ptr_name = str(dns.reversename.from_address(ip))
    except Exception as e:             # malformed IP
        return ""
    ans = dns_query(ptr_name, "PTR", nameservers, timeout, max_retries)
    if ans is None:
        return ""
    try:
        return str(next(iter(ans))).rstrip(".")
    except Exception as e:
        return ""

# ── AWS range lookup ──────────────────────────────────────────────────────────

def load_aws_networks(force_refresh: bool = False) -> list:
    """
    Download ip-ranges.json via aws_shared (cached) and return pre-built networks.
    Retries up to 3 times with 2s sleep between attempts per skill convention.
    Returns [] when aws_shared is unavailable or all attempts fail.
    """
    if not HAS_AWS_SHARED:
        return []
    for attempt in range(1, 4):
        try:
            session  = make_session()
            data     = load_aws_ranges_cached(
                session, CONFIG["cache_file"], CONFIG["token_file"],
                force_refresh=force_refresh,
            )
            prefixes = data.get("prefixes", [])
            return build_prefix_networks(prefixes)
        except Exception as e:
            console.print(
                f"[yellow][!] AWS range load attempt {attempt}/3 failed: {e}[/]"
            )
            if attempt < 3:
                time.sleep(2)
    console.print("[yellow][!] AWS range load failed after 3 attempts — IP range check disabled[/]")
    return []


def aws_range_check(ip: str, networks: list) -> Tuple[bool, str, str]:
    """
    Return (is_aws, service, cidr) for an IP against pre-built networks.
    """
    if not networks or not HAS_AWS_SHARED:
        return False, "", ""
    try:
        matches = dedupe_prefix_matches(check_ip_in_networks(ip, networks))
    except Exception as e:
        return False, "", ""
    if not matches:
        return False, "", ""
    best = matches[0]
    return True, best.get("service", "AMAZON"), best.get("ip_prefix", "")

# ── per-target scan ───────────────────────────────────────────────────────────

def scan_one(
    target:      str,
    nameservers: List[str],
    networks:    list,
    timeout:     float,
    max_depth:   int,
    check_ptr:   bool,
    max_retries: int,
) -> Optional[Hit]:
    """
    Synchronous per-target scan — safe to run in any thread.

    IP   → AWS range check + PTR lookup
    Domain → CNAME chain walk; PTR fallback if --ptr
    Returns None only when target is not AWS and not ELB.
    """

    # ── IP path ──────────────────────────────────────────────────────────────
    if is_ip(target):
        is_aws, service, cidr = aws_range_check(target, networks)
        ptr                   = ptr_query(target, nameservers, timeout, max_retries)
        region                = "unknown"
        elb_confirmed         = False
        elb_hostname          = ""
        elb_type              = ""

        if ptr:
            if is_elb(ptr):
                elb_confirmed = True
                elb_hostname  = ptr
                elb_type      = classify_elb(ptr)
                region        = extract_region(ptr)
            elif EC2_PTR_RE.match(ptr) or EC2_PTR_RE1.match(ptr):
                region = region_from_ec2_ptr(ptr)

        # Only report if definitively AWS — either in ip-ranges.json OR
        # PTR resolves to an EC2/ELB hostname (*.amazonaws.com).
        # Non-AWS IPs with PTR records (e.g. 8.8.8.8 → dns.google) are skipped.
        is_ec2_ptr: bool = bool(
            ptr and (EC2_PTR_RE.match(ptr) or EC2_PTR_RE1.match(ptr))
        )
        if not is_aws and not elb_confirmed and not is_ec2_ptr:
            return None

        return Hit(
            target        = target,
            input_type    = "IP",
            elb_confirmed = elb_confirmed,
            elb_hostname  = elb_hostname,
            elb_type      = elb_type,
            aws_confirmed = is_aws or bool(is_ec2_ptr) or elb_confirmed,
            aws_service   = service if not elb_confirmed else "ELB",
            aws_cidr      = cidr,
            region        = region,
            resolved_ips  = [target],
            cname_chain   = [],
            ptr_hostname  = ptr if not elb_confirmed else "",
            method        = "PTR-IP" if elb_confirmed else "RANGE+PTR",
        )

    # ── Domain path: CNAME chain ──────────────────────────────────────────────
    cname_chain: List[str] = []
    current:     str       = target

    for _ in range(max_depth):
        ans = dns_query(current, "CNAME", nameservers, timeout, max_retries)
        if ans is None:
            break
        try:
            cname = str(ans[0].target).rstrip(".")
        except (IndexError, AttributeError):
            break
        cname_chain.append(cname)
        if is_elb(cname):
            resolved = resolve_ips(cname, nameservers, timeout, max_retries)
            # Get CIDR from first resolved IP if aws_shared available
            cidr = ""
            if resolved and networks:
                _, _, cidr = aws_range_check(resolved[0], networks)
            return Hit(
                target        = target,
                input_type    = "DOMAIN",
                elb_confirmed = True,
                elb_hostname  = cname,
                elb_type      = classify_elb(cname),
                aws_confirmed = True,
                aws_service   = "ELB",
                aws_cidr      = cidr,
                region        = extract_region(cname),
                resolved_ips  = resolved,
                cname_chain   = cname_chain,
                ptr_hostname  = "",
                method        = "CNAME",
            )
        current = cname

    # ── Domain path: PTR fallback ─────────────────────────────────────────────
    if not check_ptr:
        return None

    target_ips = resolve_ips(target, nameservers, timeout, max_retries)
    for ip in target_ips:
        ptr = ptr_query(ip, nameservers, timeout, max_retries)
        if ptr and is_elb(ptr):
            _, _, cidr = aws_range_check(ip, networks)
            return Hit(
                target        = target,
                input_type    = "DOMAIN",
                elb_confirmed = True,
                elb_hostname  = ptr,
                elb_type      = classify_elb(ptr),
                aws_confirmed = True,
                aws_service   = "ELB",
                aws_cidr      = cidr,
                region        = extract_region(ptr),
                resolved_ips  = [ip],
                cname_chain   = cname_chain + [f"PTR({ip})"],
                ptr_hostname  = "",
                method        = "PTR",
            )

    return None

# ── output ────────────────────────────────────────────────────────────────────


def print_hit_live(prog: Progress, hit: Hit) -> None:
    """Single-line hit print inside the Progress context."""
    if hit.elb_confirmed:
        tag    = "[bold green][ELB][/]"
        detail = f"[green]{hit.elb_hostname}[/]  [dim]{hit.elb_type}[/]"
    else:
        tag    = "[bold yellow][AWS][/]"
        detail = f"[yellow]{hit.ptr_hostname or hit.aws_service}[/]  [dim]{hit.aws_cidr}[/]"

    prog.console.print(
        f"  {tag} [cyan]{hit.target:<35}[/]"
        f"  [dim]{hit.region:<14}[/]"
        f"  {detail}"
    )


def build_results_table(hits: List[Hit]) -> Table:
    tbl = Table(
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold white",
        expand=False,
    )
    tbl.add_column("Target",    style="cyan",    no_wrap=True, max_width=35)
    tbl.add_column("Type",      style="dim",     no_wrap=True, width=6)
    tbl.add_column("Status",    no_wrap=True,    width=5)
    tbl.add_column("Service",   style="magenta", no_wrap=True, width=12)
    tbl.add_column("Region",    style="yellow",  no_wrap=True, width=14)
    tbl.add_column("CIDR",      style="dim",     no_wrap=True, width=17)
    tbl.add_column("Hostname",  style="green",   no_wrap=True, max_width=55)
    tbl.add_column("ELB Type",  style="dim",     no_wrap=True, width=12)

    for h in sorted(hits, key=lambda x: (not x.elb_confirmed, x.region, x.target)):
        status = (
            "[bold green]ELB ✓[/]" if h.elb_confirmed else
            "[bold yellow]AWS[/]"  if h.aws_confirmed  else
            "[dim]-[/]"
        )
        tbl.add_row(
            h.target,
            h.input_type,
            status,
            h.aws_service or "-",
            h.region      or "-",
            h.aws_cidr    or "-",
            h.display_hostname,
            h.elb_type    or "-",
        )
    return tbl


def print_summary(
    hits:    List[Hit],
    total:   int,
    errors:  int,
    elapsed: float,
    outfile: Optional[str],
    has_ranges: bool,
) -> None:
    elb_count = sum(1 for h in hits if h.elb_confirmed)
    aws_hits  = [h for h in hits if h.aws_confirmed and not h.elb_confirmed]
    aws_count = len(aws_hits)
    no_hit    = total - len(hits)
    rate      = total / elapsed if elapsed > 0 else 0

    # Break down AWS (non-ELB) hits by service
    service_counts: Dict[str, int] = {}
    for h in aws_hits:
        svc = h.aws_service or "UNKNOWN"
        service_counts[svc] = service_counts.get(svc, 0) + 1
    svc_str = "  ".join(
        f"[magenta]{svc}[/] [dim]({n})[/]"
        for svc, n in sorted(service_counts.items(), key=lambda x: -x[1])
    )

    lines = [
        f"[bold]Targets scanned  :[/] {total:,}  "
        f"([green]{total - errors:,}[/] ok / [red]{errors:,}[/] errors)",
        f"[bold]AWS hits         :[/] {len(hits):,}  "
        f"[dim]({no_hit:,} returned nothing — non-AWS or no ELB in chain)[/]",
        f"[bold]ELBs confirmed   :[/] [bold green]{elb_count}[/]",
        f"[bold]AWS (non-ELB)    :[/] [yellow]{aws_count}[/]"
        + (f"  {svc_str}" if svc_str else ""),
        f"[bold]Elapsed          :[/] {elapsed:.1f}s  ({rate:.0f} targets/s)",
    ]
    if not has_ranges:
        lines.append("[dim]  ↳ IP range lookup unavailable (aws_shared not found)[/]")
    if outfile:
        lines += ["", f"[bold]Saved to         :[/] [underline]{outfile}[/]"]

    console.print(Panel("\n".join(lines), title="[bold]Summary[/]", border_style="green"))

# ── output writers ────────────────────────────────────────────────────────────

def write_results(hits: List[Hit], output: str, total_scanned: int = 0) -> None:
    ext = Path(output).suffix.lower()
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    n   = len(hits)

    if ext == ".json":
        with open(output, "w") as fh:
            json.dump([h.to_dict() for h in hits], fh, indent=2)
        print(f"[+] Saved {n} rows → {output}")

    elif ext == ".csv":
        rows   = [h.to_dict() for h in hits]
        fields = list(rows[0].keys()) if rows else []
        with open(output, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)
        print(f"[+] Saved {n} rows → {output}")

    elif ext in (".xlsx", ".xls") and HAS_AWS_SHARED:
        rows = [h.to_dict() for h in hits]
        df   = pd.DataFrame(rows)

        def colour_rule(idx, row):
            status = getattr(row, "status", "-")
            if status == "ELB":
                return COLOURS["elb"]
            if status == "AWS":
                return COLOURS["aws"]
            return COLOURS["danger"]

        summary = pd.DataFrame([
            {"Metric": "Total targets scanned", "Value": total_scanned if total_scanned else n},
            {"Metric": "Total AWS hits",        "Value": n},
            {"Metric": "ELBs confirmed",        "Value": sum(1 for h in hits if h.elb_confirmed)},
            {"Metric": "AWS IPs (non-ELB)",     "Value": sum(1 for h in hits if h.aws_confirmed and not h.elb_confirmed)},
            {"Metric": "Non-AWS / no hit",      "Value": (total_scanned if total_scanned else n) - n},
        ])
        write_excel(
            sheets       = {"Results": df, "Summary": summary},
            output_path  = Path(output),
            colour_rules = {"Results": colour_rule},
        )
        # write_excel already prints its own confirmation via aws_shared

    else:
        # .txt fallback — tab-separated, grepable
        with open(output, "w") as fh:
            for h in hits:
                fh.write(
                    f"{h.target}\t{h.status}\t{h.aws_service}\t"
                    f"{h.region}\t{h.aws_cidr}\t{h.display_hostname}\t{h.elb_type}\n"
                )
        print(f"[+] Saved {n} rows → {output}")

# ── main scan coordinator ─────────────────────────────────────────────────────

def run_scan(args: argparse.Namespace) -> Tuple[List[Hit], int, int]:
    targets     = load_targets(args.targets)
    nameservers = load_resolvers(getattr(args, "resolvers", None))
    total       = len(targets)
    hits:  List[Hit] = []
    errors: int       = 0

    if not targets:
        sys.exit("[-] No valid targets found in input file.")

    # Pre-load AWS IP ranges once before threading
    networks   = [] if args.no_aws_ranges else load_aws_networks(
        force_refresh=getattr(args, "force_refresh", False)
    )
    has_ranges = bool(networks)

    ip_count     = sum(1 for t in targets if is_ip(t))
    domain_count = total - ip_count

    if not args.quiet:
        target_str = (
            f"[cyan]{total:,}[/]" if ip_count == 0 else
            f"[cyan]{total:,}[/] [dim]({domain_count:,} domains / {ip_count:,} IPs)[/]"
        )
        console.print(
            f"\n[bold]Targets[/]   : {target_str}\n"
            f"[bold]Workers[/]   : {args.workers}   "
            f"[bold]Timeout[/]   : {args.timeout}s   "
            f"[bold]Retries[/]   : {args.retry}   "
            f"[bold]PTR[/]       : {'on' if args.ptr else 'off'}   "
            f"[bold]IP ranges[/] : {'on' if has_ranges else 'off (aws_shared not found)'}\n"
        )

    elb_count = 0
    aws_count = 0

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                scan_one,
                t, nameservers, networks,
                args.timeout, args.depth, args.ptr, args.retry,
            ): t
            for t in targets
        }

        with Progress(
            SpinnerColumn(style="cyan"),
            MofNCompleteColumn(),
            BarColumn(bar_width=38),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TextColumn("[green]{task.fields[elb]}[/] ELB  "
                       "[yellow]{task.fields[aws]}[/] AWS  "
                       "[red]{task.fields[err]}[/] err"),
            console=console,
            disable=args.quiet,
        ) as prog:
            tid = prog.add_task("Scanning", total=total, elb=0, aws=0, err=0)

            for fut in as_completed(futures):
                try:
                    hit = fut.result()
                except Exception as e:
                    errors += 1
                    prog.update(tid, advance=1, err=errors)
                    continue

                prog.advance(tid)

                if hit:
                    hits.append(hit)
                    if hit.elb_confirmed:       # running counters — O(1) per update
                        elb_count += 1
                    elif hit.aws_confirmed:
                        aws_count += 1
                    prog.update(tid, elb=elb_count, aws=aws_count)

                    if args.quiet:
                        print(f"{hit.target}\t{hit.status}\t{hit.display_hostname}\t{hit.region}")
                    else:
                        print_hit_live(prog, hit)

    return hits, total, errors

# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog        = "aws_hunter",
        description = "Unified AWS ELB discovery + IP range identification.",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = """
Examples:
  python aws_hunter.py -t targets.txt
  python aws_hunter.py -t targets.txt -o results.xlsx
  python aws_hunter.py -t targets.txt -w 100 --ptr
  python aws_hunter.py -t targets.txt -q | grep ELB   # pipeline
  python aws_hunter.py -t targets.txt --no-aws-ranges  # DNS only, no range download
        """,
    )
    p.add_argument("-t",  "--targets",       required=True,
                   help="Target file — domains, IPs, URLs, mixed (one per line)")
    p.add_argument("-o",  "--output",        default=None,
                   help="Save results: .xlsx / .csv / .json / .txt (auto from extension)")
    p.add_argument("-w",  "--workers",       type=int, default=80,
                   help="Parallel worker threads (default: 80)")
    p.add_argument("-q",  "--quiet",         action="store_true",
                   help="Quiet: suppress banner/progress, print TSV hits only (pipeline use)")
    p.add_argument("--timeout",              type=float, default=3.0,
                   help="DNS timeout per UDP attempt in seconds (default: 3.0)")
    p.add_argument("--retry",                type=int, default=2,
                   help="DNS retry count before TCP fallback (default: 2)")
    p.add_argument("--depth",                type=int, default=10,
                   help="Max CNAME chain hops (default: 10)")
    p.add_argument("--ptr",                  action="store_true",
                   help="Enable PTR fallback for domains (catches Route53 Alias records)")
    p.add_argument("--resolvers",            default=None,
                   help="Custom resolver file (one IP per line)")
    p.add_argument("--no-aws-ranges",        action="store_true",
                   help="Skip ip-ranges.json download — DNS only, no service/CIDR info")
    p.add_argument("--force-refresh",        action="store_true",
                   help="Force re-download of ip-ranges.json (bypass cache)")
    return p


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    if not args.quiet:
        console.print(BANNER)

    if not Path(args.targets).is_file():
        sys.exit(f"[-] Target file not found: {args.targets}")

    start = time.monotonic()

    try:
        hits, total, errors = run_scan(args)
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Interrupted[/]")
        sys.exit(130)

    elapsed = time.monotonic() - start

    if not hits:
        if not args.quiet:
            console.print(f"\n[yellow][~] No AWS assets found in {elapsed:.1f}s[/]")
        return

    if not args.quiet:
        console.print()
        console.print(Align.center(build_results_table(hits)))
        console.print()
        print_summary(hits, total, errors, elapsed, args.output,
                      has_ranges=not args.no_aws_ranges and HAS_AWS_SHARED)

    if args.output:
        write_results(hits, args.output, total_scanned=total)


if __name__ == "__main__":
    main()
