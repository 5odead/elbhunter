#!/usr/bin/env python3
"""
elbhunter.py — Passive AWS ELB Discovery Tool
Version : 2.0.0

Install : pip install dnspython rich
Usage   : python elbhunter.py -t targets.txt
          python elbhunter.py -t targets.txt -w 200 --ptr -o results.json
          python elbhunter.py -t targets.txt --resolvers ns.txt -o out.csv -q

Zero HTTP requests to target servers.
Detection via DNS CNAME chain + optional PTR reverse lookups.
ThreadPoolExecutor-based parallelism; retry + TCP fallback per query.
"""

import argparse
import csv
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

# ── dependency check ────────────────────────────────────────────────────────

try:
    import dns.exception
    import dns.name
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

# ── constants ────────────────────────────────────────────────────────────────

VERSION = "2.0.1"
BANNER  = r"""
[bold red]  ___ _    _             _            [/]
[bold red] | __| |  | |__ __ _  _ _ |_ ___ _ _ [/]
[bold red] | _|| |__| '_ \ || || ' \  _/ -_) '_|[/]
[bold red] |___|____|_.__/\_,_||_||_\__\___|_|  [/]
[bold dim]  Passive AWS ELB Discovery  v{v}[/]
""".format(v=VERSION)

ELB_RE    = re.compile(r'\.elb\.amazonaws\.com\.?$',     re.IGNORECASE)
ELB_CN_RE = re.compile(r'\.elb\.amazonaws\.com\.cn\.?$', re.IGNORECASE)
REGION_RE = re.compile(r'([a-z]{2}-(?:[a-z]+-)+\d)\.elb\.amazonaws\.com', re.IGNORECASE)

DEFAULT_RESOLVERS: List[str] = [
    "1.1.1.1", "1.0.0.1",              # Cloudflare
    "8.8.8.8", "8.8.4.4",              # Google
    "9.9.9.9", "149.112.112.112",      # Quad9
    "208.67.222.222", "208.67.220.220", # OpenDNS
]

DNS_RETRY_SLEEP = 0.1   # seconds between retry attempts

console = Console(highlight=False)

# ── data model ───────────────────────────────────────────────────────────────

class ELBHit:
    __slots__ = (
        "target", "cname_chain", "elb_hostname",
        "region", "elb_type", "ips", "method", "ts",
    )

    def __init__(
        self,
        target:      str,
        cname_chain: List[str],
        elb_hostname: str,
        region:      str,
        elb_type:    str,
        ips:         List[str],
        method:      str,
    ) -> None:
        self.target       = target
        self.cname_chain  = cname_chain
        self.elb_hostname = elb_hostname
        self.region       = region
        self.elb_type     = elb_type
        self.ips          = ips
        self.method       = method
        self.ts           = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def to_dict(self) -> Dict:
        return {
            "target":           self.target,
            "elb_hostname":     self.elb_hostname,
            "region":           self.region,
            "elb_type":         self.elb_type,
            "cname_chain":      self.cname_chain,
            "resolved_ips":     self.ips,
            "detection_method": self.method,
            "timestamp":        self.ts,
        }

# ── ELB classification helpers ───────────────────────────────────────────────

def is_elb(hostname: str) -> bool:
    return bool(ELB_RE.search(hostname) or ELB_CN_RE.search(hostname))


def extract_region(hostname: str) -> str:
    m = REGION_RE.search(hostname)
    return m.group(1) if m else "unknown"


def classify_elb(hostname: str) -> str:
    """
    Heuristic type from the ELB hostname prefix label.
    Reliably splits: Internal / K8s NLB / external (ALB/NLB/Classic).
    ALB vs NLB vs Classic are indistinguishable from hostname alone.
    """
    label = hostname.split(".")[0].lower()
    if label.startswith("internal-"):
        return "Internal ELB"
    if label.startswith("k8s-"):
        return "K8s NLB"
    # Numeric-only suffix (≥8 digits) → ALB/NLB provisioned by AWS LBC
    parts = label.rsplit("-", 1)
    if len(parts) == 2 and parts[-1].isdigit() and len(parts[-1]) >= 8:
        return "ALB/NLB"
    return "Classic/ALB"

# ── target normalisation ─────────────────────────────────────────────────────

def normalise_target(raw: str) -> Optional[str]:
    """
    Strip scheme, path, port. Skip blank lines, comments, and bare IPs.
    Returns lowercased hostname or None.
    """
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None
    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        raw = parsed.hostname or ""
    else:
        raw = raw.split("/")[0]      # drop path
    raw = raw.split(":")[0]          # drop port (safe for domains; IPv6 already filtered below)
    raw = raw.rstrip(".")
    if not raw:
        return None
    # skip bare IPv4 and IPv6 — no CNAME possible, PTR needs a domain to start from
    if re.match(r'^[\d.]+$', raw) or re.match(r'^[0-9a-fA-F:]+$', raw):
        return None
    return raw.lower()


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
        if not ns:
            console.print("[yellow][!] Resolver file empty — using built-in defaults[/]")
            return DEFAULT_RESOLVERS
        return ns
    except OSError as exc:
        console.print(f"[yellow][!] Cannot read resolver file ({exc}) — using defaults[/]")
        return DEFAULT_RESOLVERS

# ── DNS layer: sync resolver + retry + TCP fallback ──────────────────────────

def _make_sync_resolver(nameserver: str, timeout: float) -> dns.resolver.Resolver:
    """Create a sync dns.resolver.Resolver bound to a single nameserver."""
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [nameserver]
    r.timeout     = timeout
    r.lifetime    = timeout
    return r


def dns_query(
    hostname,               # str or dns.name.Name
    rdtype:       str,
    nameservers:  List[str],
    timeout:      float,
    max_retries:  int = 2,
) -> Optional[dns.resolver.Answer]:
    """
    Resolve hostname/rdtype with retry + TCP fallback.

    Strategy:
      - Up to (max_retries + 1) UDP attempts, each with a different random resolver.
      - On the final UDP failure due to Timeout, one TCP retry with the same resolver.
      - NXDOMAIN / NoAnswer → definitive negative, return None immediately (no retry).
      - All other exceptions → retry up to the limit, then return None.
    """
    last_ns = random.choice(nameservers)  # tracked for TCP fallback

    for attempt in range(max_retries + 1):
        ns = random.choice(nameservers)
        last_ns = ns
        try:
            r = _make_sync_resolver(ns, timeout)
            return r.resolve(hostname, rdtype)

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            # Definitive negative answer — no retry warranted
            return None

        except dns.exception.Timeout:
            if attempt < max_retries:
                time.sleep(DNS_RETRY_SLEEP)
                continue
            # All UDP attempts exhausted — try TCP fallback on last resolver
            try:
                r = _make_sync_resolver(last_ns, timeout * 1.5)
                return r.resolve(hostname, rdtype, tcp=True)
            except Exception:
                return None

        except dns.resolver.NoNameservers:
            # Resolver itself unreachable — rotate and retry
            if attempt < max_retries:
                time.sleep(DNS_RETRY_SLEEP)
                continue
            return None

        except Exception:
            return None

    return None


def resolve_ips(
    hostname:    str,
    nameservers: List[str],
    timeout:     float,
    max_retries: int,
) -> List[str]:
    """Resolve A records; return list of IP strings (empty on failure)."""
    ans = dns_query(hostname, "A", nameservers, timeout, max_retries)
    if ans is None:
        return []
    try:
        return [str(rr) for rr in ans]
    except Exception:
        return []

# ── per-target sync scan (runs inside ThreadPoolExecutor worker) ──────────────

def scan_target(
    target:      str,
    nameservers: List[str],
    timeout:     float,
    max_depth:   int,
    check_ptr:   bool,
    max_retries: int,
) -> Optional[ELBHit]:
    """
    Synchronous per-target scan — safe to run in any thread.

    Method 1 — CNAME chain  : follow CNAME records up to max_depth hops looking
                               for *.elb.amazonaws.com termination.
    Method 2 — PTR lookup   : (opt-in) resolve target → IPs, reverse-DNS each IP.
                               Catches Route53 Alias records that bypass CNAME.
    """

    # ── Method 1: CNAME chain ────────────────────────────────────────────────
    cname_chain: List[str] = []
    current:     str       = target

    for _ in range(max_depth):
        ans = dns_query(current, "CNAME", nameservers, timeout, max_retries)
        if ans is None:
            break  # No CNAME at this hop — chain ends here
        try:
            cname = str(ans[0].target).rstrip(".")
        except (IndexError, AttributeError):
            break
        cname_chain.append(cname)
        if is_elb(cname):
            resolved_ips = resolve_ips(cname, nameservers, timeout, max_retries)
            return ELBHit(
                target      = target,
                cname_chain = cname_chain,
                elb_hostname= cname,
                region      = extract_region(cname),
                elb_type    = classify_elb(cname),
                ips         = resolved_ips,
                method      = "CNAME",
            )
        current = cname  # follow the chain

    # ── Method 2: PTR reverse lookup ─────────────────────────────────────────
    if not check_ptr:
        return None

    target_ips: List[str] = resolve_ips(target, nameservers, timeout, max_retries)
    for ip in target_ips:
        try:
            ptr_name = str(dns.reversename.from_address(ip))
        except Exception:
            continue  # malformed IP from A record — skip

        ptr_ans = dns_query(ptr_name, "PTR", nameservers, timeout, max_retries)
        if ptr_ans is None:
            continue

        for rr in ptr_ans:
            ptr_hostname = str(rr).rstrip(".")
            if is_elb(ptr_hostname):
                return ELBHit(
                    target      = target,
                    cname_chain = cname_chain + [f"PTR({ip})"],
                    elb_hostname= ptr_hostname,
                    region      = extract_region(ptr_hostname),
                    elb_type    = classify_elb(ptr_hostname),
                    ips         = [ip],     # the specific IP whose PTR pointed to ELB
                    method      = "PTR",
                )

    return None

# ── output formatters ────────────────────────────────────────────────────────

def write_results(hits: List[ELBHit], output: str, fmt: str) -> None:
    Path(output).parent.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        with open(output, "w") as fh:
            json.dump([h.to_dict() for h in hits], fh, indent=2)

    elif fmt == "csv":
        fields = ["target", "elb_hostname", "region", "elb_type",
                  "cname_chain", "resolved_ips", "detection_method", "timestamp"]
        with open(output, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=fields)
            w.writeheader()
            for h in hits:
                row = h.to_dict()
                row["cname_chain"]  = " -> ".join(row["cname_chain"])
                row["resolved_ips"] = ", ".join(row["resolved_ips"])
                w.writerow(row)

    else:  # .txt — grepable tab-separated
        with open(output, "w") as fh:
            for h in hits:
                fh.write(
                    f"{h.target}\t{h.elb_hostname}\t"
                    f"{h.region}\t{h.elb_type}\t{h.method}\n"
                )


def detect_format(path: str) -> str:
    """Infer output format from file extension. Defaults to txt."""
    return {".json": "json", ".csv": "csv"}.get(Path(path).suffix.lower(), "txt")


def print_hit_live(prog: Progress, hit: ELBHit) -> None:
    """Thread-safe hit print — uses the Progress object's own console."""
    chain_str = " -> ".join(hit.cname_chain) if hit.cname_chain else hit.target
    prog.console.print(
        f"  [bold green][ELB][/] [cyan]{hit.target}[/]"
        f"\n       [dim]chain :[/] {chain_str}"
        f"\n       [dim]region:[/] [yellow]{hit.region}[/]"
        f"  [dim]type:[/] [magenta]{hit.elb_type}[/]"
        f"  [dim]via:[/] {hit.method}"
        f"\n       [dim]ips   :[/] {', '.join(hit.ips) or 'n/a'}"
    )


def print_summary(
    hits:    List[ELBHit],
    total:   int,
    errors:  int,
    elapsed: float,
    outfile: Optional[str],
) -> None:
    regions: Dict[str, int] = {}
    types:   Dict[str, int] = {}
    methods: Dict[str, int] = {}

    for h in hits:
        regions[h.region]  = regions.get(h.region, 0) + 1
        types[h.elb_type]  = types.get(h.elb_type, 0) + 1
        methods[h.method]  = methods.get(h.method, 0) + 1

    tbl = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold white")
    tbl.add_column("Target",       style="cyan",    no_wrap=True)
    tbl.add_column("ELB Hostname", style="green",   no_wrap=True)
    tbl.add_column("Region",       style="yellow")
    tbl.add_column("Type",         style="magenta")
    tbl.add_column("Via",          style="dim")

    for h in sorted(hits, key=lambda x: x.region):
        tbl.add_row(h.target, h.elb_hostname, h.region, h.elb_type, h.method)

    console.print()
    console.print(Align.center(tbl))
    console.print()

    rate  = total / elapsed if elapsed > 0 else 0
    clean = total - errors
    lines = [
        f"[bold]Targets scanned :[/] {total:,}  "
        f"([green]{clean:,}[/] ok / [red]{errors:,}[/] errors)",
        f"[bold]ELBs found      :[/] [green]{len(hits)}[/]  "
        f"({len(hits)/total*100:.1f}% hit rate)" if total else "",
        f"[bold]Elapsed         :[/] {elapsed:.1f}s  ({rate:.0f} targets/s)",
    ]
    if regions:
        lines += [
            "",
            "[bold]By region :[/]  " +
            "  ".join(f"[yellow]{r}[/] ({n})" for r, n in sorted(regions.items())),
            "[bold]By type   :[/]  " +
            "  ".join(f"[magenta]{tp}[/] ({n})" for tp, n in sorted(types.items())),
            "[bold]By method :[/]  " +
            "  ".join(f"{m} ({n})" for m, n in sorted(methods.items())),
        ]
    if outfile:
        lines += ["", f"[bold]Output saved :[/] [underline]{outfile}[/]"]

    console.print(Panel("\n".join(lines), title="[bold]Summary[/]", border_style="green"))

# ── main scan coordinator ────────────────────────────────────────────────────

def run_scan(args: argparse.Namespace) -> Tuple[List[ELBHit], int, int]:
    """
    Run the full scan.  Returns (hits, total_targets, error_count).
    Uses ThreadPoolExecutor so workers are naturally rate-limited to args.workers.
    No asyncio — sync DNS inside each thread with retry + TCP fallback.
    """
    targets     = load_targets(args.targets)
    nameservers = load_resolvers(getattr(args, "resolvers", None))
    total       = len(targets)
    hits:  List[ELBHit] = []
    errors: int          = 0

    if not targets:
        sys.exit("[-] No valid targets found in input file.")

    if not args.quiet:
        console.print(
            f"\n[bold]Targets[/]  : [cyan]{total:,}[/]   "
            f"[bold]Workers[/]  : {args.workers}   "
            f"[bold]Timeout[/]  : {args.timeout}s   "
            f"[bold]Retries[/]  : {args.retry}   "
            f"[bold]Depth[/]    : {args.depth}   "
            f"[bold]PTR[/]      : {'on' if args.ptr else 'off'}\n"
        )

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                scan_target,
                t, nameservers, args.timeout, args.depth, args.ptr, args.retry,
            ): t
            for t in targets
        }

        with Progress(
            SpinnerColumn(style="cyan"),
            MofNCompleteColumn(),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TextColumn("[green]{task.fields[found]}[/] found  "
                       "[red]{task.fields[errs]}[/] err"),
            console=console,
            disable=args.quiet,
        ) as prog:
            task_id = prog.add_task("Scanning", total=total, found=0, errs=0)

            for fut in as_completed(futures):
                try:
                    result = fut.result()
                except Exception:
                    errors += 1
                    prog.update(task_id, advance=1, errs=errors)
                    continue

                prog.advance(task_id)

                if result:
                    hits.append(result)
                    prog.update(task_id, found=len(hits))
                    if args.quiet:
                        # Pipeline-friendly: one ELB hostname per line
                        print(result.elb_hostname)
                    else:
                        print_hit_live(prog, result)

    return hits, total, errors

# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog        = "elbhunter",
        description = "Passive AWS ELB discovery via DNS CNAME chains (zero HTTP).",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = """
Examples:
  python elbhunter.py -t targets.txt
  python elbhunter.py -t targets.txt -w 200 --ptr -o results.json
  python elbhunter.py -t targets.txt --resolvers ns.txt -o out.csv
  python elbhunter.py -t targets.txt -q | tee elbs.txt   # pipeline mode
        """,
    )
    p.add_argument("-t",  "--targets",   required=True,
                   help="Target list file (one host/URL per line)")
    p.add_argument("-o",  "--output",    default=None,
                   help="Output file — format auto-detected from extension (.txt/.json/.csv)")
    p.add_argument("-w",  "--workers",   type=int, default=150,
                   help="ThreadPool worker count (default: 150)")
    p.add_argument("-q",  "--quiet",     action="store_true",
                   help="Quiet mode: suppress banner/progress, print only ELB hostnames (pipeline-friendly)")
    p.add_argument("--timeout",          type=float, default=3.0,
                   help="DNS timeout per UDP attempt in seconds (default: 3.0)")
    p.add_argument("--retry",            type=int, default=2,
                   help="DNS retry attempts per query before TCP fallback (default: 2)")
    p.add_argument("--depth",            type=int, default=10,
                   help="Max CNAME chain hops to follow (default: 10)")
    p.add_argument("--ptr",              action="store_true",
                   help="Enable PTR reverse lookup (catches Route53 Alias; ~2× slower)")
    p.add_argument("--resolvers",        default=None,
                   help="Custom resolver file (one IP per line; default: built-in public resolvers)")
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
        console.print("\n[yellow][!] Interrupted — partial results may be incomplete[/]")
        sys.exit(130)

    elapsed = time.monotonic() - start

    if not hits:
        if not args.quiet:
            console.print(f"\n[yellow][~] No ELBs identified in {elapsed:.1f}s[/]")
        return

    if args.output:
        fmt = detect_format(args.output)
        write_results(hits, args.output, fmt)

    if not args.quiet:
        print_summary(hits, total, errors, elapsed, args.output)


if __name__ == "__main__":
    main()
