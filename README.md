# aws_hunter

Unified AWS asset discovery tool that merges ELB CNAME-chain walking with AWS IP range identification into a single, threaded CLI. Feed it a mixed list of domains, IPs, or URLs and it tells you what is running on AWS — confirmed ELBs, EC2 instances, CloudFront, S3, and more.

---

## Overview

aws_hunter combines two previously separate workflows:

- **ELB discovery (elbhunter)** — walks the CNAME chain of each domain until it hits an `*.elb.amazonaws.com` hostname, classifies the load balancer type, and extracts the region.
- **AWS IP range identification (aws_ip_ranger)** — checks bare IPs against Amazon's published `ip-ranges.json`, returning service, region, and CIDR.

A PTR reverse-DNS fallback catches Route53 Alias records that bypass CNAME chains entirely.

---

## Features

- Mixed input — accepts domains, bare IPs, URLs, and CIDR-resolved hosts in the same file
- CNAME chain walk up to a configurable depth (default: 10 hops)
- ELB type classification: ALB/NLB, Internal ELB, K8s NLB, Classic/ALB
- IP range lookup against the official AWS `ip-ranges.json` (cached between runs)
- PTR reverse-DNS fallback for domains that use Route53 Alias records
- EC2 PTR hostname parsing for region extraction (`ec2-*.compute.amazonaws.com`)
- Threaded scanning with a configurable worker count (default: 80)
- Rich progress bar with live ELB/AWS/error counters
- Quiet/pipeline mode: suppresses UI, emits tab-separated hits to stdout
- Output formats: `.xlsx` (colour-coded with summary sheet), `.csv`, `.json`, `.txt`
- DNS retry with UDP → TCP fallback; supports custom resolver files

---

## Requirements

- Python 3.8 or later
- `aws_shared.py` in the same directory — required for IP range lookup and Excel output. Without it the tool falls back to DNS-only mode and cannot write `.xlsx`.

---

## Installation

```bash
pip install dnspython rich requests pandas openpyxl tqdm
```

Clone or copy `aws_hunter.py` and `aws_shared.py` into the same directory.

---

## Usage

```
python aws_hunter.py -t <targets_file> [options]
```

### Examples

```bash
# Basic scan, print results to terminal
python aws_hunter.py -t targets.txt

# Save to Excel with colour-coding and a summary sheet
python aws_hunter.py -t targets.txt -o results.xlsx

# Save to CSV
python aws_hunter.py -t targets.txt -o results.csv

# Save to JSON
python aws_hunter.py -t targets.txt -o results.json

# 100 workers, PTR fallback enabled
python aws_hunter.py -t targets.txt -w 100 --ptr

# Pipeline mode — pipe TSV hits to another tool
python aws_hunter.py -t targets.txt -q | grep ELB

# DNS only — skip ip-ranges.json download entirely
python aws_hunter.py -t targets.txt --no-aws-ranges

# Force refresh of the cached ip-ranges.json
python aws_hunter.py -t targets.txt --force-refresh
```

---

## Target File Format

One entry per line. Accepts:

- Bare domains: `example.com`
- Full URLs: `https://example.com/path` (hostname is extracted automatically)
- Bare IPs: `54.239.28.85`
- IPv6: `2600:1f18::/36`
- Lines beginning with `#` are treated as comments and skipped
- Duplicate entries are deduplicated automatically

---

## CLI Reference

| Flag | Default | Description |
|---|---|---|
| `-t`, `--targets` | required | Path to target file |
| `-o`, `--output` | none | Output file (extension determines format: `.xlsx`, `.csv`, `.json`, `.txt`) |
| `-w`, `--workers` | `80` | Number of parallel worker threads |
| `-q`, `--quiet` | off | Suppress banner and progress bar; print TSV hits only |
| `--timeout` | `3.0` | DNS timeout per UDP attempt, in seconds |
| `--retry` | `2` | UDP retry count before falling back to TCP |
| `--depth` | `10` | Maximum CNAME chain hops per domain |
| `--ptr` | off | Enable PTR reverse-DNS fallback for domains (catches Route53 Alias records) |
| `--resolvers` | built-in | Path to a custom resolver file (one IP per line) |
| `--no-aws-ranges` | off | Skip `ip-ranges.json` download; DNS-only mode |
| `--force-refresh` | off | Re-download `ip-ranges.json` even if a cached copy exists |

---

## Output Columns

| Column | Description |
|---|---|
| `target` | Original input value |
| `input_type` | `DOMAIN` or `IP` |
| `status` | `ELB` (confirmed load balancer), `AWS` (IP range hit), or `-` |
| `elb_confirmed` | `yes` / `no` |
| `aws_confirmed` | `yes` / `no` |
| `elb_hostname` | Full `*.elb.amazonaws.com` hostname, if found |
| `elb_type` | `ALB/NLB`, `Internal ELB`, `K8s NLB`, `Classic/ALB` |
| `aws_service` | Service from `ip-ranges.json` (e.g. `EC2`, `CLOUDFRONT`, `S3`, `ELB`) |
| `aws_cidr` | CIDR block the IP falls within |
| `region` | AWS region extracted from hostname or range data |
| `resolved_ips` | Comma-separated A records |
| `cname_chain` | Arrow-separated chain of CNAMEs walked |
| `ptr_hostname` | PTR record for IP targets, or PTR fallback result for domains |
| `method` | How the hit was confirmed: `CNAME`, `PTR`, `PTR-IP`, `RANGE+PTR` |
| `timestamp` | UTC ISO-8601 timestamp of the scan hit |

---

## Detection Logic

### Domain path

1. Walk the CNAME chain up to `--depth` hops.
2. At each hop, test the CNAME value against the ELB hostname pattern (`*.REGION.elb.amazonaws.com`, older Classic format, China variant).
3. On a match, resolve A records, optionally look up the CIDR, classify the ELB type, extract the region, and record the hit.
4. If no ELB appears in the chain and `--ptr` is set, resolve the domain to IPs and run a PTR query on each — catches Route53 Alias targets that don't produce CNAME records.

### IP path

1. Check the IP against pre-built AWS prefix networks (from `ip-ranges.json`).
2. Run a PTR query. If the PTR hostname matches an ELB or EC2 pattern, record accordingly.
3. Non-AWS IPs where PTR returns a non-Amazon hostname (e.g. `8.8.8.8` → `dns.google`) are silently skipped.

### ELB type classification

| Label | Detection rule |
|---|---|
| `Internal ELB` | First hostname label starts with `internal-` |
| `K8s NLB` | First label starts with `k8s-` |
| `ALB/NLB` | Suffix after the last `-` is 8+ hex or decimal characters |
| `Classic/ALB` | Anything else |

`dualstack.` prefixes (IPv4/IPv6 dual-stack aliases) are stripped before classification.

---

## Caching

`ip-ranges.json` is cached locally as `.aws_ip_ranges_cache.json` alongside an ETag token in `.aws_ip_ranges_token.txt`. Subsequent runs perform a conditional GET and skip the download when the file has not changed upstream. Use `--force-refresh` to bypass the cache.

---

## Dependencies

| Package | Purpose |
|---|---|
| `dnspython` | DNS resolution, CNAME walking, PTR lookups |
| `rich` | Terminal UI, progress bar, colour output |
| `requests` | Fetching `ip-ranges.json` (via `aws_shared`) |
| `pandas` | DataFrame construction for Excel/CSV output (via `aws_shared`) |
| `openpyxl` | `.xlsx` writing (via `aws_shared`) |
| `tqdm` | Optional progress dependency for `aws_shared` |
| `aws_shared` | IP range loader, Excel writer, colour rules — optional but recommended |

---

## License

MIT
