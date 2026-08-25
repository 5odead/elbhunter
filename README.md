# elbhunter

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-2.0.1-green.svg)](https://github.com/5odead/elbhunter)

**Blazingly fast, completely passive AWS Elastic Load Balancer (ELB) discovery tool.**

`elbhunter` identifies AWS Load Balancers hidden behind complex DNS CNAME chains and Route53 Alias records using **zero HTTP requests** to the target infrastructure. Built for high-scale VAPT reconnaissance workflows.

---

## Features

- **100% Passive** — Zero HTTP/HTTPS requests. No interaction with target WAFs, web servers, or load balancers.
- **Multi-Hop CNAME Walking** — Automatically follows deep CNAME chains (e.g., `app.com` → `cdn.net` → `elb.amazonaws.com`).
- **Route53 Alias Detection** — Optional PTR reverse-lookup (`--ptr`) to catch naked domains using Route53 Alias records that bypass standard CNAMEs.
- **High-Performance** — ThreadPoolExecutor-based concurrency with intelligent UDP retry and TCP fallback mechanisms.
- **Smart Classification** — Heuristically identifies ELB types (K8s NLB, ALB/NLB, Classic, Internal) and extracts AWS regions directly from hostnames.
- **Rich Output** — Color-coded terminal output with real-time progress bars and summary statistics.
- **Flexible Export** — Supports `.json`, `.csv`, and grep-friendly `.txt` output formats.

---

## Installation

**Prerequisites:** Python 3.8+ and `pip`

```bash
# 1. Clone the repository
git clone https://github.com/5odead/elbhunter.git
cd elbhunter

# 2. Install dependencies
pip install -r requirements.txt
```

**`requirements.txt`**
```
dnspython>=2.4.0
rich>=13.0.0
```

---

## Usage

### Basic Scan

Scan a list of targets and display results in the terminal:

```bash
python elbhunter.py -t targets.txt
```

### Advanced Scan *(Recommended for Large Lists)*

Scan 10,000+ targets with high concurrency, save to JSON, and enable PTR lookups:

```bash
python elbhunter.py -t targets.txt -o results.json -w 500 --ptr
```

### Quiet / Pipeline Mode

Suppress all UI elements and output only the discovered ELB hostnames — perfect for piping into other tools:

```bash
python elbhunter.py -t targets.txt -q | tee elb_hosts.txt
```

### Custom Resolvers

Use your own list of DNS resolvers instead of the built-in public ones:

```bash
python elbhunter.py -t targets.txt --resolvers my_resolvers.txt
```

---

## Command-Line Arguments

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --targets` | **(Required)** Path to file containing target domains, one per line. | — |
| `-o, --output` | Output file path. Format auto-detected from extension (`.json`, `.csv`, `.txt`). | `None` |
| `-w, --workers` | Number of concurrent ThreadPool workers. | `150` |
| `-q, --quiet` | Quiet mode. Suppresses banner/progress, prints only ELB hostnames. | `False` |
| `--timeout` | DNS timeout per UDP attempt in seconds. | `3.0` |
| `--retry` | DNS retry attempts per query before falling back to TCP. | `2` |
| `--depth` | Maximum CNAME chain hops to follow. | `10` |
| `--ptr` | Enable PTR reverse lookup. Catches Route53 Alias records (~2x slower). | `False` |
| `--resolvers` | Path to a custom file containing DNS resolver IPs, one per line. | Built-in public resolvers |

---

## How It Works — The Passive Methodology

`elbhunter` is designed to be **completely invisible** to the target's security infrastructure:

- **No Web Traffic** — The tool never sends HTTP, HTTPS, or direct TCP requests to ports 80/443. Target WAFs and Load Balancers will never log your IP.
- **Public Resolver Routing** — DNS queries are sent to trusted public resolvers (Cloudflare `1.1.1.1`, Google `8.8.8.8`, Quad9, etc.).
- **Cache Absorption** — The vast majority of queries are answered instantly from the public resolver's cache, meaning zero queries ever reach the target's authoritative DNS server.
- **CNAME Chain Walking** — If a target uses a CDN (like Cloudflare), the tool follows the CNAME chain hop-by-hop until it terminates at an `*.elb.amazonaws.com` record, revealing the true backend infrastructure.
- **PTR Fallback** — For apex domains using Route53 ALIAS records (which resolve directly to IPs without a CNAME), the `--ptr` flag performs a reverse DNS lookup on the resolved IP to uncover the hidden ELB hostname.

---

## ⚠️ Legal Disclaimer

> This tool is intended for **authorized security testing, bug bounty hunting, and VAPT reconnaissance workflows only.**

- Do **not** use this tool against targets you do not have explicit permission to test.
- The author is **not responsible** for any misuse or damage caused by this program.
- Always adhere to the **Rules of Engagement (RoE)** of your specific assessment.

---

## License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for more information.
