# Web Application Vulnerability Scanner (CLI)

A command-line security scanner for **authorized, non-destructive** detection
of common web application misconfigurations — missing security headers, weak
cookie flags, TLS/certificate issues, permissive CORS, information disclosure,
and more — with OWASP Top 10 mapping and a 0–100 risk score.

> ⚠️ **Authorized use only.** Only scan systems you own or have explicit
> written permission to test. Scanning systems without authorization may be
> illegal in your jurisdiction (e.g. the U.S. Computer Fraud and Abuse Act,
> the UK Computer Misuse Act, or equivalent laws elsewhere). This tool
> performs safe, non-destructive checks and does not perform exploitation,
> authentication bypass, credential theft, or denial-of-service.

## What it does

```
scanner scan https://your-authorized-target.com
```

1. **Validates** the target — rejects localhost, private/loopback/link-local
   IP ranges, and cloud metadata endpoints (SSRF protection), for both the
   initial target and every URL discovered while crawling.
2. **Crawls** the site (same-domain only, depth/page-limited, rate-limited).
3. Runs **security checks**: headers, cookies, TLS/HTTPS, CORS, HTTP methods,
   information disclosure, security.txt, and form security.
4. **Scores** the findings (severity + confidence weighted, log-dampened so
   volume alone can't reach "Critical").
5. Displays results in a **Rich terminal UI** and saves them to **SQLite**.
6. Generates **HTML / JSON / CSV reports** on demand.

## Install

```bash
git clone <your-repo-url>
cd web-vulnerability-scanner
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -e ".[dev]"
```

## Usage

```bash
# Full scan with defaults
scanner scan https://your-authorized-target.com

# Configure scan behavior
scanner scan https://your-authorized-target.com \
    --profile full \
    --depth 3 \
    --max-pages 100 \
    --timeout 10 \
    --rate-limit 5

# Crawl only, no checks
scanner crawl https://your-authorized-target.com

# Quick single-page headers check
scanner check https://your-authorized-target.com

# View past scans
scanner history

# Generate a report from a past scan
scanner report <scan-id> --format html
scanner report <scan-id> --format json
scanner report <scan-id> --format csv
```

Profiles:

| Profile    | Checks |
|------------|--------|
| `quick`    | Security headers only |
| `standard` | Headers + cookies + TLS + CORS + security.txt (default) |
| `full`     | All checks, including HTTP methods, info disclosure, and forms |

## Safe local testing lab

**Never point this at a system you don't control.** For development and
demoing, run a deliberately vulnerable app in Docker and scan it via its
container/network address (the scanner blocks `localhost`/loopback by
design, so use the container's bridge-network IP or run the scanner
inside the same Docker network):

```bash
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop

# Find its address on the Docker bridge network:
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' juice-shop
# e.g. 172.17.0.2

scanner scan http://172.17.0.2:3000 --profile full
```

(A plain `localhost:3000` target will be rejected by the SSRF protections —
that's intentional, not a bug. Scanning via the container's real network IP
demonstrates the tool exactly as it would behave against any other
authorized external target.)

## Project structure

```text
web-vulnerability-scanner/
├── scanner/
│   ├── cli.py                 # Typer CLI entrypoint
│   ├── core/
│   │   ├── scanner.py         # orchestrator: validate -> crawl -> check -> score
│   │   ├── crawler.py         # same-domain, depth/page-limited crawler
│   │   ├── http_client.py     # SSRF-safe HTTP client (timeouts, size limits, redirect re-validation)
│   │   ├── target_validator.py# the SSRF safety boundary — read this first
│   │   └── rate_limiter.py
│   ├── checks/                # one file per security check, common SecurityCheck interface
│   ├── models/                # Finding, ScanConfig, ScanResult (Pydantic)
│   ├── storage/                # SQLite persistence (SQLAlchemy)
│   ├── reports/                # HTML / JSON / CSV report generators
│   └── utils/                  # logging (with redaction), risk scoring
├── tests/
├── data/                       # SQLite DB lives here (gitignored)
├── reports/                    # generated reports land here (gitignored)
└── pyproject.toml
```

## Testing

```bash
pytest -v
```

20 tests cover: SSRF/target validation, header checks, cookie checks (and
confirm cookie *values* never appear in evidence/logs), and risk scoring.

## Security design notes

- **SSRF protection lives in one place**: `target_validator.validate_target()`
  resolves DNS and checks every returned IP (not just the hostname string)
  against loopback/private/link-local/reserved ranges, plus known cloud
  metadata hosts and risky ports. It's called for the initial target *and*
  every URL the crawler discovers, and again on every redirect hop.
- **No destructive requests**: only GET and (for method enumeration) OPTIONS
  are ever sent. Forms are parsed, never submitted.
- **Cookie values are never logged or stored** — only attribute flags (Secure/HttpOnly/SameSite).
- **Response size and timeout limits** prevent the scanner from being used to
  pull large amounts of data or hang indefinitely.
- Findings that can't be confirmed without active exploitation are marked
  `POTENTIAL`, not `CONFIRMED`.



A CI workflow (`.github/workflows/ci.yml`) is included and will run the test
suite automatically on every push and pull request.

## License

MIT — see `LICENSE`.
