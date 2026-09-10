# MRG-OSINT

**A lightweight, cross-platform OSINT (Open Source Intelligence) reconnaissance CLI tool**, built on real, established Python libraries instead of ad-hoc scraping.

No backend, no server, no API keys, no signup — it's a single Python script you run locally. Every lookup happens from your own machine against public data sources (WHOIS, DNS, RDAP registries, and public profile pages).

Primarily tested on **Kali Linux**, **BlackArch**, and **Fedora** — also supports Debian/Ubuntu, Arch, and macOS.

---

## ⚠️ Responsible use

This tool only queries **public** data (WHOIS records, DNS, RDAP registries, public HTTP profile pages). It does not bypass logins, rate limits, CAPTCHAs, or any access controls.

Only run it against domains, IPs, phone numbers, usernames, or emails **you are authorized to investigate** — your own assets, assets in an authorized pentest/bug-bounty scope, or public information you have a legitimate reason to check. Automated requests to some platforms may violate their Terms of Service; you're responsible for how you use this tool.

---

## Features

| Module     | What it does                                                          | Library used |
|------------|------------------------------------------------------------------------|--------------|
| `domain`   | WHOIS lookup + DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)          | [`python-whois`](https://pypi.org/project/python-whois/), [`dnspython`](https://pypi.org/project/dnspython/) |
| `ip`       | RDAP-based IP/ASN/network ownership lookup + reverse DNS               | [`ipwhois`](https://pypi.org/project/ipwhois/) |
| `phone`    | Validity, carrier, region, line type, timezone                         | [`phonenumbers`](https://pypi.org/project/phonenumbers/) (Google libphonenumber port) |
| `username` | Checks ~20 platforms for a matching public profile (multi-threaded)    | [`requests`](https://pypi.org/project/requests/) |
| `email`    | Validates email format + checks the domain's MX records                | `dnspython` |

Other niceties:
- JSON export (`-o results.json`)
- Adjustable thread count for username sweeps (`--threads`)
- `--version` / `-h` help with usage examples
- Clean, dependency-missing messages instead of crashes if a library isn't installed
- Graceful `Ctrl+C` handling

---

## Installation

### Option A — Linux (Debian/Ubuntu/Kali/Parrot, Fedora/RHEL, Arch/BlackArch) & macOS

```bash
git clone https://github.com/<your-username>/MRG-OSINT.git
cd MRG-OSINT
chmod +x install.sh
./install.sh
```

The script:
1. Detects your OS/distro (`$OSTYPE`, `/etc/os-release`)
2. Installs Python3 + pip if missing, using the right package manager (`apt`, `dnf`, `pacman`, or `brew`)
3. Also installs the `venv` module separately if needed (some minimal Debian/Ubuntu/Kali images ship `python3` without it)
4. Creates an isolated virtual environment (`.venv/`)
5. Installs all dependencies from `requirements.txt`

### Option B — Fallback installer (any OS with Python already set up)

```bash
python3 install.py
```

This only installs the pip dependencies — use it if `install.sh` doesn't suit your system (e.g. no bash, unsupported distro).

### Option C — Manual

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

## Usage

```bash
source .venv/bin/activate   # if you used install.sh / manual setup

python3 mrg_osint.py domain example.com
python3 mrg_osint.py ip 8.8.8.8
python3 mrg_osint.py phone +14155552671
python3 mrg_osint.py username johndoe
python3 mrg_osint.py email test@example.com
```

**Save results as JSON** (place `-o` *after* the subcommand):
```bash
python3 mrg_osint.py username johndoe -o results.json
```

**Tune the username sweep's concurrency:**
```bash
python3 mrg_osint.py username johndoe --threads 20
```

**Give a region hint for a phone number with no country code:**
```bash
python3 mrg_osint.py phone 4155552671 --region US
```

**Check version / help:**
```bash
python3 mrg_osint.py --version
python3 mrg_osint.py --help
```

---

## Example output

```
$ python3 mrg_osint.py domain example.com

[+] WHOIS + DNS recon for: example.com
--------------------------------------------------
[WHOIS]
  domain_name    : EXAMPLE.COM
  registrar      : RESERVED-Internet Assigned Numbers Authority
  creation_date  : 1995-08-14 04:00:00

[DNS Records]
  A     : 93.184.216.34
  MX    : 0 .
  NS    : a.iana-servers.net., b.iana-servers.net.
```

```
$ python3 mrg_osint.py username johndoe --threads 10

[+] Username sweep for: johndoe
--------------------------------------------------
  [FOUND]     GitHub       https://github.com/johndoe
  [not found] GitLab       (status 404)
  [unknown]   Instagram    (status 403 - site blocked the request)
  ...

  4 found, 6 unknown/blocked, 10 not found
```

---

## Notes on result reliability

- **`username` sweep** reports three states, not just found/not-found:
  - **FOUND** — HTTP 2xx/3xx from the profile URL
  - **not found** — clean HTTP 404
  - **unknown/blocked** — the platform returned 403/429/etc. (bot protection or rate limiting). This is *not* evidence the account doesn't exist — many major platforms (Instagram, TikTok, X, Facebook) block simple automated requests regardless of headers used.
- **`ip` module** uses RDAP (`ipwhois`) as the primary source — authoritative registry data (ASN, network owner, country, CIDR range), not a third-party rate-limited geolocation API. It does **not** return city-level geolocation (RDAP doesn't carry that data).
- **`domain` WHOIS** coverage varies by TLD and registrar — some domains return rich data, others (especially privacy-shielded ones) return very little. This is a WHOIS ecosystem limitation, not a tool bug.

---

## Project structure

```
MRG-OSINT/
├── mrg_osint.py       # main CLI tool
├── install.sh         # cross-platform installer (Linux/macOS)
├── install.py         # pure-Python fallback installer
├── requirements.txt   # Python dependencies
├── LICENSE            # MIT license
├── .gitignore
└── README.md
```

---

## Requirements

- Python 3.8+
- `requests`, `python-whois`, `dnspython`, `ipwhois`, `phonenumbers` (all auto-installed by the installer)

---

## Contributing

Issues and PRs are welcome — especially additions to the `USERNAME_SITES` dict in `mrg_osint.py`, or platform-specific install fixes for distros not yet covered.

## License

[MIT](LICENSE) — for legal, authorized OSINT and security-research use only.
