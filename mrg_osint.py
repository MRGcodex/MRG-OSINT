#!/usr/bin/env python3
"""
MRG-OSINT
=========
A lightweight, cross-platform OSINT reconnaissance CLI tool built on
established, real Python OSINT libraries (not ad-hoc scraping):

  - domain   : WHOIS (python-whois) + DNS records (dnspython)
  - ip       : RDAP IP/ASN/network whois (ipwhois) + reverse DNS
  - phone    : Carrier / region / timezone / line-type (phonenumbers)
  - username : Public profile existence sweep across platforms (requests)
  - email    : Format validation + MX record check (dnspython)

Author: MRGOLDY (project owner)
License: For legal, authorized OSINT / research use only.
"""

import argparse
import concurrent.futures
import json
import re
import socket
import sys
from datetime import datetime

# ---- Third-party libs (auto-installed by install.sh / install.py) ----
try:
    import requests
except ImportError:
    print("[!] 'requests' not installed. Run install.sh / install.py first.")
    sys.exit(1)

try:
    import whois  # python-whois
except ImportError:
    whois = None

try:
    import dns.resolver  # dnspython
    HAVE_DNS = True
except ImportError:
    HAVE_DNS = False

try:
    from ipwhois import IPWhois  # real RDAP-based IP/ASN whois library
    HAVE_IPWHOIS = True
except ImportError:
    HAVE_IPWHOIS = False

try:
    import phonenumbers
    from phonenumbers import carrier as pn_carrier
    from phonenumbers import geocoder as pn_geocoder
    from phonenumbers import timezone as pn_timezone
    HAVE_PHONENUMBERS = True
except ImportError:
    HAVE_PHONENUMBERS = False

BANNER = r"""
 __  __ ____   ____        ___  ____ ___ _   _ _____
|  \/  |  _ \ / ___|      / _ \/ ___|_ _| \ | |_   _|
| |\/| | |_) | |  _ _____| | | \___ \| ||  \| | | |
| |  | |  _ <| |_| |_____| |_| |___) | || |\  | | |
|_|  |_|_| \_\\____|      \___/|____/___|_| \_| |_|

  MRG-OSINT By-MRGCodex | Open Source Intelligence Toolkit
"""

VERSION = "1.0.0"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
DEFAULT_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}
TIMEOUT = 8

# A curated list of public sites that expose a simple "profile exists / not found"
# pattern. All requests are read-only GETs to publicly documented profile URLs.
USERNAME_SITES = {
    "GitHub": "https://github.com/{}",
    "GitLab": "https://gitlab.com/{}",
    "Snapchat": "https://www.snapchat.com/add/{}",
    "Reddit": "https://www.reddit.com/user/{}/about.json",
    "Instagram": "https://www.instagram.com/{}/",
    "Twitter/X": "https://x.com/{}",
    "Facebook": "https://www.facebook.com/{}",
    "Telegram": "https://t.me/{}",
    "Steam": "https://steamcommunity.com/id/{}",
    "TikTok": "https://www.tiktok.com/@{}",
    "Pinterest": "https://www.pinterest.com/{}/",
    "Medium": "https://medium.com/@{}",
    "DevTo": "https://dev.to/{}",
    "HackerNews": "https://news.ycombinator.com/user?id={}",
    "Twitch": "https://www.twitch.tv/{}",
    "YouTube": "https://www.youtube.com/@{}",
    "SoundCloud": "https://soundcloud.com/{}",
    "Keybase": "https://keybase.io/{}",
    "Docker Hub": "https://hub.docker.com/u/{}",
    "PyPI": "https://pypi.org/user/{}/",
    "NPM": "https://www.npmjs.com/~{}",
    "LinkedIn": "https://www.linkedin.com/in/{}/",
    "Apple Music": "https://music.apple.com/profile/{}",
    "Tumblr": "https://{}.tumblr.com/",
    "Threads": "https://www.threads.net/@{}",
    "Bluesky": "https://bsky.app/profile/{}.bsky.social",
    "Noplace": "https://www.thenoplace.com/@{}",
    "TenTen": "https://tenten.app/{}",
    "Cara": "https://cara.app/{}",
    "Airchat": "https://air.chat/{}",
    "Lemon8": "https://www.lemon8-app.com/@{}",
    "RedNote": "https://www.xiaohongshu.com/user/profile/{}",
    "Kick": "https://kick.com/{}",
    "Trovo": "https://trovo.live/s/{}",
    "Rumble": "https://rumble.com/c/{}",
    "Spill": "https://spill.com/@{}",
    "BeReal": "https://bereal.com/{}/",
    "Locket": "https://locket.camera/{}",
    "Lapse": "https://lapse.app/{}",
    "Poparazzi": "https://poparazzi.com/{}",
    "Retro": "https://retro.app/{}",
    "Yubo": "https://yubo.live/{}",
    "Wizz": "https://wizz.chat/{}",
    "Gas": "https://gasapp.io/{}",
    "Saturn": "https://www.joinsaturn.com/{}",
    "Clubhouse": "https://www.clubhouse.com/@{}",
    "Airbuds": "https://airbuds.fm/{}",
    "Substack": "https://{}.substack.com",
    "Revel": "https://revelapp.com/{}",
    "Damus": "https://damus.io/{}",
    "Primal_Nostr": "https://primal.net/p/{}",
    "Mastodon.social": "https://mastodon.social/@{}",
    "Misskey.io": "https://misskey.io/@{}",
    "Firefish": "https://firefish.social/@{}",
    "Pixelfed": "https://pixelfed.social/{}",
    "Peertube": "https://peertube.tv/c/{}",
    "TruthSocial": "https://truthsocial.com/@{}",
    "Gettr": "https://gettr.com/user/{}",
    "T2/Pebble": "https://t2.social/{}",
    "CounterSocial": "https://counter.social/{}",
    "Post.News": "https://post.news/@{}",
    "Spoutible": "https://spoutible.com/{}",
    "RTRO": "https://rtro.co/{}",
    "Gowalla": "https://gowalla.com/{}",
    "Clapper": "https://clapperapp.com/{}",
    "Favorited": "https://favorited.com/{}",
    "Yope": "https://yope.app/{}",
    "Dazzle": "https://dazzle.cam/{}",
}


def banner():
    print(BANNER)


# ------------------------------------------------------------------ #
# Domain module
# ------------------------------------------------------------------ #
def domain_lookup(target):
    print(f"\n[+] WHOIS + DNS recon for: {target}\n" + "-" * 50)

    if whois:
        try:
            w = whois.whois(target)
            print("[WHOIS]")
            found_any = False
            for field in ("domain_name", "registrar", "creation_date",
                           "expiration_date", "name_servers", "org",
                           "country", "emails", "status"):
                val = w.get(field) if isinstance(w, dict) else getattr(w, field, None)
                if val:
                    found_any = True
                    print(f"  {field:15}: {val}")
            if not found_any:
                print("  [!] WHOIS returned no usable fields (registrar may be privacy-shielded).")
        except Exception as e:
            print(f"  [!] WHOIS lookup failed: {e}")
    else:
        print("  [!] python-whois not installed. Install it with: pip install python-whois")

    print("\n[DNS Records]")
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    if HAVE_DNS:
        resolver = dns.resolver.Resolver()
        resolver.timeout = TIMEOUT
        resolver.lifetime = TIMEOUT
        any_record = False
        for rtype in record_types:
            try:
                answers = resolver.resolve(target, rtype)
                vals = ", ".join(str(r) for r in answers)
                print(f"  {rtype:6}: {vals}")
                any_record = True
            except dns.resolver.NXDOMAIN:
                print(f"  [!] Domain does not exist (NXDOMAIN).")
                break
            except (dns.resolver.NoAnswer, dns.exception.DNSException):
                continue
        if not any_record:
            print("  [!] No DNS records resolved for the queried types.")
    else:
        print("  [!] dnspython not installed. Falling back to basic A-record lookup.")
        try:
            ip = socket.gethostbyname(target)
            print(f"  A     : {ip}")
        except Exception as e:
            print(f"  [!] DNS resolution failed: {e}")


# ------------------------------------------------------------------ #
# IP module (uses the real `ipwhois` RDAP library)
# ------------------------------------------------------------------ #
def ip_lookup(target):
    print(f"\n[+] IP recon for: {target}\n" + "-" * 50)

    try:
        if ":" in target:
            socket.inet_pton(socket.AF_INET6, target)
        else:
            socket.inet_aton(target)
    except OSError:
        print(f"  [!] '{target}' is not a valid IPv4/IPv6 address.")
        return

    if HAVE_IPWHOIS:
        try:
            obj = IPWhois(target)
            res = obj.lookup_rdap(depth=1)

            network = res.get("network", {}) or {}
            print("[Network / ASN]")
            fields = [
                ("asn", "ASN"),
                ("asn_description", "ASN Org"),
                ("asn_country_code", "ASN Country"),
                ("asn_cidr", "ASN CIDR"),
            ]
            for key, label in fields:
                val = res.get(key)
                if val:
                    print(f"  {label:12}: {val}")

            if network.get("name"):
                print(f"  {'Network':12}: {network.get('name')}")
            if network.get("cidr"):
                print(f"  {'CIDR':12}: {network.get('cidr')}")
            if network.get("country"):
                print(f"  {'Country':12}: {network.get('country')}")
            if network.get("start_address") or network.get("end_address"):
                print(f"  {'Range':12}: {network.get('start_address')} - {network.get('end_address')}")

            entities = res.get("entities") or []
            if entities:
                print(f"  {'Entities':12}: {', '.join(entities)}")

            objects = res.get("objects", {}) or {}
            for handle, obj_data in list(objects.items())[:3]:
                contact = obj_data.get("contact") or {}
                name = contact.get("name")
                if name:
                    print(f"  {'Contact':12}: {name} ({handle})")

        except Exception as e:
            print(f"  [!] RDAP/WHOIS lookup via ipwhois failed: {e}")
    else:
        print("  [!] 'ipwhois' not installed. Install it with: pip install ipwhois")
        print("  [!] Falling back to public JSON geolocation API...")
        try:
            r = requests.get(f"https://ipapi.co/{target}/json/", timeout=TIMEOUT,
                              headers=DEFAULT_HEADERS)
            r.raise_for_status()
            data = r.json()
            if "error" in data:
                print(f"  [!] {data.get('reason', 'lookup failed')}")
            else:
                for f in ["ip", "city", "region", "country_name", "org", "asn"]:
                    if data.get(f) is not None:
                        print(f"  {f:12}: {data.get(f)}")
        except (requests.RequestException, ValueError) as e:
            print(f"  [!] Fallback geolocation lookup failed: {e}")

    print("\n[Reverse DNS]")
    try:
        host = socket.gethostbyaddr(target)
        print(f"  PTR record  : {host[0]}")
    except Exception:
        print("  PTR record  : (none found)")


# ------------------------------------------------------------------ #
# Phone module (uses the real `phonenumbers` library - libphonenumber port)
# ------------------------------------------------------------------ #
def phone_lookup(raw_number, region=None):
    print(f"\n[+] Phone recon for: {raw_number}\n" + "-" * 50)

    if not HAVE_PHONENUMBERS:
        print("  [!] 'phonenumbers' not installed. Install it with: pip install phonenumbers")
        return

    try:
        num = phonenumbers.parse(raw_number, region)
    except phonenumbers.NumberParseException as e:
        print(f"  [!] Could not parse number: {e}")
        print("  [i] Tip: include the country code, e.g. +14155552671, "
              "or pass a region hint (e.g. --region US).")
        return

    valid = phonenumbers.is_valid_number(num)
    possible = phonenumbers.is_possible_number(num)
    e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
    intl = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL)

    line_types = {
        0: "FIXED_LINE", 1: "MOBILE", 2: "FIXED_LINE_OR_MOBILE",
        3: "TOLL_FREE", 4: "PREMIUM_RATE", 5: "SHARED_COST",
        6: "VOIP", 7: "PERSONAL_NUMBER", 8: "PAGER",
        9: "UAN", 10: "VOICEMAIL", 27: "UNKNOWN",
    }
    ntype = phonenumbers.number_type(num)

    print(f"  valid        : {valid}")
    print(f"  possible     : {possible}")
    print(f"  e164 format  : {e164}")
    print(f"  intl format  : {intl}")
    print(f"  country code : +{num.country_code}")
    print(f"  region       : {pn_geocoder.description_for_number(num, 'en')}")
    print(f"  carrier      : {pn_carrier.name_for_number(num, 'en') or '(unknown / ported / VOIP)'}")
    print(f"  line type    : {line_types.get(ntype, 'UNKNOWN')}")
    tzs = pn_timezone.time_zones_for_number(num)
    if tzs:
        print(f"  timezone(s)  : {', '.join(tzs)}")


# ------------------------------------------------------------------ #
# Username module
# ------------------------------------------------------------------ #
def _check_site(name, url_template, username):
    url = url_template.format(username)
    session = requests.Session()
    try:
        resp = session.get(url, timeout=TIMEOUT, headers=DEFAULT_HEADERS,
                            allow_redirects=True)
    except requests.RequestException:
        return name, url, None, "ERR"

    status = resp.status_code

    # A clean 404 is a reliable "not found" signal on almost every platform.
    if status == 404:
        return name, url, False, status

    # 200-399 generally means the profile page rendered/redirected successfully.
    if status < 400:
        return name, url, True, status

    # 403/429/other blocks mean the site refused the request (bot detection,
    # rate limiting) - this is NOT evidence the profile doesn't exist, so
    # report it as unknown rather than "not found".
    return name, url, None, status


def username_search(username, max_workers=12):
    print(f"\n[+] Username sweep for: {username}\n" + "-" * 50)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(_check_site, name, tmpl, username)
            for name, tmpl in USERNAME_SITES.items()
        ]
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())

    results.sort(key=lambda r: r[0])
    for name, url, found, status in results:
        if found is True:
            print(f"  [FOUND]     {name:12} {url}")
        elif found is False:
            print(f"  [not found] {name:12} (status {status})")
        elif status == "ERR":
            print(f"  [error]     {name:12} (unreachable)")
        else:
            print(f"  [unknown]   {name:12} (status {status} - site blocked the request)")

    found_n = sum(1 for r in results if r[2] is True)
    unknown_n = sum(1 for r in results if r[2] is None)
    print(f"\n  {found_n} found, {unknown_n} unknown/blocked, "
          f"{len(results) - found_n - unknown_n} not found")
    return results


# ------------------------------------------------------------------ #
# Email module
# ------------------------------------------------------------------ #
def email_check(address):
    print(f"\n[+] Email recon for: {address}\n" + "-" * 50)
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if not re.match(pattern, address):
        print("  [!] Invalid email format.")
        return

    domain = address.split("@")[1]
    print(f"  format      : valid")
    print(f"  domain      : {domain}")

    if HAVE_DNS:
        resolver = dns.resolver.Resolver()
        resolver.timeout = TIMEOUT
        resolver.lifetime = TIMEOUT
        try:
            mx = resolver.resolve(domain, "MX")
            servers = ", ".join(str(r.exchange) for r in mx)
            print(f"  MX records  : {servers}")
            print(f"  mail-capable: yes")
        except dns.resolver.NXDOMAIN:
            print(f"  MX records  : domain does not exist")
            print(f"  mail-capable: no")
        except (dns.resolver.NoAnswer, dns.exception.DNSException):
            print(f"  MX records  : none found")
            print(f"  mail-capable: no")
    else:
        print("  [!] dnspython not installed. Install it with: pip install dnspython")


# ------------------------------------------------------------------ #
# Main
# ------------------------------------------------------------------ #
def save_output(data, path):
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"\n[+] Results saved to {path}")


def main():
    parser = argparse.ArgumentParser(
        prog="mrg-osint",
        description="MRG-OSINT By-MRGCodex - Open Source Intelligence recon toolkit",
        epilog=(
            "examples:\n"
            "  mrg_osint.py domain example.com\n"
            "  mrg_osint.py ip 8.8.8.8\n"
            "  mrg_osint.py phone +14155552671\n"
            "  mrg_osint.py username johndoe -o results.json\n"
            "  mrg_osint.py email test@example.com\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--version", action="version",
                         version=f"MRG-OSINT {VERSION}")

    # Shared parent so -o/--output works AFTER the subcommand too
    # (e.g. `mrg_osint.py username foo -o out.json`), which is the
    # intuitive way most CLI tools expect it.
    output_parent = argparse.ArgumentParser(add_help=False)
    output_parent.add_argument("-o", "--output", help="Save results to a JSON file")

    sub = parser.add_subparsers(dest="command", required=True)

    p_domain = sub.add_parser("domain", help="WHOIS + DNS recon on a domain",
                               parents=[output_parent])
    p_domain.add_argument("target", help="Domain name, e.g. example.com")

    p_ip = sub.add_parser("ip", help="RDAP/ASN whois + reverse DNS on an IP",
                           parents=[output_parent])
    p_ip.add_argument("target", help="IP address")

    p_phone = sub.add_parser("phone", help="Carrier/region/timezone lookup on a phone number",
                              parents=[output_parent])
    p_phone.add_argument("target", help="Phone number, e.g. +14155552671")
    p_phone.add_argument("--region", help="2-letter region hint if number has no country code, e.g. US")

    p_user = sub.add_parser("username", help="Search a username across public platforms",
                             parents=[output_parent])
    p_user.add_argument("target", help="Username to search")
    p_user.add_argument("--threads", type=int, default=12, help="Concurrent worker threads")

    p_email = sub.add_parser("email", help="Validate email format + check MX records",
                              parents=[output_parent])
    p_email.add_argument("target", help="Email address")

    args = parser.parse_args()
    banner()
    print(f"[i] Run time : {datetime.now().isoformat(timespec='seconds')}")
    print(f"[i] Module   : {args.command}")

    result_payload = {"command": args.command, "target": args.target}
    output_path = getattr(args, "output", None)

    if args.command == "domain":
        domain_lookup(args.target)
    elif args.command == "ip":
        ip_lookup(args.target)
    elif args.command == "phone":
        phone_lookup(args.target, region=args.region)
    elif args.command == "username":
        results = username_search(args.target, max_workers=args.threads)
        result_payload["results"] = [
            {"site": n, "url": u, "found": f, "status": s} for n, u, f, s in results
        ]
    elif args.command == "email":
        email_check(args.target)

    if output_path:
        save_output(result_payload, output_path)

    print("\n[i] Done. Use this tool only against targets you are authorized to investigate.\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user. Exiting.")
        sys.exit(130)
