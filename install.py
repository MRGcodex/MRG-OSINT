#!/usr/bin/env python3
"""
Cross-platform fallback installer for MRG-OSINT.
Use this if install.sh isn't suitable for your system (e.g. no bash).
It only installs Python dependencies via pip - it assumes python3/pip
are already present.
"""
import subprocess
import sys
import os

REQ_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")


def main():
    print("[+] MRG-OSINT dependency installer (pure Python)")
    print(f"[i] Python: {sys.version}")

    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", REQ_FILE])
    except subprocess.CalledProcessError as e:
        print(f"[!] pip install failed: {e}")
        sys.exit(1)

    print("\n[+] Done. Run it with:")
    print("    python3 mrg_osint.py username <name>")
    print("    python3 mrg_osint.py domain <domain>")
    print("    python3 mrg_osint.py ip <ip>")
    print("    python3 mrg_osint.py email <email>")


if __name__ == "__main__":
    main()
