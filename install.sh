#!/usr/bin/env bash
# MRG-OSINT installer
# Supports: Debian/Ubuntu/Kali, Fedora/RHEL, Arch/BlackArch, macOS
set -e

echo "=============================================="
echo "        MRG-OSINT  -  Installer"
echo "=============================================="

detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            kali|debian|ubuntu|parrot) echo "debian" ;;
            fedora|rhel|centos) echo "fedora" ;;
            arch|blackarch|manjaro) echo "arch" ;;
            *) echo "unknown" ;;
        esac
    else
        echo "unknown"
    fi
}

OS=$(detect_os)
echo "[i] Detected OS family: $OS"

install_python() {
    case "$OS" in
        debian)
            sudo apt-get update -y
            sudo apt-get install -y python3 python3-pip python3-venv
            ;;
        fedora)
            sudo dnf install -y python3 python3-pip
            ;;
        arch)
            sudo pacman -Sy --noconfirm python python-pip
            ;;
        macos)
            if ! command -v brew &> /dev/null; then
                echo "[!] Homebrew not found. Install it from https://brew.sh first."
                exit 1
            fi
            brew install python3
            ;;
        *)
            echo "[!] Unknown OS. Please ensure python3 + pip3 are installed manually."
            ;;
    esac
}

if ! command -v python3 &> /dev/null; then
    echo "[+] Installing Python3..."
    install_python
else
    echo "[i] Python3 already installed: $(python3 --version)"
fi

echo "[+] Setting up virtual environment (.venv)..."
if ! python3 -m venv .venv 2>/tmp/mrg_venv_err.log; then
    echo "[!] venv creation failed (often means the 'venv' module isn't installed"
    echo "    separately from python3, e.g. minimal Debian/Ubuntu/Kali images)."
    echo "[+] Attempting to install it and retry..."
    case "$OS" in
        debian) sudo apt-get update -y && sudo apt-get install -y python3-venv ;;
        fedora) sudo dnf install -y python3-virtualenv ;;
        arch)   sudo pacman -Sy --noconfirm python-virtualenv ;;
    esac
    python3 -m venv .venv
fi
source .venv/bin/activate

echo "[+] Upgrading pip..."
pip install --upgrade pip --quiet

echo "[+] Installing Python dependencies..."
pip install -r requirements.txt --quiet

chmod +x mrg_osint.py

echo ""
echo "=============================================="
echo " Install complete!"
echo ""
echo " Activate the environment with:"
echo "   source .venv/bin/activate"
echo ""
echo " Then run MRG-OSINT with, e.g.:"
echo "   python3 mrg_osint.py username johndoe"
echo "   python3 mrg_osint.py domain example.com"
echo "   python3 mrg_osint.py ip 8.8.8.8"
echo "   python3 mrg_osint.py phone +14155552671"
echo "   python3 mrg_osint.py email test@example.com"
echo "=============================================="
