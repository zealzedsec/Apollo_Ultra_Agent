#!/bin/bash
# APOLLO ULTRA V3 - Kali Linux Setup & Installation
# Run: bash ~/.config/opencode/apollo-engine/setup_kali.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$(dirname "$SCRIPT_DIR")"

echo "============================================"
echo " APOLLO ULTRA V3 - Kali Linux Setup"
echo "============================================"

# Phase 1: Install APT packages
echo ""
echo "[*] Phase 1: Installing APT packages..."
sudo apt update
sudo apt install -y \
  nmap nuclei subfinder amass httpx naabu gowitness sqlmap \
  metasploit-framework hashcat john theharvester \
  bloodhound crackmapexec responder hydra medusa wpscan nikto \
  ffuf wfuzz jq exploitdb seclists \
  ldap-utils enum4linux smbclient impacket-scripts \
  aircrack-ng dsniff \
  python3-pip curl wget git openssl \
  2>/dev/null || echo "[!] Some packages may have failed (non-critical)"

# Install additional tools not in apt repos
echo ""
echo "[*] Installing Python-based tools..."
pip3 install --user dalfox xsstrike 2>/dev/null || true

# Phase 2: Python packages
echo ""
echo "[*] Phase 2: Installing Python packages..."
pip3 install --user requests shodan censys colorama beautifulsoup4 2>/dev/null || true

# Phase 3: Decompress wordlists
echo ""
echo "[*] Phase 3: Checking wordlists..."
if [ -f /usr/share/wordlists/rockyou.txt.gz ] && [ ! -f /usr/share/wordlists/rockyou.txt ]; then
    echo "[-] Decompressing rockyou.txt.gz (~4 sec)..."
    sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz
    echo "[+] rockyou.txt ready"
fi
ls -lh /usr/share/wordlists/rockyou.txt 2>/dev/null || echo "[!] rockyou.txt not found"

# Phase 4: Initialize knowledge base
echo ""
echo "[*] Phase 4: Initializing knowledge base..."
python3 "$SCRIPT_DIR/kb_manager.py" init
python3 "$SCRIPT_DIR/kb_manager.py" project default

# Phase 5: Tool audit
echo ""
echo "[*] Phase 5: Running tool audit..."
python3 "$SCRIPT_DIR/kali_tools.py"

# Phase 6: Create .env if not exists
ENV_FILE="$CONFIG_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
    echo ""
    echo "[*] Phase 6: Creating .env template..."
    cat > "$ENV_FILE" << 'EOF'
# APOLLO ULTRA V3 - Environment Configuration
# Source: source ~/.config/opencode/.env
export DEEPSEEK_API_KEY="YOUR_API_KEY_HERE"
export APOLLO_MODEL="opencode/deepseek-v4-flash-free"
export APOLLO_SMALL_MODEL="opencode/north-mini-code-free"
export APOLLO_PROJECT="default"
export OPENCODE_CONFIG="$CONFIG_DIR/opencode.jsonc"
EOF
    echo "[!] Edit $ENV_FILE and set your DEEPSEEK_API_KEY"
else
    echo "[*] .env exists"
fi

# Summary
echo ""
echo "============================================"
echo " SETUP COMPLETE"
echo "============================================"
echo ""
echo "Launch: bash $CONFIG_DIR/apollo_activate.sh [agent] [project]"
echo ""
echo "Quick start:"
echo "  1. Edit ~/.config/opencode/.env with your API key"
echo "  2. Source it: source ~/.config/opencode/.env"
echo "  3. Launch: bash ~/.config/opencode/apollo_activate.sh"
echo ""
echo "For other agents:"
echo "  bash ~/.config/opencode/apollo_activate.sh build"
echo "  bash ~/.config/opencode/apollo_activate.sh plan"
echo "  bash ~/.config/opencode/apollo_activate.sh explore"
echo "  bash ~/.config/opencode/apollo_activate.sh general"
echo "  bash ~/.config/opencode/apollo_activate.sh scout"
echo ""
