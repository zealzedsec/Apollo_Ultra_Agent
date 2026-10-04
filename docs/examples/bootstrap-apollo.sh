#!/usr/bin/env bash
# Apollo Ultra - host bootstrap for AUTHORIZED testing.
# Run this from the repo root ON YOUR OWN MACHINE:
#   bash docs/examples/bootstrap-apollo.sh            # core + safe engagement (no tool install)
#   bash docs/examples/bootstrap-apollo.sh --tools    # also run setup_kali.sh (Kali/Debian, uses sudo apt)
#
# It installs the apollo_core package, wires up a SAFE engagement (scope enforced,
# authorization required, dry-run ON, intrusive OFF), and verifies the gate.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APOLLO_HOME="${APOLLO_HOME:-$HOME/.config/opencode/apollo-engine}"
cd "$REPO_DIR"

echo "[*] Repo:        $REPO_DIR"
echo "[*] APOLLO_HOME: $APOLLO_HOME"

echo "[*] Installing apollo_core (+ cryptography) ..."
python3 -m pip install -e . >/dev/null

mkdir -p "$APOLLO_HOME"

# Persist a SAFE posture so the gate is strict even without env vars.
cat > "$APOLLO_HOME/apollo.config.json" <<JSON
{
  "enforce_scope": true,
  "require_authorization": true,
  "dry_run": true,
  "audit_enabled": true,
  "log_level": "INFO"
}
JSON
echo "[+] Wrote safe posture -> $APOLLO_HOME/apollo.config.json (dry_run ON, scope + auth enforced)"

# Install the sanctioned-range engagement + scope (owner-authorized test targets).
cp "$REPO_DIR/docs/examples/engagement.sanctioned-demo.json" "$APOLLO_HOME/engagement.json"
cp "$REPO_DIR/docs/examples/scope.sanctioned-demo.txt"       "$APOLLO_HOME/scope.txt"
echo "[+] Installed sanctioned-range engagement.json + scope.txt"

if [ "${1:-}" = "--tools" ]; then
  if [ -x "$REPO_DIR/setup_kali.sh" ] || [ -f "$REPO_DIR/setup_kali.sh" ]; then
    echo "[*] Installing security tooling via setup_kali.sh (Kali/Debian; needs sudo) ..."
    bash "$REPO_DIR/setup_kali.sh" || echo "[!] Tool install had non-fatal errors (expected off-Kali)."
  fi
else
  echo "[*] Skipping tool install. Re-run with --tools on Kali/Debian to install nmap/nuclei/etc."
fi

echo ""
echo "[*] Verifying the safety core ..."
apollo selftest        || python3 -m apollo_core.cli selftest
echo ""
apollo engagement show || python3 -m apollo_core.cli engagement show
echo ""
echo "[*] Scope sanity:"
apollo scope check scanme.nmap.org || true
apollo scope check example.com    || true

cat <<EOF

============================================================
 Apollo bootstrap complete (SAFE posture).
============================================================
 Next:
   1. Dry-run a plan (nothing executes):
        python3 orchestrator.py quick-win scanme.nmap.org demo
        apollo audit verify
   2. For RECON-ONLY real runs against an in-scope sanctioned
      target, once tools are installed, drop dry-run:
        APOLLO_DRY_RUN=0 python3 recon_tools.py subfinder testphp.vulnweb.com
   3. Keep intrusive OFF. Never point offensive modules at a
      production third party. Validate manually; disclose via
      the program's official channel.
============================================================
EOF
