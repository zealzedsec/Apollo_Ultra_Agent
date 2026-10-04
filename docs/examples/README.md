# Apollo engagement examples (bug-bounty / authorized testing)

These are ready-to-use **engagement manifests** and **scope files** for the
`apollo_core` safety gate. They encode *who* is authorized, *what* is in scope,
and *what is forbidden*, so Apollo refuses anything out of bounds and records
every decision in the tamper-evident audit log.

> **Reality check (from current program research):** across essentially every
> public bug-bounty program, automated scanning is **restricted or prohibited**
> on production, and automated **exploitation, credential spraying, and DoS are
> universally forbidden**. "Publicly open to report" is not "authorized for
> broad automated testing." Point tooling at an **owner-sanctioned range**, keep
> production testing **manual + low-rate**, and always read the live brief first.

## Files

| File | Use |
|------|-----|
| `scope.sanctioned-demo.txt` | Allow/deny scope for owner-authorized test ranges (scanme.nmap.org, testphp.vulnweb.com). |
| `engagement.sanctioned-demo.json` | Engagement for those sanctioned ranges — `intrusive_allowed: false`. |
| `engagement.program-template.json` | Template to encode a real program's brief (starts `authorized: false`). |

## Safe posture (set these for any real run)

```bash
export APOLLO_HOME="$HOME/.config/opencode/apollo-engine"
export APOLLO_ENFORCE_SCOPE=1     # refuse out-of-scope targets
export APOLLO_REQUIRE_AUTH=1      # require an authorized, in-window engagement
export APOLLO_DRY_RUN=1           # PLAN ONLY — no command executes
export APOLLO_OPERATOR="your-handle"
cp docs/examples/engagement.sanctioned-demo.json "$APOLLO_HOME/engagement.json"
cp docs/examples/scope.sanctioned-demo.txt       "$APOLLO_HOME/scope.txt"
```

## Workflow

```bash
# 1. Confirm the gate sees your scope
apollo engagement show
apollo scope check scanme.nmap.org      # -> allowed
apollo scope check example.com          # -> blocked

# 2. DRY-RUN the plan first (nothing runs; every step is audited)
python3 orchestrator.py quick-win scanme.nmap.org demo

# 3. Review exactly what it *would* do, and the audit trail
apollo audit tail 50
apollo audit verify

# 4. Only then, on a host with the tools installed (Kali) and ONLY against a
#    sanctioned range or an automation-permitted in-scope asset, drop dry-run
#    for RECON-ONLY steps, throttled to the program's limit:
unset APOLLO_DRY_RUN
python3 recon_tools.py subfinder testphp.vulnweb.com   # passive first
# keep APOLLO_ENFORCE_SCOPE=1 and intrusive_allowed=false the whole time
```

**Never** enable `intrusive_allowed` (exploitation / spraying / C2) against a
production third party — it breaks nearly every program's rules and voids legal
safe harbor. Validate findings manually with a minimal proof of concept and
report through the program's official channel (coordinated disclosure).
