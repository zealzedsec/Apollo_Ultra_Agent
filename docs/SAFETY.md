# Apollo Ultra - Safety & Authorization Model

Apollo Ultra is built for **authorized** security assessment. v4.1 adds a core
that makes that authorization *enforceable and auditable* instead of relying on
operator discipline. This document describes the model, how to configure it, and
its limitations.

## Principles

1. **Default to the safe setting.** Enforcement flags are opt-in, but once set
   they *withhold* capability — the core never grants an action the operator
   could not already perform.
2. **One chokepoint.** Active steps flow through a single safety gate
   (`apollo_core.safety.preflight` / `@guarded_action`) that composes scope,
   engagement authorization, dry-run posture, and auditing.
3. **Prove what happened.** Every decision — allowed, blocked, or simulated — is
   written to a tamper-evident audit log.

## The three controls

### 1. Scope (`apollo_core.scope`)

A boundary-correct allow/deny evaluator for IPv4/IPv6 addresses, CIDR, ranges,
exact hostnames, wildcard domains, and URLs. **Deny always wins.** It replaces
the original matcher, which had exploitable bugs (unanchored IP regex, no octet
validation, and `*.example.com` matching `notexample.com`).

```bash
apollo scope check 10.0.0.5
apollo scope targets "nmap -sV 10.0.0.5 api.example.com"
```

### 2. Engagement authorization (`apollo_core.authorization`)

An `engagement.json` manifest encodes the rules of engagement: who is operating,
for which client, the authorized scope and deny-list, the permitted time window,
and whether intrusive/exploitative actions are allowed at all.

```bash
apollo engagement init \
  --id ACME-2026-Q1 --operator jane --client "ACME Corp" --authorized \
  --allow 10.0.0.0/24 --allow '*.acme-lab.example' \
  --deny 10.0.0.1 --intrusive \
  --start 2026-10-01T00:00:00Z --end 2026-10-31T23:59:59Z
apollo engagement show
```

### 3. Tamper-evident audit log (`apollo_core.logging.AuditLog`)

An append-only JSONL log where each entry embeds the SHA-256 of the previous
entry. Editing, inserting, or deleting any line breaks the chain, and `verify`
reports exactly where.

```bash
apollo audit tail 20
apollo audit verify     # exit 0 = intact, 2 = tampered
```

## Enforcement flags

Set via environment or `<APOLLO_HOME>/apollo.config.json`:

| Flag | Default | Effect |
|------|---------|--------|
| `APOLLO_ENFORCE_SCOPE` | off | Block actions whose target is out of engagement scope. |
| `APOLLO_REQUIRE_AUTH`  | off | Require an authorized, in-window engagement; gate intrusive actions on `intrusive_allowed`. |
| `APOLLO_DRY_RUN`       | off | Evaluate and audit every action but never execute it. |
| `APOLLO_AUDIT`         | on  | Write the audit trail. |

Recommended posture for a live engagement:

```bash
export APOLLO_ENFORCE_SCOPE=1
export APOLLO_REQUIRE_AUTH=1
export APOLLO_OPERATOR="jane"
# Dry-run the whole plan first, review the audit log, then unset for execution:
APOLLO_DRY_RUN=1 python3 orchestrator.py quick-win 10.0.0.5 acme
apollo audit tail 50
```

With both enforcement flags on, the orchestrator refuses out-of-scope or
unauthorized targets, refuses targets containing shell metacharacters (which
would otherwise be interpolated unquoted into a command), and records every
decision.

## Threat model & limitations

- **The audit chain detects tampering; it does not prevent it.** An attacker who
  can rewrite the *entire* log from a chosen point can produce a self-consistent
  chain. For strong guarantees, ship entries to append-only remote storage
  (future work). The chain's value is detecting *post-hoc edits* to a log the
  attacker could not fully recompute.
- **Cross-process append is best-effort.** A POSIX `flock` plus an in-process
  lock serializes appends; a crash mid-write could leave a partial final line,
  which `verify` surfaces as a corrupt tail.
- **Scope is matched on the literal target string**, after URL/port
  normalization. It does not resolve DNS, so a hostname in scope that resolves
  to an out-of-scope IP is not caught here — keep IP ranges in scope for network
  engagements.
- **The gate is advisory to modules that opt in.** The orchestrator enforces it
  at execution time; standalone module CLIs that build their own commands should
  route through `preflight` / `@guarded_action` to inherit the same guarantees.

## For module authors

Wrap any function that performs an active action:

```python
from apollo_core import guarded_action

@guarded_action(action="port_scan", intrusive=False)
def scan(target):
    ...
```

or check imperatively before building a command:

```python
from apollo_core import preflight

gate = preflight("auto_pwn", target=ip, intrusive=True)
if not gate.allowed:
    return {"blocked": gate.reason}
if gate.dry_run:
    return {"dry_run": True}
```
