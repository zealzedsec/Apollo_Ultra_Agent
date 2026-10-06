# apollo_ultra_agent — Identity Dossier
Status: draft | Mode: autonomous
Phase 0 evidence: `.singular/baseline/tells.txt`

## Phase 0 summary (current state, observed)
- OpenCode config + Python framework for **authorized** security assessment:
  scope engine, `engagement.json` rules-of-engagement, tamper-evident
  hash-chained audit log (`apollo audit verify`), dry-run mode, safety gate at the
  execution chokepoint, MCP-style command interface. Unified `apollo` CLI.
- Tell scan: http200-with-failure 22, emoji-as-ui 10, placeholder-names 8,
  cliche-copy 2, todo-implement 1. Surface is CLI + reports + MCP (no web
  front-end). Main lift: error/response truthfulness + a distinctive,
  authorization-forward CLI/report identity.

## 1. Subject
- Subject: a framework that will only act inside a provable authorization
  boundary, and proves every action it took afterwards.
- Audience: an operator running an authorized engagement who must demonstrate, to
  a client/auditor, exactly what was done and that it stayed in scope.
- Primary job: encode the rules of engagement, refuse anything outside them, and
  leave a tamper-evident record — authorization and audit are the product.
- World it lives in: a sealed evidence case, a chain-of-custody ledger, a flight
  recorder / black box, a stencilled equipment case with a lead seal.

## 2. References
- Physical-world references: a sealed evidence case with a chain-of-custody tag;
  a flight recorder; a stencilled ordnance/equipment case with a hazard placard.
- Anti-references: green-on-black "hacker" aesthetic; skull/"l33t" iconography;
  "military-grade"/game-changer copy; and sibling osintforge's manila field log.
- Given assets: the hash-chained audit + engagement manifest are the Given
  identity — surface them, don't decorate over them.

## 3. Archetype slots (final)
structural metaphor: **flight recorder / chain-of-custody ledger** | type
temperament: **stencil/stamped face + mono** | color story: **sealed evidence
case — verdigris + lead-seal grey on a desaturated olive-graphite** | density:
**dense** | motion: **none / state-only** | surface/texture: **flat stencil /
stamped** | grid: **single-axis ledger** | imagery strategy: **diagrammatic (scope
graph + audit chain)**

## 4. The one memorable thing
The **hash-chained audit tail** rendered as a verifiable seal: `apollo audit
verify` is a visible, designed object — a chain-of-custody record you can see
holds. Authorization state (in-scope / out-of-scope / dry-run) is always
unmistakable.

## 5. Token plan
- CLI/report color: a restrained palette — `olive`/`graphite` ground, `lead`
  neutral, `verdigris` as the single "verified/sealed" accent, plus truthful
  status colors (in-scope / denied / dry-run) that are distinction-safe and never
  color-only. No green-on-black, no emoji.
- Type: a **stencil/stamped** display face for headers/markings + **mono** for
  the audit chain, scope rules and IDs. Tabular figures; hashes in mono.
- Reports (PDF/md): same type + color system; the audit chain and engagement
  manifest are first-class sections.
- Motion: none in CLI; state-only where a TUI exists.
- Banner: concise, honest — operator, engagement id, scope summary, dry-run flag;
  never fabricated stats.

## 6. Layout concept
- One sentence (report/TUI): an engagement header (operator, client, scope,
  window, dry-run) over a single-axis, verifiable action ledger.
- Hero thesis: the first thing shown is the engagement manifest + audit-verify
  status, not a tool menu.
- Alignment: strict single axis; mono columns aligned; hashes never wrap silently.

## 7. Voice
- Adjectives: exact, accountable, unglamorous.
- Says: "ACME-2026 · in-scope · dry-run. Audit chain verified (142 entries)." /
  "Refused: 10.0.1.5 outside authorized scope." Never: emoji, "game-changer",
  skull art, 200-with-failure.
- Naming: *engagement*, *scope*, *audit*, *dry-run*, *refused* — the framework's
  own enforced vocabulary.

## 8. Collision Test log
| Plan element | Default I'd have produced | Chosen | Why different |
|---|---|---|---|
| Aesthetic | Green-on-black hacker CLI | Stencil olive + verdigris seal | Authorization/custody, not "l33t" |
| Response shape | 200 + {success:false} | RFC 9457 / honest exit codes | Fixes 22 truthfulness tells |
| Hero | Tool/command menu | Engagement manifest + audit-verify | Authorization is the product |
| Fixtures | placeholder names (×8) | Domain-specific, honest fixtures | Removes placeholder tells |

## 9. Chosen defaults (documented exceptions)
| Default kept | Why it's right for this subject |
|---|---|
| Monospace CLI | Native form for an engine whose output is a record |
| Hash/scope detail surfaced | The provable-authorization story is the identity |

## 10. Backend identity
Keep scope engine, engagement manifest, tamper-evident audit, dry-run, safety
gate. **Replace 200-with-failure with honest exit codes / RFC-9457 problem
details** for the MCP + service layers; structured logs with no emoji; resolve or
make honest the `TODO`/`NotImplemented`; refuse shell-metachar targets (already
done) and surface the refusal truthfully.

## 11. Non-negotiable constraints
Never act outside the engagement manifest; audit chain must stay verifiable;
dry-run must plan-without-executing; no credentials in repo/logs/reports; this is
authorized-assessment tooling only — identity work must not add or imply
offensive capability, only make authorization and accountability legible.
