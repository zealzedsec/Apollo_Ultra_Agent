# Apollo Ultra — surface palette & voice (SINGULAR Phase 2)

Flight-recorder / chain-of-custody identity (see IDENTITY.md). Surfaces are the
`apollo` CLI, generated reports (md/PDF), and the MCP interface — no web
front-end. "Tokens" here are the report/CLI palette and the banner/voice spec.
Design only; nothing here adds or implies offensive capability — it makes
authorization and accountability legible.

## Report / TUI palette (sealed-evidence-case — verify in render)
| Role | Value |
|---|---|
| ground | `#1a1c18` (desaturated olive-graphite) |
| panel | `#23261f` |
| lead-grey neutral | `#8c9188` |
| verdigris (verified / sealed) — ONE job | `#4a8f82` |
| in-scope | `#6f8f5a` |
| out-of-scope / refused | `#b4603a` (hazard, not neon red) |
| dry-run | `#c08a2c` |
| hash / mono fields | lead-grey on ground |

Type: a stencil/stamped face for headers/markings + mono for the audit chain,
scope rules and hashes. Tabular figures. No green-on-black, no emoji, no skulls.

## CLI banner (concise, honest)
operator · engagement id · scope summary · dry-run flag · audit-verify status.
No fabricated stats. Example: `ACME-2026 · in-scope · dry-run · audit ✓ (142)`.

## Voice
Exact, accountable, unglamorous. "Refused: 10.0.1.5 outside authorized scope." /
"Audit chain verified (142 entries)." Never: "game-changer", emoji, 200-on-failure.

## The one memorable thing
`apollo audit verify` rendered as a verifiable seal — the hash-chained
chain-of-custody shown as an object you can see holds.
