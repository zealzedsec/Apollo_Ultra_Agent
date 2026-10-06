# Asset & Dependency Ledger — apollo_ultra_agent

SINGULAR Phase 2 ledger. Licenses from common knowledge; **re-verify before
release**. No row → no ship.

| Asset | Type | Source | License (to verify) | Verify status |
|---|---|---|---|---|
| Python framework + deps | Code | pyproject.toml / requirements.txt | per package | confirm at release |
| OpenCode config | Config | own | own | owner asset |
| report/CLI theme | Design | `design/palette.md` | own | not yet applied |
| report fonts (if PDF) | Font | TBD (stencil display + mono, self-host) | OFL candidates (verify) | not chosen yet |

## Open Phase-2 / Phase-3 follow-ups (tracked, not faked)
1. **Error model (the core debt)**: adopt `PROBLEMS.md` — one RFC-9457 shape /
   honest exit codes; replace the 22 `success:false`-at-200 sites; add requestId
   + structured no-emoji logs.
2. **Fixtures**: replace placeholder names (×8) with domain-specific, honest
   fixtures; resolve the `TODO: implement` marker.
3. **Reports/CLI**: apply `design/palette.md` (stencil + verdigris seal); render
   `apollo audit verify` as a verifiable chain-of-custody object.

## Scope discipline (binding)
This is authorized-assessment tooling. Identity/design work must NOT add or imply
offensive capability — only make authorization (scope engine, engagement
manifest) and accountability (tamper-evident audit) legible. Never act outside
the engagement manifest; dry-run plans without executing; no credentials in
repo, logs, or reports.
