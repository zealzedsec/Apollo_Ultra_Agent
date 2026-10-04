# Apollo Ultra - Architecture

Apollo Ultra is an OpenCode configuration plus a Python engine of focused
modules for authorized security assessment. v4.1 introduces `apollo_core`, a
shared foundation that the engine modules build on.

## Layers

```
  opencode.jsonc / apollo_instructions.md        OpenCode agents, commands, hooks
        |
  orchestrator.py                                workflow state machine (kill chains)
        |  (every step passes the safety gate)
  apollo_core/                                   <-- NEW in v4.1: shared foundation
        |
  engine modules (kb_manager, correlator,        data, analysis, recon, reporting,
  findings_parser, nvd_enricher, ioc_engine,     and active-action modules
  report_generator, recon_*, ... )
        |
  SQLite KB (apollo.db)                          per-project intelligence store
```

## `apollo_core` package

| Module | Responsibility |
|--------|----------------|
| `config.py` | Resolve all paths and feature flags once; honor legacy env vars and an optional `apollo.config.json`. |
| `errors.py` | Shared exception hierarchy (`ApolloError` and subclasses). |
| `models.py` | `Severity`, `normalize_severity`, `severity_from_cvss`, `Finding` (+ stable `dedup_key`), `risk_score`, `ActionResult`. |
| `scope.py` | `ScopeEngine` allow/deny evaluator (IPv4/6, CIDR, ranges, wildcard domains, URLs), `extract_targets`, `is_safe_shell_token`; backward-compatible shims for `scope_validator`. |
| `authorization.py` | `EngagementContext` rules-of-engagement manifest and the `authorize()` decision. |
| `logging.py` | `get_logger` and the tamper-evident, hash-chained `AuditLog`. |
| `safety.py` | `preflight()` and the `@guarded_action` decorator tying scope + auth + dry-run + audit together. |
| `cli.py` | The unified `apollo` command. |

## Design choices

- **Additive, not disruptive.** `apollo_core` is a new subpackage. Existing flat
  modules keep working; they adopt the core via small, optional imports with
  graceful fallbacks (so a module still runs if the core is absent). The
  orchestrator and correlator demonstrate the pattern.
- **Backward compatibility.** `scope_validator.py` keeps its exact CLI and
  function contract while delegating to the corrected engine.
- **Single source of truth for severity and scope.** Modules no longer each
  carry their own `SEVERITY_WEIGHTS` dict or ad-hoc target regex.
- **Testable core.** Everything in `apollo_core` is pure logic with no network
  or external-tool dependency, so the `tests/` suite runs fast and offline and
  gates CI.

## Data model (SQLite KB)

`kb_manager.py` owns the schema: `projects`, `hosts`, `ports`,
`vulnerabilities`, `credentials` (encrypted at rest), `exploits`,
`c2_sessions`, `c2_commands`, `attack_paths`, `events`, `notes`, and
`commands_log`, with a thread-local connection pool in WAL mode. Analysis
modules (`correlator`, `attack_graph`, `report_generator`) read from it;
collection modules (`findings_parser`, recon wrappers) write to it.

## Extending the framework

1. Put shared, reusable logic in `apollo_core` with tests in `tests/`.
2. Route any active operation through `preflight` / `@guarded_action`.
3. Normalize severities and findings through `apollo_core.models`.
4. Keep module CLIs working standalone; import the core defensively.

See [SAFETY.md](SAFETY.md) for the authorization and audit model.
