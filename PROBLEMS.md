# Apollo Ultra — Problem/Error Registry (SINGULAR Phase 2/3)

The tell scan found `http200-with-failure` ×22: success and failure sharing a
200 with `{success:false}`. This registry defines the **one** error shape and a
stable code per failure mode, so the MCP/service layer stops lying about
outcomes. CLI paths use the matching honest **exit code** instead of printing a
"success" line on failure.

## The one shape (RFC 9457 Problem Details)
```json
{
  "type": "https://apollo.zedsec-labs/problems/<slug>",
  "title": "<short, specific, human>",
  "status": <http status>,
  "detail": "<what happened, to which thing, what to do>",
  "code": "<STABLE_CODE>",
  "instance": "/engagements/<id>/...",
  "requestId": "..."
}
```
Messages never apologize, never say "something went wrong", never leak internals.
These are the framework's own enforced refusals surfaced honestly — identity /
plumbing only; no change to what the tool can do.

## Codes (engine failure modes — extend as needed)
| code | status | exit | when |
|---|---|---|---|
| `OUT_OF_SCOPE` | 403 | 3 | target outside the engagement manifest's authorized scope (deny wins) |
| `NOT_AUTHORIZED` | 403 | 3 | no/invalid engagement authorization for this action |
| `DRY_RUN_BLOCKED` | 409 | 4 | intrusive action attempted while `APOLLO_DRY_RUN=1` (planned + audited, not executed) |
| `TARGET_REJECTED` | 400 | 5 | target contains shell metacharacters / fails validation |
| `OUTSIDE_WINDOW` | 403 | 3 | action outside the engagement's authorized time window |
| `CONFIG_INVALID` | 500 | 6 | engagement.json / env failed schema validation at startup (fail fast, specific) |
| `AUDIT_CHAIN_BROKEN` | 500 | 7 | `apollo audit verify` found an edit/insertion/deletion in the hash chain |
| `UPSTREAM_UNAVAILABLE` | 502 | 8 | a required dependency/tool is unreachable |

Rule: no operation returns 200 (or exit 0) on failure. Every operation returns
evidence of what happened (IDs, durations, counts), not just `{success:true}`.

## Open follow-ups (tracked, not faked)
- Replace the 22 `success:false`-at-200 sites with the shape above / honest exit
  codes; add `requestId` propagation and structured no-emoji logs.
- Resolve the `TODO: implement` / NotImplemented marker, or return
  `UPSTREAM_UNAVAILABLE` / an honest "not supported".
- Replace placeholder fixture names (×8) with domain-specific, honest fixtures.
