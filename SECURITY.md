# Security Policy

Do not commit real credentials, API keys, tokens, client data, scan results, reports, or local SQLite databases.

Before publishing a release, run:

```bash
grep -RInE 'sk-[A-Za-z0-9]{20,}|api[_-]?key=.*[A-Za-z0-9]{16,}|token=.*[A-Za-z0-9]{16,}|password=.*[A-Za-z0-9]{8,}|/home/[A-Za-z0-9_-]+' . --exclude-dir=.git || true
```

If you discover a leaked secret, revoke it immediately, remove it from git history, and rotate any related accounts or services.
