# Apollo Ultra for OpenCode

Apollo Ultra is an OpenCode configuration and Python framework for authorized security assessment workflows. It includes custom agents, slash commands, a SQLite knowledge base, reporting, IOC extraction, reconnaissance helpers, attack graph analysis, and tool orchestration through an MCP-style command interface.

This public copy is sanitized for GitHub. It does not include local databases, project artifacts, reports, caches, `node_modules`, `.env`, API keys, credentials, private paths, or personal data.

## What Is Included

- `opencode.jsonc` - OpenCode agent, command, instruction, skill, and MCP configuration.
- `apollo_instructions.md` - Apollo Ultra operating instructions for OpenCode.
- `apollo_activate.sh` - launcher that loads environment variables, initializes the KB, and starts OpenCode with an Apollo agent.
- `apollo-engine/` - Python modules for KB management, parsing, reporting, recon wrappers, CVE enrichment, graphing, and workflow orchestration.
- `.env.example` - safe template for local API keys and environment variables.
- `install.sh` - copy-paste installer for `~/.config/opencode`.

## Quick Install

Install OpenCode first:

```bash
curl -fsSL https://opencode.ai/install | bash
```

Clone or copy this repository, then run:

```bash
cd apollo-ultra-public
bash install.sh
```

Load the environment and launch Apollo Ultra:

```bash
source ~/.config/opencode/.env
bash ~/.config/opencode/apollo_activate.sh ultra default
```

## Configure API Keys

Edit the generated environment file:

```bash
nano ~/.config/opencode/.env
```

Set only the keys you need:

```bash
export DEEPSEEK_API_KEY="your_key_here"
export ZHIPUAI_API_KEY="your_key_here"
export NVD_API_KEY="your_key_here"
export VIRUSTOTAL_API_KEY="your_key_here"
export ABUSEIPDB_API_KEY="your_key_here"
export SHODAN_API_KEY="your_key_here"
```

Generate a local credential encryption key if you plan to store credentials in the KB:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Then paste it into `~/.config/opencode/.env`:

```bash
export APOLLO_ENCRYPTION_KEY="paste_generated_value_here"
```

## Optional Tool Setup

For Kali or Debian-like systems, run:

```bash
bash ~/.config/opencode/apollo-engine/setup_kali.sh
```

Check tool availability at any time:

```bash
python3 ~/.config/opencode/apollo-engine/kali_tools.py
```

Initialize or switch KB projects:

```bash
python3 ~/.config/opencode/apollo-engine/kb_manager.py init
python3 ~/.config/opencode/apollo-engine/kb_manager.py project default
python3 ~/.config/opencode/apollo-engine/kb_manager.py summary
```

## Common Launch Commands

Start the default Apollo agent:

```bash
bash ~/.config/opencode/apollo_activate.sh ultra default
```

Start another Apollo model profile:

```bash
bash ~/.config/opencode/apollo_activate.sh big-pickle default
bash ~/.config/opencode/apollo_activate.sh nemotron default
bash ~/.config/opencode/apollo_activate.sh north default
bash ~/.config/opencode/apollo_activate.sh mimo default
bash ~/.config/opencode/apollo_activate.sh pro default
```

Use built-in OpenCode agents through the same launcher:

```bash
bash ~/.config/opencode/apollo_activate.sh build default
bash ~/.config/opencode/apollo_activate.sh plan default
bash ~/.config/opencode/apollo_activate.sh explore default
bash ~/.config/opencode/apollo_activate.sh general default
```

## Useful Slash Commands

Inside OpenCode, use:

```text
/agents
/status
/tool-check
/kb summary
/plan
/report
```

Assessment workflow commands include:

```text
/recon example.com
/scan 192.0.2.10
/web https://example.com
/api https://example.com/api
/container full
/ioc extract suspicious.log
/graph paths
```

Only run assessment commands against systems you are authorized to test.

## GitHub Publishing Checklist

Run these checks before the first commit:

```bash
cd apollo-ultra-public
grep -RInE 'sk-[A-Za-z0-9]|api[_-]?key=.*[A-Za-z0-9]{16,}|token=.*[A-Za-z0-9]{16,}|password=.*[A-Za-z0-9]{8,}|/home/[A-Za-z0-9_-]+' . --exclude-dir=.git || true
git status --short
```

Recommended first commit:

```bash
git init
git add .
git commit -m "Initial sanitized Apollo Ultra public release"
```

Add your GitHub remote and push:

```bash
git remote add origin git@github.com:YOUR_USER/apollo-ultra.git
git branch -M main
git push -u origin main
```

## Files Intentionally Not Published

- `.env` and any real API keys.
- `apollo-engine/apollo.db` and other SQLite databases.
- `apollo-engine/projects/` engagement artifacts.
- `apollo-engine/reports/` generated reports.
- `apollo-engine/.active_project` local state.
- `apollo-engine/.nvd_cache.json` local cache.
- `__pycache__/`, `*.pyc`, and `node_modules/`.

## Troubleshooting

If OpenCode does not see the Apollo config, export the config path manually:

```bash
export OPENCODE_CONFIG="$HOME/.config/opencode/opencode.jsonc"
opencode --agent apollo-ultra
```

If a command cannot find a Python module, confirm the framework was installed to the expected path:

```bash
ls ~/.config/opencode/apollo-engine
python3 ~/.config/opencode/apollo-engine/kb_manager.py summary
```

After changing `opencode.jsonc`, `apollo_instructions.md`, agents, commands, skills, or MCP settings, quit and restart OpenCode. OpenCode loads configuration at startup.
