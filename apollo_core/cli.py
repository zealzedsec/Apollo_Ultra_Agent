#!/usr/bin/env python3
"""
APOLLO Core - unified command-line interface (``apollo``).

A single operator-facing entry point for the cross-cutting concerns that the
per-module CLIs never covered: inspecting config, checking scope, managing the
engagement manifest, and reading / verifying the audit trail.

    apollo version
    apollo config show
    apollo scope check 10.0.0.5
    apollo scope targets "nmap -sV 10.0.0.5 evil.example.com"
    apollo engagement show
    apollo engagement init --id ACME-2026 --allow 10.0.0.0/24 --operator jane
    apollo audit tail 20
    apollo audit verify
    apollo selftest
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import __version__
from .authorization import EngagementContext, get_engagement
from .config import get_config
from .logging import get_audit_log
from .scope import ScopeEngine, extract_targets


def _print(obj) -> None:
    if isinstance(obj, str):
        print(obj)
    else:
        print(json.dumps(obj, indent=2, default=str))


def _cmd_version(_args) -> int:
    _print({"apollo_core": __version__})
    return 0


def _cmd_config(args) -> int:
    cfg = get_config(reload=True)
    if args.config_action in (None, "show"):
        _print(cfg.to_dict())
    return 0


def _cmd_scope(args) -> int:
    engagement = get_engagement(reload=True)
    engine = engagement.scope if engagement.scope.configured else ScopeEngine.from_file(
        get_config().scope_path
    )
    if args.scope_action == "check":
        d = engine.check_target(args.target)
        _print({"target": args.target, "allowed": d.allowed, "reason": d.reason,
                "matched": d.matched, "rule_type": d.rule_type})
        return 0 if d.allowed else 2
    if args.scope_action == "targets":
        targets = extract_targets(args.command)
        results = [
            {"target": t, **{k: getattr(engine.check_target(t), k)
                             for k in ("allowed", "reason")}}
            for t in targets
        ]
        _print({"extracted": targets, "results": results})
        return 0
    return 1


def _cmd_engagement(args) -> int:
    if args.engagement_action in (None, "show"):
        _print(get_engagement(reload=True).to_dict())
        return 0
    if args.engagement_action == "init":
        ctx = EngagementContext(
            engagement_id=args.id or "",
            operator=args.operator or "",
            client=args.client or "",
            authorized=bool(args.authorized),
            scope_allow=args.allow or [],
            scope_deny=args.deny or [],
            window_start=args.start,
            window_end=args.end,
            intrusive_allowed=bool(args.intrusive),
            notes=args.notes or "",
        )
        path = ctx.save()
        _print({"saved": path, "engagement": ctx.to_dict()})
        return 0
    return 1


def _cmd_audit(args) -> int:
    log = get_audit_log(reload=True)
    if args.audit_action == "tail":
        for rec in log.tail(args.n):
            print(f"[{rec.get('ts')}] seq={rec.get('seq')} "
                  f"{rec.get('decision','').upper():8} {rec.get('action')} "
                  f"-> {rec.get('target','')} ({rec.get('actor','')})")
        return 0
    if args.audit_action == "verify":
        ok, problems = log.verify()
        _print({"ok": ok, "entries": len(log.read_all()), "problems": problems})
        return 0 if ok else 2
    return 1


def _cmd_selftest(_args) -> int:
    """Exercise the core end to end without touching any network or tool."""
    from .models import Finding, Severity, risk_score, severity_from_cvss

    checks = []
    eng = ScopeEngine(allow=["10.0.0.0/24", "*.lab.example"], deny=["10.0.0.1"])
    checks.append(("scope allow", eng.check_target("10.0.0.9").allowed is True))
    checks.append(("scope deny wins", eng.check_target("10.0.0.1").allowed is False))
    checks.append(("wildcard apex", eng.check_target("lab.example").allowed is True))
    checks.append(("wildcard boundary", eng.check_target("notlab.example").allowed is False))
    checks.append(("cvss->sev", severity_from_cvss(9.5) is Severity.CRITICAL))
    rs = risk_score([Finding("x", severity="critical"), Finding("y", severity="low")])
    checks.append(("risk label", rs["label"] == "critical"))
    log = get_audit_log(reload=True)
    log.append("selftest", target="localhost", decision="allow")
    ok, _ = log.verify()
    checks.append(("audit chain verifies", ok))
    passed = all(v for _, v in checks)
    _print({"selftest": "ok" if passed else "FAILED",
            "checks": [{"name": n, "pass": v} for n, v in checks]})
    return 0 if passed else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="apollo", description="Apollo Ultra core CLI")
    sub = p.add_subparsers(dest="command")

    sub.add_parser("version").set_defaults(func=_cmd_version)
    sub.add_parser("selftest").set_defaults(func=_cmd_selftest)

    cfg = sub.add_parser("config")
    cfg.add_argument("config_action", nargs="?", choices=["show"], default="show")
    cfg.set_defaults(func=_cmd_config)

    sc = sub.add_parser("scope")
    sc_sub = sc.add_subparsers(dest="scope_action", required=True)
    sc_check = sc_sub.add_parser("check")
    sc_check.add_argument("target")
    sc_targets = sc_sub.add_parser("targets")
    sc_targets.add_argument("command")
    sc.set_defaults(func=_cmd_scope)

    en = sub.add_parser("engagement")
    en_sub = en.add_subparsers(dest="engagement_action")
    en_sub.add_parser("show")
    en_init = en_sub.add_parser("init")
    en_init.add_argument("--id")
    en_init.add_argument("--operator")
    en_init.add_argument("--client")
    en_init.add_argument("--allow", action="append")
    en_init.add_argument("--deny", action="append")
    en_init.add_argument("--start")
    en_init.add_argument("--end")
    en_init.add_argument("--authorized", action="store_true")
    en_init.add_argument("--intrusive", action="store_true")
    en_init.add_argument("--notes")
    en.set_defaults(func=_cmd_engagement)

    au = sub.add_parser("audit")
    au_sub = au.add_subparsers(dest="audit_action", required=True)
    au_tail = au_sub.add_parser("tail")
    au_tail.add_argument("n", nargs="?", type=int, default=20)
    au_sub.add_parser("verify")
    au.set_defaults(func=_cmd_audit)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
