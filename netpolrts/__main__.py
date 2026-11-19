"""CLI.

  python -m netpolrts select OLD.yaml NEW.yaml [--no-risk] [--json]
  python -m netpolrts run    OLD.yaml NEW.yaml        # live: kubectl exec probes after you applied NEW
"""
from __future__ import annotations

import argparse
import json
import sys

from .loader import load_file
from .runner import KubectlProber, pick_canaries, run_selection
from .selection import select


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="netpolrts")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("select", "run"):
        sp = sub.add_parser(name)
        sp.add_argument("old")
        sp.add_argument("new")
        sp.add_argument("--no-risk", action="store_true", help="disable C2 risk expansion")
        sp.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    old, new = load_file(a.old), load_file(a.new)
    sel = select(old, new, risk_expansion=not a.no_risk)
    if a.cmd == "select":
        if a.json:
            print(json.dumps([{"src": "/".join(p.src), "dst": "/".join(p.dst), "port": p.port, "proto": p.proto,
                               "expected": "allow" if p.expected else "deny", "reason": p.reason} for p in sel.probes], indent=2))
        else:
            n = len(new.pods)
            print(f"changed policies : {[('/'.join(k)) for k in sel.changed_policies]}")
            print(f"pods / classes   : {n} / {sel.n_classes}")
            print(f"flipped classes  : {sel.n_flips}")
            print(f"risk tags        : {sorted(sel.tags) or '-'}")
            print(f"probes selected  : {len(sel.probes)} (exhaustive would be {n * (n - 1) * sel.space.n_ports})")
            for p in sel.probes:
                print(f"  {'/'.join(p.src)} -> {'/'.join(p.dst)} {p.proto}/{p.port}: expect {'ALLOW' if p.expected else 'DENY'} [{p.reason}]")
        return 0
    res = run_selection(sel, KubectlProber(new), pick_canaries(sel, new))
    print(f"converged={res['converged']} waited={res['waited_s']:.1f}s probes={res['probes']} failures={len(res['failures'])}")
    for p, actual in res["failures"]:
        print(f"  MISMATCH {'/'.join(p.src)} -> {'/'.join(p.dst)} {p.proto}/{p.port}: expected {'ALLOW' if p.expected else 'DENY'}, got {'ALLOW' if actual else 'DENY'} [{p.reason}]")
    return 1 if res["failures"] else 0


if __name__ == "__main__":
    sys.exit(main())
