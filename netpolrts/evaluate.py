"""Evaluation harness: one trial = one change, one (simulated) CNI profile.

Ground truth for "fault": a flow class whose simulated-CNI verdict disagrees with the
spec after the change, while it agreed before the change (i.e. the change *introduced*
the divergence). A method detects the fault if at least one of its probes lies in such
a flow class. All methods share the same port abstraction (ports mentioned in policies,
their neighbours, container ports and one default port), which is conservative for the
exhaustive baseline.
"""
from __future__ import annotations

import random
from typing import Dict, Optional

from .analysis import Space
from .model import Cluster
from .selection import select

METHODS = ("static_diff", "c1_flips", "c1_c2", "random_same_budget", "policy_scope", "exhaustive")


def run_trial(old: Cluster, new: Cluster, bug: Optional[str], rng: random.Random,
              t_deny: float = 1.0, t_allow: float = 0.05) -> Dict:
    sp = Space(old, new)
    mo, mn = sp.table("old"), sp.table("new")
    sel = select(old, new, space=sp, mo=mo, mn=mn)
    bugs = (bug,) if bug else ()
    co, cn = sp.table("old", bugs), sp.table("new", bugs)
    fault = {f for f, v in mn.items() if cn[f] != v and co[f] == mo[f]}

    n, P = sp.n_pods, sp.n_ports
    exh = n * (n - 1) * P
    scope_pods = sum(len(sp.members[c]) for c in sel.scope_classes)
    scope = (n * (n - 1) - (n - scope_pods) * max(n - scope_pods - 1, 0)) * P

    flips = [p.flow for p in sel.probes if p.reason == "flip"]
    allf = [p.flow for p in sel.probes]
    budget = len(allf)
    keys = sorted(sp.pods_new)
    rand = []
    for _ in range(budget):
        s, d = rng.sample(keys, 2)
        rand.append(sp.flow_of(s, d, rng.choice(sp.ports), rng.choice(sp.protos)))

    def hit(flows):
        return any(f in fault for f in flows)

    detect = {
        "static_diff": False,  # no live probes, cannot see CNI behaviour
        "c1_flips": hit(flips),
        "c1_c2": hit(allf),
        "random_same_budget": hit(rand),
        "policy_scope": any(f in fault and (f[0] in sel.scope_classes or f[1] in sel.scope_classes) for f in fault),
        "exhaustive": bool(fault),
    }
    # estimated wall time (ASSUMPTION-DRIVEN: denied probe waits t_deny, allowed returns in t_allow)
    denied_w = sum(sp.weight[(f[0], f[1])] for f, v in mn.items() if not v)
    allowed_w = sum(sp.weight[(f[0], f[1])] for f, v in mn.items() if v)
    t_exh = denied_w * t_deny + allowed_w * t_allow
    t_sel = sum((t_allow if p.expected else t_deny) for p in sel.probes)
    return {
        "n_pods": n, "classes": len(sp.members), "ports": P,
        "changed": len(sel.changed_policies), "tags": ",".join(sorted(sel.tags)),
        "flips": sel.n_flips, "fault_classes": len(fault), "manifested": bool(fault),
        "probes_c1": len(flips), "probes_c1c2": budget,
        "probes_scope": scope, "probes_exhaustive": exh,
        "time_c1c2_s": t_sel, "time_exhaustive_s": t_exh,
        **{f"detect_{m}": detect[m] for m in METHODS},
    }
