"""Mutation operators: realistic NetworkPolicy edits used to seed changes.

Each operator takes (cluster, rng) and returns a NEW cluster, or None if it is not
applicable. Operators are named after the mistakes they model.
"""
from __future__ import annotations

import random
from dataclasses import replace
from typing import Callable, Dict, Optional

from .model import Cluster, IPBlock, Peer, Policy, PortSpec, Rule, Selector, labels

PORTS = (80, 8080, 9090, 5432)


def _with_policy(c: Cluster, i: int, pol: Policy) -> Cluster:
    n = c.copy()
    n.policies[i] = pol
    return n


def _pick(c: Cluster, rng, pred):
    idx = [i for i, p in enumerate(c.policies) if pred(p)]
    return rng.choice(idx) if idx else None


def _non_default(p: Policy) -> bool:
    return p.name != "default-deny"


def add_rule(c: Cluster, rng) -> Optional[Cluster]:
    i = _pick(c, rng, lambda p: _non_default(p) and "Ingress" in p.policy_types)
    if i is None:
        return None
    p = c.policies[i]
    rule = Rule((Peer(ns_selector=Selector(labels({"env": rng.choice(["prod", "dev"])}))),),
                (PortSpec("TCP", rng.choice(PORTS)),))
    return _with_policy(c, i, replace(p, ingress=p.ingress + (rule,)))


def remove_rule(c: Cluster, rng) -> Optional[Cluster]:
    i = _pick(c, rng, lambda p: bool(p.ingress or p.egress))
    if i is None:
        return None
    p = c.policies[i]
    if p.ingress and (not p.egress or rng.random() < 0.5):
        k = rng.randrange(len(p.ingress))
        return _with_policy(c, i, replace(p, ingress=p.ingress[:k] + p.ingress[k + 1:]))
    k = rng.randrange(len(p.egress))
    return _with_policy(c, i, replace(p, egress=p.egress[:k] + p.egress[k + 1:]))


def _rule_with_int_port(c, rng):
    cands = [(i, d, k) for i, p in enumerate(c.policies) for d in ("ingress", "egress")
             for k, r in enumerate(getattr(p, d))
             if r.ports and isinstance(r.ports[0].port, int) and r.ports[0].end_port is None]
    return rng.choice(cands) if cands else None


def _edit_port(c, i, d, k, new_ps) -> Cluster:
    p = c.policies[i]
    rules = list(getattr(p, d))
    rules[k] = replace(rules[k], ports=(new_ps,))
    return _with_policy(c, i, replace(p, **{d: tuple(rules)}))


def change_port(c: Cluster, rng) -> Optional[Cluster]:
    x = _rule_with_int_port(c, rng)
    if not x:
        return None
    i, d, k = x
    old = getattr(c.policies[i], d)[k].ports[0]
    new_port = rng.choice([p for p in PORTS if p != old.port])
    return _edit_port(c, i, d, k, PortSpec(old.protocol, new_port))


def port_range(c: Cluster, rng) -> Optional[Cluster]:
    """Widen a single port to a range using endPort."""
    x = _rule_with_int_port(c, rng)
    if not x:
        return None
    i, d, k = x
    old = getattr(c.policies[i], d)[k].ports[0]
    return _edit_port(c, i, d, k, PortSpec(old.protocol, old.port, old.port + rng.randint(1, 100)))


def named_port(c: Cluster, rng) -> Optional[Cluster]:
    """Rewrite a numeric ingress port as the equivalent named port (no spec-level change)."""
    cands = []
    for i, p in enumerate(c.policies):
        sel_pods = [x for x in c.pods if x.namespace == p.namespace and p.pod_selector.matches(x.labels)]
        for k, r in enumerate(p.ingress):
            if not r.ports or not isinstance(r.ports[0].port, int) or r.ports[0].end_port is not None:
                continue
            names = {n for x in sel_pods for n, num, pr in x.ports if num == r.ports[0].port}
            ok = names and all(any(n == name for n, _, _ in x.ports) for x in sel_pods for name in list(names)[:1])
            if ok:
                cands.append((i, k, sorted(names)[0]))
    if not cands:
        return None
    i, k, name = rng.choice(cands)
    return _edit_port(c, i, "ingress", k, PortSpec(c.policies[i].ingress[k].ports[0].protocol, name))


def ipblock_add(c: Cluster, rng) -> Optional[Cluster]:
    i = _pick(c, rng, lambda p: _non_default(p) and "Ingress" in p.policy_types)
    if i is None:
        return None
    p = c.policies[i]
    n = rng.randrange(max(1, len(c.namespaces)))
    exc = (f"10.{n}.0.0/24",) if rng.random() < 0.5 else ()
    rule = Rule((Peer(ip_block=IPBlock(f"10.{n}.0.0/16", exc)),), (PortSpec("TCP", rng.choice(PORTS)),))
    return _with_policy(c, i, replace(p, ingress=p.ingress + (rule,)))


def selector_change(c: Cluster, rng) -> Optional[Cluster]:
    cands = [(i, d, k, j) for i, p in enumerate(c.policies) for d in ("ingress", "egress")
             for k, r in enumerate(getattr(p, d)) for j, pe in enumerate(r.peers or ())
             if pe.pod_selector is not None and pe.pod_selector.match_labels]
    if not cands:
        return None
    i, d, k, j = rng.choice(cands)
    p = c.policies[i]
    rules = list(getattr(p, d))
    peers = list(rules[k].peers)
    ml = dict(peers[j].pod_selector.match_labels)
    ml["tier"] = rng.choice(["frontend", "backend", "db"])
    peers[j] = replace(peers[j], pod_selector=Selector(labels(ml)))
    rules[k] = replace(rules[k], peers=tuple(peers))
    return _with_policy(c, i, replace(p, **{d: tuple(rules)}))


def add_overlap_policy(c: Cluster, rng) -> Optional[Cluster]:
    """Add a second policy selecting pods that another policy already selects."""
    i = _pick(c, rng, lambda p: _non_default(p) and "Ingress" in p.policy_types)
    if i is None:
        return None
    base = c.policies[i]
    name = rng.choice(["aa-extra", "zz-extra"]) + f"-{rng.randint(0, 99)}"
    rule = Rule((Peer(ns_selector=Selector(labels({"env": rng.choice(["prod", "dev"])}))),),
                (PortSpec("TCP", rng.choice(PORTS)),))
    n = c.copy()
    n.policies.append(Policy(base.namespace, name, base.pod_selector, frozenset({"Ingress"}), ingress=(rule,)))
    return n


def remove_policy(c: Cluster, rng) -> Optional[Cluster]:
    if not c.policies:
        return None
    n = c.copy()
    del n.policies[rng.randrange(len(n.policies))]
    return n


def add_egress_type(c: Cluster, rng) -> Optional[Cluster]:
    """Add 'Egress' to policyTypes of an ingress-only policy with no egress rules."""
    i = _pick(c, rng, lambda p: p.policy_types == frozenset({"Ingress"}) and not p.egress and _non_default(p))
    if i is None:
        return None
    p = c.policies[i]
    return _with_policy(c, i, replace(p, policy_types=frozenset({"Ingress", "Egress"})))


def pod_relabel(c: Cluster, rng) -> Optional[Cluster]:
    n = c.copy()
    j = rng.randrange(len(n.pods))
    p = n.pods[j]
    d = dict(p.labels)
    d["tier"] = rng.choice([t for t in ("frontend", "backend", "db") if t != d.get("tier")])
    n.pods[j] = replace(p, labels=labels(d))
    return n


def ns_relabel(c: Cluster, rng) -> Optional[Cluster]:
    n = c.copy()
    ns = rng.choice(sorted(n.namespaces))
    d = dict(n.namespaces[ns])
    d["env"] = "dev" if d.get("env") == "prod" else "prod"
    n.namespaces[ns] = labels(d)
    return n


MUTATIONS: Dict[str, Callable] = {
    "add_rule": add_rule,
    "remove_rule": remove_rule,
    "change_port": change_port,
    "port_range": port_range,
    "named_port": named_port,
    "ipblock_add": ipblock_add,
    "selector_change": selector_change,
    "add_overlap_policy": add_overlap_policy,
    "remove_policy": remove_policy,
    "add_egress_type": add_egress_type,
    "pod_relabel": pod_relabel,
    "ns_relabel": ns_relabel,
}


def mutate(c: Cluster, kind: str, rng: random.Random, tries: int = 20) -> Optional[Cluster]:
    for _ in range(tries):
        n = MUTATIONS[kind](c, rng)
        if n is not None and (n.policies != c.policies or n.pods != c.pods or n.namespaces != c.namespaces):
            return n
    return None
