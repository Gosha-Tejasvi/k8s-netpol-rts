"""Synthetic cluster generator (multi-namespace, three-tier apps) for experiments."""
from __future__ import annotations

import random

from .model import Cluster, IPBlock, Peer, Pod, Policy, PortSpec, Rule, Selector, labels

TIERS = ("frontend", "backend", "db")
TIER_PORTS = {
    "frontend": (("http", 80, "TCP"),),
    "backend": (("http", 8080, "TCP"), ("metrics", 9090, "TCP")),
    "db": (("pg", 5432, "TCP"),),
}


def sel(**kw) -> Selector:
    return Selector(match_labels=labels(kw))


def make_cluster(n_ns: int = 3, apps: int = 2, replicas: int = 3, named_frac: float = 0.3, seed: int = 0) -> Cluster:
    rng = random.Random(seed)
    c = Cluster()
    for i in range(n_ns):
        ns = f"ns{i}"
        c.namespaces[ns] = labels({"env": "prod" if i % 2 == 0 else "dev", "team": f"t{i % 2}"})
        for a in range(apps):
            for t, tier in enumerate(TIERS):
                for r in range(replicas):
                    c.pods.append(
                        Pod(ns, f"a{a}-{tier}-{r}", labels({"app": f"a{a}", "tier": tier}),
                            f"10.{i}.{a * 3 + t}.{r + 1}", TIER_PORTS[tier])
                    )
        c.policies.append(Policy(ns, "default-deny", Selector(), frozenset({"Ingress"})))
        for a in range(apps):
            app = f"a{a}"
            fe, be, db = (sel(app=app, tier=t) for t in TIERS)
            c.policies.append(Policy(ns, f"{app}-fe-in", fe, frozenset({"Ingress"}),
                ingress=(Rule((Peer(ns_selector=Selector()),), (PortSpec("TCP", 80),)),)))
            c.policies.append(Policy(ns, f"{app}-fe-out", fe, frozenset({"Egress"}),
                egress=(Rule((Peer(pod_selector=be),), (PortSpec("TCP", 8080),)),)))
            be_port = "http" if rng.random() < named_frac else 8080
            c.policies.append(Policy(ns, f"{app}-be-in", be, frozenset({"Ingress"}),
                ingress=(Rule((Peer(pod_selector=fe),), (PortSpec("TCP", be_port),)),)))
            c.policies.append(Policy(ns, f"{app}-be-out", be, frozenset({"Egress"}),
                egress=(Rule((Peer(pod_selector=db),), (PortSpec("TCP", 5432),)),)))
            c.policies.append(Policy(ns, f"{app}-db-in", db, frozenset({"Ingress"}),
                ingress=(Rule((Peer(pod_selector=be),), (PortSpec("TCP", 5432),)),)))
    return c
