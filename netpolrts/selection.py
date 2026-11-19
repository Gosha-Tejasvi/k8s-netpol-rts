"""C1 (diff-driven safe selection) and C2 (CNI-risk-aware expansion)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .analysis import Flow, Space
from .model import Cluster, Policy, PodKey
from .semantics import Evaluator

RISK_TAGS = ("named_port", "endport", "ipblock", "overlap")


@dataclass(frozen=True)
class Probe:
    src: PodKey
    dst: PodKey
    port: int
    proto: str
    expected: bool  # what the NetworkPolicy spec says should happen AFTER the change
    reason: str  # "flip" or "risk:<tag>"
    flow: Flow = field(compare=False, default=(0, 0, 0, ""))


@dataclass
class Selection:
    probes: List[Probe]
    n_flips: int
    n_classes: int
    tags: Set[str]
    scope_classes: Set[int]
    changed_policies: List[Tuple[str, str]]
    space: Space

    @property
    def flip_probes(self) -> List[Probe]:
        return [p for p in self.probes if p.reason == "flip"]


# -- change analysis ----------------------------------------------------------
def changed_policies(old: Cluster, new: Cluster):
    om = {p.key: p for p in old.policies}
    nm = {p.key: p for p in new.policies}
    return [(k, om.get(k), nm.get(k)) for k in sorted(set(om) | set(nm)) if om.get(k) != nm.get(k)]


def _selected(pol: Policy, cluster: Cluster) -> Set[PodKey]:
    return {p.key for p in cluster.pods if p.namespace == pol.namespace and pol.pod_selector.matches(p.labels)}


def risk_tags(old: Cluster, new: Cluster, changes) -> Set[str]:
    tags: Set[str] = set()
    for key, o, n in changes:
        for pol in (o, n):
            if pol is None:
                continue
            for rule in pol.ingress + pol.egress:
                for ps in rule.ports or ():
                    if isinstance(ps.port, str):
                        tags.add("named_port")
                    if ps.end_port is not None:
                        tags.add("endport")
                for peer in rule.peers or ():
                    if peer.ip_block is not None:
                        tags.add("ipblock")
    # overlap: a changed policy shares a selected pod and direction with another policy
    for cluster, which in ((old, 0), (new, 1)):
        changed = [(c[0], c[1 + which]) for c in changes if c[1 + which] is not None]
        for key, pol in changed:
            sel = _selected(pol, cluster)
            if not sel:
                continue
            for other in cluster.policies:
                if other.key == key or other.namespace != pol.namespace:
                    continue
                shared = other.policy_types & pol.policy_types
                if not shared:
                    continue
                # a policy with no rules in the shared direction (e.g. default-deny) adds no
                # allows, so it cannot create a union-vs-first/last-wins divergence
                if not (("Ingress" in shared and other.ingress) or ("Egress" in shared and other.egress)):
                    continue
                if sel & _selected(other, cluster):
                    tags.add("overlap")
                    break
    return tags


def _scope_classes(space: Space, changes) -> Set[int]:
    scope: Set[int] = set()
    for key, o, n in changes:
        for pol, cluster in ((o, space.old), (n, space.new)):
            if pol is not None:
                scope.update(space.class_of[k] for k in _selected(pol, cluster))
    # pods whose own (or namespace) labels changed
    for key, cid in space.class_of.items():
        if space.pods_old[key].labels != space.pods_new[key].labels:
            scope.add(cid)
    for ns in set(space.old.namespaces) | set(space.new.namespaces):
        if space.old.ns_labels(ns) != space.new.ns_labels(ns):
            scope.update(cid for k, cid in space.class_of.items() if k[0] == ns)
    return scope


def _risk_ports(space: Space, changes, tags: Set[str]) -> Set[int]:
    if tags & {"overlap", "ipblock"}:
        return set(space.ports)
    ports: Set[int] = set()
    names: Set[str] = set()
    for _, o, n in changes:
        for pol in (o, n):
            if pol is None:
                continue
            for rule in pol.ingress + pol.egress:
                for ps in rule.ports or ():
                    if isinstance(ps.port, int):
                        ports.update({ps.port - 1, ps.port, ps.port + 1})
                        if ps.end_port:
                            ports.update({ps.end_port, ps.end_port + 1})
                    elif isinstance(ps.port, str):
                        names.add(ps.port)
    for c in (space.old, space.new):
        for pod in c.pods:
            ports.update(num for name, num, _ in pod.ports if name in names)
    return ports & set(space.ports)


# -- selection ------------------------------------------------------------------
def select(
    old: Cluster,
    new: Cluster,
    risk_expansion: bool = True,
    space: Optional[Space] = None,
    mo: Optional[Dict[Flow, bool]] = None,
    mn: Optional[Dict[Flow, bool]] = None,
) -> Selection:
    sp = space or Space(old, new)
    mo = mo if mo is not None else sp.table("old")
    mn = mn if mn is not None else sp.table("new")
    changes = changed_policies(old, new)
    probes: List[Probe] = []
    seen: Set[Flow] = set()

    def add(flow: Flow, reason: str):
        if flow in seen:
            return
        seen.add(flow)
        a, b, port, proto = flow
        s, d = sp.rep[(a, b)]
        probes.append(Probe(s, d, port, proto, mn[flow], reason, flow))

    flips = [f for f in mn if mo[f] != mn[f]]
    for f in flips:
        add(f, "flip")
    tags = risk_tags(old, new, changes)
    scope = _scope_classes(sp, changes)
    if risk_expansion and tags:
        rports = _risk_ports(sp, changes, tags)
        for f in mn:
            if f[2] in rports and (f[0] in scope or f[1] in scope):
                add(f, "risk:" + ",".join(sorted(tags)))
    return Selection(probes, len(flips), len(sp.members), tags, scope, [c[0] for c in changes], sp)


def verify_safety(old: Cluster, new: Cluster, probes: List[Probe], space: Optional[Space] = None):
    """Pod-level check of the safety property: every pod-level flow whose verdict
    changes must belong to a flow class that has at least one probe. Returns the
    list of uncovered flipped flows (empty list == safe). Quadratic; use on small clusters."""
    sp = space or Space(old, new)
    covered = {p.flow for p in probes}
    eo, en = Evaluator(old), Evaluator(new)
    uncovered = []
    keys = sorted(sp.pods_new)
    for s in keys:
        for d in keys:
            if s == d:
                continue
            for proto in sp.protos:
                for port in sp.ports:
                    a = eo.allowed(sp.pods_old[s], sp.pods_old[d], port, proto)
                    b = en.allowed(sp.pods_new[s], sp.pods_new[d], port, proto)
                    if a != b and sp.flow_of(s, d, port, proto) not in covered:
                        uncovered.append((s, d, port, proto))
    return uncovered
