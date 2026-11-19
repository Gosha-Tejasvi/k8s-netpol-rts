"""Data model for Kubernetes NetworkPolicy analysis.

Everything is an immutable dataclass so that two policy versions can be compared
with plain equality and used as dictionary keys.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from typing import Dict, FrozenSet, List, Optional, Tuple, Union

Labels = FrozenSet[Tuple[str, str]]
PodKey = Tuple[str, str]  # (namespace, name)


def labels(d: Optional[dict] = None) -> Labels:
    return frozenset((d or {}).items())


@lru_cache(maxsize=None)
def _match(sel: "Selector", lab: Labels) -> bool:
    d = dict(lab)
    for k, v in sel.match_labels:
        if d.get(k) != v:
            return False
    for key, op, vals in sel.match_expressions:
        if op == "In":
            if d.get(key) not in vals:
                return False
        elif op == "NotIn":
            if key in d and d[key] in vals:
                return False
        elif op == "Exists":
            if key not in d:
                return False
        elif op == "DoesNotExist":
            if key in d:
                return False
        else:
            raise ValueError(f"unsupported selector operator: {op}")
    return True


@dataclass(frozen=True)
class Selector:
    """Label selector. The empty selector matches everything."""

    match_labels: Labels = frozenset()
    match_expressions: Tuple[Tuple[str, str, Tuple[str, ...]], ...] = ()

    def matches(self, lab: Labels) -> bool:
        return _match(self, lab)


@dataclass(frozen=True)
class IPBlock:
    cidr: str
    except_: Tuple[str, ...] = ()


@dataclass(frozen=True)
class Peer:
    """One entry of a rule's from/to list.

    pod_selector / ns_selector of None mean "field absent", which is different
    from an empty selector (which matches everything).
    """

    pod_selector: Optional[Selector] = None
    ns_selector: Optional[Selector] = None
    ip_block: Optional[IPBlock] = None


@dataclass(frozen=True)
class PortSpec:
    protocol: str = "TCP"
    port: Optional[Union[int, str]] = None  # int, named port (str) or None = all
    end_port: Optional[int] = None


@dataclass(frozen=True)
class Rule:
    peers: Optional[Tuple[Peer, ...]] = None  # None or empty = all peers
    ports: Optional[Tuple[PortSpec, ...]] = None  # None or empty = all ports


@dataclass(frozen=True)
class Policy:
    namespace: str
    name: str
    pod_selector: Selector
    policy_types: FrozenSet[str]
    ingress: Tuple[Rule, ...] = ()
    egress: Tuple[Rule, ...] = ()

    @property
    def key(self) -> Tuple[str, str]:
        return (self.namespace, self.name)


@dataclass(frozen=True)
class Pod:
    namespace: str
    name: str
    labels: Labels
    ip: str
    ports: Tuple[Tuple[str, int, str], ...] = ()  # (port name, number, protocol)
    node: str = ""  # optional; used only to spread canary probes across nodes

    @property
    def key(self) -> PodKey:
        return (self.namespace, self.name)


@dataclass
class Cluster:
    namespaces: Dict[str, Labels] = field(default_factory=dict)
    pods: List[Pod] = field(default_factory=list)
    policies: List[Policy] = field(default_factory=list)

    def ns_labels(self, ns: str) -> Labels:
        base = dict(self.namespaces.get(ns, frozenset()))
        base.setdefault("kubernetes.io/metadata.name", ns)
        return frozenset(base.items())

    def copy(self) -> "Cluster":
        return Cluster(dict(self.namespaces), list(self.pods), list(self.policies))

    def pod(self, key: PodKey) -> Pod:
        for p in self.pods:
            if p.key == key:
                return p
        raise KeyError(key)
