"""Reference semantics of Kubernetes NetworkPolicy, plus injectable CNI bugs.

`Evaluator(cluster)` is the model (what the spec says should happen).
`Evaluator(cluster, bugs=...)` is a *simulated* CNI that deviates from the spec in
specific, named ways. The bug profiles are illustrative stress tests inspired by
the divergences reported in the literature; they are not measurements of any
real CNI.
"""
from __future__ import annotations

import ipaddress
from functools import lru_cache
from typing import Iterable

from .model import Cluster, Peer, Pod, PortSpec, Rule, Policy

BUGS = ("named_port", "endport", "ipblock_pod", "overlap_last_wins")


@lru_cache(maxsize=None)
def _net(cidr: str):
    return ipaddress.ip_network(cidr, strict=False)


@lru_cache(maxsize=None)
def _addr(ip: str):
    return ipaddress.ip_address(ip)


def ip_in(ip: str, cidr: str) -> bool:
    a, n = _addr(ip), _net(cidr)
    return a.version == n.version and a in n


class Evaluator:
    def __init__(self, cluster: Cluster, bugs: Iterable[str] = ()):
        self.cluster = cluster
        self.bugs = frozenset(bugs)
        unknown = self.bugs - set(BUGS)
        if unknown:
            raise ValueError(f"unknown bug(s): {sorted(unknown)}")
        self._ns_labels = {}
        self._sel = {}
        for pod in cluster.pods:
            self._ns_labels.setdefault(pod.namespace, cluster.ns_labels(pod.namespace))
            for direction in ("Ingress", "Egress"):
                sel = [
                    p
                    for p in cluster.policies
                    if direction in p.policy_types
                    and p.namespace == pod.namespace
                    and p.pod_selector.matches(pod.labels)
                ]
                if "overlap_last_wins" in self.bugs and len(sel) > 1:
                    sel = [sorted(sel, key=lambda p: p.name)[-1]]
                self._sel[(pod.key, direction)] = tuple(sel)

    def selecting(self, pod: Pod, direction: str):
        return self._sel[(pod.key, direction)]

    def allowed(self, src: Pod, dst: Pod, port: int, proto: str = "TCP") -> bool:
        """Is a connection src -> dst:port/proto allowed? Needs src egress AND dst ingress."""
        return self._direction_ok(dst, src, dst, port, proto, "Ingress") and self._direction_ok(
            src, dst, dst, port, proto, "Egress"
        )

    def _direction_ok(self, subject, other, dst, port, proto, direction) -> bool:
        policies = self._sel[(subject.key, direction)]
        if not policies:
            return True  # pod not isolated in this direction
        for pol in policies:
            rules = pol.ingress if direction == "Ingress" else pol.egress
            for rule in rules:
                if self._rule_ok(pol, rule, other, dst, port, proto):
                    return True
        return False

    def _rule_ok(self, pol: Policy, rule: Rule, other: Pod, dst: Pod, port, proto) -> bool:
        if rule.ports:
            if not any(self._port_ok(ps, dst, port, proto) for ps in rule.ports):
                return False
        if rule.peers:
            return any(self._peer_ok(pol.namespace, peer, other) for peer in rule.peers)
        return True

    def _peer_ok(self, policy_ns: str, peer: Peer, other: Pod) -> bool:
        if peer.ip_block is not None:
            if "ipblock_pod" in self.bugs:
                return False  # simulated CNI ignores ipBlock for pod IPs
            blk = peer.ip_block
            if not ip_in(other.ip, blk.cidr):
                return False
            return not any(ip_in(other.ip, e) for e in blk.except_)
        if peer.ns_selector is not None:
            if not peer.ns_selector.matches(self._ns_labels[other.namespace]):
                return False
        elif other.namespace != policy_ns:
            return False
        if peer.pod_selector is not None and not peer.pod_selector.matches(other.labels):
            return False
        return True

    def _port_ok(self, ps: PortSpec, dst: Pod, port: int, proto: str) -> bool:
        if ps.protocol != proto:
            return False
        if ps.port is None:
            return True
        if isinstance(ps.port, str):
            if "named_port" in self.bugs:
                return False  # simulated CNI does not support named ports
            return any(n == ps.port and num == port and pr == proto for n, num, pr in dst.ports)
        if ps.end_port is not None and "endport" not in self.bugs:
            return ps.port <= port <= ps.end_port
        return port == ps.port
