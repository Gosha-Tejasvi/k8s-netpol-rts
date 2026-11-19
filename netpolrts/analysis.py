"""Flow space, pod equivalence classes and connectivity tables.

A *flow* is (src_class, dst_class, port, proto). Two pods are in the same class when
no selector, ipBlock or named-port lookup in EITHER policy version can tell them
apart, so every member of a class behaves identically before and after the change.
One representative pod pair therefore stands for the whole class pair.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from .model import Cluster, PodKey
from .semantics import Evaluator, ip_in

Flow = Tuple[int, int, int, str]


def _selectors(pol):
    yield "pod", pol.pod_selector
    for rule in pol.ingress + pol.egress:
        for peer in rule.peers or ():
            if peer.pod_selector is not None:
                yield "pod", peer.pod_selector
            if peer.ns_selector is not None:
                yield "ns", peer.ns_selector
            if peer.ip_block is not None:
                yield "ip", peer.ip_block


class Space:
    def __init__(self, old: Cluster, new: Cluster, default_port: int = 65000):
        self.old, self.new = old, new
        self.pods_old = {p.key: p for p in old.pods}
        self.pods_new = {p.key: p for p in new.pods}
        if set(self.pods_old) != set(self.pods_new):
            raise ValueError("pod set must be identical in both versions (pod add/remove not supported)")
        pod_keys, ns_keys, cidrs = set(), set(), set()
        for c in (old, new):
            for pol in c.policies:
                for kind, s in _selectors(pol):
                    if kind == "ip":
                        cidrs.add(s.cidr)
                        cidrs.update(s.except_)
                    else:
                        keys = {k for k, _ in s.match_labels} | {e[0] for e in s.match_expressions}
                        (pod_keys if kind == "pod" else ns_keys).update(keys)
        self.pod_keys, self.ns_keys, self.cidrs = sorted(pod_keys), sorted(ns_keys), sorted(cidrs)
        self._build_classes()
        self._build_ports(default_port)
        self.rep: Dict[Tuple[int, int], Tuple[PodKey, PodKey]] = {}
        for a, ma in self.members.items():
            for b, mb in self.members.items():
                if a != b:
                    self.rep[(a, b)] = (ma[0], mb[0])
                elif len(ma) > 1:
                    self.rep[(a, b)] = (ma[0], ma[1])
        self.weight = {k: len(self.members[k[0]]) * len(self.members[k[1]]) for k in self.rep}
        for a, ma in self.members.items():
            if (a, a) in self.weight:
                self.weight[(a, a)] = len(ma) * (len(ma) - 1)

    # -- classes ---------------------------------------------------------
    def _sig(self, cluster: Cluster, pod):
        pl, nl = dict(pod.labels), dict(cluster.ns_labels(pod.namespace))
        return (
            pod.namespace,
            tuple(pl.get(k) for k in self.pod_keys),
            tuple(nl.get(k) for k in self.ns_keys),
            tuple(ip_in(pod.ip, c) for c in self.cidrs),
            pod.ports,
        )

    def _build_classes(self):
        ids: Dict[tuple, int] = {}
        self.class_of: Dict[PodKey, int] = {}
        self.members: Dict[int, List[PodKey]] = {}
        for key in sorted(self.pods_new):
            sig = (self._sig(self.old, self.pods_old[key]), self._sig(self.new, self.pods_new[key]))
            cid = ids.setdefault(sig, len(ids))
            self.class_of[key] = cid
            self.members.setdefault(cid, []).append(key)

    def _build_ports(self, default_port: int):
        ports, protos = {default_port}, {"TCP"}
        for c in (self.old, self.new):
            for pod in c.pods:
                for _, num, pr in pod.ports:
                    ports.add(num)
                    protos.add(pr)
            for pol in c.policies:
                for rule in pol.ingress + pol.egress:
                    for ps in rule.ports or ():
                        protos.add(ps.protocol)
                        if isinstance(ps.port, int):
                            ports.update({ps.port - 1, ps.port, ps.port + 1})
                            if ps.end_port:
                                ports.update({ps.end_port, ps.end_port + 1})
        self.ports = sorted(p for p in ports if 1 <= p <= 65535)
        self.protos = sorted(protos)

    # -- tables ----------------------------------------------------------
    def table(self, which: str, bugs=()) -> Dict[Flow, bool]:
        cluster = self.old if which == "old" else self.new
        pods = self.pods_old if which == "old" else self.pods_new
        ev = Evaluator(cluster, bugs)
        t: Dict[Flow, bool] = {}
        for (a, b), (s, d) in self.rep.items():
            sp, dp = pods[s], pods[d]
            for proto in self.protos:
                for port in self.ports:
                    t[(a, b, port, proto)] = ev.allowed(sp, dp, port, proto)
        return t

    def flow_of(self, src: PodKey, dst: PodKey, port: int, proto: str) -> Flow:
        return (self.class_of[src], self.class_of[dst], port, proto)

    @property
    def n_pods(self) -> int:
        return len(self.pods_new)

    @property
    def n_ports(self) -> int:
        return len(self.ports) * len(self.protos)
