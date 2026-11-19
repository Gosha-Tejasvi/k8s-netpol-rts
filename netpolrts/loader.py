"""Load Namespace / Pod / NetworkPolicy objects from YAML into the model.

Accepts multi-document YAML and `kind: List` (e.g. `kubectl get ns,pods,netpol -A -o yaml`).
Limitations: pods must be listed explicitly (Deployments are not expanded); a pod without
status.podIP gets a synthetic 10.244.x.y address.
"""
from __future__ import annotations

from typing import Iterable, Optional

import yaml

from .model import Cluster, IPBlock, Peer, Pod, Policy, PortSpec, Rule, Selector, labels


def _sel(d: Optional[dict]) -> Optional[Selector]:
    if d is None:
        return None
    me = tuple((e["key"], e["operator"], tuple(e.get("values") or ())) for e in d.get("matchExpressions") or ())
    return Selector(labels(d.get("matchLabels")), me)


def _peer(d: dict) -> Peer:
    ip = None
    if "ipBlock" in d:
        ip = IPBlock(d["ipBlock"]["cidr"], tuple(d["ipBlock"].get("except") or ()))
    return Peer(_sel(d.get("podSelector")), _sel(d.get("namespaceSelector")), ip)


def _rule(r: dict, peer_key: str) -> Rule:
    peers = tuple(_peer(p) for p in r[peer_key]) if r.get(peer_key) else None
    ports = (tuple(PortSpec(p.get("protocol", "TCP"), p.get("port"), p.get("endPort")) for p in r["ports"])
             if r.get("ports") else None)
    return Rule(peers, ports)


def _policy(doc: dict) -> Policy:
    md, spec = doc["metadata"], doc["spec"]
    ing = tuple(_rule(r, "from") for r in spec.get("ingress") or ())
    eg = tuple(_rule(r, "to") for r in spec.get("egress") or ())
    types = frozenset(spec.get("policyTypes") or (["Ingress"] + (["Egress"] if eg else [])))
    return Policy(md.get("namespace", "default"), md["name"], _sel(spec.get("podSelector")) or Selector(), types, ing, eg)


def _pod(doc: dict, n: int) -> Pod:
    md, spec = doc["metadata"], doc.get("spec", {})
    ports = tuple((p.get("name", ""), p["containerPort"], p.get("protocol", "TCP"))
                  for c in spec.get("containers", []) for p in c.get("ports", []))
    ip = (doc.get("status") or {}).get("podIP") or f"10.244.{n // 250}.{n % 250 + 1}"
    return Pod(md.get("namespace", "default"), md["name"], labels(md.get("labels")), ip, ports, spec.get("nodeName", ""))


def load_docs(docs: Iterable[dict]) -> Cluster:
    c = Cluster()
    flat = []
    for d in docs:
        if not d:
            continue
        flat.extend(d.get("items", []) if d.get("kind") == "List" else [d])
    for d in flat:
        kind = d.get("kind")
        if kind == "Namespace":
            c.namespaces[d["metadata"]["name"]] = labels(d["metadata"].get("labels"))
        elif kind == "Pod":
            c.pods.append(_pod(d, len(c.pods)))
        elif kind == "NetworkPolicy":
            c.policies.append(_policy(d))
    for p in c.pods:
        c.namespaces.setdefault(p.namespace, frozenset())
    return c


def load_file(path: str) -> Cluster:
    with open(path) as f:
        return load_docs(yaml.safe_load_all(f))
