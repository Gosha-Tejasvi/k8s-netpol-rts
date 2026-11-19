"""Probe execution: simulated (for tests/experiments) and live (kubectl exec).

The live prober is UNTESTED against a real cluster in the authoring environment: it is a
thin wrapper that you should validate on your Kind cluster (see README, "Live runs").
"""
from __future__ import annotations

import shlex
import subprocess
import time
from typing import Callable, Dict, List, Sequence, Tuple

from .model import Cluster
from .selection import Probe, Selection
from .semantics import Evaluator

# agnhost is the image used by the upstream Kubernetes network-policy e2e tests.
DEFAULT_CMD = "/agnhost connect {ip}:{port} --timeout=1s --protocol={proto_lower}"


class SimulatedProber:
    def __init__(self, cluster: Cluster, bugs=()):
        self.ev = Evaluator(cluster, bugs)
        self.pods = {p.key: p for p in cluster.pods}
        self.calls = 0

    def probe(self, p: Probe) -> bool:
        self.calls += 1
        return self.ev.allowed(self.pods[p.src], self.pods[p.dst], p.port, p.proto)


class KubectlProber:
    def __init__(self, cluster: Cluster, template: str = DEFAULT_CMD, kubectl: str = "kubectl", timeout: float = 10.0):
        self.pods = {p.key: p for p in cluster.pods}
        self.template, self.kubectl, self.timeout = template, kubectl, timeout

    def probe(self, p: Probe) -> bool:
        src, dst = self.pods[p.src], self.pods[p.dst]
        inner = self.template.format(ip=dst.ip, port=p.port, proto=p.proto, proto_lower=p.proto.lower())
        cmd = [self.kubectl, "exec", "-n", src.namespace, src.name, "--"] + shlex.split(inner)
        try:
            return subprocess.run(cmd, capture_output=True, timeout=self.timeout).returncode == 0
        except subprocess.TimeoutExpired:
            return False


def pick_canaries(sel: Selection, cluster: Cluster, k: int = 3) -> List[Probe]:
    """Choose up to k flip probes whose destination pods sit on different nodes
    (falling back to different destination classes if node names are unknown)."""
    nodes = {p.key: p.node for p in cluster.pods}
    chosen, seen = [], set()
    for pr in sel.flip_probes:
        tag = nodes.get(pr.dst) or sel.space.class_of[pr.dst]
        if tag not in seen:
            seen.add(tag)
            chosen.append(pr)
        if len(chosen) == k:
            break
    return chosen


def wait_for_flip(prober, canaries: Sequence[Probe], poll: float = 0.5, timeout: float = 60.0,
                  sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic) -> Tuple[bool, float]:
    """Poll until every canary returns its expected verdict. Returns (converged, seconds waited)."""
    t0 = clock()
    while True:
        if all(prober.probe(c) == c.expected for c in canaries):
            return True, clock() - t0
        if clock() - t0 >= timeout:
            return False, clock() - t0
        sleep(poll)


def run_selection(sel: Selection, prober, canaries: Sequence[Probe] = (), min_wait: float = 5.0,
                  poll: float = 0.5, timeout: float = 60.0, sleep=time.sleep, clock=time.monotonic) -> Dict:
    """Wait for convergence (canary polling, or a fixed fallback when nothing flips), then run all probes."""
    if canaries:
        converged, waited = wait_for_flip(prober, canaries, poll, timeout, sleep, clock)
    else:
        sleep(min_wait)
        converged, waited = True, min_wait
    failures = []
    for p in sel.probes:
        actual = prober.probe(p)
        if actual != p.expected:
            failures.append((p, actual))
    return {"converged": converged, "waited_s": waited, "probes": len(sel.probes), "failures": failures}
