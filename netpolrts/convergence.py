"""C3: convergence-aware execution.

Problem: after `kubectl apply` of a NetworkPolicy the CNI programs rules asynchronously
on every node. Test suites typically `sleep` a fixed time. Too short -> probes read stale
dataplane state (flaky); too long -> wasted wall-clock.

Idea: poll *canary* flows whose verdict the change is known to flip; the change has
reached a node when its canary flips. Use one canary per node (or per distinct
destination node) so that a single fast node does not trigger a premature start.

`simulate` compares strategies under a SYNTHETIC delay model. The delay parameters are
placeholders: replace them with delays measured on your CNI before drawing conclusions.
"""
from __future__ import annotations

import math
import random
from typing import Callable, Dict, List, Sequence, Tuple


def sample_delay(rng: random.Random, median: float = 1.5, sigma: float = 0.8,
                 straggler_p: float = 0.05, straggler_extra=(5.0, 20.0)) -> float:
    d = rng.lognormvariate(math.log(median), sigma)
    if rng.random() < straggler_p:
        d += rng.uniform(*straggler_extra)
    return d


def simulate(trials: int = 5000, nodes: int = 3, fixed_sleeps: Sequence[float] = (1, 2, 5, 10, 30),
             poll: float = 0.25, seed: int = 0, **delay_kw) -> List[Dict]:
    rng = random.Random(seed)
    stats: Dict[str, List[Tuple[float, bool]]] = {}

    def rec(name, wait, premature):
        stats.setdefault(name, []).append((wait, premature))

    for _ in range(trials):
        delays = [sample_delay(rng, **delay_kw) for _ in range(nodes)]
        dmax = max(delays)
        for T in fixed_sleeps:
            rec(f"fixed sleep {T:g}s", T, dmax > T)
        # one canary on a random node: starts once THAT node converged
        d1 = rng.choice(delays)
        w1 = math.ceil(d1 / poll) * poll
        rec("canary x1 (one node)", w1, dmax > w1)
        # one canary per node: starts once ALL nodes converged
        wk = math.ceil(dmax / poll) * poll
        rec(f"canary x{nodes} (all nodes)", wk, dmax > wk)
    rows = []
    for name, v in stats.items():
        waits = sorted(w for w, _ in v)
        rows.append({
            "strategy": name,
            "mean_wait_s": sum(waits) / len(waits),
            "p95_wait_s": waits[int(0.95 * (len(waits) - 1))],
            "premature_pct": 100.0 * sum(1 for _, p in v if p) / len(v),
        })
    return rows
