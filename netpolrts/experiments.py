"""Run all experiments:  python -m netpolrts.experiments [--seeds 15] [--out results]

E1  detection of seeded CNI faults, per bug profile and method
E2  probe reduction and estimated time per mutation kind
E3  scaling with cluster size (probes stay ~constant, exhaustive grows ~N^2)
E4  convergence strategies (synthetic delay model)
Also writes results/trials.csv with every trial.
"""
from __future__ import annotations

import argparse
import csv
import os
import random
import statistics as st
import time
from collections import defaultdict

from .convergence import simulate
from .evaluate import METHODS, run_trial
from .generator import make_cluster
from .mutations import MUTATIONS, mutate
from .semantics import BUGS
from .analysis import Space
from .selection import select, verify_safety


def md_table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def e1_e2(seeds: int, out: str):
    rows = []
    for kind in sorted(MUTATIONS):
        for s in range(seeds):
            rng = random.Random(f"{kind}-{s}")
            old = make_cluster(n_ns=3, apps=2, replicas=3, seed=s)
            new = mutate(old, kind, rng)
            if new is None:
                continue
            for bug in (None,) + BUGS:
                r = run_trial(old, new, bug, random.Random(f"r-{kind}-{s}-{bug}"))
                rows.append({"kind": kind, "seed": s, "bug": bug or "none", **r})
    with open(os.path.join(out, "trials.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    txt = []
    # E1
    t1 = []
    for bug in BUGS:
        sub = [r for r in rows if r["bug"] == bug and r["manifested"]]
        n = len(sub)
        cells = [f"{sum(r['detect_' + m] for r in sub)}/{n}" for m in METHODS]
        t1.append([bug, n] + cells)
    txt.append("### E1. Seeded-fault detection (trials where the CNI fault actually manifested)\n")
    txt.append(md_table(["CNI bug profile", "faulty trials"] + list(METHODS), t1))
    fa = [r for r in rows if r["bug"] == "none"]
    txt.append(f"\nSanity: with a spec-compliant CNI, faults manifested in {sum(r['manifested'] for r in fa)}/{len(fa)} trials (must be 0).\n")

    # E2
    base = [r for r in rows if r["bug"] == "none"]
    t2 = []
    for kind in sorted(MUTATIONS):
        sub = [r for r in base if r["kind"] == kind]
        if not sub:
            continue
        t2.append([kind, len(sub), f"{st.mean(r['flips'] for r in sub):.1f}",
                   f"{st.mean(r['probes_c1c2'] for r in sub):.0f}",
                   f"{st.mean(r['probes_scope'] for r in sub):.0f}",
                   f"{st.mean(r['probes_exhaustive'] for r in sub):.0f}",
                   f"{100 * (1 - st.mean(r['probes_c1c2'] for r in sub) / st.mean(r['probes_exhaustive'] for r in sub)):.1f}%",
                   f"{st.mean(r['time_c1c2_s'] for r in sub):.1f}",
                   f"{st.mean(r['time_exhaustive_s'] for r in sub):.0f}"])
    allr = base
    t2.append(["ALL", len(allr), f"{st.mean(r['flips'] for r in allr):.1f}",
               f"{st.mean(r['probes_c1c2'] for r in allr):.0f}", f"{st.mean(r['probes_scope'] for r in allr):.0f}",
               f"{st.mean(r['probes_exhaustive'] for r in allr):.0f}",
               f"{100 * (1 - st.mean(r['probes_c1c2'] for r in allr) / st.mean(r['probes_exhaustive'] for r in allr)):.1f}%",
               f"{st.mean(r['time_c1c2_s'] for r in allr):.1f}", f"{st.mean(r['time_exhaustive_s'] for r in allr):.0f}"])
    txt.append("\n### E2. Probes and estimated time per change (54-pod synthetic cluster, mean over trials)\n")
    txt.append(md_table(["mutation", "n", "flipped classes", "C1+C2 probes", "policy-scope probes",
                         "exhaustive probes", "reduction vs exhaustive", "est. time C1+C2 (s)", "est. time exhaustive (s)"], t2))
    txt.append("\nEstimated time assumes denied probes wait 1.0 s (timeout) and allowed probes take 0.05 s, serial execution. These are assumptions, not measurements.\n")

    # safety (pod level, small clusters)
    unsafe = checked = 0
    for kind in sorted(MUTATIONS):
        for s in range(3):
            rng = random.Random(f"safe-{kind}-{s}")
            old = make_cluster(2, 1, 2, seed=s)
            new = mutate(old, kind, rng)
            if new is None:
                continue
            sel = select(old, new, risk_expansion=False)
            checked += 1
            unsafe += bool(verify_safety(old, new, sel.probes, sel.space))
    txt.append(f"\n### Safety check (pod-level, exhaustive ground truth, 12-pod clusters)\n\n{checked - unsafe}/{checked} changes: every flipped flow was covered by a probe.\n")
    return "\n".join(txt)


def e3():
    rows = []
    rng = random.Random(7)
    for replicas in (2, 5, 10, 30, 60):
        old = make_cluster(n_ns=4, apps=3, replicas=replicas, seed=1)
        new = mutate(old, "change_port", random.Random(11))
        t0 = time.perf_counter()
        sp = Space(old, new)
        sel = select(old, new, space=sp)
        dt = time.perf_counter() - t0
        n = sp.n_pods
        rows.append([n, len(sp.members), len(sel.probes), n * (n - 1) * sp.n_ports,
                     f"{100 * (1 - len(sel.probes) / (n * (n - 1) * sp.n_ports)):.2f}%", f"{dt:.2f}"])
    return "### E3. Scaling (change_port mutation; 4 namespaces x 3 apps)\n\n" + md_table(
        ["pods", "classes", "probes (C1+C2)", "exhaustive probes", "reduction", "selection compute time (s)"], rows)


def e4():
    rows = simulate(trials=20000, nodes=3)
    return ("### E4. Convergence strategies (SYNTHETIC delay model: lognormal median 1.5 s, 5% stragglers; 3 nodes)\n\n"
            + md_table(["strategy", "mean wait (s)", "p95 wait (s)", "premature start (%)"],
                       [[r["strategy"], f"{r['mean_wait_s']:.2f}", f"{r['p95_wait_s']:.2f}", f"{r['premature_pct']:.2f}"] for r in rows]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=15)
    ap.add_argument("--out", default="results")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    t0 = time.time()
    parts = ["# Experiment results (simulation only; see README for what this does and does not show)\n",
             e1_e2(a.seeds, a.out), "\n" + e3(), "\n" + e4()]
    report = "\n".join(parts) + f"\n\n_Generated in {time.time() - t0:.0f} s._\n"
    with open(os.path.join(a.out, "results.md"), "w") as f:
        f.write(report)
    print(report)


if __name__ == "__main__":
    main()
