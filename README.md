# netpolrts — Change-Aware Regression Test Selection for Kubernetes NetworkPolicy Updates

Given the cluster state *before* and *after* a NetworkPolicy change, `netpolrts` decides **which live
connectivity probes are worth running**, runs them only once the CNI has actually applied the change,
and compares the result with what the NetworkPolicy spec says should happen.

## What is implemented

| Contribution | Where | What it does |
|---|---|---|
| Spec semantics | `semantics.py` | Reference model of NetworkPolicy: ingress+egress, additive policies, podSelector/namespaceSelector/ipBlock+except, named ports, endPort. Also injectable *simulated CNI faults* (`named_port`, `endport`, `ipblock_pod`, `overlap_last_wins`). |
| **C1** safe selection | `analysis.py`, `selection.py` | Pods are grouped into equivalence classes (indistinguishable by any selector/ipBlock/named port in either version). The semantic diff finds every flow class whose verdict flips; one probe is chosen per flipped class. **Safety property:** every flow whose verdict changes lies in a probed class (`verify_safety` checks this at pod level). |
| **C2** CNI-risk expansion | `selection.py` | If the changed policies use features CNIs are known to diverge on (named ports, endPort, ipBlock, overlapping policies) add probes around the affected pods, because the spec-level diff alone cannot see an implementation bug there. |
| **C3** convergence-aware execution | `runner.py`, `convergence.py` | Poll canary flows (one per destination node) until they show the new verdict, instead of a fixed `sleep`. |
| Evaluation | `generator.py`, `mutations.py`, `evaluate.py`, `experiments.py` | Synthetic multi-namespace clusters, 12 mutation operators, 6 methods, fault detection, probe counts, scaling, convergence simulation. |
| Live runner | `runner.py`, `__main__.py` | `kubectl exec` prober + CLI. **Not tested against a real cluster here** (see below). |

## Run it

```bash
pip install pyyaml pytest
python -m pytest -q                         # 29 tests
python -m netpolrts.experiments --seeds 40  # ~1 minute, writes results/results.md and results/trials.csv
python -m netpolrts select examples/old.yaml examples/new_named_port.yaml
python -m netpolrts select examples/old.yaml examples/new_add_rule.yaml
```

## Results (simulation only — see `results/results.md`)

* Safety: 36/36 changes had every flipped flow covered (pod-level exhaustive check, small clusters).
* 54-pod cluster, 480 seeded changes: mean 133 probes vs 32,531 for the exhaustive matrix (99.6 % fewer), for 2.8 flipped flow classes on average.
* Scaling: probe count depends on the number of *classes*, not pods (24 probes at 72 pods and at 2,160 pods for a port change).
* Fault detection (faults that actually manifested): C1+C2 caught all of them; C1 alone missed 40/44 `named_port` faults (the edit is a no-op in the spec, so nothing flips) — that is the case C2 exists for; random probing with the same budget caught 2/44.

## Read this before you trust the numbers (limitations)

1. **The "CNIs" in E1 are simulated by me.** The four fault profiles are inspired by divergences reported in the literature, but they are not measurements of Calico, Cilium or Antrea. C2's risk tags were chosen with those fault classes in mind, so C2 catching them is partly by construction. The real test is the live experiment below; if real CNIs show no divergence on your workloads, the C2 claim must be dropped or weakened.
2. **Time numbers are assumption-driven** (denied probe = 1 s timeout, allowed = 0.05 s, serial). The convergence experiment (E4) uses a synthetic delay model, and "canary x3" tracks the slowest node by construction. Replace both with delays you measure on Kind.
3. **Port abstraction:** all methods probe the same small set of "interesting" ports (ports in policies ± 1, container ports, one default). That is conservative for the exhaustive baseline.
4. **Out of scope:** pod add/remove between versions, Deployments (list pods explicitly or export with `kubectl get pods,netpol -n NS -o yaml`), AdminNetworkPolicy/BaselineAdminNetworkPolicy, CNI-specific CRDs (CiliumNetworkPolicy, Calico GlobalNetworkPolicy), services/NAT/hostNetwork/hairpin semantics, UDP/SCTP beyond protocol matching.
5. **Prior art:** a static semantic diff is *not* new (e.g. np-guard `netpol-analyzer diff`, Kano's incremental verification). The claimed novelty is the closed loop: diff → safe live-probe selection → CNI-risk expansion → convergence-aware execution. Check IEEE Xplore / ACM DL / Scopus before submitting.

## Live runs on your laptop (Kind) — what you still have to do

```bash
kind create cluster --config live/kind-config.yaml      # default CNI disabled
# install ONE CNI per cluster (Calico, Cilium or Antrea) following its Kind docs, wait for nodes Ready
kubectl create ns shop
# deploy pods that listen on the ports you test, e.g. agnhost netexec (see examples/old.yaml for the pod specs)
kubectl get pods,netpol -n shop -o yaml > old.yaml      # snapshot BEFORE
# edit the policy -> new.yaml (e.g. examples/new_named_port.yaml shows the shape), then:
python -m netpolrts select old.yaml new.yaml            # see the plan
kubectl apply -f <changed policy>
python -m netpolrts run old.yaml new.yaml               # waits for canaries, runs probes, prints MISMATCH lines
```
The default probe command is `/agnhost connect IP:PORT --timeout=1s --protocol=tcp` run through `kubectl exec` in the source pod (the same tool the upstream e2e tests use). Check that it works in your image first; change `DEFAULT_CMD` in `runner.py` if not. Repeat with each CNI. Every `MISMATCH` is a candidate CNI divergence: verify it by hand before calling it a bug.

## Suggested experiment plan for the paper
1. Replace the simulated CNI profiles with measured behaviour: run the mutation set on Kind with Calico, Cilium and Antrea (50–200 pods), record which probes disagree with the spec.
2. Measure real convergence delays per CNI and re-run E4 with them.
3. Compare against: exhaustive matrix, all-policy-scope, random same budget, static diff only, fixed sleep.
4. Report probes, detection, wall time, flakiness, with the number of trials and confidence intervals.
