# Experiment results (simulation only; see README for what this does and does not show)

### E1. Seeded-fault detection (trials where the CNI fault actually manifested)

| CNI bug profile | faulty trials | static_diff | c1_flips | c1_c2 | random_same_budget | policy_scope | exhaustive |
|---|---|---|---|---|---|---|---|
| named_port | 44 | 0/44 | 4/44 | 44/44 | 2/44 | 44/44 | 44/44 |
| endport | 11 | 0/11 | 11/11 | 11/11 | 5/11 | 11/11 | 11/11 |
| ipblock_pod | 39 | 0/39 | 39/39 | 39/39 | 8/39 | 39/39 | 39/39 |
| overlap_last_wins | 177 | 0/177 | 177/177 | 177/177 | 12/177 | 177/177 | 177/177 |

Sanity: with a spec-compliant CNI, faults manifested in 0/480 trials (must be 0).


### E2. Probes and estimated time per change (54-pod synthetic cluster, mean over trials)

| mutation | n | flipped classes | C1+C2 probes | policy-scope probes | exhaustive probes | reduction vs exhaustive | est. time C1+C2 (s) | est. time exhaustive (s) |
|---|---|---|---|---|---|---|---|---|
| add_egress_type | 40 | 2.4 | 233 | 3432 | 31482 | 99.3% | 230.5 | 31092 |
| add_overlap_policy | 40 | 2.7 | 406 | 3619 | 33199 | 98.8% | 398.3 | 32766 |
| add_rule | 40 | 2.8 | 15 | 3572 | 32770 | 100.0% | 12.1 | 32336 |
| change_port | 40 | 2.6 | 3 | 3650 | 33485 | 100.0% | 1.8 | 33082 |
| ipblock_add | 40 | 1.9 | 410 | 3650 | 33485 | 98.8% | 402.5 | 33058 |
| named_port | 40 | 0.0 | 126 | 3432 | 31482 | 99.6% | 122.8 | 31072 |
| ns_relabel | 40 | 0.0 | 0 | 17622 | 31482 | 100.0% | 0.0 | 31072 |
| pod_relabel | 40 | 10.6 | 11 | 1166 | 31482 | 100.0% | 5.9 | 31074 |
| port_range | 40 | 3.3 | 173 | 4040 | 37063 | 99.5% | 167.9 | 36624 |
| remove_policy | 40 | 4.5 | 208 | 4851 | 31482 | 99.3% | 202.7 | 31062 |
| remove_rule | 40 | 1.4 | 3 | 3432 | 31482 | 100.0% | 3.1 | 31083 |
| selector_change | 40 | 1.2 | 6 | 3432 | 31482 | 100.0% | 6.1 | 31079 |
| ALL | 480 | 2.8 | 133 | 4658 | 32531 | 99.6% | 129.5 | 32117 |

Estimated time assumes denied probes wait 1.0 s (timeout) and allowed probes take 0.05 s, serial execution. These are assumptions, not measurements.


### Safety check (pod-level, exhaustive ground truth, 12-pod clusters)

36/36 changes: every flipped flow was covered by a probe.


### E3. Scaling (change_port mutation; 4 namespaces x 3 apps)

| pods | classes | probes (C1+C2) | exhaustive probes | reduction | selection compute time (s) |
|---|---|---|---|---|---|
| 72 | 36 | 24 | 56232 | 99.96% | 0.04 |
| 180 | 36 | 24 | 354420 | 99.99% | 0.05 |
| 360 | 36 | 24 | 1421640 | 100.00% | 0.05 |
| 1080 | 36 | 24 | 12818520 | 100.00% | 0.08 |
| 2160 | 36 | 24 | 51297840 | 100.00% | 0.12 |

### E4. Convergence strategies (SYNTHETIC delay model: lognormal median 1.5 s, 5% stragglers; 3 nodes)

| strategy | mean wait (s) | p95 wait (s) | premature start (%) |
|---|---|---|---|
| fixed sleep 1s | 1.00 | 1.00 | 97.77 |
| fixed sleep 2s | 2.00 | 2.00 | 77.70 |
| fixed sleep 5s | 5.00 | 5.00 | 30.58 |
| fixed sleep 10s | 10.00 | 10.00 | 14.08 |
| fixed sleep 30s | 30.00 | 30.00 | 0.05 |
| canary x1 (one node) | 2.82 | 9.75 | 64.64 |
| canary x3 (all nodes) | 5.32 | 17.50 | 0.00 |

_Generated in 61 s._
