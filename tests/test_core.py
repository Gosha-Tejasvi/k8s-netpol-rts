import random
import textwrap

import pytest
import yaml

from netpolrts import (Cluster, Evaluator, IPBlock, Peer, Pod, Policy, PortSpec, Rule, Selector,
                       Space, labels, select, verify_safety)
from netpolrts.convergence import simulate
from netpolrts.evaluate import run_trial
from netpolrts.generator import make_cluster
from netpolrts.loader import load_docs
from netpolrts.mutations import MUTATIONS, mutate
from netpolrts.runner import SimulatedProber, pick_canaries, run_selection, wait_for_flip


def sel(**kw):
    return Selector(labels(kw))


def three_pods():
    c = Cluster()
    for i, a in enumerate("abc"):
        c.pods.append(Pod("ns", a, labels({"app": a}), f"10.0.0.{i + 1}", (("http", 80, "TCP"),)))
    return c


def ingress_pol(name, target, peer_app, port):
    return Policy("ns", name, sel(app=target), frozenset({"Ingress"}),
                  ingress=(Rule((Peer(pod_selector=sel(app=peer_app)),), (PortSpec("TCP", port),)),))


# ---------------------------------------------------------------- semantics
def test_no_policy_allows_everything():
    c = three_pods()
    ev = Evaluator(c)
    assert ev.allowed(c.pods[0], c.pods[1], 80)


def test_ingress_whitelist_and_default_deny():
    c = three_pods()
    c.policies = [ingress_pol("p", "b", "a", 80)]
    ev = Evaluator(c)
    a, b, cc = c.pods
    assert ev.allowed(a, b, 80)
    assert not ev.allowed(cc, b, 80)  # b isolated, c not whitelisted
    assert not ev.allowed(a, b, 81)  # wrong port
    assert ev.allowed(b, a, 1234)  # a not isolated


def test_egress_and_ingress_must_both_allow():
    c = three_pods()
    a, b, _ = c.pods
    c.policies = [Policy("ns", "eg", sel(app="a"), frozenset({"Egress"}))]  # a: deny all egress
    assert not Evaluator(c).allowed(a, b, 80)


def test_additive_policies_union():
    c = three_pods()
    a, b, cc = c.pods
    c.policies = [ingress_pol("p1", "b", "a", 80), ingress_pol("p2", "b", "c", 80)]
    ev = Evaluator(c)
    assert ev.allowed(a, b, 80) and ev.allowed(cc, b, 80)


def test_namespace_selector_and_default_same_namespace():
    c = Cluster(namespaces={"x": labels({"env": "prod"}), "y": labels({"env": "dev"})})
    c.pods = [Pod("x", "p", labels({"a": "1"}), "10.0.0.1"), Pod("y", "q", labels({"a": "1"}), "10.0.1.1"),
              Pod("x", "r", labels({"a": "1"}), "10.0.0.2")]
    p, q, r = c.pods
    c.policies = [Policy("x", "pol", Selector(), frozenset({"Ingress"}),
                         ingress=(Rule((Peer(pod_selector=sel(a="1")),)),))]
    ev = Evaluator(c)
    assert ev.allowed(r, p, 80)        # same ns: podSelector alone is namespace-local
    assert not ev.allowed(q, p, 80)    # other ns not matched
    c.policies = [Policy("x", "pol", Selector(), frozenset({"Ingress"}),
                         ingress=(Rule((Peer(ns_selector=sel(env="dev")),)),))]
    assert Evaluator(c).allowed(q, p, 80)


def test_ipblock_except():
    c = three_pods()
    a, b, cc = c.pods
    c.policies = [Policy("ns", "ip", sel(app="b"), frozenset({"Ingress"}),
                         ingress=(Rule((Peer(ip_block=IPBlock("10.0.0.0/24", ("10.0.0.3/32",))),)),))]
    ev = Evaluator(c)
    assert ev.allowed(a, b, 80)
    assert not ev.allowed(cc, b, 80)


def test_named_port_and_endport():
    c = three_pods()
    a, b, _ = c.pods
    c.policies = [Policy("ns", "n", sel(app="b"), frozenset({"Ingress"}),
                         ingress=(Rule(None, (PortSpec("TCP", "http"),)),))]
    assert Evaluator(c).allowed(a, b, 80)
    assert not Evaluator(c).allowed(a, b, 81)
    c.policies = [Policy("ns", "r", sel(app="b"), frozenset({"Ingress"}),
                         ingress=(Rule(None, (PortSpec("TCP", 8000, 8100),)),))]
    ev = Evaluator(c)
    assert ev.allowed(a, b, 8050) and not ev.allowed(a, b, 8101)


def test_bug_profiles_deviate():
    c = three_pods()
    a, b, _ = c.pods
    c.policies = [Policy("ns", "n", sel(app="b"), frozenset({"Ingress"}),
                         ingress=(Rule(None, (PortSpec("TCP", "http"),)),))]
    assert not Evaluator(c, ("named_port",)).allowed(a, b, 80)
    with pytest.raises(ValueError):
        Evaluator(c, ("nope",))


# ------------------------------------------------------ C1 selection + safety
def test_no_change_no_probes():
    c = make_cluster(2, 1, 2)
    s = select(c, c.copy())
    assert s.probes == [] and s.n_flips == 0


def test_removing_a_rule_flips_flows_and_probes_cover_them():
    old = three_pods()
    old.policies = [ingress_pol("p", "b", "a", 80)]
    new = old.copy()
    new.policies = []
    s = select(old, new)
    assert any(p.reason == "flip" and p.dst == ("ns", "b") and p.expected for p in s.probes)
    assert verify_safety(old, new, s.probes) == []


@pytest.mark.parametrize("kind", sorted(MUTATIONS))
def test_safety_property_randomised(kind):
    """Every pod-level flow whose verdict changes lies in a probed flow class."""
    rng = random.Random(1234)
    checked = 0
    for seed in range(4):
        old = make_cluster(2, 1, 2, seed=seed)
        new = mutate(old, kind, rng)
        if new is None:
            continue
        s = select(old, new, risk_expansion=False)
        assert verify_safety(old, new, s.probes, s.space) == []
        checked += 1
    assert checked > 0


def test_equivalence_classes_shrink_probe_count():
    old = make_cluster(2, 1, 6)
    new = mutate(old, "change_port", random.Random(3))
    s = select(old, new)
    n = len(old.pods)
    assert s.n_classes < n
    assert len(s.probes) < n * (n - 1) * s.space.n_ports / 10


# ----------------------------------------------------------------- C2
def _overlap_scenario():
    old = three_pods()
    old.policies = [ingress_pol("m-allow-a", "b", "a", 80)]
    new = old.copy()
    new.policies = old.policies + [ingress_pol("zz-extra", "b", "c", 80)]
    return old, new


def test_c2_catches_fault_that_c1_misses():
    old, new = _overlap_scenario()
    out_c1 = out_c1c2 = None
    sp = Space(old, new)
    mo, mn = sp.table("old"), sp.table("new")
    bug = ("overlap_last_wins",)
    co, cn = sp.table("old", bug), sp.table("new", bug)
    fault = {f for f in mn if cn[f] != mn[f] and co[f] == mo[f]}
    assert fault  # a->b:80 silently lost
    c1 = select(old, new, risk_expansion=False, space=sp, mo=mo, mn=mn)
    c2 = select(old, new, risk_expansion=True, space=sp, mo=mo, mn=mn)
    assert "overlap" in c2.tags
    assert not any(p.flow in fault for p in c1.probes)
    assert any(p.flow in fault for p in c2.probes)


def test_end_to_end_with_simulated_cluster():
    old, new = _overlap_scenario()
    s = select(old, new)
    ok = run_selection(s, SimulatedProber(new), canaries=pick_canaries(s, new), sleep=lambda _: None)
    assert ok["failures"] == []
    bad = run_selection(s, SimulatedProber(new, ("overlap_last_wins",)), sleep=lambda _: None, min_wait=0)
    assert bad["failures"]


def test_trial_without_bug_has_no_fault():
    rng = random.Random(0)
    old = make_cluster(2, 1, 2)
    new = mutate(old, "add_rule", rng)
    r = run_trial(old, new, None, rng)
    assert not r["manifested"]


# ----------------------------------------------------------------- C3
def test_wait_for_flip_polls_until_expected():
    old, new = _overlap_scenario()
    s = select(old, new)
    canary = s.flip_probes[:1]

    class Lagging:
        def __init__(self):
            self.n = 0

        def probe(self, p):
            self.n += 1
            return (not p.expected) if self.n < 4 else p.expected

    t = [0.0]
    ok, waited = wait_for_flip(Lagging(), canary, poll=0.5, timeout=30,
                               sleep=lambda d: t.__setitem__(0, t[0] + d), clock=lambda: t[0])
    assert ok and waited == pytest.approx(1.5)


def test_convergence_simulation_shape():
    rows = {r["strategy"]: r for r in simulate(trials=2000, nodes=3)}
    assert rows["fixed sleep 1s"]["premature_pct"] > rows["fixed sleep 30s"]["premature_pct"]
    assert rows["canary x3 (all nodes)"]["premature_pct"] == 0
    assert rows["canary x3 (all nodes)"]["mean_wait_s"] < rows["fixed sleep 30s"]["mean_wait_s"]
    assert rows["canary x1 (one node)"]["premature_pct"] > 0


# ----------------------------------------------------------------- loader
MANIFEST = textwrap.dedent("""
apiVersion: v1
kind: List
items:
- {apiVersion: v1, kind: Namespace, metadata: {name: ns, labels: {env: prod}}}
- {apiVersion: v1, kind: Pod, metadata: {name: a, namespace: ns, labels: {app: a}}, status: {podIP: 10.0.0.1},
   spec: {containers: [{name: c, ports: [{name: http, containerPort: 80}]}]}}
- {apiVersion: v1, kind: Pod, metadata: {name: b, namespace: ns, labels: {app: b}}, status: {podIP: 10.0.0.2},
   spec: {containers: [{name: c, ports: [{name: http, containerPort: 80}]}]}}
- apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata: {name: p, namespace: ns}
  spec:
    podSelector: {matchLabels: {app: b}}
    ingress:
    - from: [{podSelector: {matchLabels: {app: a}}}]
      ports: [{protocol: TCP, port: http}]
""")


def test_loader_and_policy_types_default():
    c = load_docs(yaml.safe_load_all(MANIFEST))
    assert len(c.pods) == 2 and len(c.policies) == 1
    assert c.policies[0].policy_types == frozenset({"Ingress"})
    a, b = c.pods
    assert Evaluator(c).allowed(a, b, 80) and not Evaluator(c).allowed(a, b, 81)
