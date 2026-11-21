"""Second-stage and robustness experiments.

    python -m ism.experiments learned     # train and evaluate the learned cascade
    python -m ism.experiments adaptive    # adaptive attacker against every monitor
    python -m ism.experiments v2          # patch round: intent stack v2, retrained cascade, re-attack

Both reuse the main protocol: thresholds come from the same 4,000 benign
calibration sessions as ism.evaluate, at a 1% false-positive budget unless
stated. Training data for the learned stage comes from separate seeds.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import scenarios as sc
from .adaptive import search, summarize
from .cascade import CascadeMonitor, FEATURES, LearnedScorer, LogisticModel, collect_training_data
from .evaluate import VARIANTS, calibrate, pct, run, score_session, session_rng, summary_markdown
from .heldout import HELDOUT_FAMILIES, HELDOUT_NAMES
from .monitors import AggregateMonitor, IntentStackMonitor
from .monitors_v2 import IntentStackV2

SEED = 20261120
OUT = Path("results")


def calibrate_monitors(monitors, seed: int = SEED, n_benign: int = 4000, fpr: float = 0.01) -> dict:
    cal = [score_session(sc.benign_session(session_rng(seed, "cal", i)), monitors) for i in range(n_benign)]
    return {m.name: calibrate([max(s[m.name]) for s in cal], fpr) for m in monitors}


def train_learned(seed: int = SEED, n_benign: int = 4000, n_attack: int = 300, stage1_cls=IntentStackMonitor) -> LogisticModel:
    sessions, harms = [], []
    for i in range(n_benign):
        s = sc.benign_session(session_rng(seed, "train-benign", i))
        sessions.append(s); harms.append(None)
    for fam in sc.FAMILIES:
        for var in VARIANTS:
            for i in range(n_attack):
                s = sc.attack_session(session_rng(seed, f"train-{fam}-{var}", i), fam, var)
                sessions.append(s); harms.append(s.harm_step)
    X, y = collect_training_data(sessions, harms, stage1_cls=stage1_cls)
    model = LogisticModel().fit(X, y)
    model.n_rows, model.n_pos = int(len(y)), int(y.sum())
    return model


def learned_monitor(model: LogisticModel, v2: bool = False) -> CascadeMonitor:
    if v2:
        return CascadeMonitor(LearnedScorer(model), "learned cascade v2", stage1_cls=IntentStackV2)
    return CascadeMonitor(LearnedScorer(model), "learned cascade")


def cmd_learned(args) -> None:
    model = train_learned(args.seed)
    d = model.to_dict()
    d.update(rows=model.n_rows, positives=model.n_pos)
    (OUT / "learned_model.json").write_text(json.dumps(d, indent=2))
    mons = lambda: [IntentStackMonitor(), learned_monitor(model)]
    main = run(args.seed, monitors=mons())
    held = run(args.seed, families=HELDOUT_FAMILIES, family_names=HELDOUT_NAMES, monitors=mons())
    (OUT / "learned.json").write_text(json.dumps({"main": main, "heldout": held}, indent=2))
    weights = sorted(zip(FEATURES, model.w), key=lambda t: -abs(t[1]))
    lines = [summary_markdown(main), summary_markdown(held).replace("# Results", "# Held-out results"),
             "## Learned model weights (standardized features, largest first)", "",
             f"Trained on {model.n_rows} escalation steps ({model.n_pos} from attacks) from separate seeds.", "",
             "| Feature | Weight |", "|---|---|"]
    lines += [f"| {f} | {w:+.2f} |" for f, w in weights]
    (OUT / "learned.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


def cmd_adaptive(args) -> None:
    model = LogisticModel.from_dict(json.loads((OUT / "learned_model.json").read_text()))
    monitors = [AggregateMonitor(20), AggregateMonitor(None), IntentStackMonitor(), learned_monitor(model)]
    thr = calibrate_monitors(monitors, args.seed)
    results = []
    for m in monitors:
        for fam in sc.FAMILIES:
            for k in range(args.runs):
                results.append(search(m, thr[m.name], fam, seed=k, budget=args.budget))
    summary = summarize(results, args.budget)
    (OUT / "adaptive.json").write_text(json.dumps(
        {"thresholds": thr, "budget": args.budget, "runs": args.runs, "summary": summary,
         "results": [r.__dict__ for r in results]}, indent=2))
    lines = [f"# Adaptive attacker ({args.runs} searches per cell, budget {args.budget} queries, "
             "thresholds for 1% false positives)", "",
             "| Monitor | Attack | Evaded | Median queries | Winning tactics |", "|---|---|---|---|---|"]
    for v in summary.values():
        tac = ", ".join(f"{k} {n}" for k, n in sorted(v["winning_tactics"].items()))
        mq = "" if v["median_queries"] is None else f"{v['median_queries']:g}"
        lines.append(f"| {v['monitor']} | {v['family']} | {v['evaded']}/{v['runs']} | {mq} | {tac} |")
    (OUT / "adaptive.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


def _adaptive_table(title: str, summary: dict) -> list[str]:
    lines = [title, "", "| Monitor | Attack | Evaded | Median queries | Winning tactics |", "|---|---|---|---|---|"]
    for v in summary.values():
        tac = ", ".join(f"{k} {n}" for k, n in sorted(v["winning_tactics"].items()))
        mq = "" if v["median_queries"] is None else f"{v['median_queries']:g}"
        lines.append(f"| {v['monitor']} | {v['family']} | {v['evaded']}/{v['runs']} | {mq} | {tac} |")
    return lines


def cmd_v2(args) -> None:
    """Patch round: intent stack v2, a learned cascade retrained on it, then re-attack."""
    model = train_learned(args.seed, stage1_cls=IntentStackV2)
    d = model.to_dict()
    d.update(rows=model.n_rows, positives=model.n_pos)
    (OUT / "learned_model_v2.json").write_text(json.dumps(d, indent=2))
    mons = lambda: [IntentStackMonitor(), IntentStackV2(), learned_monitor(model, v2=True)]
    main = run(args.seed, monitors=mons())
    held = run(args.seed, families=HELDOUT_FAMILIES, family_names=HELDOUT_NAMES, monitors=mons())
    attack = [IntentStackV2(), learned_monitor(model, v2=True)]
    thr = calibrate_monitors(attack, args.seed)
    results = [search(m, thr[m.name], fam, seed=k, budget=args.budget)
               for m in attack for fam in sc.FAMILIES for k in range(args.runs)]
    summary = summarize(results, args.budget)
    (OUT / "v2.json").write_text(json.dumps({"main": main, "heldout": held, "adaptive": {
        "thresholds": thr, "budget": args.budget, "runs": args.runs, "summary": summary,
        "results": [r.__dict__ for r in results]}}, indent=2))
    lines = [summary_markdown(main).replace("# Results", "# Patch round (v2) results"),
             summary_markdown(held).replace("# Results", "# Patch round (v2), held-out families")]
    lines += _adaptive_table(f"## Adaptive attacker against the patched monitors ({args.runs} searches per cell, "
                             f"budget {args.budget} queries, thresholds for 1% false positives)", summary)
    (OUT / "v2.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["learned", "adaptive", "v2"])
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--runs", type=int, default=20)
    ap.add_argument("--budget", type=int, default=150)
    args = ap.parse_args(argv)
    OUT.mkdir(exist_ok=True)
    {"learned": cmd_learned, "adaptive": cmd_adaptive, "v2": cmd_v2}[args.command](args)


if __name__ == "__main__":
    main()
