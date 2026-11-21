"""Run the experiment.

    python -m ism.evaluate                  # main results, written to results/
    python -m ism.evaluate --sweep          # also sweep the benign look-alike rate

Protocol: each monitor's alarm threshold is calibrated on one set of benign
sessions to a target false-positive rate, then measured on fresh benign
sessions and on attack sessions. An attack counts as blocked when the monitor
alarms at or before the step that would complete the forbidden goal.
"""
from __future__ import annotations

import argparse
import json
import math
import random
from pathlib import Path

from . import scenarios as sc
from .ledger import Ledger
from .monitors import default_monitors

VARIANTS = ("plain", "evasive")


def session_rng(seed: int, split: str, i: int) -> random.Random:
    return random.Random(f"{seed}/{split}/{i}")


def score_session(session: sc.Session, monitors) -> dict[str, list[float]]:
    ledger = Ledger()
    for a in session.actions:
        ledger.append(a)
    if not ledger.verify():
        raise RuntimeError("ledger failed verification")
    actions = ledger.actions()
    out = {}
    for m in monitors:
        m.reset()
        out[m.name] = [m.score(a) for a in actions]
    return out


def calibrate(max_scores: list[float], fpr: float) -> float:
    """Alarm when score > threshold; at most floor(fpr * n) calibration sessions alarm."""
    s = sorted(max_scores)
    k = int(fpr * len(s))
    return s[len(s) - k - 1]


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def first_alarm(scores: list[float], thr: float) -> int | None:
    return next((i for i, s in enumerate(scores) if s > thr), None)


def run(seed: int = 20261120, n_benign: int = 4000, n_attack: int = 400, window: int = 20,
        fprs=(0.01, 0.05), families=None, lookalike: float = sc.LOOKALIKE_RATE,
        family_names=None, monitors=None) -> dict:
    fams = families or sc.FAMILIES
    names = family_names or list(fams)
    monitors = monitors or default_monitors(window)
    mnames = [m.name for m in monitors]

    cal = [score_session(sc.benign_session(session_rng(seed, "cal", i), lookalike), monitors) for i in range(n_benign)]
    cal_max = {m: [max(s[m]) for s in cal] for m in mnames}
    thresholds = {str(f): {m: calibrate(cal_max[m], f) for m in mnames} for f in fprs}

    test = [score_session(sc.benign_session(session_rng(seed, "test", i), lookalike), monitors) for i in range(n_benign)]
    benign_fpr = {str(f): {m: sum(max(s[m]) > thresholds[str(f)][m] for s in test) / n_benign for m in mnames}
                  for f in fprs}

    attacks = {}
    for fam in names:
        for var in VARIANTS:
            sessions = [sc.attack_session(session_rng(seed, f"{fam}-{var}", i), fam, var, fams, lookalike)
                        for i in range(n_attack)]
            scored = [score_session(s, monitors) for s in sessions]
            cell = {"n": n_attack, "mean_length": sum(len(s.actions) for s in sessions) / n_attack}
            for f in fprs:
                for m in mnames:
                    thr = thresholds[str(f)][m]
                    blocked = detected = 0
                    for s, sco in zip(sessions, scored):
                        i = first_alarm(sco[m], thr)
                        if i is not None:
                            detected += 1
                            blocked += i <= s.harm_step
                    cell.setdefault(str(f), {})[m] = {
                        "blocked": blocked / n_attack, "blocked_ci": wilson(blocked, n_attack),
                        "detected": detected / n_attack,
                    }
            attacks[f"{fam}/{var}"] = cell

    return {"config": {"seed": seed, "n_benign": n_benign, "n_attack": n_attack, "window": window,
                       "fprs": list(fprs), "lookalike_rate": lookalike, "families": names},
            "monitors": mnames, "thresholds": thresholds, "benign_fpr": benign_fpr, "attacks": attacks}


def sweep(seed: int, rates=(0.0, 0.01, 0.02, 0.05), n_benign: int = 3000, n_attack: int = 300) -> list[dict]:
    rows = []
    for r in rates:
        res = run(seed=seed + 1, n_benign=n_benign, n_attack=n_attack, fprs=(0.01,), lookalike=r,
                  family_names=["redirect", "secret_leak"])
        row = {"lookalike_rate": r}
        for key, cell in res["attacks"].items():
            row[key] = cell["0.01"]["intent stack"]["blocked"]
        row["benign_fpr"] = res["benign_fpr"]["0.01"]["intent stack"]
        rows.append(row)
    return rows


def pct(x: float) -> str:
    return f"{100 * x:.1f}%"


def summary_markdown(res: dict, sweep_rows: list[dict] | None = None) -> str:
    mnames = res["monitors"]
    lines = [f"# Results (seed {res['config']['seed']})", ""]
    c = res["config"]
    lines.append(f"{c['n_benign']} calibration and {c['n_benign']} test benign sessions; {c['n_attack']} attack "
                 f"sessions per family and variant; aggregate window {c['window']} steps; benign look-alike rate "
                 f"{pct(c['lookalike_rate'])}.")
    for f in c["fprs"]:
        f = str(f)
        lines += ["", f"## Blocked before harm, threshold set for {pct(float(f))} false positives", ""]
        lines.append("| Attack | " + " | ".join(mnames) + " |")
        lines.append("|---|" + "---|" * len(mnames))
        for key, cell in res["attacks"].items():
            vals = []
            for m in mnames:
                v = cell[f][m]
                lo, hi = v["blocked_ci"]
                vals.append(f"{pct(v['blocked'])} ({pct(lo)} to {pct(hi)})")
            lines.append(f"| {key} | " + " | ".join(vals) + " |")
        lines.append("| benign false positives (test) | " + " | ".join(pct(res["benign_fpr"][f][m]) for m in mnames) + " |")
    if sweep_rows:
        lines += ["", "## Intent stack vs. benign look-alike rate (threshold for 1% false positives)", ""]
        keys = [k for k in sweep_rows[0] if "/" in k]
        lines.append("| Look-alike rate | " + " | ".join(keys) + " | benign false positives |")
        lines.append("|---|" + "---|" * (len(keys) + 1))
        for r in sweep_rows:
            lines.append(f"| {pct(r['lookalike_rate'])} | " + " | ".join(pct(r[k]) for k in keys)
                         + f" | {pct(r['benign_fpr'])} |")
    return "\n".join(lines) + "\n"


def plot(res: dict, path: Path) -> None:
    """Small multiples: one panel per false-positive budget, same axes."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    surface, ink, ink2, grid = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
    colors = ["#2a78d6", "#eb6834", "#1baf7a"]  # categorical slots 1 to 3
    mnames = [m for m in res["monitors"] if m != "per-action policy"]
    keys = list(res["attacks"])
    fprs = [str(f) for f in res["config"]["fprs"]]
    fig, axes = plt.subplots(len(fprs), 1, figsize=(10, 2.6 * len(fprs) + 0.8), dpi=160, sharex=True)
    fig.patch.set_facecolor(surface)
    width = 0.26
    for ax, f in zip(axes, fprs):
        ax.set_facecolor(surface)
        for j, m in enumerate(mnames):
            xs = [i + (j - 1) * width for i in range(len(keys))]
            ys = [100 * res["attacks"][k][f][m]["blocked"] for k in keys]
            ax.bar(xs, ys, width=width, color=colors[j], edgecolor=surface, linewidth=1.5, label=m, zorder=3)
        ax.set_ylim(0, 105)
        ax.set_yticks([0, 50, 100])
        ax.tick_params(axis="y", colors=ink2, labelsize=8)
        ax.grid(axis="y", color=grid, linewidth=0.8, zorder=0)
        for s in ("top", "right", "left"):
            ax.spines[s].set_visible(False)
        ax.spines["bottom"].set_color(grid)
        ax.set_title(f"Alarm threshold set for {pct(float(f))} benign false positives", color=ink,
                     fontsize=9, loc="left")
        ax.set_ylabel("Blocked (%)", color=ink2, fontsize=8)
    axes[-1].set_xticks(range(len(keys)))
    axes[-1].set_xticklabels([k.replace("/", "\n") for k in keys], color=ink2, fontsize=8)
    fig.suptitle("Attacks blocked before harm (the per-action policy blocks 0% by construction)",
                 color=ink, fontsize=10, x=0.01, ha="left")
    leg = axes[-1].legend(frameon=False, fontsize=8, ncol=3, loc="upper left", bbox_to_anchor=(0, -0.32))
    for t in leg.get_texts():
        t.set_color(ink)
    fig.tight_layout()
    fig.savefig(path, facecolor=surface)
    plt.close(fig)


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seed", type=int, default=20261120)
    ap.add_argument("--n-benign", type=int, default=4000)
    ap.add_argument("--n-attack", type=int, default=400)
    ap.add_argument("--window", type=int, default=20)
    ap.add_argument("--out", default="results")
    ap.add_argument("--sweep", action="store_true")
    ap.add_argument("--heldout", action="store_true", help="evaluate the held-out family instead")
    args = ap.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    if args.heldout:
        from .heldout import HELDOUT_FAMILIES, HELDOUT_NAMES
        res = run(args.seed, args.n_benign, args.n_attack, args.window, families=HELDOUT_FAMILIES,
                  family_names=HELDOUT_NAMES)
        (out / "heldout.json").write_text(json.dumps(res, indent=2))
        (out / "heldout.md").write_text(summary_markdown(res))
        print(summary_markdown(res))
        return

    res = run(args.seed, args.n_benign, args.n_attack, args.window)
    rows = sweep(args.seed) if args.sweep else None
    if rows:
        res["sweep"] = rows
    (out / "results.json").write_text(json.dumps(res, indent=2))
    (out / "summary.md").write_text(summary_markdown(res, rows))
    try:
        plot(res, out / "blocked_before_harm.png")
    except ImportError:
        print("matplotlib not installed; skipping the figure")
    print(summary_markdown(res, rows))


if __name__ == "__main__":
    main()
