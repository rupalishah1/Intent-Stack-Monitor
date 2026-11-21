"""Walk through one attack session step by step.

    python -m ism.demo --family redirect --variant evasive

Prints each action, whether the per-action policy allows it, and every
monitor's score, then the intent stack's explanation at the step that would
complete the forbidden goal.
"""
from __future__ import annotations

import argparse

from . import scenarios as sc
from .evaluate import session_rng
from .monitors import IntentStackMonitor, default_monitors
from .policy import decide


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--family", default="redirect", choices=list(sc.FAMILIES))
    ap.add_argument("--variant", default="evasive", choices=["plain", "evasive"])
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--all-steps", action="store_true", help="print noise steps too")
    args = ap.parse_args(argv)

    s = sc.attack_session(session_rng(args.seed, "demo", 0), args.family, args.variant)
    monitors = default_monitors()
    for m in monitors:
        m.reset()
    print(f"{args.family} / {args.variant}: {len(s.actions)} steps, forbidden goal completes at step {s.harm_step}\n")
    print("scores: " + " | ".join(m.name for m in monitors))
    quiet = {"search_docs", "read_doc", "get_balance", "list_invoices"}
    for a in s.actions:
        scores = [m.score(a) for m in monitors]
        if args.all_steps or a.tool not in quiet or a.step == s.harm_step:
            flag = "  <-- completes the forbidden goal" if a.step == s.harm_step else ""
            print(f"{a.describe():<95} policy={decide(a)[0]:<5} " + " ".join(f"{x:4.2f}" for x in scores) + flag)
        if a.step == s.harm_step:
            stack = next(m for m in monitors if isinstance(m, IntentStackMonitor))
            explain = stack.explain()
    print("\nIntent stack at the harmful step (most advanced first):")
    for line in explain:
        print("  " + line)


if __name__ == "__main__":
    main()
