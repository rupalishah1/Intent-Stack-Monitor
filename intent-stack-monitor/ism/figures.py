"""Draw the figures in results/ from the saved JSON (no recomputation).

    python -m ism.figures
"""
from __future__ import annotations

import json
from pathlib import Path

from .evaluate import plot

OUT = Path("results")
SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]  # categorical slots 1 to 4


def second_stages(path: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    c = json.loads((OUT / "claude_cascade.json").read_text())["main"]
    cells = ["redirect/plain", "redirect/evasive", "secret_leak/plain", "secret_leak/evasive"]
    names = ["intent stack v2", "learned cascade v2", "Claude cascade v2", "Claude cascade v2 (thinking)"]
    fig, ax = plt.subplots(figsize=(10, 3.6), dpi=160)
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)
    w = 0.2
    for j, m in enumerate(names):
        xs = [i + (j - 1.5) * w for i in range(len(cells))]
        ys = [100 * c["attacks"][k]["0.01"][m]["blocked"] for k in cells]
        ax.bar(xs, ys, width=w, color=SERIES[j], edgecolor=SURFACE, linewidth=1.5, label=m, zorder=3)
    ax.set_xticks(range(len(cells)))
    ax.set_xticklabels([k.replace("/", "\n").replace("_", " ") for k in cells], color=INK2, fontsize=8)
    ax.set_ylim(0, 105)
    ax.set_yticks([0, 25, 50, 75, 100])
    ax.set_ylabel("Blocked before harm (%)", color=INK2, fontsize=8)
    ax.tick_params(axis="y", colors=INK2, labelsize=8)
    ax.grid(axis="y", color=GRID, linewidth=0.8, zorder=0)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.spines["bottom"].set_color(GRID)
    ax.set_title("Compositional attacks blocked at a 1% false-positive budget (100 attacks per bar)",
                 color=INK, fontsize=10, loc="left")
    leg = ax.legend(frameon=False, fontsize=8, ncol=4, loc="upper left", bbox_to_anchor=(0, -0.2))
    for t in leg.get_texts():
        t.set_color(INK)
    fig.tight_layout()
    fig.savefig(path, facecolor=SURFACE)
    plt.close(fig)


def main() -> None:
    plot(json.loads((OUT / "results.json").read_text()), OUT / "blocked_before_harm.png")
    second_stages(OUT / "second_stages_1pct.png")


if __name__ == "__main__":
    main()
