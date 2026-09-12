"""Chart rendering for reports. Matplotlib, Agg backend (no display needed),
returns each chart as a `data:image/png;base64,...` URI so it can be embedded
directly into Markdown (`![alt](uri)`) or HTML `<img src="uri">` with no
separate asset files to manage.
"""
from __future__ import annotations

import base64
import io

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

# Palette: colorblind-safe categorical set, consistent across every chart in
# a report so a color always means the same series across sections.
PALETTE = [
    "#2563eb",  # blue
    "#f97316",  # orange
    "#16a34a",  # green
    "#dc2626",  # red
    "#7c3aed",  # purple
    "#0891b2",  # teal
    "#ca8a04",  # amber
    "#db2777",  # pink
]
NEUTRAL_GRID = "#e5e7eb"
NEUTRAL_TEXT = "#374151"


def _style_axes(ax, title: str | None, ylabel: str | None = None):
    if title:
        ax.set_title(title, fontsize=12, color=NEUTRAL_TEXT, pad=12)
    if ylabel:
        ax.set_ylabel(ylabel, fontsize=10, color=NEUTRAL_TEXT)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color(NEUTRAL_GRID)
    ax.spines["bottom"].set_color(NEUTRAL_GRID)
    ax.tick_params(colors=NEUTRAL_TEXT, labelsize=9)
    ax.yaxis.grid(True, color=NEUTRAL_GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def _check_series_lengths(categories: list, series: dict[str, list]) -> None:
    for name, values in series.items():
        if len(values) != len(categories):
            raise ValueError(
                f"series {name!r} has {len(values)} value(s) but there are "
                f"{len(categories)} categories/labels -- lengths must match"
            )


def _to_data_uri(fig) -> str:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight", transparent=False, facecolor="white")
    plt.close(fig)
    encoded = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def bar_chart(labels: list[str], values: list[float], title: str = "", ylabel: str = "", horizontal: bool = False) -> str:
    fig, ax = plt.subplots(figsize=(7, 4))
    colors = [PALETTE[i % len(PALETTE)] for i in range(len(labels))]
    if horizontal:
        ax.barh(labels, values, color=colors)
        ax.invert_yaxis()
    else:
        ax.bar(labels, values, color=colors)
        plt.setp(ax.get_xticklabels(), rotation=30, ha="right")
    _style_axes(ax, title, ylabel)
    fig.tight_layout()
    return _to_data_uri(fig)


def grouped_bar_chart(categories: list[str], series: dict[str, list[float]], title: str = "", ylabel: str = "") -> str:
    import numpy as np

    _check_series_lengths(categories, series)
    fig, ax = plt.subplots(figsize=(8, 4.5))
    n_series = len(series)
    x = np.arange(len(categories))
    width = 0.8 / max(n_series, 1)
    for i, (name, values) in enumerate(series.items()):
        ax.bar(x + i * width, values, width, label=name, color=PALETTE[i % len(PALETTE)])
    ax.set_xticks(x + width * (n_series - 1) / 2)
    ax.set_xticklabels(categories, rotation=30, ha="right")
    ax.legend(frameon=False, fontsize=9)
    _style_axes(ax, title, ylabel)
    fig.tight_layout()
    return _to_data_uri(fig)


def line_chart(x_labels: list[str], series: dict[str, list[float]], title: str = "", ylabel: str = "") -> str:
    _check_series_lengths(x_labels, series)
    fig, ax = plt.subplots(figsize=(8, 4))
    for i, (name, values) in enumerate(series.items()):
        ax.plot(x_labels, values, marker="o", label=name, color=PALETTE[i % len(PALETTE)], linewidth=2)
    if len(series) > 1:
        ax.legend(frameon=False, fontsize=9)
    plt.setp(ax.get_xticklabels(), rotation=30, ha="right")
    _style_axes(ax, title, ylabel)
    fig.tight_layout()
    return _to_data_uri(fig)


def pie_chart(labels: list[str], values: list[float], title: str = "") -> str:
    fig, ax = plt.subplots(figsize=(5.5, 5.5))
    if not values or sum(values) == 0:
        ax.text(0.5, 0.5, "No data", ha="center", va="center", fontsize=11, color=NEUTRAL_TEXT, transform=ax.transAxes)
        ax.axis("off")
        if title:
            ax.set_title(title, fontsize=12, color=NEUTRAL_TEXT, pad=12)
        fig.tight_layout()
        return _to_data_uri(fig)
    colors = [PALETTE[i % len(PALETTE)] for i in range(len(labels))]
    ax.pie(
        values,
        labels=labels,
        autopct="%1.0f%%",
        colors=colors,
        textprops={"color": NEUTRAL_TEXT, "fontsize": 9},
        wedgeprops={"edgecolor": "white", "linewidth": 1},
    )
    if title:
        ax.set_title(title, fontsize=12, color=NEUTRAL_TEXT, pad=12)
    fig.tight_layout()
    return _to_data_uri(fig)


def histogram(values: list[float], bins: int = 20, title: str = "", xlabel: str = "", ylabel: str = "Count") -> str:
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.hist(values, bins=bins, color=PALETTE[0], edgecolor="white")
    if xlabel:
        ax.set_xlabel(xlabel, fontsize=10, color=NEUTRAL_TEXT)
    _style_axes(ax, title, ylabel)
    fig.tight_layout()
    return _to_data_uri(fig)


def stacked_bar_chart(categories: list[str], series: dict[str, list[float]], title: str = "", ylabel: str = "") -> str:
    import numpy as np

    _check_series_lengths(categories, series)
    fig, ax = plt.subplots(figsize=(8, 4.5))
    bottom = np.zeros(len(categories))
    for i, (name, values) in enumerate(series.items()):
        values_arr = np.array(values, dtype=float)
        ax.bar(categories, values_arr, bottom=bottom, label=name, color=PALETTE[i % len(PALETTE)])
        bottom += values_arr
    ax.legend(frameon=False, fontsize=9, loc="upper left", bbox_to_anchor=(1.02, 1))
    plt.setp(ax.get_xticklabels(), rotation=30, ha="right")
    _style_axes(ax, title, ylabel)
    fig.tight_layout()
    return _to_data_uri(fig)
