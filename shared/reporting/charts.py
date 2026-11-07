"""Chart rendering for reports. Matplotlib, Agg backend (no display needed),
returns each chart as a `data:image/svg+xml;base64,...` URI so it can be
embedded directly into Markdown (`![alt](uri)`) or HTML `<img src="uri">`
with no separate asset files to manage. SVG keeps every chart sharp at any
zoom level and in the PDF, where a raster chart would blur when printed.

Visual rules (shared by every chart so a report reads as one system):

- One series is one color: every bar of a single-series chart takes
  palette slot 1. Bars are never colored per-bar, because that suggests a
  meaning the data doesn't have.
- Categorical colors are assigned in fixed palette order, never cycled
  past eight; a ninth category folds into "Other".
- Severity charts use the severity colors, the same ones as the report's
  severity labels, so HIGH is the same color in a chart and in a table.
- Thin marks, solid hairline gridlines on the value axis only, values
  labeled at bar tips, integer ticks for counts.
- Text uses ink colors, never a series color.
"""
from __future__ import annotations

import base64
import io

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import FuncFormatter, MaxNLocator  # noqa: E402

# Categorical palette in its validated order (adjacent pairs clear the
# colorblind-separation floor in this order -- it is not cosmetic).
PALETTE = [
    "#2a78d6",  # blue
    "#eb6834",  # orange
    "#1baf7a",  # aqua
    "#eda100",  # yellow
    "#e87ba4",  # magenta
    "#008300",  # green
    "#6250d6",  # violet
    "#e34948",  # red
]
OTHER_COLOR = "#c3c2b7"

# Severity is a status scale, not a category: these colors are reserved for
# it and match the severity labels the HTML/PDF report draws.
SEVERITY_FILL = {
    "CRITICAL": "#d03b3b",
    "HIGH": "#ec835a",
    "MEDIUM": "#fab219",
    "LOW": "#86b6ef",
    "INFORMATIONAL": "#c3c2b7",
}
SEVERITY_ORDER = list(SEVERITY_FILL)

SURFACE = "#ffffff"
INK_PRIMARY = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
GRIDLINE = "#e1e0d9"
BASELINE = "#c3c2b7"

# Kept for callers that imported the old names.
NEUTRAL_GRID = GRIDLINE
NEUTRAL_TEXT = INK_SECONDARY



def _font_families() -> list[str]:
    """The installed subset of the preferred UI fonts, then DejaVu Sans
    (bundled with matplotlib). Listing families explicitly turns on
    matplotlib's per-glyph fallback, so a character the first font lacks
    (an arrow in a flow label) comes from the next one instead of
    rendering as a box."""
    from matplotlib import font_manager

    available = []
    for family in ("Inter", "Helvetica Neue", "Helvetica", "Arial"):
        try:
            font_manager.findfont(font_manager.FontProperties(family=family), fallback_to_default=False)
        except ValueError:
            continue
        available.append(family)
    return available + ["DejaVu Sans"]


matplotlib.rcParams.update(
    {
        "font.family": _font_families(),
        "font.size": 9,
        "axes.titlesize": 11,
        "axes.titleweight": "bold",
        "axes.titlelocation": "left",
        "axes.titlecolor": INK_PRIMARY,
        "axes.labelcolor": INK_SECONDARY,
        "xtick.color": INK_MUTED,
        "ytick.color": INK_MUTED,
        "xtick.labelcolor": INK_SECONDARY,
        "ytick.labelcolor": INK_SECONDARY,
        "legend.frameon": False,
        "legend.fontsize": 8.5,
        "svg.fonttype": "path",
        # Stable element IDs, so the same data renders byte-identical SVG.
        "svg.hashsalt": "aws-well-architected-and-analysis",
    }
)


# ---------------------------------------------------------------- formats
def _compact(value: float) -> str:
    sign = "-" if value < 0 else ""
    value = abs(value)
    for threshold, suffix in ((1e12, "T"), (1e9, "B"), (1e6, "M"), (1e3, "K")):
        if value >= threshold:
            scaled = value / threshold
            text = f"{scaled:.1f}".rstrip("0").rstrip(".") if scaled < 100 else f"{scaled:.0f}"
            return f"{sign}{text}{suffix}"
    if value == int(value):
        return f"{sign}{int(value):,}"
    return f"{sign}{value:,.1f}"


def _bytes(value: float) -> str:
    for threshold, suffix in ((1024**4, "TiB"), (1024**3, "GiB"), (1024**2, "MiB"), (1024, "KiB")):
        if abs(value) >= threshold:
            return f"{value / threshold:.1f} {suffix}"
    return f"{value:.0f} B"


VALUE_FORMATS = {
    "count": _compact,
    "number": _compact,
    "usd": lambda v: f"${_compact(v)}" if v >= 0 else f"-${_compact(-v)}",
    "bytes": _bytes,
    "percent": lambda v: f"{v:.0f}%",
}


def format_value(value: float, value_format: str = "count") -> str:
    """Format a number the way chart labels and KPI tiles show it:
    1,284 / 12.9K / $4.2M / 3.1 GiB / 87%."""
    return VALUE_FORMATS[value_format](float(value))


# ---------------------------------------------------------------- helpers
def _style_axes(ax, title: str | None, ylabel: str | None = None, value_axis: str = "y"):
    if title:
        ax.set_title(title, pad=14)
    if ylabel:
        if value_axis == "y":
            ax.set_ylabel(ylabel)
        else:
            ax.set_xlabel(ylabel)
    for side in ("top", "right", "left", "bottom"):
        ax.spines[side].set_visible(False)
    baseline = "bottom" if value_axis == "y" else "left"
    ax.spines[baseline].set_visible(True)
    ax.spines[baseline].set_color(BASELINE)
    ax.spines[baseline].set_linewidth(0.8)
    ax.tick_params(length=0, labelsize=8.5, pad=6)
    grid_axis = ax.yaxis if value_axis == "y" else ax.xaxis
    grid_axis.grid(True, color=GRIDLINE, linewidth=0.6, linestyle="-")
    ax.set_axisbelow(True)


def _value_axis_format(ax, value_axis: str, value_format: str, integer: bool) -> None:
    axis = ax.yaxis if value_axis == "y" else ax.xaxis
    if integer:
        axis.set_major_locator(MaxNLocator(integer=True, nbins=5))
    else:
        axis.set_major_locator(MaxNLocator(nbins=5))
    axis.set_major_formatter(FuncFormatter(lambda v, _pos: format_value(v, value_format)))


def _check_series_lengths(categories: list, series: dict[str, list]) -> None:
    for name, values in series.items():
        if len(values) != len(categories):
            raise ValueError(
                f"series {name!r} has {len(values)} value(s) but there are "
                f"{len(categories)} categories/labels -- lengths must match"
            )


def _series_colors(names: list[str]) -> list[str]:
    if len(names) > len(PALETTE):
        raise ValueError(
            f"{len(names)} series exceed the {len(PALETTE)} categorical colors -- "
            "fold the smallest into 'Other' before charting"
        )
    return PALETTE[: len(names)]


def _to_data_uri(fig) -> str:
    buf = io.BytesIO()
    fig.savefig(
        buf,
        format="svg",
        bbox_inches="tight",
        pad_inches=0.12,
        facecolor=SURFACE,
        metadata={"Date": None},
    )
    plt.close(fig)
    encoded = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/svg+xml;base64,{encoded}"


def _empty(title: str, figsize=(7, 2.2)) -> str:
    fig, ax = plt.subplots(figsize=figsize)
    ax.text(0.5, 0.5, "No data", ha="center", va="center", fontsize=10, color=INK_MUTED, transform=ax.transAxes)
    ax.axis("off")
    if title:
        ax.set_title(title, pad=14)
    return _to_data_uri(fig)


def _label_bars(ax, bars, values, value_format: str, horizontal: bool) -> None:
    labels = [format_value(v, value_format) for v in values]
    ax.bar_label(bars, labels=labels, padding=4, fontsize=8.5, color=INK_SECONDARY)
    # Leave room past the longest bar so its tip label isn't clipped.
    peak = max([v for v in values if v is not None] + [0])
    if peak > 0:
        if horizontal:
            ax.set_xlim(0, peak * 1.16)
        else:
            ax.set_ylim(0, peak * 1.14)


# ---------------------------------------------------------------- charts
def bar_chart(
    labels: list[str],
    values: list[float],
    title: str = "",
    ylabel: str = "",
    horizontal: bool = False,
    colors: list[str] | None = None,
    value_format: str = "count",
) -> str:
    """One series of bars, one color, each value labeled at its tip.

    `colors` is for bars whose color *means* something per bar (severity,
    pass/fail); leave it unset for an ordinary single series."""
    if not labels:
        return _empty(title)
    if colors is not None and len(colors) != len(labels):
        raise ValueError("colors must have one entry per bar")
    fill = colors or [PALETTE[0]] * len(labels)
    integer = value_format in ("count", "number") and all(float(v).is_integer() for v in values)
    if horizontal:
        fig, ax = plt.subplots(figsize=(7.2, max(1.6, 0.42 * len(labels) + 0.9)))
        bars = ax.barh(labels, values, color=fill, height=0.58)
        ax.invert_yaxis()
        _style_axes(ax, title, ylabel, value_axis="x")
        _value_axis_format(ax, "x", value_format, integer)
    else:
        fig, ax = plt.subplots(figsize=(7.2, 3.6))
        bars = ax.bar(labels, values, color=fill, width=0.56)
        if max(len(str(label)) for label in labels) > 10 or len(labels) > 6:
            plt.setp(ax.get_xticklabels(), rotation=30, ha="right")
        _style_axes(ax, title, ylabel, value_axis="y")
        _value_axis_format(ax, "y", value_format, integer)
    _label_bars(ax, bars, values, value_format, horizontal)
    fig.tight_layout()
    return _to_data_uri(fig)


def severity_chart(counts: dict[str, int], title: str = "", value_format: str = "count") -> str:
    """Horizontal bars in severity order (CRITICAL first), each in its
    severity color, zero levels omitted."""
    present = [s for s in SEVERITY_ORDER if counts.get(s)]
    if not present:
        return _empty(title)
    return bar_chart(
        present,
        [counts[s] for s in present],
        title=title,
        horizontal=True,
        colors=[SEVERITY_FILL[s] for s in present],
        value_format=value_format,
    )


def grouped_bar_chart(categories: list[str], series: dict[str, list[float]], title: str = "", ylabel: str = "", value_format: str = "count") -> str:
    import numpy as np

    _check_series_lengths(categories, series)
    names = list(series)
    colors = _series_colors(names)
    fig, ax = plt.subplots(figsize=(8, 4))
    n_series = len(series)
    x = np.arange(len(categories))
    width = min(0.8 / max(n_series, 1), 0.28)
    for i, name in enumerate(names):
        ax.bar(x + i * width, series[name], width * 0.92, label=name, color=colors[i])
    ax.set_xticks(x + width * (n_series - 1) / 2)
    ax.set_xticklabels(categories, rotation=30 if len(categories) > 4 else 0, ha="right" if len(categories) > 4 else "center")
    if n_series > 1:
        ax.legend(loc="upper left", bbox_to_anchor=(1.0, 1.0))
    _style_axes(ax, title, ylabel)
    values = [v for vals in series.values() for v in vals]
    _value_axis_format(ax, "y", value_format, all(float(v).is_integer() for v in values))
    fig.tight_layout()
    return _to_data_uri(fig)


def line_chart(x_labels: list[str], series: dict[str, list[float]], title: str = "", ylabel: str = "", value_format: str = "count") -> str:
    _check_series_lengths(x_labels, series)
    names = list(series)
    colors = _series_colors(names)
    fig, ax = plt.subplots(figsize=(8, 3.8))
    for i, name in enumerate(names):
        ax.plot(
            x_labels,
            series[name],
            label=name,
            color=colors[i],
            linewidth=2,
            solid_capstyle="round",
            solid_joinstyle="round",
            marker="o",
            markersize=6,
            markeredgecolor=SURFACE,
            markeredgewidth=1.5,
        )
    if len(names) > 1:
        ax.legend(loc="upper left", bbox_to_anchor=(1.0, 1.0))
    elif names and series[names[0]]:
        # One series: label its latest value, the number the reader wants.
        last = series[names[0]][-1]
        ax.annotate(
            format_value(last, value_format),
            (len(x_labels) - 1, last),
            textcoords="offset points",
            xytext=(0, 9),
            ha="center",
            fontsize=8.5,
            color=INK_SECONDARY,
        )
    if len(x_labels) > 6:
        plt.setp(ax.get_xticklabels(), rotation=30, ha="right")
    _style_axes(ax, title, ylabel)
    _value_axis_format(ax, "y", value_format, False)
    ax.set_ylim(bottom=0)
    fig.tight_layout()
    return _to_data_uri(fig)


def donut_chart(labels: list[str], values: list[float], title: str = "", value_format: str = "count", max_segments: int = 6) -> str:
    """Part-to-whole at a glance: a donut with the total in the middle and a
    legend carrying each segment's value and share. More than
    `max_segments` categories fold the smallest into "Other"."""
    pairs = [(str(label), float(v)) for label, v in zip(labels, values, strict=True) if v and v > 0]
    total = sum(v for _, v in pairs)
    if not pairs or total <= 0:
        return _empty(title, figsize=(6.5, 3.2))
    pairs.sort(key=lambda p: p[1], reverse=True)
    if len(pairs) > max_segments:
        head, tail = pairs[: max_segments - 1], pairs[max_segments - 1 :]
        pairs = head + [("Other", sum(v for _, v in tail))]
    colors = [OTHER_COLOR if label == "Other" else PALETTE[i] for i, (label, _) in enumerate(pairs)]
    fig, ax = plt.subplots(figsize=(7.2, 3.4))
    wedges, _ = ax.pie(
        [v for _, v in pairs],
        colors=colors,
        startangle=90,
        counterclock=False,
        wedgeprops={"width": 0.34, "edgecolor": SURFACE, "linewidth": 2},
    )
    ax.text(0, 0.1, format_value(total, value_format), ha="center", va="center", fontsize=15, fontweight="bold", color=INK_PRIMARY)
    ax.text(0, -0.2, "total", ha="center", va="center", fontsize=8.5, color=INK_MUTED)
    ax.set_aspect("equal")
    legend_labels = [f"{label}  {format_value(v, value_format)} ({100 * v / total:.0f}%)" for label, v in pairs]
    ax.legend(wedges, legend_labels, loc="center left", bbox_to_anchor=(1.02, 0.5), handlelength=1, handleheight=1)
    if title:
        ax.set_title(title, pad=10)
    fig.tight_layout()
    return _to_data_uri(fig)


def pie_chart(labels: list[str], values: list[float], title: str = "", value_format: str = "count") -> str:
    """Kept for existing callers; renders the donut form."""
    return donut_chart(labels, values, title=title, value_format=value_format)


def histogram(values: list[float], bins: int = 20, title: str = "", xlabel: str = "", ylabel: str = "Count") -> str:
    fig, ax = plt.subplots(figsize=(7.2, 3.6))
    ax.hist(values, bins=bins, color=PALETTE[0], edgecolor=SURFACE, linewidth=1)
    if xlabel:
        ax.set_xlabel(xlabel)
    _style_axes(ax, title, ylabel)
    ax.yaxis.set_major_locator(MaxNLocator(integer=True, nbins=5))
    fig.tight_layout()
    return _to_data_uri(fig)


def stacked_bar_chart(categories: list[str], series: dict[str, list[float]], title: str = "", ylabel: str = "", value_format: str = "count", colors: dict[str, str] | None = None) -> str:
    """Stacked columns. `colors` maps a series name to a color when the
    series carry meaning (severity); otherwise palette order applies."""
    import numpy as np

    _check_series_lengths(categories, series)
    names = list(series)
    fills = [colors[n] for n in names] if colors else _series_colors(names)
    fig, ax = plt.subplots(figsize=(8, 4))
    bottom = np.zeros(len(categories))
    for i, name in enumerate(names):
        values_arr = np.array(series[name], dtype=float)
        # The surface-colored edge is the 2px gap between stacked segments.
        ax.bar(categories, values_arr, bottom=bottom, label=name, color=fills[i], width=0.56, edgecolor=SURFACE, linewidth=1.2)
        bottom += values_arr
    ax.legend(loc="upper left", bbox_to_anchor=(1.0, 1.0))
    if len(categories) > 4:
        plt.setp(ax.get_xticklabels(), rotation=30, ha="right")
    _style_axes(ax, title, ylabel)
    _value_axis_format(ax, "y", value_format, all(float(v).is_integer() for vals in series.values() for v in vals))
    fig.tight_layout()
    return _to_data_uri(fig)
