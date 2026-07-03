"""Shockwave Theme - Centralized color palette, icons and gradient helpers."""

from rich.text import Text

# ---------------------------------------------------------------------------
# Palette
# ---------------------------------------------------------------------------

PRIMARY = "medium_orchid1"
PRIMARY_DIM = "dark_magenta"
ACCENT = "bright_cyan"
SUCCESS = "spring_green2"
WARNING = "gold1"
DANGER = "bright_red"
TEXT = "grey93"
MUTED = "grey50"

BORDER_STYLE = PRIMARY_DIM

# ---------------------------------------------------------------------------
# Icons
# ---------------------------------------------------------------------------

ICONS = {
    "target": "◎",
    "status": "⚡",
    "time": "◷",
    "user": "☉",
    "info": "▸",
    "success": "✓",
    "error": "✕",
    "warning": "!",
    "section": "ꕥ",
    "arrow": "→",
}

# ---------------------------------------------------------------------------
# Gradient helpers
# ---------------------------------------------------------------------------

GRADIENT_START = (177, 60, 255)
GRADIENT_END = (0, 220, 255)


def _lerp(a, b, t):
    return int(a + (b - a) * t)


def _hex(rgb):
    return "#{:02x}{:02x}{:02x}".format(*rgb)


def gradient_style(index, total, start=GRADIENT_START, end=GRADIENT_END):
    t = 0 if total <= 1 else index / (total - 1)
    rgb = tuple(_lerp(start[i], end[i], t) for i in range(3))
    return _hex(rgb)


def gradient_text(lines):
    text = Text(no_wrap=True, overflow="crop")
    total = len(lines)

    for i, line in enumerate(lines):
        style = f"bold {gradient_style(i, total)}"
        text.append(line + "\n", style=style)

    return text


def gradient_inline(s):
    text = Text(no_wrap=True, overflow="crop")
    n = len(s)

    for i, ch in enumerate(s):
        style = f"bold {gradient_style(i, n)}"
        text.append(ch, style=style)

    return text