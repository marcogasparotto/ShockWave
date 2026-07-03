"""Shockwave Theme - Purple & Black color palette, icons and gradient helpers."""

from rich.text import Text

# ---------------------------------------------------------------------------
# Palette  (roxo / preto / tons intermediarios)
# ---------------------------------------------------------------------------

PRIMARY = "medium_purple"          # roxo medio - titulos e labels
PRIMARY_DIM = "purple4"            # roxo escuro - bordas
ACCENT = "bright_magenta"         # magenta vibrante - destaques
SECONDARY = "medium_orchid"       # orquidea - complementar
SUCCESS = "magenta"               # magenta para sucesso
WARNING = "dark_orange"           # laranja escuro para avisos
DANGER = "red1"                   # vermelho para erros
TEXT = "grey89"                   # texto principal
MUTED = "grey42"                  # texto secundario
BG_DARK = "grey7"                 # fundo escuro
HIGHLIGHT = "plum1"               # destaque claro

BORDER_STYLE = "purple4"

# ---------------------------------------------------------------------------
# Icons
# ---------------------------------------------------------------------------

ICONS = {
    "target": "\u25ce",
    "status": "\u26a1",
    "time": "\u25f7",
    "user": "\u2609",
    "info": "\u25b8",
    "success": "\u2713",
    "error": "\u2715",
    "warning": "!",
    "section": "\ua945",
    "arrow": "\u2192",
    "lock": "\U0001f512",
    "globe": "\U0001f310",
    "scan": "\u25c9",
    "network": "\u2b82",
    "packet": "\u25a3",
    "chart": "\u2593",
    "report": "\u2261",
    "shield": "\u25c6",
}

# ---------------------------------------------------------------------------
# Gradient helpers  (roxo escuro -> roxo claro / magenta)
# ---------------------------------------------------------------------------

GRADIENT_START = (75, 0, 130)      # indigo escuro
GRADIENT_MID = (148, 0, 211)       # violeta
GRADIENT_END = (218, 112, 214)     # orquidea


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
