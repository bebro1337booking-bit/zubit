#!/usr/bin/env python3
"""Generate the Zubit README images (stdlib only).

    python zubit/assets/make_images.py

Writes banner.svg, how-it-works.svg and social-preview.svg next to this file.
The style follows the logo: #FED102 yellow, pastel pink / cyan / lavender, black pixel outlines.
"""

from __future__ import annotations

import base64
import os
import random
from html import escape

HERE = os.path.dirname(os.path.abspath(__file__))

YELLOW = "#FED102"
INK = "#16121C"
CREAM = "#FFF8DC"
PINK = "#F7A6E4"
CYAN = "#8DE6F2"
LAV = "#B59BF3"
MINT = "#BDF2C4"

MONO = "Consolas, 'Cascadia Mono', 'DejaVu Sans Mono', 'Liberation Mono', 'Courier New', monospace"
CHAR_W = 0.6  # monospace advance as a fraction of font size


def notch(x: float, y: float, w: float, h: float, c: float) -> str:
    """Rectangle with stepped (pixel) corners."""
    pts = [
        (x + c, y), (x + w - c, y), (x + w - c, y + c), (x + w, y + c),
        (x + w, y + h - c), (x + w - c, y + h - c), (x + w - c, y + h), (x + c, y + h),
        (x + c, y + h - c), (x, y + h - c), (x, y + c), (x + c, y + c),
    ]
    return " ".join(f"{px:.0f},{py:.0f}" for px, py in pts)


def pixel_box(x, y, w, h, fill, border=4, shadow=8, corner=8) -> str:
    out = []
    if shadow:
        out.append(f'<polygon points="{notch(x + shadow, y + shadow, w, h, corner)}" fill="{INK}"/>')
    out.append(f'<polygon points="{notch(x, y, w, h, corner)}" fill="{INK}"/>')
    out.append(
        f'<polygon points="{notch(x + border, y + border, w - 2 * border, h - 2 * border, corner - border / 2)}" fill="{fill}"/>'
    )
    return "".join(out)


def text(x, y, s, size, fill=INK, weight="normal", anchor="start", extra="") -> str:
    return (
        f'<text x="{x}" y="{y}" font-family="{MONO}" font-size="{size}" font-weight="{weight}" '
        f'fill="{fill}" text-anchor="{anchor}" {extra}>{escape(s)}</text>'
    )


def sparkle(x, y, s, color) -> str:
    return (
        f'<rect x="{x - s / 2}" y="{y - 1.5 * s}" width="{s}" height="{3 * s}" fill="{color}"/>'
        f'<rect x="{x - 1.5 * s}" y="{y - s / 2}" width="{3 * s}" height="{s}" fill="{color}"/>'
        f'<rect x="{x - s / 2}" y="{y - s / 2}" width="{s}" height="{s}" fill="#FFFFFF"/>'
    )


def confetti(w, h, n, seed, avoid=()) -> str:
    rng = random.Random(seed)
    out = []
    colors = [CYAN, PINK, CREAM, LAV]
    for _ in range(n):
        x, y = rng.uniform(10, w - 10), rng.uniform(10, h - 10)
        if any(ax <= x <= ax + aw and ay <= y <= ay + ah for ax, ay, aw, ah in avoid):
            continue
        s = rng.choice([6, 8, 10])
        out.append(f'<rect x="{x:.0f}" y="{y:.0f}" width="{s}" height="{s}" fill="{rng.choice(colors)}" opacity="0.9"/>')
    return "".join(out)


def chip(x, y, label, fill, size=18) -> tuple[str, float]:
    w = len(label) * CHAR_W * size + 30
    h = size + 20
    svg = pixel_box(x, y, w, h, fill, border=3, shadow=5, corner=6) + text(
        x + w / 2, y + h / 2 + size * 0.36, label, size, weight="bold", anchor="middle"
    )
    return svg, w


def arrow_right(x, y, length=28) -> str:
    return (
        f'<rect x="{x}" y="{y - 3}" width="{length - 10}" height="6" fill="{INK}"/>'
        f'<polygon points="{x + length - 12},{y - 11} {x + length},{y} {x + length - 12},{y + 11}" fill="{INK}"/>'
    )


def logo_data_uri() -> str:
    with open(os.path.join(HERE, "logo-440.jpg"), "rb") as f:
        return "data:image/jpeg;base64," + base64.b64encode(f.read()).decode()


def svg(w, h, body, title) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" '
        f'role="img" aria-label="{escape(title)}" shape-rendering="crispEdges">'
        f"<title>{escape(title)}</title>{body}</svg>\n"
    )


def hero(w, h, logo_size, logo_xy, text_x, title_y, seed) -> str:
    """Shared banner / social-preview layout."""
    lx, ly = logo_xy
    body = [f'<rect width="{w}" height="{h}" fill="{YELLOW}"/>']
    body.append(confetti(w, h, 70, seed, avoid=[(lx, ly, logo_size, logo_size), (text_x - 10, title_y - 110, w, 330)]))
    body.append(sparkle(w - 70, 60, 8, LAV))
    body.append(sparkle(text_x + 30, h - 38, 6, CYAN))
    body.append(
        f'<image href="{logo_data_uri()}" x="{lx}" y="{ly}" width="{logo_size}" height="{logo_size}" '
        f'image-rendering="optimizeQuality"/>'
    )
    # Title with a hard pixel shadow.
    t = "Zubit"
    body.append(text(text_x + 7, title_y + 7, t, 128, fill=INK, weight="bold"))
    body.append(
        text(text_x, title_y, t, 128, fill=CREAM, weight="bold",
             extra=f'stroke="{INK}" stroke-width="5" paint-order="stroke" stroke-linejoin="miter"')
    )
    subtitle = "Quantum Resistant Zebra for Zcash Blockchain"
    sub_size = min(33, int((w - text_x - 40) / (len(subtitle) * CHAR_W)))
    body.append(text(text_x + 2, title_y + 56, subtitle, sub_size, weight="bold"))
    # Tagline card.
    card_y = title_y + 84
    body.append(pixel_box(text_x, card_y, min(730, w - text_x - 40), 92, CREAM))
    body.append(text(text_x + 24, card_y + 38, "Post-quantum ML-DSA-44 signatures for", 21))
    body.append(text(text_x + 24, card_y + 68, "transparent ZEC, as a soft fork in Zebra", 21))
    # Chips.
    cx = text_x
    for label, fill in [("FIPS 204", PINK), ("Rust", CYAN), ("Zebra 6.4.2", LAV), ("Regtest demo", MINT)]:
        s, cw = chip(cx, card_y + 118, label, fill)
        body.append(s)
        cx += cw + 22
    return "".join(body)


def banner() -> str:
    w, h = 1280, 480
    body = hero(w, h, 440, (24, 20), 500, 170, seed=1)
    body += text(w - 24, h - 18, "research fork · not active on mainnet", 14, anchor="end", extra='opacity="0.75"')
    return svg(w, h, body, "Zubit — Quantum Resistant Zebra for Zcash Blockchain")


def social_preview() -> str:
    # GitHub social preview: 1280x640.
    w, h = 1280, 640
    body = hero(w, h, 520, (8, 60), 540, 250, seed=2)
    return svg(w, h, body, "Zubit — Quantum Resistant Zebra for Zcash Blockchain")


def how_it_works() -> str:
    w, h = 1280, 700
    b = [f'<rect width="{w}" height="{h}" fill="{YELLOW}"/>']
    b.append(confetti(w, h, 26, 3, avoid=[(0, 80, w, 600), (20, 10, 900, 75)]))
    b.append(text(40, 62, "How Zubit protects a transparent output", 36, weight="bold"))

    cards = [
        ("1 · KEY", PINK, [
            ("ML-DSA-44 (FIPS 204)", "bold"),
            ("public key   1 312 B", ""),
            ("signature    2 420 B", ""),
            ("secret key stays in", ""),
            ("the wallet", ""),
        ]),
        ("2 · LOCK  (P2PQH output)", CYAN, [
            ('04 "ZUB1" OP_DROP', "bold"),
            ("20 <BLAKE2b-256(pk)>", "bold"),
            ("39-byte scriptPubKey", ""),
            ("commits to the key's", ""),
            ("hash only", ""),
        ]),
        ("3 · SPEND", LAV, [
            ("scriptSig = pk || sig", "bold"),
            ("8 canonical pushes", ""),
            ("3 755 bytes", ""),
            ("signs ZIP 244 SIGHASH_ALL", ""),
            ('context "Zubit-v1"', ""),
        ]),
    ]
    cw, ch, gap, top = 368, 250, 48, 100
    for i, (head, color, lines) in enumerate(cards):
        x = 40 + i * (cw + gap)
        b.append(pixel_box(x, top, cw, ch, CREAM))
        b.append(f'<rect x="{x + 4}" y="{top + 4}" width="{cw - 8}" height="46" fill="{color}"/>')
        b.append(f'<rect x="{x + 4}" y="{top + 50}" width="{cw - 8}" height="4" fill="{INK}"/>')
        b.append(text(x + 20, top + 36, head, 19, weight="bold"))
        for j, (line, weight) in enumerate(lines):
            b.append(text(x + 20, top + 92 + j * 33, line, 18, weight=weight or "normal"))
        if i < 2:
            b.append(arrow_right(x + cw + 12, top + ch / 2, 30))

    # Validation pipeline.
    py = 400
    b.append(pixel_box(40, py, 1200, 250, CREAM))
    b.append(text(64, py + 44, "Zebra checks every P2PQH spend (after the activation height)", 21, weight="bold"))
    steps = [
        ("Legacy Script", "push-only, passes", CREAM),
        ("Version", "tx must be v5+", CREAM),
        ("Key commitment", "BLAKE2b(pk) = hash", CREAM),
        ("ML-DSA-44", "verify over sighash", CREAM),
        ("Accept tx", "otherwise: reject", MINT),
    ]
    sw, sgap, sy = 196, 40, py + 78
    for i, (head, sub, fill) in enumerate(steps):
        x = 64 + i * (sw + sgap)
        b.append(pixel_box(x, sy, sw, 96, fill if i == 4 else "#FFFFFF", border=3, shadow=5, corner=6))
        b.append(text(x + sw / 2, sy + 40, head, 18, weight="bold", anchor="middle"))
        b.append(text(x + sw / 2, sy + 70, sub, 14, anchor="middle"))
        if i < 4:
            b.append(arrow_right(x + sw + 6, sy + 48, 28))
    b.append(text(64, py + 214, "Old nodes see P2PQH as anyone-can-spend, so the rule is a soft fork.", 16))
    b.append(text(64, py + 236, "Before activation the mempool refuses to create or spend P2PQH outputs.", 16))
    return svg(w, h, "".join(b), "How Zubit protects a transparent output")


def demo_terminal() -> str:
    """Terminal render of a real `zubit-wallet demo` run (regtest/demo-output.txt)."""
    import re

    path = os.path.join(HERE, "demo-output.txt")
    with open(path, encoding="utf-8") as f:
        raw = [line.rstrip("\n") for line in f]

    lines: list[tuple[str, str]] = []
    for line in raw:
        m = re.search(r"original error: (Qr\(\w+\))", line)
        if m:
            lines.append(("       node: " + m.group(1), PINK))
        elif "[ok] rejected" in line:
            lines.append((line.replace("[ok] rejected:", "✗ rejected:"), "#FFFFFF"))
        elif line.startswith("["):
            lines.append((line, CYAN))
        elif "mined at height" in line or line.startswith("Demo passed"):
            lines.append((re.sub(r"\b([0-9a-f]{12})[0-9a-f]{52}\b", r"\1…", line), MINT))
        elif line.strip():
            lines.append((re.sub(r"\b([0-9a-f]{16})[0-9a-f]{20,}\b", r"\1…", line), "#E8E4F0"))
        else:
            lines.append(("", "#FFFFFF"))

    size, lh = 16, 25
    w = 1280
    h = 110 + lh * len(lines)
    b = [f'<rect width="{w}" height="{h}" fill="{YELLOW}"/>']
    b.append(pixel_box(24, 20, w - 56, h - 48, INK, border=4, shadow=8))
    b.append(f'<rect x="28" y="24" width="{w - 64}" height="40" fill="{LAV}"/>')
    b.append(f'<rect x="28" y="64" width="{w - 64}" height="4" fill="{INK}"/>')
    for i, c in enumerate([PINK, CYAN, MINT]):
        b.append(f'<rect x="{48 + i * 26}" y="36" width="16" height="16" fill="{c}" stroke="{INK}" stroke-width="3"/>')
    b.append(text(w / 2, 50, "zubit-wallet demo 127.0.0.1:18232 demo-key.json", 16, weight="bold", anchor="middle"))
    for i, (line, color) in enumerate(lines):
        b.append(text(52, 100 + i * lh, line, size, fill=color, extra='xml:space="preserve"'))
    return svg(w, h, "".join(b), "Output of the Zubit Regtest demo")


def main() -> None:
    for name, content in [
        ("banner.svg", banner()),
        ("how-it-works.svg", how_it_works()),
        ("social-preview.svg", social_preview()),
        ("demo.svg", demo_terminal()),
    ]:
        with open(os.path.join(HERE, name), "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
        print("wrote", name, len(content), "bytes")


if __name__ == "__main__":
    main()
