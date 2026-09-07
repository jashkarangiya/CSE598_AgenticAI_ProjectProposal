#!/usr/bin/env python3
"""Render a command's real terminal output to an SVG for the README.

Stdlib only, same as everything else here. The point is that the images in the
README cannot drift from the code: they are regenerated from live output, and
CI-style verification just reruns this and diffs.

    python3 docs/render_svg.py
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

BG, FG, DIM, CHROME = "#0d1117", "#c9d1d9", "#6e7681", "#161b22"
RED, GREEN, AMBER, BLUE = "#ff7b72", "#3fb950", "#d29922", "#79c0ff"

# Longest match first: NOT_HALLUCINATED must win over HALLUCINATED.
WORDS = [
    ("NOT_HALLUCINATED", DIM), ("HALLUCINATED", RED), ("UNVERIFIED", AMBER),
    ("MISLOCATED", RED), ("DECLARED_ONLY", AMBER), ("LOCATED", GREEN),
    ("OUT_OF_RANGE", RED), ("IN_RANGE", GREEN), ("UNREACHABLE", AMBER),
    ("REACHABLE", GREEN), ("DEFINED", GREEN), ("MENTIONED", AMBER),
    ("ABSENT", RED), ("EXISTS", GREEN), ("STRIPPED", BLUE),
    ("REGRESSION", RED), ("FAIL", RED), ("PASS", GREEN),
    ("READ FIRST", GREEN), ("DEPRIORITIZE", DIM),
]
TOKEN_RE = re.compile("(%s)" % "|".join(w for w, _ in WORDS))
COLOR = dict(WORDS)

CW, LH, PAD, TOP = 8.4, 19.0, 18.0, 40.0   # char width, line height, padding


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def spans(line):
    """Colour whole status words; everything else inherits the default fill."""
    out = []
    for part in TOKEN_RE.split(line):
        if not part:
            continue
        if part in COLOR:
            out.append('<tspan fill="%s">%s</tspan>' % (COLOR[part], esc(part)))
        elif set(part.strip()) in ({"-"}, {"="}) and len(part.strip()) > 8:
            out.append('<tspan fill="%s">%s</tspan>' % (DIM, esc(part)))
        else:
            out.append(esc(part))
    return "".join(out)


def render(title, text, out_path):
    lines = text.rstrip("\n").split("\n")
    cols = max(len(l) for l in lines + [title]) + 2
    w = int(cols * CW + PAD * 2)
    h = int(TOP + len(lines) * LH + PAD)

    body = "\n".join(
        '  <text x="%.1f" y="%.1f" xml:space="preserve">%s</text>'
        % (PAD, TOP + i * LH, spans(l))
        for i, l in enumerate(lines))

    svg = '''<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" \
viewBox="0 0 {w} {h}" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" \
font-size="13.5">
  <rect width="{w}" height="{h}" rx="8" fill="{bg}"/>
  <rect width="{w}" height="28" rx="8" fill="{chrome}"/>
  <rect y="20" width="{w}" height="8" fill="{chrome}"/>
  <circle cx="18" cy="14" r="5" fill="#ff5f57"/>
  <circle cx="36" cy="14" r="5" fill="#febc2e"/>
  <circle cx="54" cy="14" r="5" fill="#28c840"/>
  <text x="72" y="18.5" fill="{dim}" font-size="12">{title}</text>
  <g fill="{fg}">
{body}
  </g>
</svg>
'''.format(w=w, h=h, bg=BG, chrome=CHROME, dim=DIM, fg=FG,
           title=esc(title), body=body)
    open(out_path, "w", encoding="utf-8").write(svg)
    return out_path, w, h


SHOTS = [
    ("demo.svg", "python3 demo.py", ["python3", "demo.py"]),
    ("queue.svg", "python3 slopgate.py corpus/reports --repo examples/target_repo",
     ["python3", "slopgate.py", "corpus/reports", "--repo", "examples/target_repo"]),
    ("eval.svg", "python3 eval/run_eval.py", ["python3", "eval/run_eval.py"]),
]


def main():
    for name, title, cmd in SHOTS:
        out = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
        if out.returncode:
            sys.exit("%s failed:\n%s%s" % (title, out.stdout, out.stderr))
        p, w, h = render(title, out.stdout, os.path.join(HERE, name))
        print("wrote %s (%dx%d)" % (os.path.relpath(p, ROOT), w, h))


if __name__ == "__main__":
    main()
