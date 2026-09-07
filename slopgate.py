#!/usr/bin/env python3
"""SlopGate entry point.

    python3 slopgate.py REPORT.md            # one report, full evidence bundle
    python3 slopgate.py inbox/               # a queue, ranked by what to read first
    python3 slopgate.py inbox/ --repo ../curl

`src` goes on the path ahead of this directory so that `slopgate` resolves to
the package rather than to this launcher, which shares its name.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from slopgate.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
