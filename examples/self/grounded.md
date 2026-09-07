# Unbounded input to strip_comments()

**Severity:** Medium
**CWE:** CWE-400
**Affected file:** src/slopgate/ground.py
**Affected function:** strip_comments
**Affected line:** 46
**Version:** minihttp-1_0

## Summary

`strip_comments()` runs an unbounded regex over whole files with no size cap,
so a pathological source file could dominate triage time.

## Proof of concept

Point `--repo` at a tree containing a multi-megabyte generated source file.
