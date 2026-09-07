# Out-of-bounds read in url_legacy_unescape()

**Severity:** High
**CWE:** CWE-125 Out-of-bounds Read
**Affected file:** lib/url.c
**Affected function:** url_legacy_unescape()
**Version:** minihttp-1_0

## Summary

`url_legacy_unescape()` advances the read pointer by three bytes whenever it
encounters a `%` character, without checking that two more bytes remain in the
string. A string ending in `%` walks the read pointer past the NUL terminator.

## Proof of concept

Pass a string ending in a bare `%`.
