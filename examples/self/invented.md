# Sanitizer bypass in normalize_report_encoding()

**Severity:** High
**CWE:** CWE-74
**Affected file:** src/slopgate/extract.py
**Affected function:** normalize_report_encoding
**Affected line:** 30
**Version:** minihttp-1_0

## Summary

`normalize_report_encoding()` decodes percent-escapes after `sanitize()` has
run, so an encoded instruction span survives into the model prompt.

## Proof of concept

Submit a report whose injection payload is percent-encoded.
