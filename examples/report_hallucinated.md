# Heap buffer overflow in curl_easy_parse_header()

**Severity:** Critical
**CWE:** CWE-122 Heap-based Buffer Overflow
**Affected file:** lib/http_chunks.c
**Affected function:** curl_easy_parse_header()
**Affected line:** 214
**Version:** minihttp-1_0

## Summary

The function `curl_easy_parse_header()` in `lib/http_chunks.c` copies the
attacker-supplied header value into a fixed 256-byte stack buffer without
validating its length. A remote server returning an oversized header can
overwrite the saved return address and achieve remote code execution.

## Proof of concept

Send a response containing a header longer than 256 bytes. The call chain is
`chunk_decode()` -> `curl_easy_parse_header()` -> `memcpy()`.

## Suggested patch

Bound the copy with `outlen` before calling `memcpy()`.
