# Length-confusion heap overflow in chunk_decode()

**Severity:** High
**CWE:** CWE-787 Out-of-bounds Write
**Affected file:** lib/http_chunks.c
**Affected function:** chunk_decode()
**Version:** minihttp-1_0

## Summary

`chunk_decode()` calls `chunk_read_size()` to obtain the declared chunk length
`want`, grows the destination to `want` bytes, and then executes
`memcpy(st->data, buf, want)`. The declared length is never compared against
`len`, the number of bytes actually present in `buf`. A response advertising a
chunk larger than the bytes delivered causes a read past the end of `buf`.

## Proof of concept

Call `chunk_decode(&st, "ffff\r\nA", 7)`. The declared size is 65535 but only
7 bytes are available.

## Suggested patch

Clamp `want` to the remaining bytes in `buf` before the copy.
