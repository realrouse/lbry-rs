# lbry-blob-iroh protocol

**ALPN:** `lbry-blob-iroh/1`

## Ticket

URL-safe base64 (no pad) of JSON `iroh::EndpointAddr`.

## Commands (one bi-stream each)

| Cmd | Value | Client sends | Server replies |
|-----|-------|--------------|----------------|
| Have | `1` | hash hex | `u8` 0/1 |
| GetBlob | `2` | hash hex | `u32` status; if OK then `u64` len + bytes |
| PutBlob | `3` | hash hex + `u64` len + bytes | `u32` status |

Hash on wire: `u8` length + ASCII hex (prefer lowercase). SHA-384 hex is 96 chars.

### Status codes

| Code | Meaning |
|------|---------|
| 0 | OK |
| 1 | Not found (Get) |
| 2 | Bad request |
| 3 | Hash mismatch (Put) |

## Put rules

1. Client claims hash H and sends body B.  
2. Server computes SHA-384(B) and requires equality with H (case-insensitive hex).  
3. Server writes `dir/<h>` and returns OK.  
4. Max body size: 3 MiB.

## Content model

See `lbry-blob`: LBRY-shaped sd JSON + encrypted content blobs. Transport does not replace content encryption keys.
