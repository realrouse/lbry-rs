# lbry-rs

Rust crates for **LBRY-shaped content** and **Iroh P2P transfer**.

Seed of a Rust LBRY **data plane**: stream descriptors, SHA-384 blobs, AES-256-CBC, and a download/**upload** superpeer over Iroh (relay-friendly). Not a full wallet/chain port.

**Repo:** https://github.com/realrouse/lbry-rs

## Crates

| Crate | Path | Role |
|-------|------|------|
| **`lbry-blob`** | `crates/lbry-blob` | Pack/parse sd, hash verify, encrypt/decrypt, disk store |
| **`lbry-blob-iroh`** | `crates/lbry-blob-iroh` | ALPN `lbry-blob-iroh/1`: Have / Get / **Put**, tickets, superpeer loop |
| **`browser-superpeer`** | `bins/browser-superpeer` | CLI + localhost companion (play + **web upload**) |

## Protocol (summary)

- **Have** / **GetBlob** — download peer  
- **PutBlob** — peer upload; superpeer verifies `SHA-384(bytes) == claimed hash` then stores (P2P reflector-style storage, not classic LBRY upload-RPC product surface)

See [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Quick start

```bash
cargo build --release

# Terminal 1: empty or seed store
mkdir -p /tmp/sp-blobs
./target/release/browser-superpeer superpeer --blobs /tmp/sp-blobs
# copy ticket

# Terminal 2: CLI pack + upload
./target/release/browser-superpeer pack --input fixtures/source_demo.wav --out /tmp/mypack
./target/release/browser-superpeer upload --ticket 'TICKET' --blobs /tmp/mypack

# Fetch elsewhere
./target/release/browser-superpeer fetch --ticket 'TICKET' --sd-hash "$(jq -r .sd_hash /tmp/mypack/DEMO.json)" --out /tmp/out.wav

# Web companion (play + upload UI)
./target/release/browser-superpeer companion
# open http://127.0.0.1:8787
```

Demo fixtures (pre-packed) live under `fixtures/demo/`.

## Roadmap (next, not done here)

1. ~~Upload over Iroh (CLI then web)~~ — this release  
2. **P2P CDN** — leechers re-share verified blobs; reuse Iroh demo patterns  
3. Language eval notes — keep blob crypto in Rust; wallet stay out of scope  

## Related research

Planning notes live in [rouse-willgrokit](https://github.com/realrouse/rouse-willgrokit) (`research/scoped-mvp-browser-superpeer`, etc.).

## License

MIT OR Apache-2.0
