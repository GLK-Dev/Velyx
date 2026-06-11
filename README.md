# Velyx Protocol

![Status](https://img.shields.io/badge/status-active%20development-orange)
![Rust](https://img.shields.io/badge/rust-2024%20edition-blue)
![License](https://img.shields.io/badge/license-GPL--3.0--only-blue)

**A censorship-resilient, fountain-encoded peer-to-peer protocol for hostile networks.**

Velyx is a Rust-based P2P network stack designed for privacy-sensitive and loss-prone environments. It combines authenticated Noise handshakes, deterministic wire framing, and fountain-coded data delivery to keep sessions moving when conventional P2P systems stall.

---

## The Whitepaper

For the full protocol model, threat assumptions, and benchmark narrative, read the whitepaper:

👉 [Velyx Whitepaper](./WHITEPAPER.md)

---

## The Problem

Legacy P2P stacks still fail in the places modern users actually live:

1. DPI and ISP filtering can identify plaintext handshakes and routing traffic.
2. Rare-piece availability can collapse a transfer when one peer disappears.
3. Lossy, jittery links make ARQ-heavy protocols degrade sharply under pressure.
4. Ad hoc extensions make interoperability and upgrades difficult to reason about.

## The Solution

Velyx rebuilds the stack around three core ideas:

* **Infinite Swarm Dynamics (RaptorQ):** data is sent as coded symbols instead of fixed file pieces, so receivers recover from any sufficient subset.
* **Noise_XX handshakes:** the transport is encrypted from the first packet, with identity and capability negotiation folded into a compact secure channel setup.
* **VWP framing:** a custom UDP wire protocol provides explicit packet types, session state, replay protection, and control-channel teardown semantics.

## Benchmarks

Velyx includes a benchmark harness and chaotic network profiles to measure survivability under loss, reorder, jitter, and teardown stress.

![Survivability Curve](./charts/survivability_curve.png)

![AllFrames Stress Test](./charts/allframes_stress.png)

Velyx is built to finish sessions where TCP would time out or stall.

## Getting Started

Requirements:

1. Rust stable toolchain.
2. Python 3.8+ for chart generation.

Build and test:

1. `cargo check`
2. `cargo test`

Run a benchmark matrix:

1. `cargo run --release -- benchmark whitepaper_benchmarks.csv --payload-bytes 262144`

Generate charts:

1. `python scripts/plot_benchmarks.py --input whitepaper_benchmarks.csv --outdir charts`

## Documentation

📚 [Read the Velyx Whitepaper](./WHITEPAPER.md)

## Roadmap

Planned work on the path to 1.0:

1. Kademlia DHT integration for decentralized peer discovery.
2. WebRTC and QUIC-oriented pluggable transport modes.
3. Stronger obfuscation profiles for DPI-heavy environments.
4. More benchmark profiles and interop vectors.

## Contributing

Contributions are welcome from network engineers, cryptographers, and Rust developers.

Useful contributions include:

1. Security review and protocol analysis.
2. Interoperability testing and alternate implementations.
3. Benchmark profiles, charts, and reproducibility improvements.
4. VEP drafts and wire-level compatibility proposals.

## License

GPL-3.0-only. See [LICENSE](./LICENSE).
