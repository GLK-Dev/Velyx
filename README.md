# Velyx Protocol

Velyx is a next-generation open P2P protocol built for hostile network realities: secure by default, negotiation-driven, and engineered for cross-implementation interoperability.

If you want a protocol that is not just a codebase but a future standard, this is that project.

## Why Velyx
1. Cryptography first: Noise XX handshake + encrypted transport mode.
2. Explicit wire contract: deterministic binary framing with strict validation.
3. Real interoperability path: published VEP standards and test vectors.
4. Upgrade-friendly design: version ranges and capability negotiation.
5. Anti-fragile roadmap: replay protection, ACK semantics, and extensible registries.

## Project Highlights
1. Language: Rust.
2. Security baseline: Ed25519 identities and Noise_XX_25519_ChaChaPoly_BLAKE2s.
3. Formal docs: Whitepaper + VEP-001/002/003.
4. Interop tests: stable vectors for wire and negotiation payloads.

## Standards Track
1. VEP-001: Wire format and capability negotiation.
2. VEP-002: Capability bit registry.
3. VEP-003: Error codes and ACK semantics.

## Repository Layout
1. src/main.rs: MVP node (initiator/responder) runtime.
2. src/lib.rs: protocol primitives (wire packet, replay window, negotiation structs).
3. tests/interop.rs: interoperability tests.
4. test_vectors/wire_vectors.json: canonical vectors.
5. WHITEPAPER.md: architecture and long-term direction.
6. VEP-001.md, VEP-002.md, VEP-003.md: normative drafts.

## Quick Start
Requirements:

1. Rust toolchain (stable).

Build and test:

1. cargo check
2. cargo test

Run responder:

1. cargo run -- responder 0.0.0.0:9000

Run initiator:

1. cargo run -- initiator 0.0.0.0:0 127.0.0.1:9000

Expected result:

1. Successful secure handshake.
2. Negotiated version/capabilities printed in logs.
3. Encrypted ping/pong exchange completed.

## Vision
Velyx is designed to become a global, open, developer-owned protocol standard.

Not a closed product.
Not security by obscurity.
A transparent protocol with rigorous drafts, test vectors, and reproducible behavior.

## Author
mjojo (https://github.com/GLK-Dev)

## Contributing
Contributions are welcome in three lanes:

1. Security review and cryptographic analysis.
2. Alternative client implementations for interop testing.
3. VEP proposals for protocol evolution.

When proposing protocol changes, include:

1. Wire-level impact.
2. Backward-compatibility analysis.
3. Test vectors and test updates.

## License
GPL-3.0-only. See LICENSE.
