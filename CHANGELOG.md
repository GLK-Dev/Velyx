# Changelog

All notable changes to Velyx will be documented in this file.

## [draft-0.1] - 2026-06-11
### Added
1. VEP-001: formal wire format, packet taxonomy, replay rules, capability negotiation.
2. VEP-002: capability-bit registry and extension policy.
3. VEP-003: error code registry and ACK semantics.
4. VEP-004: session state machine and lifecycle transitions.
5. Canonical interoperability vectors for wire, capability, ACK, and Error payloads.
6. Rust protocol primitives for WirePacket, ReplayWindow, Capability negotiation, AckFrame, and ErrorFrame.
7. Integration tests for vector stability and negotiation interop.
8. Project README with quick start and standards map.

### Changed
1. Whitepaper governance now references VEP-001 through VEP-004.
2. Runtime handshake now uses formal packet envelope and negotiated capabilities.

### Security
1. Replay detection and out-of-window rejection implemented.
2. Handshake echo validation enforces downgrade resistance.
