# Velyx Protocol Whitepaper (Draft v0.1)

## Abstract
Velyx is a censorship-resilient, privacy-first, and high-availability P2P protocol intended for global open standardization.
The protocol combines modern authenticated encryption, metadata minimization, and erasure/fountain-style data coding to improve survivability and transfer continuity under adversarial network conditions.

## 1. Problem Statement
Current P2P systems still face four persistent constraints:

1. DPI detectability and selective throttling.
2. Metadata leakage (who talks to whom, when, and how much).
3. Content availability collapse when rare blocks disappear.
4. Upgrade friction when cryptographic primitives evolve.

## 2. Goals and Non-Goals
### Goals
1. Fast authenticated session setup over UDP-based transport.
2. Strong forward secrecy and cryptographic agility.
3. Practical anti-censorship transport obfuscation.
4. Robust data reconstruction with packet loss tolerance.
5. Open governance for protocol evolution.

### Non-Goals
1. Perfect anonymity under all global passive adversaries.
2. Immediate replacement of all existing BitTorrent deployments.
3. Mandatory token economics at protocol layer.

## 3. Threat Model
Velyx defends primarily against:

1. Passive traffic collection.
2. Active packet tampering/injection.
3. Replay attempts.
4. Network-level filtering and throttling.

Velyx does not assume trusted infrastructure and should remain useful with partially malicious peers.

## 4. Protocol Stack
1. Transport Layer: UDP baseline, QUIC-compatible framing path for future versions.
2. Secure Channel Layer: Noise framework handshake (initially XX pattern).
3. Peer Discovery Layer: DHT-compatible routing and optional rendezvous relays.
4. Data Plane Layer: chunk graph + fountain/FEC extension.
5. Control Plane Layer: session management, capability negotiation, and versioning.

## 5. Cryptography
1. Session handshake: Noise_XX_25519_ChaChaPoly_BLAKE2s (MVP baseline).
2. Node identity: Ed25519 public key as stable peer identity.
3. Forward secrecy: ephemeral DH in each session handshake.
4. Roadmap: post-quantum hybrid KEM option (e.g., Kyber + X25519).

## 6. Data Dissemination and Integrity
Velyx roadmap introduces a fountain/FEC mode for swarm resilience:

1. Source object split into k symbols.
2. Encoder generates an arbitrary stream of coded symbols.
3. Receiver reconstructs original object after collecting k + m symbols.

Approximate recovery behavior:

P_success(m) ~ 1 - 256^(-m)

This removes strict dependence on rare block availability and improves recovery under churn.

## 7. Anti-Censorship Strategy
1. Pluggable transports with traffic-shape adaptation.
2. Session camouflage profiles (timing and packet-size envelopes).
3. Optional relay-assisted NAT traversal and fallback routes.

## 8. Governance and Standardization
1. Open-source reference implementation (Rust) under copyleft or dual-license model.
2. VEP process (Velyx Enhancement Proposals).
3. Security audits, reproducible builds, and interop test vectors.

## 9. MVP Scope (Current Implementation)
1. Peer ID generation (Ed25519).
2. UDP socket communication.
3. Noise XX handshake between initiator and responder.
4. Encrypted ping/pong exchange after handshake.

## 10. Milestones
1. M1: handshake + encrypted transport baseline.
2. M2: DHT discovery + NAT traversal prototype.
3. M3: coded data plane (fountain/FEC).
4. M4: obfuscation plugin framework.
5. M5: third-party security review and VEP-1 release.

## 11. Open Questions
1. Which obfuscation profiles are safest under modern DPI heuristics?
2. Should relay incentives be protocol-native or application-level?
3. Which post-quantum transition schedule minimizes deployment risk?

## 12. Conclusion
Velyx aims to become a practical open P2P standard optimized for adversarial network realities: secure by default, resilient under churn, and incrementally evolvable.
