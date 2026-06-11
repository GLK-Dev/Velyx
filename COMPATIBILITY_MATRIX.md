# Velyx Compatibility Matrix (draft-0.1)

## Protocol Baseline
1. Wire version: V1.
2. Handshake: Noise_XX_25519_ChaChaPoly_BLAKE2s.
3. Transport: UDP.

## Feature Matrix
| Feature | Spec | Reference Status | Interop Test Status |
|---|---|---|---|
| Wire framing and packet decoding | VEP-001 | Implemented | Passing |
| Capability negotiation | VEP-001 | Implemented | Passing |
| Capability bit registry | VEP-002 | Defined | Passing (mask vectors) |
| Replay window protection | VEP-001 | Implemented | Passing |
| ACK payload format | VEP-003 | Implemented in lib | Passing |
| Error payload format | VEP-003 | Implemented in lib | Passing |
| Session lifecycle model | VEP-004 | Specified | N/A (doc-level) |

## Capability Bits (V1)
| Bit | Hex | Name | Status |
|---|---|---|---|
| 0 | 0x0000000000000001 | CAP_FEC_V1 | Advertised |
| 1 | 0x0000000000000002 | CAP_DHT_V1 | Advertised |
| 2 | 0x0000000000000004 | CAP_OBFS_V1 | Advertised |
| 3 | 0x0000000000000008 | CAP_RELAY_V1 | Advertised |

## Interop Artifacts
1. test_vectors/wire_vectors.json
2. tests/interop.rs

## Client Guidance
1. External clients should target V1 only for draft-0.1.
2. Clients must fail closed on unsupported version or invalid negotiation echo.
3. Clients should validate ACK/Error payloads per VEP-003 before acting.
