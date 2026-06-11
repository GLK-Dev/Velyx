# Release Draft 0.1

Version label: draft-0.1
Date: 2026-06-11
Author: mjojo (https://github.com/GLK-Dev)

## Included Standards
1. VEP-001
2. VEP-002
3. VEP-003
4. VEP-004

## Included Code and Tests
1. src/lib.rs protocol primitives and control frames.
2. src/main.rs handshake runtime baseline.
3. tests/interop.rs interoperability checks.
4. test_vectors/wire_vectors.json canonical vectors.

## Release Validation
1. cargo test passes.
2. Wire vectors are stable.
3. Negotiation vectors are stable.
4. ACK/Error vectors are stable.

## Recommended Tagging Command
Use after committing release files:

1. git tag -a draft-0.1 -m "Velyx draft-0.1: VEP-001..004 baseline"
2. git push origin draft-0.1
