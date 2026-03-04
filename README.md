OI Verifier

Reference verifier and conformance suite for OI bundles.

This repository contains the reference implementation used to verify OI bundles.
Verification is deterministic, offline, and performed at the byte level.

What this is

OI provides tamper-evident evidence infrastructure.

Bundles are sealed with Ed25519 signatures and verified against the bundle manifest and checksums.

Verification checks:
	•	signature validity
	•	canonical JSON encoding
	•	artifact checksums
	•	bundle structure

SEALED means: the bundle has not been altered since sealing.
SEALED does NOT mean: true, complete, authorized, compliant, or admissible.

Quick start

Run verification against a bundle:

python verifier-kit/verify.py <bundle_path>

Example:

python verifier-kit/verify.py golden/cyber/bundle_valid

Conformance suite

The repository includes a deterministic conformance suite under:

conformance/

These vectors define the expected behavior of compliant verifiers.

Implementations that pass the conformance vectors should produce identical verification outcomes.

Repository structure

verifier-kit/        reference verification implementation
lib/                 canonical JSON + Ed25519 helpers
conformance/         verification test vectors
golden/              example sealed bundles
test_bundle_valid/   valid bundle examples
test_bundle_tampered/ tampered bundle examples

License

Apache License 2.0
:::
