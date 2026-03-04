# Conformance Test Suite — OpaqueInfra v1.1.0

Normative reference: `oi-docs/05_verification/04_conformance_test_vectors.md`

## Rule

No code merges to main unless ALL vectors pass.
Vectors win. If docs and vectors disagree, vectors are correct.

## Vector Classes

### TAMPER
Modified file content, altered checksums, corrupted signature.
Expected: INTEGRITY: BROKEN

### SCHEMA
Malformed receipt.json, invalid keyset.json, missing required fields,
unknown fields (additionalProperties: false).
Expected: INTEGRITY: BROKEN

### ZIP
Path traversal, symlinks, case collisions, NUL bytes, absolute paths.
Expected: INTEGRITY: BROKEN

### POLICY
Trust policy evaluation with allow/deny lists.
Expected: INTEGRITY: SEALED, TRUST_POLICY_OUTCOME varies.

### CHAINING
Chain gaps, wrong prev_bundle_hash, fork detection.
Expected: profile-driven FAIL or informational chain status.

---

## Red Team Regression Vectors (Normative — MUST be present)

These vectors were identified during the spec red team pass (2026-03-02).
They MUST be included to prevent regression on critical integrity properties.

### RT-01: Stale receipt.bundle_hash (CRITICAL — tests Step 4b)

- **Class:** TAMPER
- **Setup:** Bundle where checksums.sha256 and all file hashes are internally
  consistent, Ed25519 signature is mathematically valid, BUT receipt.json.bundle_hash
  does not match BHI recomputed from current checksums.sha256 + BUILD_INFO.json.
- **Attack:** Artifact modified post-sealing, checksums updated, receipt left unchanged.
- **Expected:** INTEGRITY: BROKEN (Step 4b fails)
- **Rationale:** Without this vector, a verifier that skips BHI recomputation
  would falsely report SEALED.

### RT-02: CRLF in checksums.sha256 (tests Step 3)

- **Class:** TAMPER
- **Setup:** Valid bundle except checksums.sha256 contains \r\n line endings
  instead of \n.
- **Expected:** INTEGRITY: BROKEN (Step 3 rejects CR bytes)

### RT-03: Signature key_id not in keyset.json (tests Step 6)

- **Class:** SCHEMA
- **Setup:** Valid bundle where receipt.json.signatures[0].key_id does not match
  any key_id in keyset.json.keys.
- **Expected:** INTEGRITY: BROKEN (Step 6 fails key resolution)

### RT-04: Trust policy with key fingerprint — allow (tests trust policy)

- **Class:** POLICY
- **Setup:** Valid SEALED bundle + trust policy where signing key's
  fingerprint_sha256 is in allow list.
- **Expected:** INTEGRITY: SEALED, TRUST_POLICY_OUTCOME: ALLOWED

### RT-05: Trust policy with key fingerprint — deny (tests deny-first)

- **Class:** POLICY
- **Setup:** Valid SEALED bundle + trust policy where signing key's
  fingerprint_sha256 is in both allow and deny lists.
- **Expected:** INTEGRITY: SEALED, TRUST_POLICY_OUTCOME: DENIED (deny-first)

### RT-06: Chain fork — duplicate prev_bundle_hash (tests fork detection)

- **Class:** CHAINING
- **Setup:** Three bundles where bundle B and bundle C both have
  prev_bundle_hash pointing to bundle A.
- **Expected:** CHAIN: FORK_DETECTED (informational)

---

## Directory Structure

```
conformance/
├── README.md              ← this file
├── vectors/
│   ├── RT-01/             ← one directory per vector
│   │   ├── bundle/        ← test bundle contents
│   │   ├── policy.json    ← trust policy (if applicable)
│   │   └── expected.json  ← expected verifier output
│   ├── RT-02/
│   ├── RT-03/
│   ├── RT-04/
│   ├── RT-05/
│   ├── RT-06/
│   └── ...                ← additional TAMPER/SCHEMA/ZIP vectors
└── run_conformance.sh     ← runs verifier against all vectors, reports pass/fail
```

## expected.json Format

```json
{
  "integrity": "SEALED" or "BROKEN",
  "trust_policy_outcome": "ALLOWED" or "DENIED" or "NOT_APPLIED",
  "chain": "OK" or "FORK_DETECTED" or "NOT_PRESENT",
  "must_contain_failure_step": "4b" (optional — asserts specific step failed)
}
```

## Running

```bash
./conformance/run_conformance.sh
```

Exit 0 = all vectors pass. Exit 1 = at least one failure. No merge on failure.
