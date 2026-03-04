# OpaqueInfra Verifier

Offline, deterministic integrity verification for OpaqueInfra evidence bundles.

## What it does

The OpaqueInfra verifier checks sealed evidence bundles at the byte level. It produces a binary verdict: `INTEGRITY: SEALED` or `INTEGRITY: BROKEN`. It runs offline — no network, no account, no vendor infrastructure required.

## Quick start

```
pip install cryptography
python3 verifier-kit/verify.py path/to/bundle/
python3 verifier-kit/verify.py bundle.zip
```

## What SEALED means

- The bundle has not been modified since sealing
- The Ed25519 signature is mathematically valid

## What SEALED does not mean

SEALED does not assert identity, authorization, correctness, completeness, compliance, or admissibility. A sealed bundle is only as honest as the recorder that produced it.

## Repository contents

- `verifier-kit/` — verifier source code
- `lib/` — support modules (Ed25519, canonical JSON)
- `golden/` — frozen reference bundles (valid + tampered)
- `conformance/` — conformance tests

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Trademark

OpaqueInfra is a trademark of OpaqueInfra. See [TRADEMARK.md](TRADEMARK.md).

## Contact

records@opaqueinfra.com
