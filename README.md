# OpaqueInfra — Stage 2

Clean implementation of OpaqueInfra spec v1.1.0 (red-team hardened, baseline-locked).

## What this is

Tamper-evident evidence infrastructure. Bundles are sealed with Ed25519 signatures.
Verification is offline, byte-level, and deterministic.

SEALED means: untampered since sealing.
SEALED does NOT mean: true, complete, authorized, compliant, or admissible.

## Spec

The normative spec tree is in `oi-docs/`. It is immutable. Code conforms to spec.

## Build order

See `BUILD_ORDER.md`. Stages are sequential with human approval gates.

## Governance

See `CLAUDE.md` for rules, schemas, and banned tokens.
See `AI_CHANGE_LOG.md` for the AI-assisted development ledger.

## License

See LICENSE.
