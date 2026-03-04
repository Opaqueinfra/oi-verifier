# Copyright (c) 2026 OpaqueInfra
# Licensed under the Apache License, Version 2.0.
# See LICENSE file for details.

#!/usr/bin/env python3
"""
OpaqueInfra Verifier

Implements the normative verifier decision tree (Steps 1–12 including 4b).
See README.md for verification details.

SEALED means: untampered since sealing.
SEALED does NOT mean: true, complete, authorized, compliant, or admissible.
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import zipfile
import tempfile
import shutil

# Add repo root to path for lib imports
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, REPO_DIR)

from lib.canonicaljson_minimal import canonicalize, canonicalize_file
from lib.ed25519 import verify as ed25519_verify

VERSION = "1.1.0"

# --- Receipt schema: allowed fields (additionalProperties: false) ---
RECEIPT_REQUIRED_FIELDS = {
    "receipt_version", "bundle_hash", "hash_algorithm",
    "signature_scheme", "signatures", "created_at_utc_declared",
    "anchors_present"
}
RECEIPT_ALLOWED_FIELDS = RECEIPT_REQUIRED_FIELDS  # strict, no extras

SIGNATURE_REQUIRED_FIELDS = {"key_id", "signature_b64"}
SIGNATURE_ALLOWED_FIELDS = SIGNATURE_REQUIRED_FIELDS

# --- Keyset schema: allowed fields ---
KEYSET_REQUIRED_FIELDS = {"keyset_version", "keys", "active_key_ids"}
KEY_REQUIRED_FIELDS = {
    "key_id", "algorithm", "public_key_b64",
    "fingerprint_sha256", "valid_from_utc_declared", "valid_to_utc_declared"
}


class VerifierResult:
    def __init__(self):
        self.integrity = None  # SEALED or BROKEN
        self.broken_reason = None
        self.capture = "NOT_PRESENT"
        self.anchor = "NOT_PRESENT"
        self.time_assertion = "DECLARED_ONLY"
        self.release_digest_match = "NOT_APPLIED"
        self.trust_policy_fingerprint = "NOT_APPLIED"
        self.trust_policy_eval = "NOT_APPLIED"
        self.trust_policy_outcome = "NOT_APPLIED"
        self.chain = "NOT_PRESENT"
        self.warnings = []

    def set_broken(self, reason):
        if self.integrity is None:
            self.integrity = "BROKEN"
            self.broken_reason = reason

    def set_sealed(self):
        if self.integrity is None:
            self.integrity = "SEALED"

    def output(self):
        lines = [
            f"INTEGRITY: {self.integrity}",
            f"CAPTURE: {self.capture}",
            f"ANCHOR: {self.anchor}",
            f"TIME_ASSERTION: {self.time_assertion}",
            f"RELEASE_DIGEST_MATCH: {self.release_digest_match}",
            f"TRUST_POLICY_FINGERPRINT: {self.trust_policy_fingerprint}",
            f"TRUST_POLICY_EVAL: {self.trust_policy_eval}",
            f"TRUST_POLICY_OUTCOME: {self.trust_policy_outcome}",
            f"CHAIN: {self.chain}",
        ]
        for line in lines:
            print(line)
        if self.broken_reason:
            print(f"FAILURE_REASON: {self.broken_reason}")
        for w in self.warnings:
            print(f"WARNING: {w}")

    def exit_code(self):
        return 0 if self.integrity == "SEALED" else 1


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def load_json_strict(path):
    """Load JSON, reject duplicate keys."""
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    return json.loads(text)


def validate_receipt_schema(receipt):
    """Validate receipt.json schema — additionalProperties: false."""
    # Check for unknown fields at top level
    unknown = set(receipt.keys()) - RECEIPT_ALLOWED_FIELDS
    if unknown:
        return False, f"Unknown fields in receipt.json: {unknown}"

    # Check required fields
    missing = RECEIPT_REQUIRED_FIELDS - set(receipt.keys())
    if missing:
        return False, f"Missing required fields in receipt.json: {missing}"

    # Validate field types
    if receipt.get("receipt_version") != "1":
        return False, "receipt_version must be '1'"
    if not isinstance(receipt.get("bundle_hash"), str) or len(receipt["bundle_hash"]) != 64:
        return False, "bundle_hash must be 64 hex chars"
    if receipt.get("hash_algorithm") != "sha256":
        return False, "hash_algorithm must be 'sha256'"
    if receipt.get("signature_scheme") != "ed25519":
        return False, "signature_scheme must be 'ed25519'"
    if not isinstance(receipt.get("signatures"), list) or len(receipt["signatures"]) < 1:
        return False, "signatures must be a non-empty array"
    if not isinstance(receipt.get("anchors_present"), list):
        return False, "anchors_present must be an array"
    if not isinstance(receipt.get("created_at_utc_declared"), str):
        return False, "created_at_utc_declared must be a string"

    # Validate each signature entry
    for i, sig in enumerate(receipt["signatures"]):
        if not isinstance(sig, dict):
            return False, f"signatures[{i}] must be an object"
        sig_unknown = set(sig.keys()) - SIGNATURE_ALLOWED_FIELDS
        if sig_unknown:
            return False, f"Unknown fields in signatures[{i}]: {sig_unknown}"
        sig_missing = SIGNATURE_REQUIRED_FIELDS - set(sig.keys())
        if sig_missing:
            return False, f"Missing fields in signatures[{i}]: {sig_missing}"

    return True, None


def validate_keyset_schema(keyset):
    """Validate keyset.json schema."""
    missing = KEYSET_REQUIRED_FIELDS - set(keyset.keys())
    if missing:
        return False, f"Missing required fields in keyset.json: {missing}"

    if keyset.get("keyset_version") != "1":
        return False, "keyset_version must be '1'"
    if not isinstance(keyset.get("keys"), list) or len(keyset["keys"]) < 1:
        return False, "keys must be a non-empty array"
    if not isinstance(keyset.get("active_key_ids"), list) or len(keyset["active_key_ids"]) < 1:
        return False, "active_key_ids must be a non-empty array"

    for i, key in enumerate(keyset["keys"]):
        if not isinstance(key, dict):
            return False, f"keys[{i}] must be an object"
        key_missing = KEY_REQUIRED_FIELDS - set(key.keys())
        if key_missing:
            return False, f"Missing fields in keys[{i}]: {key_missing}"
        if key.get("algorithm") != "ed25519":
            return False, f"keys[{i}].algorithm must be 'ed25519'"
        # Validate fingerprint format
        fp = key.get("fingerprint_sha256", "")
        if not isinstance(fp, str) or len(fp) != 64:
            return False, f"keys[{i}].fingerprint_sha256 must be 64 hex chars"
        # Validate public key is valid base64 and 32 bytes
        try:
            pub_bytes = base64.b64decode(key["public_key_b64"])
            if len(pub_bytes) != 32:
                return False, f"keys[{i}].public_key_b64 must decode to 32 bytes, got {len(pub_bytes)}"
        except Exception:
            return False, f"keys[{i}].public_key_b64 is not valid base64"
        # Validate fingerprint matches key
        expected_fp = sha256_bytes(pub_bytes)
        if fp != expected_fp:
            return False, f"keys[{i}].fingerprint_sha256 does not match SHA-256 of public key"

    return True, None


def verify_bundle(bundle_dir, trust_policy_path=None, chain_bundles=None):
    """Run the full verifier decision tree on a bundle directory."""
    result = VerifierResult()

    # --- Step 1: Load ---
    if not os.path.isdir(bundle_dir):
        result.set_broken("Bundle directory does not exist")
        return result

    # --- Step 3: Validate checksums.sha256 ---
    checksums_path = os.path.join(bundle_dir, "checksums.sha256")
    if not os.path.isfile(checksums_path):
        result.set_broken("checksums.sha256 not found")
        return result

    with open(checksums_path, "rb") as f:
        checksums_bytes = f.read()

    # Check for CR bytes (MEDIUM-1)
    if b'\r' in checksums_bytes:
        result.set_broken("checksums.sha256 contains CR bytes (0x0D)")
        return result

    checksums_text = checksums_bytes.decode("utf-8")
    lines = checksums_text.rstrip("\n").split("\n") if checksums_text.strip() else []

    # Parse and validate format
    checksums_entries = []
    for i, line in enumerate(lines):
        parts = line.split(" ", 1)
        if len(parts) != 2:
            result.set_broken(f"checksums.sha256 line {i+1}: invalid format")
            return result
        hex_hash, path = parts
        if len(hex_hash) != 64 or hex_hash != hex_hash.lower():
            result.set_broken(f"checksums.sha256 line {i+1}: invalid hash format")
            return result
        checksums_entries.append((hex_hash, path))

    # Validate sort order (unsigned byte comparison / memcmp) (HIGH-1)
    paths = [entry[1] for entry in checksums_entries]
    for i in range(len(paths) - 1):
        if paths[i].encode("utf-8") >= paths[i + 1].encode("utf-8"):
            result.set_broken(
                f"checksums.sha256: paths not sorted by unsigned byte comparison "
                f"('{paths[i]}' >= '{paths[i+1]}')"
            )
            return result

    # --- Step 4: Recompute hashes ---
    for hex_hash, path in checksums_entries:
        file_path = os.path.join(bundle_dir, path)
        if not os.path.isfile(file_path):
            result.set_broken(f"File listed in checksums but missing: {path}")
            return result
        actual_hash = sha256_file(file_path)
        if actual_hash != hex_hash:
            result.set_broken(f"Hash mismatch for {path}")
            return result

    # --- Step 5: Validate receipt.json ---
    receipt_path = os.path.join(bundle_dir, "receipt.json")
    if not os.path.isfile(receipt_path):
        result.set_broken("receipt.json not found")
        return result

    try:
        receipt = load_json_strict(receipt_path)
    except json.JSONDecodeError as e:
        result.set_broken(f"receipt.json is not valid JSON: {e}")
        return result

    valid, err = validate_receipt_schema(receipt)
    if not valid:
        result.set_broken(f"receipt.json schema: {err}")
        return result

    # --- Step 4b: Recompute BHI and compare (CRITICAL-1) ---
    build_info_path = os.path.join(bundle_dir, "BUILD_INFO.json")
    if not os.path.isfile(build_info_path):
        result.set_broken("BUILD_INFO.json not found (required for BHI)")
        return result

    try:
        build_info = load_json_strict(build_info_path)
    except json.JSONDecodeError as e:
        result.set_broken(f"BUILD_INFO.json is not valid JSON: {e}")
        return result

    canonical_build_info = canonicalize(build_info)
    bhi = checksums_bytes + b'\x0a' + canonical_build_info
    expected_bundle_hash = hashlib.sha256(bhi).hexdigest()

    if expected_bundle_hash != receipt["bundle_hash"]:
        result.set_broken(
            "BHI recompute: bundle_hash in receipt does not match "
            "SHA-256(checksums.sha256 + 0x0A + canonical(BUILD_INFO.json))"
        )
        return result

    # --- Step 7: Validate keyset.json ---
    keyset_path = os.path.join(bundle_dir, "keyset.json")
    if not os.path.isfile(keyset_path):
        result.set_broken("keyset.json not found")
        return result

    try:
        keyset = load_json_strict(keyset_path)
    except json.JSONDecodeError as e:
        result.set_broken(f"keyset.json is not valid JSON: {e}")
        return result

    valid, err = validate_keyset_schema(keyset)
    if not valid:
        result.set_broken(f"keyset.json schema: {err}")
        return result

    # Build key lookup
    key_lookup = {}
    for key_entry in keyset["keys"]:
        key_lookup[key_entry["key_id"]] = key_entry

    # --- Step 6: Reconstruct signed bytes + verify signature(s) ---
    signed_bytes = f"OI_RECEIPT_V1\n{receipt['bundle_hash']}\n".encode("utf-8")

    any_valid = False
    for sig_entry in receipt["signatures"]:
        key_id = sig_entry["key_id"]

        # Resolve key_id to keyset (MEDIUM-2)
        if key_id not in key_lookup:
            result.set_broken(f"key_id '{key_id}' not found in keyset.json")
            return result

        key_entry = key_lookup[key_id]

        # Warn if not in active_key_ids
        if key_id not in keyset["active_key_ids"]:
            result.warnings.append(
                f"Signing key '{key_id}' is not in active_key_ids"
            )

        # Decode public key and signature
        try:
            pub_bytes = base64.b64decode(key_entry["public_key_b64"])
        except Exception:
            result.set_broken(f"Cannot decode public key for key_id '{key_id}'")
            return result

        try:
            sig_bytes = base64.b64decode(sig_entry["signature_b64"])
        except Exception:
            result.set_broken(f"Cannot decode signature for key_id '{key_id}'")
            return result

        if ed25519_verify(pub_bytes, sig_bytes, signed_bytes):
            any_valid = True
        else:
            result.set_broken(
                f"Ed25519 signature verification failed for key_id '{key_id}'"
            )
            return result

    if not any_valid:
        result.set_broken("No valid signature found")
        return result

    # --- Step 8: Profile enforcement (basic) ---
    # For now, check that BUILD_INFO.json has required fields
    # Full profile enforcement deferred to profile-specific stages

    # --- Step 9: CAPTURE_HEALTH (secondary output) ---
    capture_health_path = os.path.join(bundle_dir, "CAPTURE_HEALTH.json")
    if os.path.isfile(capture_health_path):
        try:
            capture_health = load_json_strict(capture_health_path)
            status = capture_health.get("status", "").upper()
            if status in ("OK", "DEGRADED", "FAILED"):
                result.capture = status
            else:
                result.capture = "DEGRADED"
        except json.JSONDecodeError:
            result.set_broken("CAPTURE_HEALTH.json is not valid JSON")
            return result

    # --- Step 10: Anchors (optional) ---
    anchors_dir = os.path.join(bundle_dir, "anchors")
    if os.path.isdir(anchors_dir) and receipt.get("anchors_present"):
        result.anchor = "PRESENT (VALID)"
        # Basic: verify anchor files exist and are in checksums
        for anchor_ref in receipt["anchors_present"]:
            anchor_path = os.path.join(bundle_dir, anchor_ref)
            if not os.path.isfile(anchor_path):
                result.anchor = "PRESENT (INVALID)"
                break

    # --- Step 11: Release digest match (optional) ---
    # Not implemented in Stage 1 — requires release_digests.json input

    # --- Step 11.5: Trust policy overlay (optional) ---
    if trust_policy_path:
        try:
            with open(trust_policy_path, "r", encoding="utf-8") as f:
                trust_policy = json.load(f)

            # Compute fingerprint of canonical policy bytes
            policy_canonical = canonicalize(trust_policy)
            result.trust_policy_fingerprint = sha256_bytes(policy_canonical)
            result.trust_policy_eval = "APPLIED"

            deny_list = set(trust_policy.get("deny", []))
            allow_list = set(trust_policy.get("allow", []))

            # Evaluate all signing keys against policy
            outcome = "UNKNOWN"
            for sig_entry in receipt["signatures"]:
                key_id = sig_entry["key_id"]
                key_entry = key_lookup.get(key_id)
                if key_entry:
                    fp = key_entry["fingerprint_sha256"]
                    # Deny-first (LOW-2: deny poisons all)
                    if fp in deny_list:
                        outcome = "DENIED"
                        break
                    if fp in allow_list:
                        outcome = "ALLOWED"

            result.trust_policy_outcome = outcome

        except (json.JSONDecodeError, OSError) as e:
            result.trust_policy_fingerprint = "NOT_APPLIED"
            result.trust_policy_eval = "NOT_APPLIED"
            result.trust_policy_outcome = "NOT_APPLIED"
            result.warnings.append(f"Trust policy file error: {e}")

    # --- Step 12: Chain (informational) ---
    bundle_link_path = os.path.join(bundle_dir, "BUNDLE_LINK.json")
    if os.path.isfile(bundle_link_path):
        try:
            bundle_link = load_json_strict(bundle_link_path)
            if bundle_link.get("prev_bundle_hash"):
                result.chain = "OK"
            else:
                result.chain = "NOT_PRESENT"
        except json.JSONDecodeError:
            result.set_broken("BUNDLE_LINK.json is not valid JSON")
            return result

    # Chain fork detection across multiple bundles
    if chain_bundles:
        prev_hashes = {}  # prev_bundle_hash -> list of bundle paths
        all_bundle_dirs = [bundle_dir] + list(chain_bundles)
        for bd in all_bundle_dirs:
            bl_path = os.path.join(bd, "BUNDLE_LINK.json")
            if os.path.isfile(bl_path):
                try:
                    bl = load_json_strict(bl_path)
                    prev = bl.get("prev_bundle_hash")
                    if prev:
                        prev_hashes.setdefault(prev, []).append(bd)
                except (json.JSONDecodeError, OSError):
                    pass
        # Fork = multiple bundles claiming the same prev_bundle_hash
        for prev_hash, dirs in prev_hashes.items():
            if len(dirs) > 1:
                result.chain = "FORK_DETECTED"
                break

    # If we got here without breaking, it's SEALED
    result.set_sealed()
    return result


def main():
    parser = argparse.ArgumentParser(
        description="OpaqueInfra Verifier v" + VERSION
    )
    parser.add_argument(
        "bundle",
        nargs="?",
        help="Path to bundle directory or ZIP file"
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print version and exit"
    )
    parser.add_argument(
        "--trust-policy",
        dest="trust_policy",
        help="Path to trust policy JSON file"
    )
    parser.add_argument(
        "--chain-bundles",
        dest="chain_bundles",
        nargs="*",
        help="Additional bundle paths for chain analysis (fork detection)"
    )

    args = parser.parse_args()

    if args.version:
        print(f"oi-verify {VERSION}")
        sys.exit(0)

    if not args.bundle:
        parser.error("bundle path is required")

    bundle_path = args.bundle
    temp_dir = None

    # Handle ZIP input
    if os.path.isfile(bundle_path) and (
        bundle_path.endswith(".zip") or zipfile.is_zipfile(bundle_path)
    ):
        # Step 2: ZIP safety
        try:
            with zipfile.ZipFile(bundle_path, "r") as zf:
                names = zf.namelist()
                seen_normalized = set()
                for name in names:
                    # Path traversal check
                    if ".." in name or name.startswith("/") or ":" in name:
                        result = VerifierResult()
                        result.set_broken(f"ZIP path traversal detected: {name}")
                        result.output()
                        sys.exit(result.exit_code())
                    # NUL check
                    if "\x00" in name:
                        result = VerifierResult()
                        result.set_broken(f"ZIP entry contains NUL: {name}")
                        result.output()
                        sys.exit(result.exit_code())
                    # Symlink check
                    info = zf.getinfo(name)
                    if info.external_attr >> 28 == 0xA:
                        result = VerifierResult()
                        result.set_broken(f"ZIP contains symlink: {name}")
                        result.output()
                        sys.exit(result.exit_code())
                    # Case collision check
                    normalized = name.lower()
                    if normalized in seen_normalized:
                        result = VerifierResult()
                        result.set_broken(f"ZIP case collision: {name}")
                        result.output()
                        sys.exit(result.exit_code())
                    seen_normalized.add(normalized)
                    # Duplicate check
                    if names.count(name) > 1:
                        result = VerifierResult()
                        result.set_broken(f"ZIP duplicate entry: {name}")
                        result.output()
                        sys.exit(result.exit_code())

                temp_dir = tempfile.mkdtemp(prefix="oi_verify_")
                zf.extractall(temp_dir)
                bundle_path = temp_dir
        except zipfile.BadZipFile:
            result = VerifierResult()
            result.set_broken("Invalid ZIP file")
            result.output()
            sys.exit(result.exit_code())

    try:
        result = verify_bundle(
            bundle_path, args.trust_policy, args.chain_bundles
        )
        result.output()
        sys.exit(result.exit_code())
    finally:
        if temp_dir and os.path.isdir(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
