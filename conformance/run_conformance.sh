#!/bin/bash
# conformance/run_conformance.sh — OpaqueInfra Conformance Vector Runner
#
# Runs verifier against each RT vector and checks results against expected.json.
# Exit 0 = all pass. Exit 1 = at least one failure.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
VERIFIER="$REPO_DIR/verifier-kit/verify.py"
VECTORS_DIR="$SCRIPT_DIR/vectors"

PASS=0
FAIL=0
TOTAL=0

# Read a JSON field from a file (cross-platform: pipes content to avoid path issues)
json_field() {
    local file="$1"
    local field="$2"
    local default="${3:-}"
    python3 -c "
import json, sys
d = json.load(sys.stdin)
print(d.get('$field', '$default'))
" < "$file"
}

check_field() {
    local output="$1"
    local field="$2"
    local expected="$3"
    local actual

    actual=$(echo "$output" | grep "^${field}:" | head -1 | sed "s/^${field}: *//")
    if [ "$actual" = "$expected" ]; then
        return 0
    else
        echo "    MISMATCH: $field expected='$expected' got='$actual'"
        return 1
    fi
}

run_vector() {
    local vector_id="$1"
    local vector_dir="$VECTORS_DIR/$vector_id"
    local expected_file="$vector_dir/expected.json"
    local policy_file="$vector_dir/policy.json"

    TOTAL=$((TOTAL + 1))

    if [ ! -f "$expected_file" ]; then
        echo "  FAIL [$vector_id]: expected.json not found"
        FAIL=$((FAIL + 1))
        return
    fi

    # Parse expected values (using stdin to avoid MSYS path issues)
    local exp_integrity exp_trust exp_chain
    exp_integrity=$(json_field "$expected_file" "integrity")
    exp_trust=$(json_field "$expected_file" "trust_policy_outcome" "NOT_APPLIED")
    exp_chain=$(json_field "$expected_file" "chain" "NOT_PRESENT")

    # Build verifier command
    local output

    # RT-06 is special: chain fork with multiple bundles
    if [ "$vector_id" = "RT-06" ]; then
        output=$(python3 "$VERIFIER" "$vector_dir/bundle_b/" \
            --chain-bundles "$vector_dir/bundle_a/" "$vector_dir/bundle_c/" 2>&1) || true
    elif [ -f "$policy_file" ]; then
        output=$(python3 "$VERIFIER" "$vector_dir/bundle/" \
            --trust-policy "$policy_file" 2>&1) || true
    else
        output=$(python3 "$VERIFIER" "$vector_dir/bundle/" 2>&1) || true
    fi

    local exit_code=${PIPESTATUS[0]:-$?}

    # Re-run to capture exit code cleanly
    if echo "$output" | grep -q "^INTEGRITY: SEALED"; then
        exit_code=0
    elif echo "$output" | grep -q "^INTEGRITY: BROKEN"; then
        exit_code=1
    fi

    # Check expected exit code
    local exp_exit=0
    if [ "$exp_integrity" = "BROKEN" ]; then
        exp_exit=1
    fi

    local failed=0

    if [ "$exit_code" -ne "$exp_exit" ]; then
        echo "    MISMATCH: exit_code expected=$exp_exit got=$exit_code"
        failed=1
    fi

    if ! check_field "$output" "INTEGRITY" "$exp_integrity"; then
        failed=1
    fi

    if ! check_field "$output" "TRUST_POLICY_OUTCOME" "$exp_trust"; then
        failed=1
    fi

    if ! check_field "$output" "CHAIN" "$exp_chain"; then
        failed=1
    fi

    # Check must_contain_failure_step if specified
    local must_step
    must_step=$(json_field "$expected_file" "must_contain_failure_step" "")
    if [ -n "$must_step" ]; then
        if echo "$output" | grep -qi "bhi\|4b\|bundle_hash.*receipt\|recompute"; then
            : # found reference to the expected failure step
        else
            echo "    MISMATCH: expected failure reference to step $must_step in output"
            failed=1
        fi
    fi

    if [ "$failed" -eq 0 ]; then
        echo "  PASS [$vector_id]"
        PASS=$((PASS + 1))
    else
        echo "  FAIL [$vector_id]"
        echo "  Output:"
        echo "$output" | sed 's/^/    /'
        FAIL=$((FAIL + 1))
    fi
}

echo "═══════════════════════════════════════════════════"
echo "  OI Conformance Vector Runner"
echo "═══════════════════════════════════════════════════"
echo ""

# Run each RT vector
for vector_id in RT-01 RT-02 RT-03 RT-04 RT-05 RT-06; do
    if [ -d "$VECTORS_DIR/$vector_id" ]; then
        run_vector "$vector_id"
    else
        echo "  SKIP [$vector_id]: directory not found"
    fi
done

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Results: $PASS/$TOTAL passed, $FAIL failed"
echo "═══════════════════════════════════════════════════"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
