#!/bin/bash

# Comprehensive cipher suite test script for rustls-rustcrypto
# Tests ALL possible combinations of cipher suite components using Cartesian product

set -e

echo "Testing ALL possible cipher suite combinations..."
echo "=================================================="
echo "This will test the complete Cartesian product of:"
echo "  - AEAD algorithms: aead-aes-gcm, aead-aes-ccm, aead-chacha20poly1305"
echo "  - Hash algorithms: hash-sha224, hash-sha256, hash-sha384, hash-sha512"
echo "  - Verify algorithms: 16 different verification schemes"
echo "  - Sign algorithms: 6 different signing schemes"
echo "  - Key exchange: kx-p256, kx-p384, kx-p521, kx-x25519, kx-x448"
echo ""
echo "Total combinations: 3 × 4 × 16 × 6 × 5 = $(echo "3*4*16*6*5" | bc) combinations"
echo "=================================================="
echo ""

# Component arrays
AEAD_ALGORITHMS=("aead-aes-gcm" "aead-aes-ccm" "aead-chacha20poly1305")
HASH_ALGORITHMS=("hash-sha224" "hash-sha256" "hash-sha384" "hash-sha512")
VERIFY_ALGORITHMS=(
    "verify-ecdsa-p256-sha256" "verify-ecdsa-p256-sha384" "verify-ecdsa-p256-sha512"
    "verify-ecdsa-p384-sha256" "verify-ecdsa-p384-sha384" "verify-ecdsa-p384-sha512"
    "verify-ecdsa-p521-sha256" "verify-ecdsa-p521-sha384" "verify-ecdsa-p521-sha512"
    "verify-eddsa-ed25519"
    "verify-rsa-pkcs1-sha256" "verify-rsa-pkcs1-sha384" "verify-rsa-pkcs1-sha512"
    "verify-rsa-pss-sha256" "verify-rsa-pss-sha384" "verify-rsa-pss-sha512"
)
SIGN_ALGORITHMS=(
    "sign-ecdsa-p256" "sign-ecdsa-p384" "sign-ecdsa-p521"
    "sign-eddsa-ed25519"
    "sign-rsa-pkcs1" "sign-rsa-pss"
)
KEY_EXCHANGE_ALGORITHMS=("kx-p256" "kx-p384" "kx-p521" "kx-x25519" "kx-x448")

# Counters
total_combinations=$(echo "${#AEAD_ALGORITHMS[@]} * ${#HASH_ALGORITHMS[@]} * ${#VERIFY_ALGORITHMS[@]} * ${#SIGN_ALGORITHMS[@]} * ${#KEY_EXCHANGE_ALGORITHMS[@]}" | bc)
tested_count=0
passed_count=0
failed_count=0

echo "Starting comprehensive test of $total_combinations combinations..."
echo ""

# Function to test a cipher suite combination
test_cipher_suite() {
    local aead="$1"
    local hash="$2"
    local verify="$3"
    local sign="$4"
    local kx="$5"

    ((tested_count++))

    # Build feature string
    local features="tls12,$aead,$hash,$verify,$sign,$kx"

    # Create a short name for display
    local name="${aead#*-}-${hash#*-}-${verify#*-verify-}-${sign#*-}-${kx#*-}"

    echo "[$tested_count/$total_combinations] Testing: $name"
    echo "  Features: $features"

    # Test the combination
    if cargo test --features "$features" >/dev/null 2>&1; then
        echo "  ✅ PASSED"
        ((passed_count++))
        return 0
    else
        echo "  ❌ FAILED (incompatible combination)"
        ((failed_count++))
        return 1
    fi
}

# Test all combinations using nested loops (Cartesian product)
for aead in "${AEAD_ALGORITHMS[@]}"; do
    for hash in "${HASH_ALGORITHMS[@]}"; do
        for verify in "${VERIFY_ALGORITHMS[@]}"; do
            for sign in "${SIGN_ALGORITHMS[@]}"; do
                for kx in "${KEY_EXCHANGE_ALGORITHMS[@]}"; do
                    test_cipher_suite "$aead" "$hash" "$verify" "$sign" "$kx"
                    echo ""
                done
            done
        done
    done
done

echo "=================================================="
echo "COMPREHENSIVE TEST RESULTS:"
echo "=================================================="
echo "Total combinations tested: $tested_count"
echo "Passed: $passed_count"
echo "Failed: $failed_count"
echo "Success rate: $(echo "scale=2; $passed_count * 100 / $tested_count" | bc)%"
echo ""
echo "Note: Failed combinations are expected as not all component combinations"
echo "are compatible or implemented in the codebase."
echo ""
echo "To run specific combinations:"
echo "  cargo test --features 'tls12,aead-aes-gcm,hash-sha256,verify-rsa-pkcs1-sha256,sign-rsa-pkcs1,kx-p256'"
echo ""
echo "For GitHub Actions matrix testing, see: .github/workflows/cipher-suite-test.yml"
echo "To regenerate this script, run: python generate-cipher-suite-tests.py --shell"