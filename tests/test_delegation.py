"""
Tests for Delegation-based Secret Sharing.

Tests the formulas with hardcoded values:
- Scheme 1: K_D = KDF(s)
- Scheme 2: K_D^C = KDF(H(s || caps))
- User composition: K_U* = KDF(K_U || K_D)
- Security properties
"""

import pytest
from ensf.crypto.delegation import (
    DelegationScheme,
    Capability,
    compose_user_key,
    encrypt_data,
    decrypt_data,
    kdf,
    hash_with_capabilities,
)


# =============================================================================
# HARDCODED TEST VALUES
# =============================================================================

# Threshold W = 3
THRESHOLD = 3

# Admin weights
ADMIN_WEIGHTS = {
    "admin1": 2,  # w_1 = 2
    "admin2": 1,  # w_2 = 1
    "admin3": 1,  # w_3 = 1
}

# User key K_U (32 bytes)
USER_KEY = b"user_secret_key_32bytes_padding_"

# Capability keys for admin1 (32 bytes each)
CAPABILITY_KEYS = {
    Capability.READ: b"read_capability_key_32bytes_____",
    Capability.WRITE: b"write_capability_key_32bytes____",
    Capability.DELETE: b"delete_capability_key_32bytes___",
}

# Test data
TEST_DATA = b"This is the user's private data D_U"


# =============================================================================
# TEST CLASSES
# =============================================================================


class TestCoalitionValidation:
    """Test coalition weight validation: Σw_i ≥ W"""

    def test_valid_coalition_meets_threshold(self):
        """Coalition with Σw_i ≥ W should be valid."""
        scheme = DelegationScheme(threshold=THRESHOLD)

        # admin1 + admin2 = 2 + 1 = 3 >= 3
        assert scheme.validate_coalition({"admin1": 2, "admin2": 1}) is True

        # admin1 + admin3 = 2 + 1 = 3 >= 3
        assert scheme.validate_coalition({"admin1": 2, "admin3": 1}) is True

        # all admins = 4 >= 3
        assert scheme.validate_coalition(ADMIN_WEIGHTS) is True

    def test_invalid_coalition_below_threshold(self):
        """Coalition with Σw_i < W should be invalid."""
        scheme = DelegationScheme(threshold=THRESHOLD)

        # admin1 alone = 2 < 3
        assert scheme.validate_coalition({"admin1": 2}) is False

        # admin2 + admin3 = 1 + 1 = 2 < 3
        assert scheme.validate_coalition({"admin2": 1, "admin3": 1}) is False

    def test_share_secret_rejects_invalid_coalition(self):
        """share_secret should raise error for invalid coalition."""
        scheme = DelegationScheme(threshold=THRESHOLD)
        secret = scheme.generate_secret()

        with pytest.raises(ValueError, match="Invalid coalition"):
            scheme.share_secret(secret, {"admin1": 2})  # weight 2 < 3


class TestSecretSharing:
    """Test secret sharing: {s_i} ← Share(s) and s = Rec({s_i})"""

    def test_share_distributes_by_weight(self):
        """Each admin should receive shares equal to their weight."""
        scheme = DelegationScheme(threshold=THRESHOLD)
        secret = scheme.generate_secret()

        shares = scheme.share_secret(secret, {"admin1": 2, "admin2": 1})

        assert len(shares["admin1"]) == 2  # weight 2
        assert len(shares["admin2"]) == 1  # weight 1

    def test_reconstruct_with_sufficient_shares(self):
        """Reconstruction with ≥ threshold shares should succeed."""
        scheme = DelegationScheme(threshold=THRESHOLD)
        secret = 12345  # Fixed secret for testing

        shares = scheme.share_secret(secret, {"admin1": 2, "admin2": 1})

        # Combine all shares
        all_shares = shares["admin1"] + shares["admin2"]
        reconstructed = scheme.reconstruct_secret(all_shares)

        assert reconstructed == secret

    def test_reconstruct_with_different_subsets(self):
        """Any subset of shares meeting threshold should work."""
        scheme = DelegationScheme(threshold=THRESHOLD)
        secret = 99999

        shares = scheme.share_secret(secret, ADMIN_WEIGHTS)

        # admin1(2) + admin2(1) = 3 shares
        subset1 = shares["admin1"] + shares["admin2"]
        assert scheme.reconstruct_secret(subset1) == secret

        # admin1(2) + admin3(1) = 3 shares
        subset2 = shares["admin1"] + shares["admin3"]
        assert scheme.reconstruct_secret(subset2) == secret


class TestScheme1:
    """Test Scheme 1: K_D = KDF(s)"""

    def test_scheme1_derives_key(self):
        """Scheme 1 should derive 32-byte key from secret."""
        scheme = DelegationScheme(threshold=THRESHOLD)
        secret = scheme.generate_secret()

        result = scheme.derive_delegation_key_scheme1(secret)

        assert len(result.key) == 32
        assert result.capabilities == set()  # read-only

    def test_scheme1_deterministic(self):
        """Same secret should produce same key."""
        scheme = DelegationScheme(threshold=THRESHOLD)
        secret = 12345

        result1 = scheme.derive_delegation_key_scheme1(secret)
        result2 = scheme.derive_delegation_key_scheme1(secret)

        assert result1.key == result2.key

    def test_scheme1_different_secrets_different_keys(self):
        """Different secrets should produce different keys."""
        scheme = DelegationScheme(threshold=THRESHOLD)

        result1 = scheme.derive_delegation_key_scheme1(100)
        result2 = scheme.derive_delegation_key_scheme1(200)

        assert result1.key != result2.key


class TestScheme2:
    """Test Scheme 2: K_D^C = KDF(H(s || K_j^op for op ∈ C))"""

    def test_scheme2_derives_key_with_capabilities(self):
        """Scheme 2 should include capabilities in result."""
        scheme = DelegationScheme(threshold=THRESHOLD)
        secret = scheme.generate_secret()

        caps = {Capability.READ: CAPABILITY_KEYS[Capability.READ]}
        result = scheme.derive_delegation_key_scheme2(secret, caps)

        assert len(result.key) == 32
        assert Capability.READ in result.capabilities

    def test_scheme2_different_caps_different_keys(self):
        """Different capability sets should produce different keys."""
        scheme = DelegationScheme(threshold=THRESHOLD)
        secret = 12345

        caps_read = {Capability.READ: CAPABILITY_KEYS[Capability.READ]}
        caps_write = {Capability.WRITE: CAPABILITY_KEYS[Capability.WRITE]}

        result1 = scheme.derive_delegation_key_scheme2(secret, caps_read)
        result2 = scheme.derive_delegation_key_scheme2(secret, caps_write)

        assert result1.key != result2.key

    def test_scheme2_multiple_capabilities(self):
        """Multiple capabilities should all be included."""
        scheme = DelegationScheme(threshold=THRESHOLD)
        secret = 12345

        caps = {
            Capability.READ: CAPABILITY_KEYS[Capability.READ],
            Capability.WRITE: CAPABILITY_KEYS[Capability.WRITE],
        }
        result = scheme.derive_delegation_key_scheme2(secret, caps)

        assert result.capabilities == {Capability.READ, Capability.WRITE}

    def test_scheme2_empty_caps_equals_scheme1(self):
        """Empty capabilities should fall back to Scheme 1."""
        scheme = DelegationScheme(threshold=THRESHOLD)
        secret = 12345

        result1 = scheme.derive_delegation_key_scheme1(secret)
        result2 = scheme.derive_delegation_key_scheme2(secret, {})

        assert result1.key == result2.key


class TestUserKeyComposition:
    """Test user key composition: K_U* = KDF(K_U || K_D)"""

    def test_compose_produces_valid_key(self):
        """Composed key should be 32 bytes."""
        delegation_key = b"d" * 32

        composed = compose_user_key(USER_KEY, delegation_key)

        assert len(composed) == 32

    def test_compose_deterministic(self):
        """Same inputs should produce same composed key."""
        delegation_key = b"d" * 32

        composed1 = compose_user_key(USER_KEY, delegation_key)
        composed2 = compose_user_key(USER_KEY, delegation_key)

        assert composed1 == composed2

    def test_different_user_keys_different_composed(self):
        """Different user keys should produce different composed keys."""
        delegation_key = b"d" * 32
        user_key1 = b"a" * 32
        user_key2 = b"b" * 32

        composed1 = compose_user_key(user_key1, delegation_key)
        composed2 = compose_user_key(user_key2, delegation_key)

        assert composed1 != composed2

    def test_different_delegation_keys_different_composed(self):
        """Different delegation keys should produce different composed keys."""
        composed1 = compose_user_key(USER_KEY, b"a" * 32)
        composed2 = compose_user_key(USER_KEY, b"b" * 32)

        assert composed1 != composed2


class TestEncryptionDecryption:
    """Test encryption/decryption: C = Enc(D_U), D_U = Dec(C)"""

    def test_round_trip(self):
        """Dec(Enc(D_U)) should equal D_U."""
        key = b"k" * 32

        ciphertext = encrypt_data(TEST_DATA, key)
        plaintext = decrypt_data(ciphertext, key)

        assert plaintext == TEST_DATA

    def test_wrong_key_fails(self):
        """Decryption with wrong key should produce garbage."""
        key1 = b"a" * 32
        key2 = b"b" * 32

        ciphertext = encrypt_data(TEST_DATA, key1)
        wrong_plaintext = decrypt_data(ciphertext, key2)

        assert wrong_plaintext != TEST_DATA


class TestSecurityProperties:
    """Test security guarantees from specification."""

    def test_insufficient_coalition_cannot_derive_key(self):
        """
        If Σw_i < W, Pr[K_D known] ≈ 0

        Coalition below threshold cannot create valid secret sharing.
        """
        scheme = DelegationScheme(threshold=THRESHOLD)
        secret = scheme.generate_secret()

        # Cannot even share the secret with insufficient coalition
        with pytest.raises(ValueError):
            scheme.share_secret(secret, {"admin2": 1})  # weight 1 < 3

    def test_admin_alone_cannot_access_data(self):
        """
        Without K_U, Pr[admin gets D_U] ≈ 0

        Admin has delegation key but not user key.
        """
        scheme = DelegationScheme(threshold=THRESHOLD)
        secret = scheme.generate_secret()

        # Admin creates delegation key
        delegation = scheme.derive_delegation_key_scheme1(secret)

        # User encrypts data with composed key
        composed_key = compose_user_key(USER_KEY, delegation.key)
        ciphertext = encrypt_data(TEST_DATA, composed_key)

        # Admin tries to decrypt with just delegation key (wrong)
        wrong_plaintext = decrypt_data(ciphertext, delegation.key)
        assert wrong_plaintext != TEST_DATA

    def test_user_alone_cannot_access_data(self):
        """
        Without K_D, user cannot decrypt.

        User has their key but no delegation from admins.
        """
        scheme = DelegationScheme(threshold=THRESHOLD)
        secret = scheme.generate_secret()

        # Create correct composed key
        delegation = scheme.derive_delegation_key_scheme1(secret)
        composed_key = compose_user_key(USER_KEY, delegation.key)

        # Encrypt data
        ciphertext = encrypt_data(TEST_DATA, composed_key)

        # User tries with only their key (wrong)
        wrong_plaintext = decrypt_data(ciphertext, USER_KEY)
        assert wrong_plaintext != TEST_DATA

    def test_admin_and_user_together_can_access(self):
        """
        Admin coalition + user = successful access.
        """
        scheme = DelegationScheme(threshold=THRESHOLD)
        secret = scheme.generate_secret()

        # Admin coalition creates and shares secret
        shares = scheme.share_secret(secret, {"admin1": 2, "admin2": 1})

        # Reconstruct
        all_shares = shares["admin1"] + shares["admin2"]
        reconstructed = scheme.reconstruct_secret(all_shares)

        # Derive delegation key
        delegation = scheme.derive_delegation_key_scheme1(reconstructed)

        # User composes key
        composed_key = compose_user_key(USER_KEY, delegation.key)

        # Encrypt and decrypt
        ciphertext = encrypt_data(TEST_DATA, composed_key)
        plaintext = decrypt_data(ciphertext, composed_key)

        assert plaintext == TEST_DATA


class TestEndToEndScenarios:
    """Complete workflow tests."""

    def test_scheme1_full_workflow(self):
        """
        Full Scheme 1 workflow:
        1. Admins form coalition
        2. Generate and share secret
        3. Derive K_D = KDF(s)
        4. User composes K_U* = KDF(K_U || K_D)
        5. Encrypt/decrypt data
        """
        # Setup
        scheme = DelegationScheme(threshold=THRESHOLD)

        # Step 1-2: Coalition generates secret
        secret = scheme.generate_secret()
        shares = scheme.share_secret(secret, {"admin1": 2, "admin2": 1})

        # Step 3: Reconstruct and derive K_D
        all_shares = shares["admin1"] + shares["admin2"]
        reconstructed = scheme.reconstruct_secret(all_shares)
        delegation = scheme.derive_delegation_key_scheme1(reconstructed)

        # Step 4: User composes key
        user_composed = compose_user_key(USER_KEY, delegation.key)

        # Step 5: Encrypt/decrypt
        ciphertext = encrypt_data(TEST_DATA, user_composed)
        plaintext = decrypt_data(ciphertext, user_composed)

        assert plaintext == TEST_DATA
        assert delegation.capabilities == set()  # read-only

    def test_scheme2_full_workflow(self):
        """
        Full Scheme 2 workflow with capabilities:
        1. Admins form coalition
        2. Generate and share secret
        3. Derive K_D^C = KDF(H(s || caps))
        4. User composes K_U* = KDF(K_U || K_D^C)
        5. Encrypt/decrypt data
        """
        # Setup
        scheme = DelegationScheme(threshold=THRESHOLD)

        # Step 1-2: Coalition generates secret
        secret = scheme.generate_secret()
        shares = scheme.share_secret(secret, {"admin1": 2, "admin2": 1})

        # Step 3: Reconstruct and derive K_D^C with read+write
        all_shares = shares["admin1"] + shares["admin2"]
        reconstructed = scheme.reconstruct_secret(all_shares)

        caps = {
            Capability.READ: CAPABILITY_KEYS[Capability.READ],
            Capability.WRITE: CAPABILITY_KEYS[Capability.WRITE],
        }
        delegation = scheme.derive_delegation_key_scheme2(reconstructed, caps)

        # Step 4: User composes key
        user_composed = compose_user_key(USER_KEY, delegation.key)

        # Step 5: Encrypt/decrypt
        ciphertext = encrypt_data(TEST_DATA, user_composed)
        plaintext = decrypt_data(ciphertext, user_composed)

        assert plaintext == TEST_DATA
        assert delegation.capabilities == {Capability.READ, Capability.WRITE}
