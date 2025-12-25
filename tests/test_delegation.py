"""Tests for Delegation module."""

import pytest
from ensf.crypto.delegation import (
    DelegationScheme,
    DelegationKey,
    AdminShare,
    compose_user_key,
)
from ensf.crypto.capability import Capability, CapabilityKey
from ensf.crypto.aes import KEY_SIZE


class TestDelegationKey:
    """Tests for DelegationKey."""

    def test_has_capability_empty_means_read(self):
        """Empty capabilities should grant read-only."""
        dk = DelegationKey(key=b"x" * KEY_SIZE, capabilities=set())

        assert dk.has_capability(Capability.READ) is True
        assert dk.has_capability(Capability.WRITE) is False
        assert dk.has_capability(Capability.DELETE) is False

    def test_has_capability_with_caps(self):
        """Should correctly report granted capabilities."""
        dk = DelegationKey(
            key=b"x" * KEY_SIZE, capabilities={Capability.READ, Capability.WRITE}
        )

        assert dk.has_capability(Capability.READ) is True
        assert dk.has_capability(Capability.WRITE) is True
        assert dk.has_capability(Capability.DELETE) is False

    def test_to_bytes_and_from_bytes(self):
        """Round-trip serialization."""
        dk = DelegationKey(
            key=b"y" * KEY_SIZE, capabilities={Capability.WRITE, Capability.DELETE}
        )

        data = dk.to_bytes()
        recovered = DelegationKey.from_bytes(data)

        assert recovered.key == dk.key
        assert recovered.capabilities == dk.capabilities


class TestDelegationScheme:
    """Tests for DelegationScheme."""

    def test_validate_coalition_valid(self):
        """Coalition meeting threshold should be valid."""
        scheme = DelegationScheme(threshold=5)

        assert scheme.validate_coalition({"A": 3, "B": 2}) is True
        assert scheme.validate_coalition({"A": 5}) is True
        assert scheme.validate_coalition({"A": 2, "B": 2, "C": 1}) is True

    def test_validate_coalition_invalid(self):
        """Coalition below threshold should be invalid."""
        scheme = DelegationScheme(threshold=5)

        assert scheme.validate_coalition({"A": 2, "B": 2}) is False
        assert scheme.validate_coalition({"A": 4}) is False

    def test_share_secret_distributes_by_weight(self):
        """Each admin should get shares equal to their weight."""
        scheme = DelegationScheme(threshold=3)
        secret = scheme.generate_secret()

        shares = scheme.share_secret(secret, {"A": 2, "B": 1})

        assert len(shares["A"]) == 2
        assert len(shares["B"]) == 1

    def test_share_secret_insufficient_coalition_fails(self):
        """Sharing with insufficient coalition should fail."""
        scheme = DelegationScheme(threshold=5)
        secret = scheme.generate_secret()

        with pytest.raises(ValueError, match="Coalition weight"):
            scheme.share_secret(secret, {"A": 2, "B": 2})

    def test_reconstruct_with_threshold(self):
        """Reconstruction with threshold shares should succeed."""
        scheme = DelegationScheme(threshold=3)
        secret = scheme.generate_secret()

        shares = scheme.share_secret(secret, {"A": 2, "B": 1})
        all_shares = shares["A"] + shares["B"]

        recovered = scheme.reconstruct_secret(all_shares)
        assert recovered == secret

    def test_scheme1_produces_valid_key(self):
        """Scheme 1 should produce correct size key with no capabilities."""
        scheme = DelegationScheme(threshold=2)
        secret = scheme.generate_secret()

        dk = scheme.derive_delegation_key_scheme1(secret)

        assert len(dk.key) == KEY_SIZE
        assert dk.capabilities == set()

    def test_scheme2_produces_key_with_capabilities(self):
        """Scheme 2 should include capabilities in delegation key."""
        scheme = DelegationScheme(threshold=2)
        secret = scheme.generate_secret()

        cap_keys = [
            CapabilityKey.generate(Capability.READ),
            CapabilityKey.generate(Capability.WRITE),
        ]

        dk = scheme.derive_delegation_key_scheme2(secret, cap_keys)

        assert len(dk.key) == KEY_SIZE
        assert Capability.READ in dk.capabilities
        assert Capability.WRITE in dk.capabilities
        assert Capability.DELETE not in dk.capabilities

    def test_scheme2_no_caps_falls_back_to_scheme1(self):
        """Scheme 2 with empty capabilities should behave like Scheme 1."""
        scheme = DelegationScheme(threshold=2)
        secret = scheme.generate_secret()

        dk1 = scheme.derive_delegation_key_scheme1(secret)
        dk2 = scheme.derive_delegation_key_scheme2(secret, [])

        # Same key (both use scheme1 derivation)
        assert dk1.key == dk2.key

    def test_different_capabilities_different_keys(self):
        """Different capability sets should produce different keys."""
        scheme = DelegationScheme(threshold=2)
        secret = scheme.generate_secret()

        cap_read = [CapabilityKey.generate(Capability.READ)]
        cap_write = [CapabilityKey.generate(Capability.WRITE)]

        dk1 = scheme.derive_delegation_key_scheme2(secret, cap_read)
        dk2 = scheme.derive_delegation_key_scheme2(secret, cap_write)

        assert dk1.key != dk2.key


class TestComposeUserKey:
    """Tests for user key composition."""

    def test_compose_user_key_produces_valid_key(self):
        """Composed key should be correct size."""
        user_key = b"u" * KEY_SIZE
        dk = DelegationKey(key=b"d" * KEY_SIZE, capabilities=set())

        composed = compose_user_key(user_key, dk)

        assert len(composed) == KEY_SIZE

    def test_compose_key_deterministic(self):
        """Same inputs should produce same composed key."""
        user_key = b"u" * KEY_SIZE
        dk = DelegationKey(key=b"d" * KEY_SIZE, capabilities=set())

        composed1 = compose_user_key(user_key, dk)
        composed2 = compose_user_key(user_key, dk)

        assert composed1 == composed2

    def test_different_user_keys_different_composed(self):
        """Different user keys should produce different composed keys."""
        dk = DelegationKey(key=b"d" * KEY_SIZE, capabilities=set())

        composed1 = compose_user_key(b"a" * KEY_SIZE, dk)
        composed2 = compose_user_key(b"b" * KEY_SIZE, dk)

        assert composed1 != composed2

    def test_different_delegation_keys_different_composed(self):
        """Different delegation keys should produce different composed keys."""
        user_key = b"u" * KEY_SIZE
        dk1 = DelegationKey(key=b"a" * KEY_SIZE, capabilities=set())
        dk2 = DelegationKey(key=b"b" * KEY_SIZE, capabilities=set())

        composed1 = compose_user_key(user_key, dk1)
        composed2 = compose_user_key(user_key, dk2)

        assert composed1 != composed2


class TestAdminShare:
    """Tests for AdminShare serialization."""

    def test_to_bytes_and_from_bytes(self):
        """Round-trip serialization."""
        from ensf.crypto.shamir import Share

        shares = [Share(x=1, y=100), Share(x=2, y=200)]
        admin_share = AdminShare(admin_id="admin1", shares=shares)

        data = admin_share.to_bytes()
        recovered = AdminShare.from_bytes(data)

        assert recovered.admin_id == "admin1"
        assert len(recovered.shares) == 2
        assert recovered.shares[0].x == 1
