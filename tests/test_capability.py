"""Tests for Capability module."""

import pytest
from ensf.crypto.capability import (
    Capability,
    CapabilityKey,
    CapabilityKeySet,
    hash_capability_keys,
    CAPABILITY_KEY_SIZE,
)


class TestCapabilityKey:
    """Tests for CapabilityKey."""

    def test_generate_creates_correct_size(self):
        """Generated key should be correct size."""
        key = CapabilityKey.generate(Capability.READ)
        assert len(key.key) == CAPABILITY_KEY_SIZE
        assert key.capability == Capability.READ

    def test_to_bytes_and_from_bytes(self):
        """Round-trip serialization."""
        key = CapabilityKey.generate(Capability.WRITE)
        data = key.to_bytes()
        recovered = CapabilityKey.from_bytes(data)

        assert recovered.capability == Capability.WRITE
        assert recovered.key == key.key


class TestCapabilityKeySet:
    """Tests for CapabilityKeySet."""

    def test_generate_full(self):
        """Full set should have all capabilities."""
        keyset = CapabilityKeySet.generate_full()

        assert keyset.has_capability(Capability.READ)
        assert keyset.has_capability(Capability.WRITE)
        assert keyset.has_capability(Capability.DELETE)

    def test_get_capabilities(self):
        """Should return correct capability set."""
        keyset = CapabilityKeySet(
            read_key=CapabilityKey.generate(Capability.READ),
            write_key=None,
            delete_key=CapabilityKey.generate(Capability.DELETE),
        )

        caps = keyset.get_capabilities()
        assert Capability.READ in caps
        assert Capability.WRITE not in caps
        assert Capability.DELETE in caps

    def test_to_bytes_and_from_bytes(self):
        """Round-trip serialization."""
        keyset = CapabilityKeySet.generate_full()
        data = keyset.to_bytes()
        recovered = CapabilityKeySet.from_bytes(data)

        assert recovered.read_key.key == keyset.read_key.key
        assert recovered.write_key.key == keyset.write_key.key
        assert recovered.delete_key.key == keyset.delete_key.key


class TestHashCapabilityKeys:
    """Tests for hash_capability_keys."""

    def test_deterministic(self):
        """Same inputs should produce same hash."""
        secret = b"x" * 32
        keys = [
            CapabilityKey(capability=Capability.READ, key=b"a" * 32),
            CapabilityKey(capability=Capability.WRITE, key=b"b" * 32),
        ]

        hash1 = hash_capability_keys(secret, keys)
        hash2 = hash_capability_keys(secret, keys)

        assert hash1 == hash2

    def test_order_independent(self):
        """Order of keys should not matter (sorted internally)."""
        secret = b"x" * 32
        key_r = CapabilityKey(capability=Capability.READ, key=b"a" * 32)
        key_w = CapabilityKey(capability=Capability.WRITE, key=b"b" * 32)

        hash1 = hash_capability_keys(secret, [key_r, key_w])
        hash2 = hash_capability_keys(secret, [key_w, key_r])

        assert hash1 == hash2

    def test_different_keys_different_hash(self):
        """Different capability keys should produce different hashes."""
        secret = b"x" * 32
        keys1 = [CapabilityKey(capability=Capability.READ, key=b"a" * 32)]
        keys2 = [CapabilityKey(capability=Capability.READ, key=b"b" * 32)]

        hash1 = hash_capability_keys(secret, keys1)
        hash2 = hash_capability_keys(secret, keys2)

        assert hash1 != hash2
