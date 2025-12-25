"""Integration tests for end-to-end delegation scenarios."""

import tempfile
import pytest
from pathlib import Path

from ensf.crypto.delegation import DelegationScheme, compose_user_key
from ensf.crypto.capability import Capability, CapabilityKey
from ensf.crypto.aes import encrypt, decrypt
from ensf.core.admin import Admin, AdminRegistry
from ensf.core.user import User, UserRegistry
from ensf.core.keystore import KeyStore


class TestSecurityProperties:
    """Test security guarantees from spec."""

    def test_insufficient_coalition_cannot_derive_key(self):
        """
        If Σwᵢ < W, coalition cannot derive delegation key.
        """
        scheme = DelegationScheme(threshold=5)
        secret = scheme.generate_secret()

        # Coalition with weight 4 < threshold 5
        with pytest.raises(ValueError, match="Coalition weight"):
            scheme.share_secret(secret, {"A": 2, "B": 2})

    def test_admin_alone_cannot_decrypt(self):
        """
        Without K_U, admins cannot access user data.

        Even with delegation key, data requires user's private key.
        """
        scheme = DelegationScheme(threshold=2)
        secret = scheme.generate_secret()
        shares = scheme.share_secret(secret, {"A": 2})

        # Admin derives delegation key
        dk = scheme.derive_delegation_key_scheme1(secret)

        # User's key (admin doesn't have this)
        user_key = b"u" * 32

        # Compose correct key and encrypt
        correct_key = compose_user_key(user_key, dk)
        plaintext = b"secret user data"
        encrypted = encrypt(plaintext, correct_key)

        # Admin tries to decrypt with just delegation key (wrong)
        from cryptography.exceptions import InvalidTag

        with pytest.raises(InvalidTag):
            decrypt(encrypted, dk.key)  # Using dk.key directly fails

    def test_user_alone_cannot_decrypt(self):
        """
        Without K_D, user cannot access their data.

        User needs admins to create delegation key.
        """
        user_key = b"u" * 32

        # Create delegation key via admin coalition
        scheme = DelegationScheme(threshold=2)
        secret = scheme.generate_secret()
        dk = scheme.derive_delegation_key_scheme1(secret)

        # Correct composed key
        correct_key = compose_user_key(user_key, dk)

        # Encrypt data
        plaintext = b"secret user data"
        encrypted = encrypt(plaintext, correct_key)

        # User tries with only their key (wrong)
        from cryptography.exceptions import InvalidTag

        with pytest.raises(InvalidTag):
            decrypt(encrypted, user_key)  # Using user_key directly fails

    def test_admin_and_user_together_can_decrypt(self):
        """
        Admins form coalition → create K_D → user combines with K_U → access.
        """
        # Admin coalition creates delegation
        scheme = DelegationScheme(threshold=3)
        secret = scheme.generate_secret()
        shares = scheme.share_secret(secret, {"A": 2, "B": 1})

        # Reconstruct secret
        all_shares = shares["A"] + shares["B"]
        reconstructed = scheme.reconstruct_secret(all_shares)
        assert reconstructed == secret

        # Derive delegation key
        dk = scheme.derive_delegation_key_scheme1(reconstructed)

        # User combines keys
        user_key = b"u" * 32
        composed = compose_user_key(user_key, dk)

        # Encrypt and decrypt
        plaintext = b"user's private data"
        encrypted = encrypt(plaintext, composed)
        decrypted = decrypt(encrypted, composed)

        assert decrypted == plaintext


class TestScheme1VsScheme2:
    """Test differences between delegation schemes."""

    def test_scheme1_is_read_only(self):
        """Scheme 1 grants read-only access."""
        scheme = DelegationScheme(threshold=2)
        secret = scheme.generate_secret()

        dk = scheme.derive_delegation_key_scheme1(secret)

        assert dk.has_capability(Capability.READ) is True
        assert dk.has_capability(Capability.WRITE) is False
        assert dk.has_capability(Capability.DELETE) is False

    def test_scheme2_grants_specified_capabilities(self):
        """Scheme 2 grants only the capabilities provided."""
        scheme = DelegationScheme(threshold=2)
        secret = scheme.generate_secret()

        cap_keys = [
            CapabilityKey.generate(Capability.READ),
            CapabilityKey.generate(Capability.WRITE),
        ]

        dk = scheme.derive_delegation_key_scheme2(secret, cap_keys)

        assert dk.has_capability(Capability.READ) is True
        assert dk.has_capability(Capability.WRITE) is True
        assert dk.has_capability(Capability.DELETE) is False

    def test_scheme1_and_scheme2_produce_different_keys(self):
        """Same secret should produce different keys in different schemes."""
        scheme = DelegationScheme(threshold=2)
        secret = scheme.generate_secret()

        dk1 = scheme.derive_delegation_key_scheme1(secret)

        cap_keys = [CapabilityKey.generate(Capability.READ)]
        dk2 = scheme.derive_delegation_key_scheme2(secret, cap_keys)

        assert dk1.key != dk2.key


class TestKeyStoreIntegration:
    """Test KeyStore with full workflow."""

    @pytest.fixture
    def temp_store(self):
        """Create temporary keystore directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_full_workflow(self, temp_store):
        """
        End-to-end: init → add admins → add user → delegate → encrypt → decrypt.
        """
        keystore = KeyStore(temp_store)

        # Initialize
        admin_registry = AdminRegistry(threshold=3)
        user_registry = UserRegistry()

        # Add admins
        admin1 = Admin.generate("admin1", weight=2, with_capabilities=True)
        admin2 = Admin.generate("admin2", weight=1, with_capabilities=False)
        admin_registry.add(admin1)
        admin_registry.add(admin2)

        # Add user
        user = User.generate("user1")
        user_registry.add(user)

        # Save
        keystore.save_admin_registry(admin_registry)
        keystore.save_user_registry(user_registry)

        # Verify persistence
        loaded_admins = keystore.load_admin_registry()
        loaded_users = keystore.load_user_registry()

        assert loaded_admins.threshold == 3
        assert loaded_admins.get("admin1").weight == 2
        assert loaded_admins.get("admin2").weight == 1
        assert loaded_users.get("user1") is not None

        # Create delegation
        scheme = DelegationScheme(threshold=3)
        secret = scheme.generate_secret()

        weights = loaded_admins.get_weights(["admin1", "admin2"])
        assert loaded_admins.validate_coalition(["admin1", "admin2"])

        shares = scheme.share_secret(secret, weights)

        # Save admin shares
        from ensf.crypto.delegation import AdminShare

        for admin_id, share_list in shares.items():
            admin_share = AdminShare(admin_id=admin_id, shares=share_list)
            keystore.save_admin_share(admin_share)

        # Derive delegation key
        dk = scheme.derive_delegation_key_scheme1(secret)
        keystore.save_delegation_key("delegation1", dk)

        # Load and verify
        loaded_dk = keystore.load_delegation_key("delegation1")
        assert loaded_dk.key == dk.key

        # Compose key
        composed = compose_user_key(user.key, dk)

        # Encrypt/decrypt
        plaintext = b"test data"
        encrypted = encrypt(plaintext, composed)
        decrypted = decrypt(encrypted, composed)

        assert decrypted == plaintext
