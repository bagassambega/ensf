"""Tests for AES-256-GCM encryption."""

import pytest
from cryptography.exceptions import InvalidTag

from ensf.crypto.aes import (
    encrypt,
    decrypt,
    EncryptedData,
    KEY_SIZE,
    NONCE_SIZE,
)


class TestEncryptedData:
    """Tests for EncryptedData serialization."""

    def test_to_bytes_and_from_bytes(self):
        """Round-trip serialization."""
        # Ciphertext must be at least TAG_SIZE (16 bytes) since GCM appends auth tag
        ed = EncryptedData(nonce=b"x" * NONCE_SIZE, ciphertext=b"y" * 20)

        data = ed.to_bytes()
        recovered = EncryptedData.from_bytes(data)

        assert recovered.nonce == ed.nonce
        assert recovered.ciphertext == ed.ciphertext

    def test_from_bytes_too_short(self):
        """Should raise on data too short."""
        with pytest.raises(ValueError, match="too short"):
            EncryptedData.from_bytes(b"short")


class TestAESEncryption:
    """Tests for AES-256-GCM encryption/decryption."""

    def test_round_trip(self):
        """Encrypt then decrypt should return original."""
        key = b"k" * KEY_SIZE
        plaintext = b"Hello, World! This is a test message."

        encrypted = encrypt(plaintext, key)
        decrypted = decrypt(encrypted, key)

        assert decrypted == plaintext

    def test_empty_plaintext(self):
        """Should handle empty plaintext."""
        key = b"k" * KEY_SIZE
        plaintext = b""

        encrypted = encrypt(plaintext, key)
        decrypted = decrypt(encrypted, key)

        assert decrypted == b""

    def test_large_plaintext(self):
        """Should handle large data."""
        key = b"k" * KEY_SIZE
        plaintext = b"x" * (1024 * 1024)  # 1 MB

        encrypted = encrypt(plaintext, key)
        decrypted = decrypt(encrypted, key)

        assert decrypted == plaintext

    def test_wrong_key_fails(self):
        """Decryption with wrong key should fail authentication."""
        key1 = b"a" * KEY_SIZE
        key2 = b"b" * KEY_SIZE
        plaintext = b"secret data"

        encrypted = encrypt(plaintext, key1)

        with pytest.raises(InvalidTag):
            decrypt(encrypted, key2)

    def test_tampered_ciphertext_fails(self):
        """Tampered ciphertext should fail authentication."""
        key = b"k" * KEY_SIZE
        plaintext = b"secret data"

        encrypted = encrypt(plaintext, key)

        # Tamper with ciphertext
        tampered = EncryptedData(
            nonce=encrypted.nonce, ciphertext=b"x" + encrypted.ciphertext[1:]
        )

        with pytest.raises(InvalidTag):
            decrypt(tampered, key)

    def test_unique_nonce_per_encryption(self):
        """Each encryption should use a different nonce."""
        key = b"k" * KEY_SIZE
        plaintext = b"same data"

        encrypted1 = encrypt(plaintext, key)
        encrypted2 = encrypt(plaintext, key)

        assert encrypted1.nonce != encrypted2.nonce
        assert encrypted1.ciphertext != encrypted2.ciphertext

    def test_invalid_key_size(self):
        """Should reject incorrect key sizes."""
        with pytest.raises(ValueError, match="Key must be 32 bytes"):
            encrypt(b"data", b"short_key")

        with pytest.raises(ValueError, match="Key must be 32 bytes"):
            decrypt(
                EncryptedData(nonce=b"x" * NONCE_SIZE, ciphertext=b"data"), b"short_key"
            )
