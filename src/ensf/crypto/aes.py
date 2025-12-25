"""
AES-256-GCM authenticated encryption.

AES-256-GCM (Advanced Encryption Standard with Galois/Counter Mode):
    - AES: Block cipher with 256-bit key, considered quantum-resistant at 128-bit level
    - GCM: Authenticated mode providing both confidentiality and integrity
    - Produces ciphertext + authentication tag (detects tampering)

Why GCM over CBC or CTR alone:
    - CBC: No built-in integrity; vulnerable to padding oracle attacks
    - CTR: No integrity; bit-flipping attacks possible
    - GCM: Authenticated encryption; tampered data is rejected

Reference:
    NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: GCM
    https://csrc.nist.gov/publications/detail/sp/800-38d/final
"""

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Nonce size for GCM mode. 96 bits (12 bytes) is recommended by NIST.
NONCE_SIZE = 12

# Authentication tag size. 128 bits (16 bytes) is the maximum and most secure.
TAG_SIZE = 16

# AES key size. 256 bits for maximum security.
KEY_SIZE = 32


@dataclass(frozen=True)
class EncryptedData:
    """
    Container for encrypted data with all components needed for decryption.

    Attributes:
        nonce: Random initialization vector (12 bytes)
        ciphertext: Encrypted data including authentication tag
    """

    nonce: bytes
    ciphertext: bytes

    def to_bytes(self) -> bytes:
        """
        Serialize to binary format.

        Format:
            - 12 bytes: nonce
            - remaining: ciphertext (includes 16-byte auth tag)
        """
        return self.nonce + self.ciphertext

    @classmethod
    def from_bytes(cls, data: bytes) -> "EncryptedData":
        """
        Deserialize from binary format.

        Args:
            data: Binary data from to_bytes()

        Returns:
            EncryptedData instance

        Raises:
            ValueError: If data is too short
        """
        if len(data) < NONCE_SIZE + TAG_SIZE:
            raise ValueError(
                f"Encrypted data too short: got {len(data)}, "
                f"minimum {NONCE_SIZE + TAG_SIZE}"
            )

        nonce = data[:NONCE_SIZE]
        ciphertext = data[NONCE_SIZE:]
        return cls(nonce=nonce, ciphertext=ciphertext)


def encrypt(plaintext: bytes, key: bytes) -> EncryptedData:
    """
    Encrypt data using AES-256-GCM.

    Generates a random nonce for each encryption. Never reuse nonces with
    the same key, as this completely breaks GCM security.

    Args:
        plaintext: Data to encrypt (arbitrary length)
        key: 256-bit (32 byte) encryption key

    Returns:
        EncryptedData containing nonce and ciphertext

    Raises:
        ValueError: If key is wrong size
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")

    # Generate random nonce. os.urandom uses system CSPRNG.
    nonce = os.urandom(NONCE_SIZE)

    # Create cipher and encrypt
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)

    return EncryptedData(nonce=nonce, ciphertext=ciphertext)


def decrypt(encrypted: EncryptedData, key: bytes) -> bytes:
    """
    Decrypt data using AES-256-GCM.

    Verifies authentication tag before returning plaintext. If the tag
    doesn't match (data tampered or wrong key), raises an exception.

    Args:
        encrypted: EncryptedData from encrypt()
        key: 256-bit encryption key (must match encryption key)

    Returns:
        Decrypted plaintext

    Raises:
        ValueError: If key is wrong size
        cryptography.exceptions.InvalidTag: If authentication fails
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")

    cipher = AESGCM(key)
    plaintext = cipher.decrypt(
        encrypted.nonce, encrypted.ciphertext, associated_data=None
    )

    return plaintext


def encrypt_file(filepath: str, key: bytes, output_path: str) -> None:
    """
    Encrypt a file and write to output path.

    Args:
        filepath: Path to file to encrypt
        key: 256-bit encryption key
        output_path: Path to write encrypted output
    """
    with open(filepath, "rb") as f:
        plaintext = f.read()

    encrypted = encrypt(plaintext, key)

    with open(output_path, "wb") as f:
        f.write(encrypted.to_bytes())


def decrypt_file(filepath: str, key: bytes, output_path: str) -> None:
    """
    Decrypt a file and write to output path.

    Args:
        filepath: Path to encrypted file
        key: 256-bit decryption key
        output_path: Path to write decrypted output

    Raises:
        cryptography.exceptions.InvalidTag: If authentication fails
    """
    with open(filepath, "rb") as f:
        data = f.read()

    encrypted = EncryptedData.from_bytes(data)
    plaintext = decrypt(encrypted, key)

    with open(output_path, "wb") as f:
        f.write(plaintext)
