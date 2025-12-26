"""
Directory Encryption Module.

Provides functions to encrypt and decrypt directories using
the delegation scheme with authenticated encryption.

Uses AES-GCM for production encryption of actual file contents.
The delegation keys are used to derive the AES key.
"""

import os
import tarfile
import tempfile
import hashlib
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .delegation import (
    DelegationScheme,
    DelegationKeys,
    UserKeys,
    Operation,
    AuthenticatedCiphertext,
)


# AES-GCM constants
NONCE_SIZE = 12
KEY_SIZE = 32
TAG_SIZE = 16


def derive_aes_key(key: int, prime: int) -> bytes:
    """
    Derive 32-byte AES key from field element.

    For real keys (large prime), use the integer bytes.
    For toy example (p=17), use expanded hash.
    """
    key_bytes = key.to_bytes(32, "big")
    return hashlib.sha256(key_bytes).digest()


@dataclass
class EncryptedDirectory:
    """
    Encrypted directory container.

    Attributes:
        nonce: 12-byte random nonce
        ciphertext: Encrypted tar archive
        auth_tag: Optional authentication tag for write/delete
        operation: Operation type used
    """

    nonce: bytes
    ciphertext: bytes
    auth_tag: Optional[bytes] = None
    operation: Operation = Operation.READ

    def to_bytes(self) -> bytes:
        """Serialize to bytes."""
        # Format: op (1) + nonce (12) + tag_len (1) + tag (0-16) + ciphertext
        result = bytearray()
        result.append(self.operation.value)
        result.extend(self.nonce)

        if self.auth_tag:
            result.append(len(self.auth_tag))
            result.extend(self.auth_tag)
        else:
            result.append(0)

        result.extend(self.ciphertext)
        return bytes(result)

    @classmethod
    def from_bytes(cls, data: bytes) -> "EncryptedDirectory":
        """Deserialize from bytes."""
        offset = 0

        operation = Operation(data[offset])
        offset += 1

        nonce = data[offset : offset + NONCE_SIZE]
        offset += NONCE_SIZE

        tag_len = data[offset]
        offset += 1

        auth_tag = None
        if tag_len > 0:
            auth_tag = data[offset : offset + tag_len]
            offset += tag_len

        ciphertext = data[offset:]

        return cls(
            nonce=nonce, ciphertext=ciphertext, auth_tag=auth_tag, operation=operation
        )


class DirectoryEncryption:
    """
    Encrypt and decrypt directories using delegation keys.

    Read operations use standard AES-GCM.
    Write/Delete operations include authentication tags for verification.
    """

    def __init__(self, scheme: DelegationScheme):
        self.scheme = scheme

    def _archive_directory(self, dir_path: Path) -> bytes:
        """Create tar archive of directory."""
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            with tarfile.open(tmp_path, "w") as tar:
                tar.add(dir_path, arcname=dir_path.name)

            with open(tmp_path, "rb") as f:
                return f.read()
        finally:
            os.unlink(tmp_path)

    def _extract_archive(self, archive_data: bytes, output_path: Path) -> None:
        """Extract tar archive to directory."""
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
            tmp.write(archive_data)
            tmp_path = tmp.name

        try:
            output_path.mkdir(parents=True, exist_ok=True)
            with tarfile.open(tmp_path, "r") as tar:
                tar.extractall(path=output_path, filter="data")
        finally:
            os.unlink(tmp_path)

    def encrypt_for_read(
        self, dir_path: Path, user_keys: UserKeys
    ) -> EncryptedDirectory:
        """
        Encrypt directory for read operation.

        C = Enc_{K_U^read}(D_U)
        """
        archive = self._archive_directory(dir_path)

        aes_key = derive_aes_key(user_keys.read, self.scheme.prime)
        nonce = os.urandom(NONCE_SIZE)

        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, archive, None)

        return EncryptedDirectory(
            nonce=nonce, ciphertext=ciphertext, operation=Operation.READ
        )

    def decrypt_for_read(
        self, encrypted: EncryptedDirectory, user_keys: UserKeys, output_path: Path
    ) -> bool:
        """
        Decrypt directory for read operation.

        D_U = Dec_{K_U^read}(C)

        Returns True on success, False on failure.
        """
        try:
            aes_key = derive_aes_key(user_keys.read, self.scheme.prime)
            aesgcm = AESGCM(aes_key)

            archive = aesgcm.decrypt(encrypted.nonce, encrypted.ciphertext, None)

            self._extract_archive(archive, output_path)
            return True
        except Exception:
            return False

    def encrypt_for_write(
        self, dir_path: Path, user_keys: UserKeys
    ) -> Optional[EncryptedDirectory]:
        """
        Encrypt directory for write operation.

        (C', τ) = EncAuth_{K_U^write}(D_U')

        Returns None if user lacks write capability.
        """
        if user_keys.write is None:
            return None

        archive = self._archive_directory(dir_path)

        aes_key = derive_aes_key(user_keys.write, self.scheme.prime)
        nonce = os.urandom(NONCE_SIZE)

        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, archive, None)

        # Create authentication tag: τ = H(K_U^write || ciphertext)
        tag_input = user_keys.write.to_bytes(32, "big") + ciphertext
        auth_tag = hashlib.sha256(tag_input).digest()[:TAG_SIZE]

        return EncryptedDirectory(
            nonce=nonce,
            ciphertext=ciphertext,
            auth_tag=auth_tag,
            operation=Operation.WRITE,
        )

    def verify_and_decrypt_write(
        self, encrypted: EncryptedDirectory, user_keys: UserKeys, output_path: Path
    ) -> bool:
        """
        Verify and decrypt write operation.

        DecAuth_{K_U^write}(C', τ) = D_U' or ⊥

        Returns True on success, False on failure.
        """
        if user_keys.write is None:
            return False

        if encrypted.auth_tag is None:
            return False

        # Verify authentication tag
        expected_tag_input = user_keys.write.to_bytes(32, "big") + encrypted.ciphertext
        expected_tag = hashlib.sha256(expected_tag_input).digest()[:TAG_SIZE]

        if encrypted.auth_tag != expected_tag:
            return False  # ⊥

        try:
            aes_key = derive_aes_key(user_keys.write, self.scheme.prime)
            aesgcm = AESGCM(aes_key)

            archive = aesgcm.decrypt(encrypted.nonce, encrypted.ciphertext, None)

            self._extract_archive(archive, output_path)
            return True
        except Exception:
            return False
