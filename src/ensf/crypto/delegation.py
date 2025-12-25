"""
Delegation key derivation schemes.

Implements two delegation schemes:

Scheme 1 (Basic Delegation):
    - Coalition of admins agrees on random secret s
    - Secret shared via SSS among coalition
    - Delegation key: K_D = KDF(s)
    - Grants read-only access

Scheme 2 (Delegation with Capabilities):
    - Same as Scheme 1, plus capability keys
    - Composite secret: s' = H(s || K^read || K^write || ...)
    - Delegation key: K_D^C = KDF(s')
    - Grants capabilities matching provided keys

User Key Composition:
    K_U* = KDF(K_U || K_D)

This ensures neither admins alone nor user alone can access data.
"""

import os
import secrets
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .shamir import Share, PRIME, generate_shares, reconstruct_secret
from .capability import (
    Capability,
    CapabilityKey,
    CapabilityKeySet,
    hash_capability_keys,
)
from .aes import KEY_SIZE


@dataclass
class DelegationKey:
    """
    A delegation key with associated capabilities.

    Attributes:
        key: 256-bit delegation key
        capabilities: Set of granted capabilities (empty = read-only)
    """

    key: bytes
    capabilities: set[Capability]

    def has_capability(self, cap: Capability) -> bool:
        """Check if this delegation grants the specified capability."""
        # Empty capabilities means read-only
        if not self.capabilities:
            return cap == Capability.READ
        return cap in self.capabilities

    def to_bytes(self) -> bytes:
        """
        Serialize to binary format.

        Format:
            - 1 byte: capability flags
            - 32 bytes: key
        """
        flags = 0
        if Capability.READ in self.capabilities:
            flags |= 1
        if Capability.WRITE in self.capabilities:
            flags |= 2
        if Capability.DELETE in self.capabilities:
            flags |= 4

        return bytes([flags]) + self.key

    @classmethod
    def from_bytes(cls, data: bytes) -> "DelegationKey":
        """Deserialize from binary format."""
        flags = data[0]
        key = data[1 : 1 + KEY_SIZE]

        capabilities = set()
        if flags & 1:
            capabilities.add(Capability.READ)
        if flags & 2:
            capabilities.add(Capability.WRITE)
        if flags & 4:
            capabilities.add(Capability.DELETE)

        return cls(key=key, capabilities=capabilities)


def _derive_key(input_material: bytes, info: bytes) -> bytes:
    """
    Derive a key using HKDF-SHA256.

    Args:
        input_material: Input keying material
        info: Context/application-specific info

    Returns:
        32-byte derived key
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=b"ensf-delegation-v2",
        info=info,
    )
    return hkdf.derive(input_material)


class DelegationScheme:
    """
    Combined delegation scheme supporting both Scheme 1 and Scheme 2.

    Attributes:
        threshold: Minimum total weight required for valid coalition
        prime: Prime for finite field arithmetic
    """

    def __init__(self, threshold: int, prime: int = PRIME):
        """
        Initialize delegation scheme.

        Args:
            threshold: Minimum combined weight for valid coalition (W)
            prime: Prime for SSS field
        """
        if threshold < 1:
            raise ValueError("Threshold must be at least 1")

        self.threshold = threshold
        self.prime = prime

    def validate_coalition(self, weights: dict[str, int]) -> bool:
        """
        Check if coalition meets threshold requirement.

        Args:
            weights: Mapping of admin_id to weight

        Returns:
            True if sum of weights >= threshold
        """
        return sum(weights.values()) >= self.threshold

    def generate_secret(self) -> int:
        """Generate random secret s in Z_p."""
        return secrets.randbelow(self.prime)

    def share_secret(
        self, secret: int, admin_weights: dict[str, int]
    ) -> dict[str, list[Share]]:
        """
        Split secret among admins according to their weights.

        Each admin receives shares equal to their weight.

        Args:
            secret: Secret to split
            admin_weights: Mapping of admin_id to weight

        Returns:
            Mapping of admin_id to list of shares
        """
        if not self.validate_coalition(admin_weights):
            raise ValueError(
                f"Coalition weight {sum(admin_weights.values())} "
                f"< threshold {self.threshold}"
            )

        total_shares = sum(admin_weights.values())
        all_shares = generate_shares(
            secret=secret,
            n_shares=total_shares,
            threshold=self.threshold,
            prime=self.prime,
        )

        # Distribute shares by weight
        result: dict[str, list[Share]] = {}
        idx = 0
        for admin_id, weight in admin_weights.items():
            result[admin_id] = all_shares[idx : idx + weight]
            idx += weight

        return result

    def reconstruct_secret(self, shares: list[Share]) -> int:
        """
        Reconstruct secret from shares.

        Args:
            shares: Collected shares (must meet threshold)

        Returns:
            Reconstructed secret
        """
        if len(shares) < self.threshold:
            raise ValueError(
                f"Insufficient shares: {len(shares)} < threshold {self.threshold}"
            )
        return reconstruct_secret(shares, self.prime)

    def derive_delegation_key_scheme1(self, secret: int) -> DelegationKey:
        """
        Scheme 1: Basic delegation with read-only access.

        K_D = KDF(s)

        Args:
            secret: Reconstructed secret from SSS

        Returns:
            DelegationKey with empty capabilities (read-only)
        """
        secret_bytes = secret.to_bytes(32, byteorder="big")
        key = _derive_key(secret_bytes, b"scheme1-basic")

        return DelegationKey(key=key, capabilities=set())

    def derive_delegation_key_scheme2(
        self, secret: int, capability_keys: list[CapabilityKey]
    ) -> DelegationKey:
        """
        Scheme 2: Delegation with capabilities.

        s' = H(s || K^op_1 || K^op_2 || ...)
        K_D^C = KDF(s')

        Args:
            secret: Reconstructed secret from SSS
            capability_keys: Capability keys to include

        Returns:
            DelegationKey with corresponding capabilities
        """
        if not capability_keys:
            # No capabilities = fall back to Scheme 1
            return self.derive_delegation_key_scheme1(secret)

        secret_bytes = secret.to_bytes(32, byteorder="big")

        # Compute s' = H(s || caps)
        composite_secret = hash_capability_keys(secret_bytes, capability_keys)

        # Derive key
        key = _derive_key(composite_secret, b"scheme2-capability")

        # Extract granted capabilities
        capabilities = {ck.capability for ck in capability_keys}

        return DelegationKey(key=key, capabilities=capabilities)


def compose_user_key(user_key: bytes, delegation_key: DelegationKey) -> bytes:
    """
    Compute final user access key.

    K_U* = KDF(K_U || K_D)

    Args:
        user_key: User's private key (32 bytes)
        delegation_key: Delegation key from coalition

    Returns:
        32-byte composed key for data encryption/decryption
    """
    if len(user_key) != KEY_SIZE:
        raise ValueError(f"User key must be {KEY_SIZE} bytes")

    input_material = user_key + delegation_key.key

    return _derive_key(input_material, b"user-composed-key")


@dataclass
class AdminShare:
    """
    An admin's shares for a delegation session.

    Attributes:
        admin_id: Admin identifier
        shares: List of SSS shares (count = weight)
    """

    admin_id: str
    shares: list[Share]

    def to_bytes(self) -> bytes:
        """Serialize to binary format."""
        admin_bytes = self.admin_id.encode("utf-8")

        result = bytearray()
        result.append(len(admin_bytes))
        result.extend(admin_bytes)
        result.append(len(self.shares))

        for share in self.shares:
            result.extend(share.to_bytes())

        return bytes(result)

    @classmethod
    def from_bytes(cls, data: bytes) -> "AdminShare":
        """Deserialize from binary format."""
        offset = 0

        admin_len = data[offset]
        offset += 1
        admin_id = data[offset : offset + admin_len].decode("utf-8")
        offset += admin_len

        num_shares = data[offset]
        offset += 1

        shares = []
        for _ in range(num_shares):
            share = Share.from_bytes(data[offset : offset + 64])
            shares.append(share)
            offset += 64

        return cls(admin_id=admin_id, shares=shares)
