"""
Delegation-based Secret Sharing Schemes.

Implements the formulas:

Scheme 1 (Basic Delegation):
    - Coalition S agrees on random secret: s ←$ Z_p
    - {s_i} ← Share(s)
    - s = Rec({s_i})
    - K_D = KDF(s)

Scheme 2 (Delegation with Capabilities):
    - C ⊆ {read, write, delete}
    - s' = H(s || K_j^op for op ∈ C)
    - K_D^C = KDF(s')

User Key Composition:
    - K_U* = KDF(K_U || K_D^C)
    - C = Enc_{K_U*}(D_U)
    - D_U = Dec_{K_U*}(C)
"""

import hashlib
import secrets
from dataclasses import dataclass
from enum import Enum, auto

from .shamir import Share, PRIME, generate_shares, reconstruct_secret


class Capability(Enum):
    """Access capability types."""

    READ = auto()
    WRITE = auto()
    DELETE = auto()


def kdf(input_material: bytes, info: bytes = b"ensf") -> bytes:
    """
    Key Derivation Function.

    Simple KDF using SHA-256 for demonstration.
    In production, use HKDF from cryptography library.

    Formula: KDF(x) = SHA256(info || x)

    Args:
        input_material: Input keying material
        info: Context string

    Returns:
        32-byte derived key
    """
    return hashlib.sha256(info + input_material).digest()


def hash_with_capabilities(
    secret: bytes, capability_keys: dict[Capability, bytes]
) -> bytes:
    """
    Compute composite secret for Scheme 2.

    Formula: s' = H(s || K_j^read || K_j^write || K_j^delete)

    Args:
        secret: Base secret s
        capability_keys: Mapping of Capability → key bytes

    Returns:
        32-byte hash
    """
    # Sort by capability value for deterministic ordering
    sorted_caps = sorted(capability_keys.keys(), key=lambda c: c.value)

    data = bytearray(secret)
    for cap in sorted_caps:
        data.extend(capability_keys[cap])

    return hashlib.sha256(bytes(data)).digest()


@dataclass
class DelegationResult:
    """Result of delegation key derivation."""

    key: bytes
    capabilities: set[Capability]


class DelegationScheme:
    """
    Weighted Secret Sharing with Delegation.

    Implements:
        - Coalition validation: Σw_i ≥ W
        - Scheme 1: K_D = KDF(s)
        - Scheme 2: K_D^C = KDF(H(s || caps))
    """

    def __init__(self, threshold: int, prime: int = PRIME):
        """
        Initialize scheme.

        Args:
            threshold: Minimum combined weight W for valid coalition
            prime: Prime for Z_p field
        """
        self.threshold = threshold
        self.prime = prime

    def validate_coalition(self, weights: dict[str, int]) -> bool:
        """
        Check if coalition is valid.

        Formula: Σ_{A_i ∈ S} w_i ≥ W
        """
        return sum(weights.values()) >= self.threshold

    def generate_secret(self) -> int:
        """Generate random secret s ←$ Z_p."""
        return secrets.randbelow(self.prime)

    def share_secret(
        self, secret: int, weights: dict[str, int]
    ) -> dict[str, list[Share]]:
        """
        Split secret among admins by weight.

        Formula: {s_i} ← Share(s)

        Each admin gets shares equal to their weight.
        """
        if not self.validate_coalition(weights):
            raise ValueError(
                f"Invalid coalition: Σw_i = {sum(weights.values())} < W = {self.threshold}"
            )

        total = sum(weights.values())
        all_shares = generate_shares(secret, total, self.threshold, self.prime)

        result = {}
        idx = 0
        for admin_id, weight in weights.items():
            result[admin_id] = all_shares[idx : idx + weight]
            idx += weight

        return result

    def reconstruct_secret(self, shares: list[Share]) -> int:
        """
        Reconstruct secret from shares.

        Formula: s = Rec({s_i})
        """
        return reconstruct_secret(shares, self.prime)

    def derive_delegation_key_scheme1(self, secret: int) -> DelegationResult:
        """
        Scheme 1: Basic delegation (read-only).

        Formula: K_D = KDF(s)
        """
        secret_bytes = secret.to_bytes(32, "big")
        key = kdf(secret_bytes, b"scheme1")

        return DelegationResult(key=key, capabilities=set())

    def derive_delegation_key_scheme2(
        self, secret: int, capability_keys: dict[Capability, bytes]
    ) -> DelegationResult:
        """
        Scheme 2: Delegation with capabilities.

        Formula:
            s' = H(s || K_j^op for op ∈ C)
            K_D^C = KDF(s')
        """
        if not capability_keys:
            return self.derive_delegation_key_scheme1(secret)

        secret_bytes = secret.to_bytes(32, "big")
        composite = hash_with_capabilities(secret_bytes, capability_keys)
        key = kdf(composite, b"scheme2")

        return DelegationResult(key=key, capabilities=set(capability_keys.keys()))


def compose_user_key(user_key: bytes, delegation_key: bytes) -> bytes:
    """
    Derive final user access key.

    Formula: K_U* = KDF(K_U || K_D^C)
    """
    return kdf(user_key + delegation_key, b"user-key")


def encrypt_data(data: bytes, key: bytes) -> bytes:
    """
    Simple XOR encryption for demonstration.

    Formula: C = Enc_{K_U*}(D_U)

    In production, use AES-GCM.
    """
    # Expand key to data length using hash chain
    key_stream = b""
    counter = 0
    while len(key_stream) < len(data):
        key_stream += hashlib.sha256(key + counter.to_bytes(4, "big")).digest()
        counter += 1

    return bytes(a ^ b for a, b in zip(data, key_stream[: len(data)]))


def decrypt_data(ciphertext: bytes, key: bytes) -> bytes:
    """
    Simple XOR decryption.

    Formula: D_U = Dec_{K_U*}(C)
    """
    # XOR is symmetric
    return encrypt_data(ciphertext, key)
