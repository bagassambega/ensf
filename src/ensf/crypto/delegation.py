"""
Formal Delegation-based Access Control Scheme.

Implements the algorithm as specified:

ACTORS:
    - Administrators A = {A_1, ..., A_n} with:
        - Base secret share s_i ∈ F_p
        - Weight w_i ∈ N
        - Capability keys {K_i^op | op ∈ {read, write, delete}}
    - User U with private key K_U ∈ F_p

THRESHOLDS:
    - W_read: threshold for read-only delegation
    - W_cap: threshold for capability delegation (W_cap >= W_read)

CASE 1 (Read-Only):
    - Reconstruct s from shares
    - K_D^read = KDF(s)
    - K_U^read = KDF(K_U || K_D^read)
    - C = Enc_{K_U^read}(D_U)

CASE 2 (With Capabilities):
    - Φ(x,y) = KDF(H(x || y))
    - K_D^read = KDF(s)
    - K_D^op = Φ(s, K_j^op) for op ∈ C
    - K_U^op = KDF(K_U || K_D^op)
    - Write/Delete use authenticated encryption
"""

import hashlib
import secrets
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional

from .shamir import Share, PRIME, generate_shares, reconstruct_secret


class Operation(Enum):
    """Operation types O = {read, write, delete}."""

    READ = auto()
    WRITE = auto()
    DELETE = auto()


# =============================================================================
# CRYPTOGRAPHIC PRIMITIVES
# =============================================================================


def kdf(x: int, prime: int = PRIME) -> int:
    """
    Key Derivation Function: KDF(x) -> F_p

    For production, this would use HKDF.
    For the toy example (p=17): KDF(z) = z
    """
    if prime == 17:
        # Toy example: identity function
        return x % prime

    # Real implementation: hash-based
    x_bytes = x.to_bytes(32, "big")
    h = hashlib.sha256(x_bytes).digest()
    return int.from_bytes(h, "big") % prime


def hash_concat(x: int, y: int, prime: int = PRIME) -> int:
    """
    Hash function: H(x || y) -> F_p

    For the toy example (p=17): H(x||y) = x + y mod p
    """
    if prime == 17:
        # Toy example: addition
        return (x + y) % prime

    # Real implementation: SHA-256
    data = x.to_bytes(32, "big") + y.to_bytes(32, "big")
    h = hashlib.sha256(data).digest()
    return int.from_bytes(h, "big") % prime


def phi(x: int, y: int, prime: int = PRIME) -> int:
    """
    Composition function: Φ(x, y) = KDF(H(x || y))

    Used to derive capability delegation keys.
    """
    h = hash_concat(x, y, prime)
    return kdf(h, prime)


# =============================================================================
# SYMMETRIC ENCRYPTION
# =============================================================================


def encrypt(plaintext: int, key: int, prime: int = PRIME) -> int:
    """
    Symmetric encryption: Enc_K(m) -> c

    For toy example: c = m + k mod p
    """
    return (plaintext + key) % prime


def decrypt(ciphertext: int, key: int, prime: int = PRIME) -> int:
    """
    Symmetric decryption: Dec_K(c) -> m

    For toy example: m = c - k mod p
    """
    return (ciphertext - key) % prime


@dataclass
class AuthenticatedCiphertext:
    """(C, τ) pair from authenticated encryption."""

    ciphertext: int
    tag: int


def encrypt_auth(
    plaintext: int, key: int, prime: int = PRIME
) -> AuthenticatedCiphertext:
    """
    Authenticated encryption: EncAuth_K(m) -> (c, τ)

    For toy example:
        c = m + k mod p
        τ = k + c mod p
    """
    c = (plaintext + key) % prime
    tau = (key + c) % prime
    return AuthenticatedCiphertext(ciphertext=c, tag=tau)


def decrypt_auth(
    auth_ct: AuthenticatedCiphertext, key: int, prime: int = PRIME
) -> Optional[int]:
    """
    Authenticated decryption: DecAuth_K(c, τ) -> m or ⊥

    Returns None (⊥) if verification fails.

    For toy example:
        Verify: k + c ≡ τ mod p
        If valid: m = c - k mod p
    """
    expected_tag = (key + auth_ct.ciphertext) % prime

    if expected_tag != auth_ct.tag:
        return None  # ⊥

    return (auth_ct.ciphertext - key) % prime


# =============================================================================
# ADMINISTRATOR
# =============================================================================


@dataclass
class Administrator:
    """
    Administrator A_i with:
        - id: identifier i
        - share: secret share s_i = f(i)
        - weight: w_i
        - capability_keys: {K_i^op | op ∈ O}
    """

    id: int
    share: int
    weight: int
    capability_keys: dict[Operation, int]


# =============================================================================
# DELEGATION KEYS
# =============================================================================


@dataclass
class DelegationKeys:
    """
    Delegation keys from coalition to user.

    K_D^read always set.
    K_D^write, K_D^delete = None (⊥) if not granted.
    """

    read: int
    write: Optional[int] = None
    delete: Optional[int] = None

    def get(self, op: Operation) -> Optional[int]:
        if op == Operation.READ:
            return self.read
        elif op == Operation.WRITE:
            return self.write
        elif op == Operation.DELETE:
            return self.delete
        return None


@dataclass
class UserKeys:
    """
    User's derived operation keys.

    K_U^op = KDF(K_U || K_D^op) if K_D^op ≠ ⊥
           = ⊥ otherwise
    """

    read: int
    write: Optional[int] = None
    delete: Optional[int] = None

    def get(self, op: Operation) -> Optional[int]:
        if op == Operation.READ:
            return self.read
        elif op == Operation.WRITE:
            return self.write
        elif op == Operation.DELETE:
            return self.delete
        return None


# =============================================================================
# DELEGATION SCHEME
# =============================================================================


class DelegationScheme:
    """
    Implements the formal delegation algorithm.

    Attributes:
        prime: Field F_p
        w_read: Threshold for read delegation
        w_cap: Threshold for capability delegation
        t: Effective threshold for Shamir SSS
        master_secret: s ∈ F_p
    """

    def __init__(
        self,
        prime: int = PRIME,
        w_read: int = 3,
        w_cap: int = 3,
    ):
        """
        Initialize scheme with thresholds.

        Args:
            prime: Field prime p
            w_read: W_read threshold
            w_cap: W_cap threshold (must be >= w_read)
        """
        if w_cap < w_read:
            raise ValueError("W_cap must be >= W_read")

        self.prime = prime
        self.w_read = w_read
        self.w_cap = w_cap
        self.t = w_read  # Effective threshold = W_read
        self.master_secret: Optional[int] = None

    def setup_secret(self, secret: Optional[int] = None) -> int:
        """
        Generate or set master secret s ∈ F_p.
        """
        if secret is None:
            self.master_secret = secrets.randbelow(self.prime)
        else:
            self.master_secret = secret % self.prime
        return self.master_secret

    def generate_shares(self, admin_weights: dict[int, int]) -> list[Administrator]:
        """
        Shamir Secret Sharing Setup.

        1. Construct polynomial f(x) = s + a_1*x + ... + a_{t-1}*x^{t-1}
        2. Each A_i receives s_i = f(i)

        Args:
            admin_weights: {admin_id: weight}

        Returns:
            List of Administrator objects with shares
        """
        if self.master_secret is None:
            raise ValueError("Call setup_secret first")

        n = len(admin_weights)
        shares = generate_shares(
            secret=self.master_secret, n_shares=n, threshold=self.t, prime=self.prime
        )

        admins = []
        for i, (admin_id, weight) in enumerate(admin_weights.items()):
            # Generate random capability keys
            cap_keys = {
                Operation.READ: secrets.randbelow(self.prime),
                Operation.WRITE: secrets.randbelow(self.prime),
                Operation.DELETE: secrets.randbelow(self.prime),
            }

            admin = Administrator(
                id=admin_id, share=shares[i].y, weight=weight, capability_keys=cap_keys
            )
            admins.append(admin)

        return admins

    def validate_coalition(
        self, admins: list[Administrator], for_capability: bool = False
    ) -> bool:
        """
        Check if coalition meets threshold.

        Σ w_i >= W_read (for read)
        Σ w_i >= W_cap (for capabilities)
        """
        total_weight = sum(a.weight for a in admins)
        threshold = self.w_cap if for_capability else self.w_read
        return total_weight >= threshold

    def reconstruct_secret(self, admins: list[Administrator]) -> int:
        """
        Reconstruct s = Rec({(i, s_i)}).

        Uses Lagrange interpolation.
        """
        shares = [Share(x=a.id, y=a.share) for a in admins]
        return reconstruct_secret(shares, self.prime)

    def delegate_case1(self, admins: list[Administrator]) -> DelegationKeys:
        """
        Case 1: Read-Only Delegation.

        1. Validate Σ w_i >= W_read
        2. Reconstruct s
        3. K_D^read = KDF(s)
        4. K_D^write = K_D^delete = ⊥
        """
        if not self.validate_coalition(admins, for_capability=False):
            raise ValueError(
                f"Coalition weight {sum(a.weight for a in admins)} "
                f"< W_read {self.w_read}"
            )

        s = self.reconstruct_secret(admins)
        k_d_read = kdf(s, self.prime)

        return DelegationKeys(read=k_d_read, write=None, delete=None)

    def delegate_case2(
        self,
        admins: list[Administrator],
        capability_provider: Administrator,
        capabilities: set[Operation],
    ) -> DelegationKeys:
        """
        Case 2: Delegation with Capability Keys.

        1. Validate Σ w_i >= W_cap
        2. Reconstruct s
        3. K_D^read = KDF(s)
        4. K_D^op = Φ(s, K_j^op) for op ∈ C
        """
        if not self.validate_coalition(admins, for_capability=True):
            raise ValueError(
                f"Coalition weight {sum(a.weight for a in admins)} "
                f"< W_cap {self.w_cap}"
            )

        s = self.reconstruct_secret(admins)
        k_d_read = kdf(s, self.prime)

        # Derive capability delegation keys
        k_d_write = None
        k_d_delete = None

        if Operation.WRITE in capabilities:
            k_j_write = capability_provider.capability_keys[Operation.WRITE]
            k_d_write = phi(s, k_j_write, self.prime)

        if Operation.DELETE in capabilities:
            k_j_delete = capability_provider.capability_keys[Operation.DELETE]
            k_d_delete = phi(s, k_j_delete, self.prime)

        return DelegationKeys(read=k_d_read, write=k_d_write, delete=k_d_delete)

    def derive_user_keys(
        self, user_key: int, delegation_keys: DelegationKeys
    ) -> UserKeys:
        """
        User derives operation keys.

        K_U^op = KDF(K_U || K_D^op) if K_D^op ≠ ⊥
               = ⊥ otherwise

        For toy example: K_U^op = K_U + K_D^op mod p
        """
        # Read key always derived
        k_u_read = self._derive_user_op_key(user_key, delegation_keys.read)

        # Write/delete only if delegation granted
        k_u_write = None
        k_u_delete = None

        if delegation_keys.write is not None:
            k_u_write = self._derive_user_op_key(user_key, delegation_keys.write)

        if delegation_keys.delete is not None:
            k_u_delete = self._derive_user_op_key(user_key, delegation_keys.delete)

        return UserKeys(read=k_u_read, write=k_u_write, delete=k_u_delete)

    def _derive_user_op_key(self, user_key: int, delegation_key: int) -> int:
        """
        K_U^op = KDF(K_U || K_D^op)

        For toy example (p=17): K_U + K_D mod p
        """
        if self.prime == 17:
            return (user_key + delegation_key) % self.prime

        # Real: KDF of concatenation
        return kdf(hash_concat(user_key, delegation_key, self.prime), self.prime)

    # =========================================================================
    # OPERATIONS
    # =========================================================================

    def read_encrypt(self, data: int, user_keys: UserKeys) -> int:
        """
        Read operation: C = Enc_{K_U^read}(D_U)
        """
        return encrypt(data, user_keys.read, self.prime)

    def read_decrypt(self, ciphertext: int, user_keys: UserKeys) -> int:
        """
        Read operation: D_U = Dec_{K_U^read}(C)
        """
        return decrypt(ciphertext, user_keys.read, self.prime)

    def write_encrypt(
        self, data: int, user_keys: UserKeys
    ) -> Optional[AuthenticatedCiphertext]:
        """
        Write operation: (C', τ) = EncAuth_{K_U^write}(D_U')

        Returns None if user lacks write capability.
        """
        if user_keys.write is None:
            return None

        return encrypt_auth(data, user_keys.write, self.prime)

    def write_verify(
        self, auth_ct: AuthenticatedCiphertext, user_keys: UserKeys
    ) -> Optional[int]:
        """
        Server verifies write: DecAuth_{K_U^write}(C', τ)

        Returns plaintext if valid, None (⊥) otherwise.
        """
        if user_keys.write is None:
            return None

        return decrypt_auth(auth_ct, user_keys.write, self.prime)

    def delete_encrypt(
        self, resource_id: int, user_keys: UserKeys
    ) -> Optional[AuthenticatedCiphertext]:
        """
        Delete operation: (cmd, τ) = EncAuth_{K_U^delete}("delete" || id)

        Returns None if user lacks delete capability.
        """
        if user_keys.delete is None:
            return None

        # Encode "delete" || id as single integer for toy example
        # In real implementation, would be bytes
        cmd = resource_id
        return encrypt_auth(cmd, user_keys.delete, self.prime)

    def delete_verify(
        self, auth_ct: AuthenticatedCiphertext, user_keys: UserKeys
    ) -> Optional[int]:
        """
        Server verifies delete: DecAuth_{K_U^delete}(cmd, τ)

        Returns resource_id if valid, None (⊥) otherwise.
        """
        if user_keys.delete is None:
            return None

        return decrypt_auth(auth_ct, user_keys.delete, self.prime)
