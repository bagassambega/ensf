"""
Shamir Secret Sharing (SSS) implementation over a finite field.

This module implements (t, n) threshold secret sharing where:
- A secret S is split into n shares
- Any t shares can reconstruct S
- Fewer than t shares reveal no information about S

The scheme uses polynomial interpolation over a prime field GF(p).

Mathematical Basis:
    1. Secret S becomes the constant term (a_0) of a polynomial
    2. Polynomial: f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
    3. Shares are points (x_i, f(x_i)) on this polynomial
    4. Reconstruction uses Lagrange interpolation to recover a_0 = S

Reference:
    Shamir, A. (1979). "How to share a secret". Communications of the ACM.
"""

import secrets
from dataclasses import dataclass


# 256-bit prime for the finite field.
# This is a safe prime (p = 2q + 1 where q is also prime) commonly used
# in cryptographic applications. Provides security equivalent to AES-256.
PRIME = 2**256 - 189


@dataclass(frozen=True)
class Share:
    """
    A single share in the secret sharing scheme.

    Attributes:
        x: The x-coordinate (evaluation point). Must be non-zero.
        y: The y-coordinate (polynomial evaluation at x).
    """

    x: int
    y: int

    def to_bytes(self) -> bytes:
        """
        Serialize share to binary format.

        Format: 32 bytes (x, big-endian) + 32 bytes (y, big-endian)
        Total: 64 bytes per share
        """
        x_bytes = self.x.to_bytes(32, byteorder="big")
        y_bytes = self.y.to_bytes(32, byteorder="big")
        return x_bytes + y_bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "Share":
        """
        Deserialize share from binary format.

        Args:
            data: 64-byte binary representation

        Returns:
            Share instance

        Raises:
            ValueError: If data is not exactly 64 bytes
        """
        if len(data) != 64:
            raise ValueError(f"Share data must be 64 bytes, got {len(data)}")
        x = int.from_bytes(data[:32], byteorder="big")
        y = int.from_bytes(data[32:], byteorder="big")
        return cls(x=x, y=y)


def _generate_polynomial(secret: int, threshold: int, prime: int) -> list[int]:
    """
    Generate a random polynomial with the secret as constant term.

    The polynomial has degree (threshold - 1), meaning threshold points
    are needed to uniquely determine it (and recover the secret).

    Args:
        secret: The secret value to hide (becomes coefficient a_0)
        threshold: Number of shares needed for reconstruction
        prime: The prime defining the finite field

    Returns:
        List of coefficients [a_0, a_1, ..., a_{t-1}] where a_0 = secret
    """
    coefficients = [secret]

    # Generate (threshold - 1) random coefficients for higher-degree terms.
    # These are uniformly random in [0, prime-1].
    for _ in range(threshold - 1):
        coefficients.append(secrets.randbelow(prime))

    return coefficients


def _evaluate_polynomial(coefficients: list[int], x: int, prime: int) -> int:
    """
    Evaluate polynomial at point x using Horner's method.

    Horner's method computes f(x) = a_0 + x*(a_1 + x*(a_2 + ...)) efficiently
    with O(n) multiplications instead of O(n^2) for naive evaluation.

    Args:
        coefficients: Polynomial coefficients [a_0, a_1, ..., a_{t-1}]
        x: Point at which to evaluate
        prime: Modulus for finite field arithmetic

    Returns:
        f(x) mod prime
    """
    result = 0

    # Process coefficients in reverse order (highest degree first)
    for coeff in reversed(coefficients):
        result = (result * x + coeff) % prime

    return result


def _mod_inverse(a: int, prime: int) -> int:
    """
    Compute modular multiplicative inverse using Fermat's little theorem.

    For prime p: a^(-1) = a^(p-2) mod p

    This works because a^(p-1) = 1 mod p (Fermat's little theorem),
    so a * a^(p-2) = a^(p-1) = 1 mod p, meaning a^(p-2) is the inverse.

    Args:
        a: Value to invert (must be non-zero mod prime)
        prime: Prime modulus

    Returns:
        Modular inverse of a

    Raises:
        ValueError: If a is zero (no inverse exists)
    """
    if a % prime == 0:
        raise ValueError("Cannot compute inverse of zero")

    return pow(a, prime - 2, prime)


def generate_shares(
    secret: int, n_shares: int, threshold: int, prime: int = PRIME
) -> list[Share]:
    """
    Split a secret into n shares with threshold t.

    Args:
        secret: The secret to split (integer in [0, prime-1])
        n_shares: Total number of shares to generate
        threshold: Minimum shares needed for reconstruction
        prime: Prime for finite field (default: 256-bit prime)

    Returns:
        List of Share objects

    Raises:
        ValueError: If parameters are invalid

    Example:
        >>> shares = generate_shares(12345, n_shares=3, threshold=2)
        >>> len(shares)
        3
        >>> # Any 2 shares can reconstruct the secret
    """
    if threshold < 1:
        raise ValueError("Threshold must be at least 1")
    if n_shares < threshold:
        raise ValueError("Number of shares must be >= threshold")
    if not 0 <= secret < prime:
        raise ValueError(f"Secret must be in range [0, {prime-1}]")

    # Generate random polynomial with secret as constant term
    coefficients = _generate_polynomial(secret, threshold, prime)

    # Evaluate at points x = 1, 2, ..., n_shares
    # x = 0 is avoided because f(0) = secret (would leak the secret)
    shares = []
    for x in range(1, n_shares + 1):
        y = _evaluate_polynomial(coefficients, x, prime)
        shares.append(Share(x=x, y=y))

    return shares


def reconstruct_secret(shares: list[Share], prime: int = PRIME) -> int:
    """
    Reconstruct secret from shares using Lagrange interpolation.

    Lagrange interpolation finds the unique polynomial of degree < t
    passing through t points, then evaluates it at x = 0 to get the secret.

    The formula is:
        f(0) = sum_{i} y_i * L_i(0)

    Where L_i(0) is the Lagrange basis polynomial evaluated at 0:
        L_i(0) = product_{j != i} (0 - x_j) / (x_i - x_j)
               = product_{j != i} (-x_j) / (x_i - x_j)

    Args:
        shares: List of Share objects (at least threshold shares)
        prime: Prime for finite field

    Returns:
        Reconstructed secret

    Raises:
        ValueError: If shares list is empty or contains duplicates
    """
    if not shares:
        raise ValueError("At least one share required")

    # Check for duplicate x values (would cause division by zero)
    x_values = [s.x for s in shares]
    if len(x_values) != len(set(x_values)):
        raise ValueError("Duplicate x values in shares")

    secret = 0

    for i, share_i in enumerate(shares):
        # Compute Lagrange basis polynomial L_i(0)
        numerator = 1
        denominator = 1

        for j, share_j in enumerate(shares):
            if i == j:
                continue

            # L_i(0) = product of (-x_j) / (x_i - x_j)
            numerator = (numerator * (-share_j.x)) % prime
            denominator = (denominator * (share_i.x - share_j.x)) % prime

        # Compute L_i(0) = numerator / denominator
        lagrange_coeff = (numerator * _mod_inverse(denominator, prime)) % prime

        # Add contribution: y_i * L_i(0)
        secret = (secret + share_i.y * lagrange_coeff) % prime

    return secret
