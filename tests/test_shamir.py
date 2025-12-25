"""Tests for Shamir Secret Sharing implementation."""

import pytest
from ensf.crypto.shamir import (
    Share,
    generate_shares,
    reconstruct_secret,
    PRIME,
    _generate_polynomial,
    _evaluate_polynomial,
)


class TestShare:
    """Tests for Share dataclass and serialization."""

    def test_to_bytes_and_from_bytes(self):
        """Round-trip serialization should preserve values."""
        share = Share(x=42, y=123456789)
        data = share.to_bytes()

        assert len(data) == 64  # 32 bytes x + 32 bytes y

        recovered = Share.from_bytes(data)
        assert recovered.x == share.x
        assert recovered.y == share.y

    def test_from_bytes_wrong_size(self):
        """Should raise ValueError for incorrect data size."""
        with pytest.raises(ValueError, match="must be 64 bytes"):
            Share.from_bytes(b"too short")


class TestPolynomial:
    """Tests for polynomial operations."""

    def test_polynomial_constant_term(self):
        """Polynomial evaluated at 0 should return the secret (constant term)."""
        secret = 12345
        coeffs = _generate_polynomial(secret, threshold=3, prime=PRIME)

        assert coeffs[0] == secret
        assert len(coeffs) == 3  # threshold = degree + 1

    def test_polynomial_evaluation(self):
        """Simple polynomial evaluation check."""
        # f(x) = 5 + 3x + 2x^2
        coeffs = [5, 3, 2]
        prime = 997  # small prime for testing

        # f(1) = 5 + 3 + 2 = 10
        assert _evaluate_polynomial(coeffs, 1, prime) == 10

        # f(2) = 5 + 6 + 8 = 19
        assert _evaluate_polynomial(coeffs, 2, prime) == 19


class TestShamirSSS:
    """Tests for the complete Shamir secret sharing scheme."""

    def test_generate_correct_number_of_shares(self):
        """Should generate exactly n_shares shares."""
        shares = generate_shares(secret=100, n_shares=5, threshold=3)
        assert len(shares) == 5

    def test_reconstruct_with_threshold_shares(self):
        """Reconstruction with exactly t shares should succeed."""
        secret = 42
        shares = generate_shares(secret=secret, n_shares=5, threshold=3)

        # Use exactly 3 shares (threshold)
        recovered = reconstruct_secret(shares[:3])
        assert recovered == secret

    def test_reconstruct_with_more_than_threshold(self):
        """Reconstruction with more than t shares should succeed."""
        secret = 99999
        shares = generate_shares(secret=secret, n_shares=5, threshold=3)

        # Use all 5 shares
        recovered = reconstruct_secret(shares)
        assert recovered == secret

    def test_reconstruct_with_different_share_subsets(self):
        """Any t shares should reconstruct the secret."""
        secret = 777
        shares = generate_shares(secret=secret, n_shares=5, threshold=3)

        # Try different combinations of 3 shares
        assert reconstruct_secret([shares[0], shares[1], shares[2]]) == secret
        assert reconstruct_secret([shares[0], shares[2], shares[4]]) == secret
        assert reconstruct_secret([shares[2], shares[3], shares[4]]) == secret

    def test_reconstruct_insufficient_shares_gives_wrong_result(self):
        """Fewer than t shares should NOT reconstruct correct secret."""
        secret = 12345
        shares = generate_shares(secret=secret, n_shares=5, threshold=3)

        # Only 2 shares - reconstruction will complete but give wrong answer
        # (This is the security property: t-1 shares reveal nothing)
        wrong_secret = reconstruct_secret(shares[:2])

        # With high probability, this is not equal to the secret
        # (probability of collision is 1/PRIME, essentially zero)
        assert wrong_secret != secret

    def test_different_secrets_different_shares(self):
        """Different secrets should produce different shares."""
        shares1 = generate_shares(secret=100, n_shares=3, threshold=2)
        shares2 = generate_shares(secret=200, n_shares=3, threshold=2)

        # At least one share should differ (in y-value)
        y_values_1 = {s.y for s in shares1}
        y_values_2 = {s.y for s in shares2}

        assert y_values_1 != y_values_2

    def test_large_secret(self):
        """Should handle secrets up to 256 bits."""
        secret = 2**255 - 1  # Large 256-bit value
        shares = generate_shares(secret=secret, n_shares=3, threshold=2)
        recovered = reconstruct_secret(shares[:2])

        assert recovered == secret

    def test_invalid_threshold(self):
        """Should raise ValueError for threshold < 1."""
        with pytest.raises(ValueError, match="Threshold must be at least 1"):
            generate_shares(secret=100, n_shares=3, threshold=0)

    def test_insufficient_n_shares(self):
        """Should raise ValueError if n_shares < threshold."""
        with pytest.raises(ValueError, match="Number of shares must be >= threshold"):
            generate_shares(secret=100, n_shares=2, threshold=3)

    def test_secret_out_of_range(self):
        """Should raise ValueError for secret >= prime."""
        with pytest.raises(ValueError, match="Secret must be in range"):
            generate_shares(secret=PRIME + 1, n_shares=3, threshold=2)

    def test_reconstruct_empty_shares(self):
        """Should raise ValueError for empty share list."""
        with pytest.raises(ValueError, match="At least one share"):
            reconstruct_secret([])

    def test_reconstruct_duplicate_x_values(self):
        """Should raise ValueError for duplicate x coordinates."""
        share = Share(x=1, y=100)
        with pytest.raises(ValueError, match="Duplicate x values"):
            reconstruct_secret([share, share])
