"""
Tests for Formal Delegation Scheme.

Implements the toy example from specification:
    p = 17
    Admins: A_1, A_2, A_3 with w_1=2, w_2=1, w_3=1
    Thresholds: W_read=3, W_cap=3
    User key: K_U = 7
    Master secret: s = 5
    Polynomial: f(x) = 5 + 3x mod 17
    Shares: s_1=8, s_2=11, s_3=14

Plus 3 comprehensive test cases.
"""

import pytest
from ensf.crypto.delegation import (
    DelegationScheme,
    Operation,
    Administrator,
    DelegationKeys,
    UserKeys,
    AuthenticatedCiphertext,
    encrypt,
    decrypt,
    encrypt_auth,
    decrypt_auth,
    kdf,
    hash_concat,
    phi,
)
from ensf.crypto.shamir import Share, generate_shares, reconstruct_secret


# =============================================================================
# TOY EXAMPLE CONSTANTS (p=17)
# =============================================================================

P = 17  # Prime field

# Administrators
ADMIN_WEIGHTS = {1: 2, 2: 1, 3: 1}  # A_1: w=2, A_2: w=1, A_3: w=1

# Thresholds
W_READ = 3
W_CAP = 3

# User
K_U = 7

# Master secret
S = 5

# Polynomial f(x) = 5 + 3x => shares: f(1)=8, f(2)=11, f(3)=14
SHARES = {1: 8, 2: 11, 3: 14}

# Capability key for A_1
K_1_WRITE = 6


# =============================================================================
# TEST: TOY EXAMPLE FROM SPECIFICATION
# =============================================================================


class TestToyExample:
    """
    Tests using the exact values from the specification.

    Verifies:
        H(x||y) = x + y mod 17
        KDF(z) = z
        EncAuth_k(m) = (m+k, k+(m+k))
    """

    def test_primitives_toy_mode(self):
        """Verify primitives work in toy mode (p=17)."""
        # KDF(z) = z
        assert kdf(5, P) == 5
        assert kdf(11, P) == 11

        # H(x||y) = x + y mod p
        assert hash_concat(5, 6, P) == 11
        assert hash_concat(10, 10, P) == 3  # 20 mod 17 = 3

        # Φ(x,y) = KDF(H(x||y)) = x + y mod p
        assert phi(5, 6, P) == 11

    def test_secret_reconstruction(self):
        """
        Coalition S = {A_1, A_2} reconstructs s = 5.

        Using Lagrange interpolation with shares (1,8) and (2,11).
        """
        shares = [
            Share(x=1, y=SHARES[1]),  # (1, 8)
            Share(x=2, y=SHARES[2]),  # (2, 11)
        ]

        s = reconstruct_secret(shares, P)
        assert s == S  # s = 5

    def test_case1_read_only_delegation(self):
        """
        Case 1: Read-Only Delegation

        Expected:
            K_D^read = KDF(s) = 5
            K_U^read = K_U + K_D^read = 7 + 5 = 12

        For D_U = 9:
            C = Enc(9) = 9 + 12 = 21 ≡ 4 mod 17
            Dec(4) = 4 - 12 = -8 ≡ 9 mod 17
        """
        scheme = DelegationScheme(prime=P, w_read=W_READ, w_cap=W_CAP)
        scheme.master_secret = S

        # Create admins with shares
        admins = [
            Administrator(id=1, share=SHARES[1], weight=2, capability_keys={}),
            Administrator(id=2, share=SHARES[2], weight=1, capability_keys={}),
        ]

        # Delegate Case 1
        delegation = scheme.delegate_case1(admins)

        assert delegation.read == 5  # K_D^read = KDF(s) = 5
        assert delegation.write is None
        assert delegation.delete is None

        # User derives keys
        user_keys = scheme.derive_user_keys(K_U, delegation)

        assert user_keys.read == 12  # K_U^read = 7 + 5 = 12
        assert user_keys.write is None
        assert user_keys.delete is None

        # Encrypt/Decrypt
        D_U = 9
        C = scheme.read_encrypt(D_U, user_keys)
        assert C == 4  # 9 + 12 = 21 ≡ 4 mod 17

        decrypted = scheme.read_decrypt(C, user_keys)
        assert decrypted == D_U  # 4 - 12 = -8 ≡ 9 mod 17

    def test_case2_with_write_capability(self):
        """
        Case 2: Delegation with Write Capability

        A_1 provides K_1^write = 6.

        Expected:
            K_D^read = 5
            K_D^write = Φ(5, 6) = 5 + 6 = 11
            K_U^read = 7 + 5 = 12
            K_U^write = 7 + 11 = 18 ≡ 1 mod 17
        """
        scheme = DelegationScheme(prime=P, w_read=W_READ, w_cap=W_CAP)
        scheme.master_secret = S

        # Create admins
        cap_provider = Administrator(
            id=1,
            share=SHARES[1],
            weight=2,
            capability_keys={Operation.WRITE: K_1_WRITE},
        )
        admin2 = Administrator(id=2, share=SHARES[2], weight=1, capability_keys={})

        # Delegate Case 2 with write capability
        delegation = scheme.delegate_case2(
            admins=[cap_provider, admin2],
            capability_provider=cap_provider,
            capabilities={Operation.WRITE},
        )

        assert delegation.read == 5  # K_D^read = 5
        assert delegation.write == 11  # K_D^write = Φ(5,6) = 11
        assert delegation.delete is None

        # User derives keys
        user_keys = scheme.derive_user_keys(K_U, delegation)

        assert user_keys.read == 12  # 7 + 5 = 12
        assert user_keys.write == 1  # 7 + 11 = 18 ≡ 1 mod 17
        assert user_keys.delete is None

    def test_authorized_write_accepted(self):
        """
        Authorized write with proper key is accepted.

        D_U' = 10:
            C' = 10 + 1 = 11
            τ = 1 + 11 = 12

        Server verifies: 1 + 11 = 12 ✓
        """
        scheme = DelegationScheme(prime=P, w_read=W_READ, w_cap=W_CAP)
        scheme.master_secret = S

        # Setup delegation with write
        cap_provider = Administrator(
            id=1,
            share=SHARES[1],
            weight=2,
            capability_keys={Operation.WRITE: K_1_WRITE},
        )
        admin2 = Administrator(id=2, share=SHARES[2], weight=1, capability_keys={})

        delegation = scheme.delegate_case2(
            admins=[cap_provider, admin2],
            capability_provider=cap_provider,
            capabilities={Operation.WRITE},
        )
        user_keys = scheme.derive_user_keys(K_U, delegation)

        # Write with proper key
        D_U_prime = 10
        auth_ct = scheme.write_encrypt(D_U_prime, user_keys)

        assert auth_ct is not None
        assert auth_ct.ciphertext == 11  # 10 + 1 = 11
        assert auth_ct.tag == 12  # 1 + 11 = 12

        # Server verifies
        result = scheme.write_verify(auth_ct, user_keys)
        assert result == D_U_prime  # Accepted, returns 10

    def test_unauthorized_write_rejected(self):
        """
        Write attempt with read key is rejected.

        Using K_U^read = 12 instead of K_U^write = 1:
            C'' = 10 + 12 = 22 ≡ 5 mod 17
            τ'' = 12 + 5 = 17 ≡ 0 mod 17

        Server checks with K_U^write = 1:
            Expected: 1 + 5 = 6 ≠ 0
            Result: DecAuth = ⊥
        """
        scheme = DelegationScheme(prime=P, w_read=W_READ, w_cap=W_CAP)

        # Encrypt with wrong key (read key instead of write key)
        k_u_read = 12  # User's read key
        k_u_write = 1  # User's write key

        D_U_prime = 10

        # Attacker uses read key
        wrong_ct = encrypt_auth(D_U_prime, k_u_read, P)
        assert wrong_ct.ciphertext == 5  # 10 + 12 = 22 ≡ 5
        assert wrong_ct.tag == 0  # 12 + 5 = 17 ≡ 0

        # Server tries to verify with write key
        result = decrypt_auth(wrong_ct, k_u_write, P)

        # Expected tag: 1 + 5 = 6, actual tag: 0
        # Verification fails
        assert result is None  # ⊥


# =============================================================================
# TEST CASE 1: COALITION THRESHOLD VALIDATION
# =============================================================================


class TestCase1CoalitionThreshold:
    """
    Test Case 1: Verify coalition threshold enforcement.

    Scenario:
        - 3 admins with weights w_1=2, w_2=1, w_3=1
        - W_read = 3
        - Valid coalitions: {A_1, A_2}, {A_1, A_3}, {A_2, A_3, A_1}
        - Invalid: {A_2}, {A_3}, {A_2, A_3}

    Success Criteria:
        - Valid coalitions can derive delegation keys
        - Invalid coalitions raise ValueError
        - Reconstructed secret is correct for all valid coalitions
    """

    @pytest.fixture
    def scheme_and_admins(self):
        """Setup scheme and generate admins."""
        scheme = DelegationScheme(prime=P, w_read=3, w_cap=3)
        scheme.setup_secret(S)

        admins = [
            Administrator(id=1, share=SHARES[1], weight=2, capability_keys={}),
            Administrator(id=2, share=SHARES[2], weight=1, capability_keys={}),
            Administrator(id=3, share=SHARES[3], weight=1, capability_keys={}),
        ]

        return scheme, admins

    def test_valid_coalition_a1_a2(self, scheme_and_admins):
        """Coalition {A_1, A_2}: weight = 2+1 = 3 >= W_read."""
        scheme, admins = scheme_and_admins
        coalition = [admins[0], admins[1]]  # A_1, A_2

        assert scheme.validate_coalition(coalition) is True

        delegation = scheme.delegate_case1(coalition)
        assert delegation.read == kdf(S, P)

    def test_valid_coalition_a1_a3(self, scheme_and_admins):
        """Coalition {A_1, A_3}: weight = 2+1 = 3 >= W_read."""
        scheme, admins = scheme_and_admins
        coalition = [admins[0], admins[2]]  # A_1, A_3

        assert scheme.validate_coalition(coalition) is True

        delegation = scheme.delegate_case1(coalition)
        assert delegation.read == kdf(S, P)

    def test_invalid_coalition_a2_a3(self, scheme_and_admins):
        """Coalition {A_2, A_3}: weight = 1+1 = 2 < W_read."""
        scheme, admins = scheme_and_admins
        coalition = [admins[1], admins[2]]  # A_2, A_3

        assert scheme.validate_coalition(coalition) is False

        with pytest.raises(ValueError, match="< W_read"):
            scheme.delegate_case1(coalition)

    def test_invalid_coalition_single_admin(self, scheme_and_admins):
        """Single admin A_1: weight = 2 < W_read."""
        scheme, admins = scheme_and_admins
        coalition = [admins[0]]  # Only A_1

        assert scheme.validate_coalition(coalition) is False

        with pytest.raises(ValueError):
            scheme.delegate_case1(coalition)


# =============================================================================
# TEST CASE 2: READ OPERATION ISOLATION
# =============================================================================


class TestCase2ReadIsolation:
    """
    Test Case 2: Verify read-only delegation cannot perform writes.

    Scenario:
        - User receives read-only delegation (Case 1)
        - User attempts to perform write operation

    Success Criteria:
        - User can read/decrypt data successfully
        - User cannot produce valid write authentication
        - write_encrypt returns None (no write key)
    """

    @pytest.fixture
    def read_only_user(self):
        """Setup user with read-only delegation."""
        scheme = DelegationScheme(prime=P, w_read=W_READ, w_cap=W_CAP)
        scheme.master_secret = S

        admins = [
            Administrator(id=1, share=SHARES[1], weight=2, capability_keys={}),
            Administrator(id=2, share=SHARES[2], weight=1, capability_keys={}),
        ]

        delegation = scheme.delegate_case1(admins)
        user_keys = scheme.derive_user_keys(K_U, delegation)

        return scheme, user_keys

    def test_read_operation_succeeds(self, read_only_user):
        """User with read-only can read data."""
        scheme, user_keys = read_only_user

        data = 9
        ciphertext = scheme.read_encrypt(data, user_keys)
        decrypted = scheme.read_decrypt(ciphertext, user_keys)

        assert decrypted == data

    def test_write_operation_blocked(self, read_only_user):
        """User with read-only cannot write."""
        scheme, user_keys = read_only_user

        assert user_keys.write is None  # No write key

        result = scheme.write_encrypt(10, user_keys)
        assert result is None  # Cannot create authenticated write

    def test_delete_operation_blocked(self, read_only_user):
        """User with read-only cannot delete."""
        scheme, user_keys = read_only_user

        assert user_keys.delete is None  # No delete key

        result = scheme.delete_encrypt(1, user_keys)
        assert result is None  # Cannot create authenticated delete


# =============================================================================
# TEST CASE 3: CAPABILITY DELEGATION AND VERIFICATION
# =============================================================================


class TestCase3CapabilityDelegation:
    """
    Test Case 3: Full capability delegation workflow.

    Scenario:
        - Admin A_1 provides write and delete capability keys
        - User receives full delegation (Case 2)
        - User performs read, write, and delete operations
        - Server verifies each operation

    Success Criteria:
        - All operation keys are derived correctly
        - Authenticated ciphertexts pass verification
        - Cross-operation attacks fail (using wrong key)
    """

    @pytest.fixture
    def full_delegation(self):
        """Setup user with full capability delegation."""
        scheme = DelegationScheme(prime=P, w_read=W_READ, w_cap=W_CAP)
        scheme.master_secret = S

        cap_provider = Administrator(
            id=1,
            share=SHARES[1],
            weight=2,
            capability_keys={
                Operation.WRITE: K_1_WRITE,
                Operation.DELETE: 10,  # K_1^delete = 10
            },
        )
        admin2 = Administrator(id=2, share=SHARES[2], weight=1, capability_keys={})

        delegation = scheme.delegate_case2(
            admins=[cap_provider, admin2],
            capability_provider=cap_provider,
            capabilities={Operation.WRITE, Operation.DELETE},
        )
        user_keys = scheme.derive_user_keys(K_U, delegation)

        return scheme, user_keys

    def test_all_operation_keys_derived(self, full_delegation):
        """All operation keys should be derived."""
        scheme, user_keys = full_delegation

        assert user_keys.read is not None
        assert user_keys.write is not None
        assert user_keys.delete is not None

    def test_write_operation_verified(self, full_delegation):
        """Write operation produces valid authentication."""
        scheme, user_keys = full_delegation

        data = 10
        auth_ct = scheme.write_encrypt(data, user_keys)

        assert auth_ct is not None

        # Server verification
        result = scheme.write_verify(auth_ct, user_keys)
        assert result == data

    def test_delete_operation_verified(self, full_delegation):
        """Delete operation produces valid authentication."""
        scheme, user_keys = full_delegation

        resource_id = 5
        auth_ct = scheme.delete_encrypt(resource_id, user_keys)

        assert auth_ct is not None

        # Server verification
        result = scheme.delete_verify(auth_ct, user_keys)
        assert result == resource_id

    def test_cross_operation_attack_fails(self, full_delegation):
        """
        Using write key for delete verification fails.

        Even with valid authenticated ciphertext for write,
        it should fail verification as a delete operation.
        """
        scheme, user_keys = full_delegation

        # Create valid write ciphertext
        write_ct = scheme.write_encrypt(10, user_keys)

        # Try to pass it off as delete operation
        # (using delete verification with write ciphertext)
        fake_delete_ct = AuthenticatedCiphertext(
            ciphertext=write_ct.ciphertext, tag=write_ct.tag
        )

        # Verify with delete key should fail
        # (unless by chance the keys are equal, check they're not)
        if user_keys.write != user_keys.delete:
            result = scheme.delete_verify(fake_delete_ct, user_keys)
            assert result is None  # Verification fails
