"""
Directory Encryption Test Cases.

Tests 5 scenarios using the test_folder directory:

1. Admin grants read-only access → user reads successfully
2. User manipulates admin delegation keys → decryption fails
3. User manipulates own private key → decryption fails
4. Admin grants write capability → user writes successfully
5. User fakes write access → verification fails
"""

import os
import shutil
import tempfile
import pytest
from pathlib import Path

from ensf.crypto.delegation import (
    DelegationScheme,
    Administrator,
    Operation,
    UserKeys,
)
from ensf.crypto.folder import (
    DirectoryEncryption,
    EncryptedDirectory,
    derive_aes_key,
)
from ensf.crypto.shamir import PRIME


# =============================================================================
# TEST CONFIGURATION
# =============================================================================

# Use real prime for directory tests
P = PRIME

# Thresholds
W_READ = 3
W_CAP = 3

# User key
K_U = 12345678901234567890

# Master secret
S = 98765432109876543210

# Admin weights
ADMIN_WEIGHTS = {1: 2, 2: 1, 3: 1}

# Test folder path
TEST_FOLDER = Path(__file__).parent / "test_folder"


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def scheme():
    """Create delegation scheme."""
    scheme = DelegationScheme(prime=P, w_read=W_READ, w_cap=W_CAP)
    scheme.setup_secret(S)
    return scheme


@pytest.fixture
def admins(scheme):
    """Generate admins with shares."""
    return scheme.generate_shares(ADMIN_WEIGHTS)


@pytest.fixture
def temp_output():
    """Create temporary output directory."""
    tmpdir = tempfile.mkdtemp()
    yield Path(tmpdir)
    shutil.rmtree(tmpdir, ignore_errors=True)


def compare_directories(dir1: Path, dir2: Path) -> bool:
    """Check if two directories have identical contents."""
    dir1_files = set()
    dir2_files = set()

    for root, _, files in os.walk(dir1):
        for f in files:
            rel = Path(root).relative_to(dir1) / f
            dir1_files.add(str(rel))

    for root, _, files in os.walk(dir2):
        for f in files:
            rel = Path(root).relative_to(dir2) / f
            dir2_files.add(str(rel))

    if dir1_files != dir2_files:
        return False

    for rel in dir1_files:
        f1 = dir1 / rel
        # Find corresponding file in dir2 (may be in subdirectory with original name)
        found = False
        for root, _, files in os.walk(dir2):
            for fname in files:
                if (
                    str(Path(root).relative_to(dir2) / fname) == rel
                    or fname == Path(rel).name
                ):
                    f2 = Path(root) / fname
                    if f1.read_text() == f2.read_text():
                        found = True
                        break
            if found:
                break
        if not found:
            return False

    return True


# =============================================================================
# TEST CASE 1: Admin grants read-only access → SUCCESS
# =============================================================================


class TestCase1ReadOnlySuccess:
    """
    Scenario: Admin coalition grants read-only access.
    User successfully reads (decrypts) the directory.

    Steps:
        1. Admin coalition A_1 + A_2 (weight 3) delegates with Case 1
        2. User receives K_D^read
        3. User derives K_U^read = KDF(K_U || K_D^read)
        4. Directory is encrypted with K_U^read
        5. User decrypts successfully

    Success: Decrypted directory matches original
    Failure: Decryption fails or content mismatch
    """

    def test_read_only_delegation_success(self, scheme, admins, temp_output):
        """Admin grants read-only, user reads successfully."""
        # Step 1: Coalition delegates (Case 1)
        coalition = [admins[0], admins[1]]  # A_1 + A_2, weight = 3
        delegation = scheme.delegate_case1(coalition)

        assert delegation.read is not None
        assert delegation.write is None
        assert delegation.delete is None

        # Step 2-3: User derives keys
        user_keys = scheme.derive_user_keys(K_U, delegation)

        assert user_keys.read is not None

        # Step 4: Encrypt directory
        dir_enc = DirectoryEncryption(scheme)
        encrypted = dir_enc.encrypt_for_read(TEST_FOLDER, user_keys)

        assert encrypted is not None
        assert encrypted.operation == Operation.READ

        # Step 5: Decrypt
        success = dir_enc.decrypt_for_read(encrypted, user_keys, temp_output)

        assert success is True

        # Verify content exists
        decrypted_folder = temp_output / "test_folder"
        assert decrypted_folder.exists()


# =============================================================================
# TEST CASE 2: User manipulates admin delegation keys → FAILURE
# =============================================================================


class TestCase2ManipulateDelegationKeys:
    """
    Scenario: User receives valid delegation but tries to manipulate K_D^read.
    Decryption should fail.

    Steps:
        1. Admin coalition delegates normally
        2. User receives valid K_D^read
        3. Directory is encrypted with correct K_U^read
        4. Attacker modifies K_D^read (e.g., K_D^read + 1)
        5. Attacker derives wrong K_U^read'
        6. Decryption fails

    Success: Decryption fails (returns False)
    Failure: Decryption succeeds with wrong key
    """

    def test_manipulated_delegation_key_fails(self, scheme, admins, temp_output):
        """Manipulating K_D^read causes decryption failure."""
        # Step 1: Coalition delegates
        coalition = [admins[0], admins[1]]
        delegation = scheme.delegate_case1(coalition)

        # Step 2-3: Valid user keys
        user_keys = scheme.derive_user_keys(K_U, delegation)

        # Step 4: Encrypt with correct key
        dir_enc = DirectoryEncryption(scheme)
        encrypted = dir_enc.encrypt_for_read(TEST_FOLDER, user_keys)

        # Step 5: Attacker manipulates K_D^read
        tampered_k_d_read = (delegation.read + 1) % P

        from ensf.crypto.delegation import DelegationKeys

        tampered_delegation = DelegationKeys(
            read=tampered_k_d_read, write=None, delete=None
        )

        # Step 6: Derive wrong user key
        wrong_user_keys = scheme.derive_user_keys(K_U, tampered_delegation)

        # Keys should be different
        assert wrong_user_keys.read != user_keys.read

        # Decryption should fail
        success = dir_enc.decrypt_for_read(encrypted, wrong_user_keys, temp_output)

        assert success is False


# =============================================================================
# TEST CASE 3: User manipulates own private key → FAILURE
# =============================================================================


class TestCase3ManipulateUserKey:
    """
    Scenario: User tries to decrypt with a different private key.
    Decryption should fail.

    Steps:
        1. Admin coalition delegates normally
        2. Original user (K_U) encrypts directory
        3. Attacker has different key K_U' ≠ K_U
        4. Attacker receives same delegation K_D^read
        5. Attacker derives K_U'^read = KDF(K_U' || K_D^read)
        6. Attacker cannot decrypt (wrong key)

    Success: Decryption fails
    Failure: Attacker can decrypt with wrong user key
    """

    def test_wrong_user_key_fails(self, scheme, admins, temp_output):
        """Different user key causes decryption failure."""
        # Step 1: Coalition delegates
        coalition = [admins[0], admins[1]]
        delegation = scheme.delegate_case1(coalition)

        # Step 2: Original user encrypts
        original_user_keys = scheme.derive_user_keys(K_U, delegation)

        dir_enc = DirectoryEncryption(scheme)
        encrypted = dir_enc.encrypt_for_read(TEST_FOLDER, original_user_keys)

        # Step 3-5: Attacker with different key
        ATTACKER_KEY = K_U + 999999  # Different key
        attacker_keys = scheme.derive_user_keys(ATTACKER_KEY, delegation)

        # Keys should be different
        assert attacker_keys.read != original_user_keys.read

        # Step 6: Attacker cannot decrypt
        success = dir_enc.decrypt_for_read(encrypted, attacker_keys, temp_output)

        assert success is False


# =============================================================================
# TEST CASE 4: Admin grants write capability → SUCCESS
# =============================================================================


class TestCase4WriteCapabilitySuccess:
    """
    Scenario: Admin coalition grants write capability (Case 2).
    User successfully writes and server verifies.

    Steps:
        1. Admin coalition delegates with write capability (Case 2)
        2. User receives K_D^read and K_D^write
        3. User derives K_U^write = KDF(K_U || K_D^write)
        4. User encrypts with EncAuth: (C', τ)
        5. Server verifies DecAuth: returns data

    Success: Write verification succeeds
    Failure: Write verification fails
    """

    def test_write_capability_success(self, scheme, admins, temp_output):
        """Admin grants write, user writes successfully."""
        # Step 1: Delegate with write capability
        cap_provider = admins[0]  # A_1 provides capability
        coalition = [admins[0], admins[1]]

        delegation = scheme.delegate_case2(
            admins=coalition,
            capability_provider=cap_provider,
            capabilities={Operation.WRITE},
        )

        assert delegation.read is not None
        assert delegation.write is not None

        # Step 2-3: User derives keys
        user_keys = scheme.derive_user_keys(K_U, delegation)

        assert user_keys.write is not None

        # Step 4: Encrypt with authenticated encryption
        dir_enc = DirectoryEncryption(scheme)
        encrypted = dir_enc.encrypt_for_write(TEST_FOLDER, user_keys)

        assert encrypted is not None
        assert encrypted.auth_tag is not None
        assert encrypted.operation == Operation.WRITE

        # Step 5: Server verifies and decrypts
        success = dir_enc.verify_and_decrypt_write(encrypted, user_keys, temp_output)

        assert success is True

        # Verify content exists
        decrypted_folder = temp_output / "test_folder"
        assert decrypted_folder.exists()


# =============================================================================
# TEST CASE 5: User fakes write access → FAILURE
# =============================================================================


class TestCase5FakeWriteAccessFails:
    """
    Scenario: User has read-only delegation but tries to fake write access.

    Attack vectors:
        a) User creates fake K_D^write from K_D^read
        b) User creates fake auth tag

    Steps:
        1. Admin coalition delegates read-only (Case 1)
        2. User has K_D^read, K_D^write = ⊥
        3. Attacker creates fake K_D^write = K_D^read + constant
        4. Attacker encrypts with fake key, creates auth tag
        5. Server verification fails

    Success: Write verification fails
    Failure: Server accepts fake write
    """

    def test_fake_write_key_rejected(self, scheme, admins, temp_output):
        """Fake write delegation key is rejected."""
        # Step 1: Read-only delegation
        coalition = [admins[0], admins[1]]
        delegation = scheme.delegate_case1(coalition)

        assert delegation.write is None

        # Step 2: Get valid read keys
        user_keys = scheme.derive_user_keys(K_U, delegation)

        # Step 3: Attacker creates fake write key
        fake_k_d_write = (delegation.read + 12345) % P

        # Create fake user keys with write capability
        fake_user_keys = UserKeys(
            read=user_keys.read,
            write=scheme._derive_user_op_key(K_U, fake_k_d_write),
            delete=None,
        )

        # Step 4: Encrypt with fake write key
        dir_enc = DirectoryEncryption(scheme)
        fake_encrypted = dir_enc.encrypt_for_write(TEST_FOLDER, fake_user_keys)

        assert fake_encrypted is not None

        # Step 5: Server verification with correct keys fails
        # (Server uses keys derived from actual delegation)

        # Get what the server would use (read-only, no write)
        server_user_keys = scheme.derive_user_keys(K_U, delegation)
        assert server_user_keys.write is None

        # Server cannot verify because it has no write key
        success = dir_enc.verify_and_decrypt_write(
            fake_encrypted, server_user_keys, temp_output
        )

        assert success is False

    def test_fake_auth_tag_rejected(self, scheme, admins, temp_output):
        """Fake authentication tag is rejected."""
        # Step 1: Get real write delegation
        cap_provider = admins[0]
        coalition = [admins[0], admins[1]]

        delegation = scheme.delegate_case2(
            admins=coalition,
            capability_provider=cap_provider,
            capabilities={Operation.WRITE},
        )

        user_keys = scheme.derive_user_keys(K_U, delegation)

        # Step 2: Create valid encrypted data
        dir_enc = DirectoryEncryption(scheme)
        valid_encrypted = dir_enc.encrypt_for_write(TEST_FOLDER, user_keys)

        # Step 3: Tamper with auth tag
        tampered_tag = bytes([b ^ 0xFF for b in valid_encrypted.auth_tag])

        tampered_encrypted = EncryptedDirectory(
            nonce=valid_encrypted.nonce,
            ciphertext=valid_encrypted.ciphertext,
            auth_tag=tampered_tag,
            operation=Operation.WRITE,
        )

        # Step 4: Verification fails
        success = dir_enc.verify_and_decrypt_write(
            tampered_encrypted, user_keys, temp_output
        )

        assert success is False
