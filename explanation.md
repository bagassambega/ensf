# Algorithm Mapping Document

## Test Results

```
39 tests passed
```

---

## File Structure

| Component | File |
|-----------|------|
| Shamir SSS | `src/ensf/crypto/shamir.py` |
| Delegation Scheme | `src/ensf/crypto/delegation.py` |
| Directory Encryption | `src/ensf/crypto/folder.py` |
| Delegation Tests | `tests/test_delegation.py` |
| Directory Tests | `tests/test_folder_encryption.py` |
| Test Data | `tests/test_folder/` |

---

## Algorithm → Code Mapping

### Actors

| Specification | Code |
|--------------|------|
| `A_i` with `s_i, w_i, {K_i^op}` | `Administrator` dataclass |
| User `K_U ∈ F_p` | `user_key: int` |
| `O = {read, write, delete}` | `Operation` enum |

### Primitives

| Formula | Function | Toy (p=17) |
|---------|----------|------------|
| `KDF(x)` | `kdf()` | `x` |
| `H(x\|\|y)` | `hash_concat()` | `x+y mod p` |
| `Φ(x,y) = KDF(H(x\|\|y))` | `phi()` | `x+y mod p` |
| `Enc_K(m)` | `encrypt()` | `m+k mod p` |
| `EncAuth_K(m) = (c, τ)` | `encrypt_auth()` | `(m+k, k+c)` |

### Cases

| Case | Method | Keys Produced |
|------|--------|---------------|
| Case 1 | `delegate_case1()` | K_D^read only |
| Case 2 | `delegate_case2()` | K_D^read + K_D^{write,delete} |

### Directory Encryption

| Operation | Method | Uses |
|-----------|--------|------|
| Read encrypt | `encrypt_for_read()` | AES-GCM with K_U^read |
| Read decrypt | `decrypt_for_read()` | AES-GCM decrypt |
| Write encrypt | `encrypt_for_write()` | AES-GCM + auth tag |
| Write verify | `verify_and_decrypt_write()` | Verify tag first |

---

## Test Cases

### Directory Encryption Tests

| Test | Scenario | Expected | Why |
|------|----------|----------|-----|
| **Case 1: Read Success** | Admin grants read-only | Decrypt succeeds | Correct K_U^read |
| **Case 2: Tamper K_D** | User modifies K_D^read | Decrypt fails | Wrong derived key |
| **Case 3: Wrong K_U** | Different user key | Decrypt fails | K_U' ≠ K_U |
| **Case 4: Write Success** | Admin grants write | Verify succeeds | Valid (C', τ) |
| **Case 5a: Fake K_D^write** | User fakes write key | Verify fails | Server has no write key |
| **Case 5b: Fake τ** | User tampers auth tag | Verify fails | τ' ≠ expected |

### Success Criteria

| Condition | Result |
|-----------|--------|
| Correct keys | `True` / data returned |
| Wrong/tampered keys | `False` / `None` returned |
| Missing capability | `None` returned |

### Failure Detection

| Attack | Detection |
|--------|-----------|
| Modified K_D | AES-GCM decryption fails (wrong key) |
| Modified K_U | AES-GCM decryption fails (wrong key) |
| Fake write key | Server lacks K_U^write, returns False |
| Tampered auth tag | `expected_tag ≠ auth_tag` check fails |

---

## Security Properties Verified

| Property | Test |
|----------|------|
| Σw_i < W → no delegation | `TestCase1CoalitionThreshold` |
| Admin alone → no access | `TestCase3ManipulateUserKey` |
| User alone → no access | `TestCase2ManipulateDelegationKeys` |
| Read-only → no write | `TestCase5FakeWriteAccessFails` |
| Auth tag integrity | `test_fake_auth_tag_rejected` |
