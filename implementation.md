# Folder Encryption Implementation

## Algorithm Overview

### Key Derivation Chain

The folder encryption system uses a layered key derivation approach:

$$
\text{Master Secret} \xrightarrow{\text{SSS}} \text{Admin Shares} \xrightarrow{\text{Coalition}} s \xrightarrow{\text{KDF}} K_D \xrightarrow{\text{Compose}} K_U^{op} \xrightarrow{\text{AES-GCM}} \text{Encrypted Folder}
$$

### Mathematical Definitions

**Field**: All computations in $\mathbb{F}_p$ where $p$ is a 256-bit prime.

**Shamir Secret Sharing**:
$$
f(x) = s + a_1 x + a_2 x^2 + \cdots + a_{t-1} x^{t-1} \pmod{p}
$$

**Share Distribution**: Admin $A_i$ receives $s_i = f(i)$

**Reconstruction** (Lagrange interpolation):
$$
s = \sum_{i \in S} s_i \cdot L_i(0) \pmod{p}
$$
where $L_i(0) = \prod_{j \in S, j \neq i} \frac{-j}{i-j}$

---

## Key Derivation

### Case 1: Read-Only Delegation

$$
K_D^{\text{read}} = \text{KDF}(s)
$$

$$
K_U^{\text{read}} = \text{KDF}(K_U \,\|\, K_D^{\text{read}})
$$

### Case 2: Capability Delegation

$$
\Phi(x, y) = \text{KDF}(H(x \,\|\, y))
$$

$$
K_D^{op} = \Phi(s, K_j^{op}), \quad op \in \{\text{write}, \text{delete}\}
$$

$$
K_U^{op} = \text{KDF}(K_U \,\|\, K_D^{op})
$$

---

## Folder Encryption Pseudocode

### Read Encryption

```python
def encrypt_for_read(folder_path, user_keys):
    # Step 1: Archive folder to bytes
    archive = tar_compress(folder_path)
    
    # Step 2: Derive AES key from K_U^read
    aes_key = SHA256(K_U_read.to_bytes(32))
    
    # Step 3: Generate random nonce
    nonce = random_bytes(12)
    
    # Step 4: Encrypt with AES-GCM
    ciphertext = AES_GCM_Encrypt(aes_key, nonce, archive)
    
    return EncryptedDirectory(nonce, ciphertext)
```

### Read Decryption

```python
def decrypt_for_read(encrypted, user_keys, output_path):
    # Step 1: Derive AES key from K_U^read
    aes_key = SHA256(K_U_read.to_bytes(32))
    
    # Step 2: Decrypt with AES-GCM
    try:
        archive = AES_GCM_Decrypt(aes_key, encrypted.nonce, encrypted.ciphertext)
    except AuthenticationError:
        return False  # Wrong key
    
    # Step 3: Extract archive
    tar_extract(archive, output_path)
    return True
```

### Write Encryption (Authenticated)

```python
def encrypt_for_write(folder_path, user_keys):
    if K_U_write is None:
        return None  # No write capability
    
    # Step 1: Archive and encrypt
    archive = tar_compress(folder_path)
    aes_key = SHA256(K_U_write.to_bytes(32))
    nonce = random_bytes(12)
    ciphertext = AES_GCM_Encrypt(aes_key, nonce, archive)
    
    # Step 2: Create authentication tag
    # τ = H(K_U^write || ciphertext)
    tag_input = K_U_write.to_bytes(32) + ciphertext
    auth_tag = SHA256(tag_input)[:16]
    
    return EncryptedDirectory(nonce, ciphertext, auth_tag)
```

### Write Verification

```python
def verify_and_decrypt_write(encrypted, user_keys, output_path):
    if K_U_write is None:
        return False
    
    # Step 1: Verify authentication tag
    expected_tag = SHA256(K_U_write.to_bytes(32) + encrypted.ciphertext)[:16]
    
    if encrypted.auth_tag != expected_tag:
        return False  # ⊥ - Verification failed
    
    # Step 2: Decrypt
    aes_key = SHA256(K_U_write.to_bytes(32))
    archive = AES_GCM_Decrypt(aes_key, encrypted.nonce, encrypted.ciphertext)
    tar_extract(archive, output_path)
    return True
```

---

## Test Cases

### Test Configuration

| Parameter | Value |
|-----------|-------|
| Prime $p$ | 256-bit (PRIME constant) |
| Threshold $W$ | 3 |
| Admin weights | $w_1=2, w_2=1, w_3=1$ |
| User key $K_U$ | 12345678901234567890 |
| Master secret $s$ | 98765432109876543210 |

---

## Test Results with Mathematical Explanation

### Test 1: Read-Only Delegation Success

| Step | Operation | Value |
|------|-----------|-------|
| 1 | Coalition $S = \{A_1, A_2\}$ | $\sum w_i = 2 + 1 = 3 \geq W$ ✓ |
| 2 | Reconstruct $s$ | $s = \text{Rec}(\{s_1, s_2\}) = 98765432109876543210$ |
| 3 | $K_D^{\text{read}} = \text{KDF}(s)$ | SHA256-based derivation |
| 4 | $K_U^{\text{read}} = \text{KDF}(K_U \,\|\, K_D^{\text{read}})$ | Composed key |
| 5 | $C = \text{AES-GCM}_{K_U^{\text{read}}}(\text{folder})$ | Encrypted |
| 6 | $\text{folder} = \text{AES-GCM}^{-1}_{K_U^{\text{read}}}(C)$ | **Decrypted ✓** |

**Why it works**: User has correct $K_U$ and coalition provided correct $K_D^{\text{read}}$. The derived $K_U^{\text{read}}$ matches the encryption key.

---

### Test 2: Manipulated Delegation Key Fails

| Step | Operation | Value |
|------|-----------|-------|
| 1 | Valid delegation | $K_D^{\text{read}} = k$ |
| 2 | Encrypt with correct key | $C = \text{AES-GCM}_{K_U^{\text{read}}}(\text{folder})$ |
| 3 | Attacker modifies | $K_D'^{\text{read}} = k + 1$ |
| 4 | Wrong derived key | $K_U'^{\text{read}} = \text{KDF}(K_U \,\|\, K_D'^{\text{read}}) \neq K_U^{\text{read}}$ |
| 5 | Decryption attempt | **Fails ✗** |

**Mathematical proof**:
$$
K_D'^{\text{read}} = K_D^{\text{read}} + 1 \pmod{p}
$$
$$
K_U'^{\text{read}} = \text{KDF}(K_U \,\|\, K_D'^{\text{read}}) \neq \text{KDF}(K_U \,\|\, K_D^{\text{read}}) = K_U^{\text{read}}
$$

Since $K_U'^{\text{read}} \neq K_U^{\text{read}}$, AES-GCM authentication fails.

---

### Test 3: Wrong User Key Fails

| Step | Operation | Value |
|------|-----------|-------|
| 1 | Original user encrypts | $K_U = 12345678901234567890$ |
| 2 | Attacker has different key | $K_U' = K_U + 999999$ |
| 3 | Same delegation key | $K_D^{\text{read}}$ (identical) |
| 4 | Attacker's derived key | $K_U'^{\text{read}} = \text{KDF}(K_U' \,\|\, K_D^{\text{read}})$ |
| 5 | Decryption attempt | **Fails ✗** |

**Mathematical proof**:
$$
K_U' = 12345678901234567890 + 999999 = 12345678902234567889 \neq K_U
$$
$$
K_U'^{\text{read}} = \text{KDF}(K_U' \,\|\, K_D^{\text{read}}) \neq \text{KDF}(K_U \,\|\, K_D^{\text{read}}) = K_U^{\text{read}}
$$

Different $K_U$ produces different $K_U^{\text{read}}$, AES-GCM fails.

---

### Test 4: Write Capability Success

| Step | Operation | Value |
|------|-----------|-------|
| 1 | Coalition weight | $\sum w_i = 3 \geq W_{\text{cap}}$ ✓ |
| 2 | $K_D^{\text{write}} = \Phi(s, K_1^{\text{write}})$ | Derived from capability key |
| 3 | $K_U^{\text{write}} = \text{KDF}(K_U \,\|\, K_D^{\text{write}})$ | Composed |
| 4 | $(C', \tau) = \text{EncAuth}_{K_U^{\text{write}}}(\text{folder})$ | Encrypted + tag |
| 5 | Verify: $\tau_{\text{expected}} = H(K_U^{\text{write}} \,\|\, C')$ | $\tau = \tau_{\text{expected}}$ ✓ |
| 6 | Decrypt | **Success ✓** |

**Why it works**: User has valid $K_U^{\text{write}}$, authentication tag is computed with same key, verification passes.

---

### Test 5a: Fake Write Key Rejected

| Step | Operation | Value |
|------|-----------|-------|
| 1 | Read-only delegation | $K_D^{\text{write}} = \bot$ |
| 2 | Attacker creates fake | $K_D'^{\text{write}} = K_D^{\text{read}} + 12345$ |
| 3 | Fake user key | $K_U'^{\text{write}} = \text{KDF}(K_U \,\|\, K_D'^{\text{write}})$ |
| 4 | Attacker encrypts | $(C', \tau') = \text{EncAuth}_{K_U'^{\text{write}}}(\text{folder})$ |
| 5 | Server checks | Server has $K_U^{\text{write}} = \bot$ |
| 6 | Verification | **Fails ✗** (no write key) |

**Why it fails**: Server only has keys from valid delegation. Since delegation was read-only, server has no $K_U^{\text{write}}$ to verify against.

---

### Test 5b: Tampered Auth Tag Rejected

| Step | Operation | Value |
|------|-----------|-------|
| 1 | Valid write encryption | $\tau = H(K_U^{\text{write}} \,\|\, C')$ |
| 2 | Attacker tampers | $\tau' = \tau \oplus \texttt{0xFF...}$ |
| 3 | Server verifies | $\tau_{\text{expected}} = H(K_U^{\text{write}} \,\|\, C')$ |
| 4 | Comparison | $\tau' \neq \tau_{\text{expected}}$ |
| 5 | Result | **Rejected ✗** |

**Mathematical proof**:
$$
\tau' = \tau \oplus \texttt{0xFF...} \neq \tau = H(K_U^{\text{write}} \,\|\, C')
$$

Any modification to $\tau$ makes it not match the expected tag computed from $K_U^{\text{write}}$ and $C'$.

---

## Summary

| Test | Result | Key Insight |
|------|--------|-------------|
| 1. Read success | ✓ | Correct $K_U$ + correct $K_D$ = valid $K_U^{\text{read}}$ |
| 2. Tamper $K_D$ | ✗ | $K_D' \neq K_D \Rightarrow K_U'^{\text{read}} \neq K_U^{\text{read}}$ |
| 3. Wrong $K_U$ | ✗ | $K_U' \neq K_U \Rightarrow K_U'^{\text{read}} \neq K_U^{\text{read}}$ |
| 4. Write success | ✓ | Valid capability key produces valid auth tag |
| 5a. Fake $K_D^{\text{write}}$ | ✗ | Server has no write key to verify |
| 5b. Tamper $\tau$ | ✗ | $\tau' \neq H(K_U^{\text{write}} \,\|\, C')$ |
