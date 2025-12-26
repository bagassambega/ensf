# ENSF - Delegation-based Access Control

Implementation of Weighted Secret Sharing with Delegation for Access Control.

## Features

- **n Administrators** with configurable weights
- **Weighted Coalition Threshold** for delegation authorization
- **Case 1**: Read-only delegation (K_D^read = KDF(s))
- **Case 2**: Capability-enhanced delegation (K_D^op = Φ(s, K_j^op))
- **User Key Composition**: K_U^op = KDF(K_U || K_D^op)
- **Authenticated Encryption** for write/delete operations

## Installation

```bash
# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install package with dev dependencies
pip install -e ".[dev]"
```

## Running Tests

```bash
# Activate virtual environment
source .venv/bin/activate

# Run all tests
pytest tests/ -v

# Run only delegation algorithm tests
pytest tests/test_delegation.py -v

# Run only directory encryption tests
pytest tests/test_folder_encryption.py -v

# Run with coverage
pytest tests/ --cov=ensf
```

### Test Cases

| Test File | Description |
|-----------|-------------|
| `test_shamir.py` | Shamir Secret Sharing primitives |
| `test_delegation.py` | Delegation schemes (Case 1 & 2) with toy example (p=17) |
| `test_folder_encryption.py` | Directory encryption with 5 security scenarios |

### Directory Encryption Test Scenarios

| # | Scenario | Expected Result |
|---|----------|-----------------|
| 1 | Admin grants read-only | Decrypt succeeds |
| 2 | User manipulates K_D^read | Decrypt fails |
| 3 | Wrong user key K_U | Decrypt fails |
| 4 | Admin grants write capability | Verify succeeds |
| 5a | User fakes K_D^write | Verify fails |
| 5b | User tampers auth tag | Verify fails |

## Security Guarantees

- Coalition weight < threshold → cannot create delegation key
- Admin alone → cannot decrypt user data
- User alone → cannot decrypt user data
- Admin + User with delegation → can decrypt
- Read-only delegation → cannot perform write/delete

## Documentation

See [explanation.md](explanation.md) for algorithm-to-code mapping.
