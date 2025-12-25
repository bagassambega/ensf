# ENSF - Delegation-based Access Control

Implementation of Weighted Secret Sharing with Delegation for Access Control.

## Features

- **n Administrators** with configurable weights
- **Weighted Coalition Threshold** for delegation authorization
- **Scheme 1**: Basic delegation (read-only)
- **Scheme 2**: Capability-enhanced delegation (read/write/delete)
- **User Key Composition**: K_U* = KDF(K_U || K_D)

## Installation

```bash
# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install package with dev dependencies
pip install -e ".[dev]"
```

## Usage

```bash
# Initialize system with threshold W
ensf init --threshold 3

# Add administrators
ensf add-admin admin1 --weight 2
ensf add-admin admin2 --weight 1

# Add user
ensf add-user user1

# Create delegation key (Scheme 1 - read only)
ensf delegate -a admin1,admin2 -n delegation1

# Create delegation key (Scheme 2 - with capabilities)
ensf delegate -a admin1,admin2 -n delegation2 -c read,write -p admin1

# Export keys for distribution
ensf export user-key user1 -o user1.key
ensf export delegation delegation1 -o delegation1.key

# Encrypt user data
ensf encrypt -u user1 -d delegation1 secret.txt secret.enc

# Decrypt (requires both user key and delegation key)
ensf decrypt -u user1.key -d delegation1.key secret.enc secret.txt
```

## Security Guarantees

- Coalition weight < threshold → cannot create delegation key
- Admin alone → cannot decrypt user data
- User alone → cannot decrypt user data
- Admin + User with delegation → can decrypt
