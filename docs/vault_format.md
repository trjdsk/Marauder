# Vault Format Specification

## Overview

The Marauder vault format provides versioned, tamper-resistant storage for encrypted password data. The format uses authenticated encryption with associated data (AEAD) to ensure both confidentiality and integrity.

## File Structure

```
+------------------+
|   Header (64B)   |
+------------------+
| Encrypted Payload|
+------------------+
```

### Header Structure (64 bytes)

```
Offset  Size  Field      Description
------  ----  ---------  -----------------------------------------
0       4     magic      File identifier: "MRDR" (0x4D524452)
4       2     version    Format version (little-endian)
6       32    salt       Random salt (reserved for future use)
38      12    nonce      Encryption nonce for AES-GCM
50      14    reserved   Reserved for future use (zero-filled)
```

### Header Fields

- **magic** (4 bytes): Constant identifier `b"MRDR"` to identify vault files
- **version** (2 bytes): Format version number (currently 1)
- **salt** (32 bytes): Random salt (reserved for future key derivation)
- **nonce** (12 bytes): 96-bit nonce for AES-256-GCM encryption
- **reserved** (14 bytes): Zero-filled reserved space for future extensions

### Encrypted Payload

The payload is encrypted using AES-256-GCM with:
- **Key**: 32-byte master key
- **Nonce**: From header (12 bytes)
- **Associated Data (AAD)**: Complete header (64 bytes)

The AAD binding ensures that any modification to the header will be detected during decryption.

## Security Properties

### Corruption Detection

1. **Magic Check**: Invalid magic bytes are rejected immediately
2. **Version Check**: Unsupported versions are rejected
3. **Authentication**: GCM authentication tag verifies integrity of both header and payload
4. **AAD Binding**: Header modifications are detected via associated data

### Atomic Writes

The repository uses atomic write operations:
1. Write to temporary file (`.tmp` suffix)
2. Flush and sync to disk
3. Atomic rename/replace operation
4. On failure, temporary file is cleaned up

This ensures the vault survives crashes mid-write.

### Fail-Closed Behavior

Any corruption or tampering results in hard failure:
- Invalid magic → `ValueError`
- Unsupported version → `ValueError`
- Tampered header → `ValueError` (via AAD verification)
- Tampered ciphertext → `ValueError` (via GCM authentication)
- Wrong key → `ValueError` (via GCM authentication)

The vault never returns corrupted or partially decrypted data.

## Versioning

### Current Version: 1

Version 1 features:
- Fixed 64-byte header
- AES-256-GCM encryption
- Header-payload AAD binding
- Magic and version validation

### Version Compatibility

- **Downgrade Prevention**: Higher versions cannot be opened by older code
- **Upgrade Path**: Future versions will maintain backward compatibility where possible
- **Version Check**: `version > VAULT_VERSION` is rejected

## Usage

### Packing a Vault

```python
from marauder.vault.format import pack_vault

payload = b"encrypted data"
master_key = b"..." # 32 bytes
vault_data = pack_vault(payload, master_key)
```

### Unpacking a Vault

```python
from marauder.vault.format import unpack_vault

payload = unpack_vault(vault_data, master_key)
```

### Repository Operations

```python
from marauder.vault.repository import VaultRepository
from pathlib import Path

repo = VaultRepository(Path("vault.mrdr"))
repo.save(payload, master_key)
payload = repo.load(master_key)
```

## Error Handling

All operations raise `ValueError` on corruption or tampering:
- Invalid format
- Wrong key
- Tampered data
- Unsupported version

The vault never silently accepts corrupted data.

