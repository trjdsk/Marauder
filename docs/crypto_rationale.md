# Cryptographic Design Rationale

This document explains the cryptographic design decisions made for Marauder's password manager, providing justification for algorithm choices, parameter selection, and security considerations.

## Overview

Marauder uses a defense-in-depth approach to cryptographic security, combining proven algorithms with industry-standard parameters to protect user credentials and sensitive data.

## Key Derivation: Argon2id

### Why Argon2id?

Argon2id was chosen over alternatives (PBKDF2, scrypt, bcrypt) for the following reasons:

1. **Modern Standard**: Argon2 won the Password Hashing Competition (2015) and is recommended by OWASP, NIST, and other security organizations.

2. **Memory-Hard Function**: Argon2id provides strong resistance against both GPU-based attacks (through memory hardness) and side-channel attacks (through its hybrid design).

3. **Hybrid Design**: Argon2id combines the best of Argon2i (side-channel resistant) and Argon2d (memory-hard), providing protection against both attack vectors.

4. **Configurability**: Argon2id allows fine-tuning of memory, time, and parallelism costs to balance security and performance.

5. **Proven Security**: Extensive cryptanalysis has shown Argon2id to be secure when properly configured.

### Parameter Selection: OWASP Recommendations

We use OWASP-recommended parameters for Argon2id:

- **Memory Cost (m)**: 64 MB (65,536 KB)
  - Provides strong resistance to GPU attacks
  - Reasonable performance on modern hardware
  - Can be increased for higher security if needed

- **Time Cost (t)**: 3 iterations
  - Balances security and user experience
  - Prevents brute-force attacks while maintaining acceptable performance
  - OWASP minimum recommendation

- **Parallelism (p)**: 4 lanes
  - Utilizes multi-core processors effectively
  - Prevents excessive resource consumption
  - Standard for desktop applications

- **Output Length**: 32 bytes (256 bits)
  - Matches AES-256 key size requirement
  - Provides 256 bits of security

These parameters provide a good balance between security and usability. The memory cost of 64 MB makes GPU-based attacks expensive, while the time cost of 3 iterations ensures reasonable performance on modern hardware.

## Encryption: AES-256-GCM

### Why AES-256-GCM?

1. **Authenticated Encryption**: GCM (Galois/Counter Mode) provides both confidentiality and authenticity in a single operation, preventing tampering attacks.

2. **Industry Standard**: AES is the most widely analyzed and trusted symmetric encryption algorithm, approved by NIST for top-secret information.

3. **256-bit Keys**: AES-256 provides 256 bits of security, matching the key derivation output and providing strong protection against brute-force attacks.

4. **Performance**: AES-GCM is hardware-accelerated on modern CPUs, providing excellent performance.

5. **Nonce-based**: Each encryption uses a unique nonce, ensuring that the same plaintext produces different ciphertexts.

### Nonce Size: 12 Bytes (96 bits)

We use 12-byte (96-bit) nonces for the following reasons:

1. **GCM Standard**: 96-bit nonces are the standard for GCM and are recommended by NIST.

2. **Uniqueness**: With secure random generation, 96 bits provide sufficient entropy to ensure uniqueness for the lifetime of the key.

3. **Efficiency**: 12-byte nonces are efficient to store and transmit while providing adequate security.

4. **Compatibility**: 96-bit nonces are widely supported and well-tested in cryptographic libraries.

### Key Size: 256 bits (32 bytes)

1. **Security Margin**: 256-bit keys provide 256 bits of security, which is considered secure against both classical and quantum attacks (with appropriate post-quantum considerations).

2. **Future-Proofing**: 256-bit keys provide a large security margin against advances in cryptanalysis.

3. **Standard**: AES-256 is the standard for high-security applications.

## Secure Random Generation

### Implementation: `secrets.token_bytes()`

We use Python's `secrets.token_bytes()` function because:

1. **Cryptographically Secure**: Uses the operating system's cryptographically secure random number generator (e.g., `/dev/urandom` on Unix, `CryptGenRandom` on Windows).

2. **Standard Library**: Part of Python's standard library, well-tested and maintained.

3. **OS Integration**: Leverages the operating system's secure random source, which is the gold standard for cryptographic randomness.

4. **No External Dependencies**: Reduces attack surface and dependency management complexity.

## Memory Zeroing

### Best-Effort Approach

Memory zeroing in Python faces significant challenges:

1. **Python's Memory Management**: Python's garbage collector and memory allocator make it difficult to guarantee immediate memory clearing.

2. **Immutable Objects**: `bytes` objects are immutable and cannot be zeroed in-place.

3. **Copy-on-Write**: Some operating systems use copy-on-write semantics, making it difficult to ensure memory is actually overwritten.

### Implementation Strategy

We use a best-effort approach:

1. **Mutable Data (`bytearray`)**: Attempts to zero in-place using:
   - `secure-delete` library if available (provides secure deletion)
   - `ctypes.memset` as fallback (attempts to zero memory)
   - Python assignment as last resort (less secure but better than nothing)

2. **Immutable Data (`bytes`)**: Documents the limitation and recommends avoiding keeping sensitive data in memory longer than necessary.

3. **Documentation**: Clearly documents Python's limitations and provides guidance for secure coding practices.

### Security Considerations

While we cannot guarantee perfect memory zeroing in Python, we:

1. **Minimize Exposure**: Design APIs to minimize the time sensitive data remains in memory.

2. **Best Practices**: Follow secure coding practices to reduce the window of vulnerability.

3. **Transparency**: Document limitations clearly so developers understand the security model.

## Security Considerations

### Known Limitations

1. **Memory Zeroing**: Python's memory management makes perfect memory zeroing difficult. We use best-effort approaches and document limitations.

2. **Timing Attacks**: Python's high-level nature makes constant-time operations difficult. We rely on well-tested cryptographic libraries that implement constant-time operations at the C level.

3. **Side-Channel Attacks**: While we use side-channel resistant algorithms (Argon2id), Python's execution environment may still leak information through timing or other side channels. This is mitigated by using well-tested cryptographic libraries.

### Mitigations

1. **Proven Libraries**: We use well-tested, audited cryptographic libraries (`cryptography`, `argon2-cffi`) rather than implementing cryptography ourselves.

2. **Input Validation**: All functions validate inputs to prevent invalid operations that could lead to security issues.

3. **Error Handling**: Error messages do not leak sensitive information about keys, passwords, or plaintext.

4. **No Logging of Secrets**: We ensure that no plaintext secrets, keys, or passwords are logged or exposed in error messages.

5. **Secure Defaults**: All cryptographic operations use secure default parameters, reducing the risk of misconfiguration.

## Future Considerations

1. **Post-Quantum Cryptography**: As quantum computing advances, we may need to consider post-quantum cryptographic algorithms. However, AES-256 and Argon2id remain secure against classical attacks and provide reasonable protection against known quantum attacks.

2. **Parameter Tuning**: Users with higher security requirements may want to increase Argon2id parameters (memory cost, time cost) at the expense of performance.

3. **Hardware Security Modules**: Future versions may integrate with hardware security modules (HSMs) for key storage and operations.

## References

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST Special Publication 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Argon2 Specification](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf)
- [NIST Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)](https://csrc.nist.gov/publications/detail/sp/800-38d/final)


