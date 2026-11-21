# PQ-SysGuard Architecture & System Design

PQ-SysGuard is a modular Linux system-administration and security toolkit built with zero-trust principles and NIST post-quantum cryptographic standards.

---

## 1. High-Level Architecture

The toolkit consists of four core functional modules, supported by common utilities for structured configuration, JSON logging, and persistent SQLite auditing.

```mermaid
flowchart TD
    CLI["PQ-SysGuard CLI (Typer + Rich)"] --> Config["Config Manager (YAML + Env)"]
    CLI --> Logger["Structured Logger (JSON / Console)"]
    
    CLI --> M["1. Monitor Module"]
    CLI --> T["2. Troubleshoot Module"]
    CLI --> S["3. Security Module"]
    CLI --> V["4. Vault Module (PQC)"]

    M --> Telemetry["psutil Telemetry Engine"]
    M --> Storage[("SQLite Metrics & Audit DB")]

    T --> Journal["systemd-journald & Logs"]
    T --> Rules["Automated Diagnostic Engine"]

    S --> Audit["Audit Checks (SSH, Ports, Perms)"]
    S --> Remediation["Remediation Engine (Requires --apply)"]

    V --> KEM["ML-KEM-768 (Key Encapsulation)"]
    V --> DSA["ML-DSA-65 (Digital Signatures)"]
    V --> Sym["AES-256-GCM Streaming (1 MB Chunks)"]
    V --> KDF["Argon2id (Key Wrapping at Rest)"]
```

---

## 2. Core Modules Description

| Module | Primary Responsibility | Key Components | State / Safety Defaults |
| :--- | :--- | :--- | :--- |
| **`monitor`** | Server health telemetry | CPU, RAM, Disk, Network, Process table | Read-only |
| **`troubleshoot`** | Root cause automated triage | Log analysis, service failure detection, OOM inspection | Read-only |
| **`security`** | Hardening verification & remediation | SSH daemon config, open ports, permissions, update status | **Read-only by default**; `--apply` required for changes |
| **`vault`** | Post-quantum file protection | ML-KEM-768, ML-DSA-65, chunked AES-256-GCM | Ephemeral symmetric file key; zeroized buffers |

---

## 3. Post-Quantum Vault: Hybrid Cryptographic Flow

The vault guarantees resilience against future cryptanalytically relevant quantum computers ("Harvest Now, Decrypt Later" attack vectors).

### Encryption Pipeline

```mermaid
flowchart LR
    File["Plaintext File"] --> Chunk["1 MB Streaming Chunks"]
    FileKey["Ephemeral 256-bit Key\n(os.urandom)"] --> AES["AES-256-GCM\nPer-Chunk Encryption"]
    Chunk --> AES
    AES --> Payload["Encrypted Chunks + Auth Tags"]

    FileKey --> KEM["ML-KEM-768 Encapsulation\n(Recipient Public Key)"]
    KEM --> WrappedKey["Encapsulated Key Header"]

    Payload --> Package["Ciphertext Package"]
    WrappedKey --> Package

    Package --> Sign["ML-DSA-65 Signature\n(Sender Private Key)"]
    Sign --> Out[".pqe Encrypted File"]
```

### Key Encapsulation & Authentication Specification
1. **Symmetric File Key**: 256-bit ephemeral key generated using `os.urandom()`.
2. **Bulk Encryption**: AES-256-GCM streaming in 1 MB chunks with unique nonces and authenticated chunk counters to prevent reordering, truncating, or replay attacks.
3. **Key Encapsulation**: The ephemeral symmetric key is encapsulated to recipient's public key using **ML-KEM-768** (FIPS 203).
4. **Package Authentication**: The header and chunk authentication manifests are signed using **ML-DSA-65** (FIPS 204) private key.
5. **Private Key Storage at Rest**: Private keys on disk are encrypted using **Argon2id** (memory cost: 64 MB, time cost: 3 iterations) and **AES-256-GCM**.

---

## 4. Non-Negotiable Security Architecture

1. **Strictly Parameterized Subprocesses**: Never use `shell=True`. All system inquiries and remediations execute with fixed argument arrays (`execve` semantics) and input validation.
2. **Explicit Consent for Changes**: Security audits and troubleshooting are strictly observational unless the operator passes `--apply`.
3. **Memory Hygiene**: Ephemeral symmetric keys and plaintext buffers are explicitly overwritten (`bytearray` zeroization) as soon as operations conclude.
4. **Structured JSON Auditability**: All operational actions are logged as structured JSON with automatic redaction of sensitive credentials and keys.
