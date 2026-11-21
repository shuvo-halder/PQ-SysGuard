# PQ-SysGuard

**PQ-SysGuard** is a modular Linux system-administration and security toolkit designed with zero-trust principles and NIST-standardized Post-Quantum Cryptography (PQC).

---

## Capabilities & Architecture

PQ-SysGuard is organized into four core modules:
1. **`monitor`**: Real-time server telemetry (CPU, RAM, disk, network, processes, and service health) backed by SQLite metrics storage.
2. **`troubleshoot`**: Automated system diagnosis and triage (systemd-journald logs, failed units, OOM events, disk inode exhaustion).
3. **`security`**: Hardening compliance audit (SSH configuration, unauthorized listening ports, file permissions, updates). **Strictly read-only by default; `--apply` is mandatory for modifications.**
4. **`vault`**: Post-quantum cryptographic file vault combining ephemeral AES-256-GCM chunked streaming (1 MB chunks with per-chunk authentication tags), **ML-KEM-768** key encapsulation (FIPS 203), and **ML-DSA-65** digital signatures (FIPS 204).

For technical details and system sequence diagrams, refer to [ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Security Principles & Non-Negotiable Rules

1. **No Custom Cryptography**: Uses only vetted libraries (`cryptography`, `liboqs`) and NIST-standardized post-quantum algorithms.
2. **Hybrid & Authenticated**: Ephemeral 256-bit symmetric file keys are wrapped via ML-KEM-768; encrypted file chunks are authenticated; packages are signed via ML-DSA-65.
3. **Encrypted Private Keys at Rest**: Private keys are protected using Argon2id (64 MB memory cost, 3 iterations) + AES-GCM.
4. **Strict Sanitization**: Zero secrets or credentials in logs; structured JSON logging enforces automated redaction of sensitive fields.
5. **Safe Execution**: All system commands run via parameterized argument lists (`execve` semantics, `shell=False`).
6. **Streaming Protection**: Large files stream in authenticated 1 MB chunks to prevent RAM exhaustion and block truncation/reordering attacks.
7. **Read-Only Default**: Audit operations are strictly non-destructive unless explicit `--apply` consent is provided.

---

## Installation & Setup

### Prerequisites
- Python 3.12+ (managed with `venv` or `uv`)
- Linux (Ubuntu/Debian, RHEL/Rocky, Arch) or cross-platform development environment

### Quickstart

```bash
# 1. Clone repository
git clone https://github.com/example/pq-sysguard.git
cd pq-sysguard

# 2. Create virtual environment & install dependencies
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e ".[dev]"

# Alternatively, using Make or Just:
make install
# or: just install
```

---

## CLI Usage

Run the top-level help command:
```bash
pqsysguard --help
```

### 1. Server Health Monitoring
```bash
pqsysguard monitor
```

### 2. Automated Troubleshooting
```bash
pqsysguard troubleshoot
```

### 3. Hardening Audit & Remediation
```bash
# Read-only audit (Default)
pqsysguard security

# Enforce automated remediation
pqsysguard security --apply
```

### 4. Post-Quantum File Vault
```bash
# Generate ML-KEM-768 and ML-DSA-65 key pairs
pqsysguard vault keygen --out-dir ./keys

# Encrypt a file (hybrid AES-256-GCM + ML-KEM-768 + ML-DSA-65)
pqsysguard vault encrypt payload.tar.gz --recipient-key keys/recipient_kem.pub --signing-key keys/sender_dsa.priv

# Decrypt and verify signature
pqsysguard vault decrypt payload.tar.gz.pqe --key keys/recipient_kem.priv --sender-key keys/sender_dsa.pub
```

---

## Development & Quality Assurance

```bash
# Run test suite with branch coverage
make test      # or: pytest --cov=src/pqsysguard tests/

# Run static analysis and linting (Ruff, Mypy)
make lint      # or: ruff check src/ tests/ && mypy src/ tests/

# Run security static analysis
bandit -r src/ -c pyproject.toml
```

---

## Known Limitations & Production Caveats

- **CPython Buffer Zeroization**: Python manages memory through its garbage collector and pymalloc allocator. While mutable buffers (`bytearray`) are overwritten in-place with zeroes upon completion, Python does not provide guaranteed kernel-level secure memory wiping for immutable objects (like `bytes` and `str`). For ultra-high assurance environments, a native C extension (`mlock` + `explicit_bzero`) is recommended.
- **Phase 1 Status**: This release establishes the project scaffolding, configuration loader (YAML + environment overrides), structured JSON logging with redaction, CLI dispatch hierarchy, and testing harness. Subcommands currently operate as structured placeholders awaiting subsequent phase implementations.
