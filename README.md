# Cassandra Threat Analysis & Defensive Research Framework

## 1. Executive Summary & System Overview

**Cassandra** is an academic research framework implemented in **Rust (2021 Edition)** designed to study the technical mechanics, execution vectors, and detection signatures of modern ransomware threats. 

This repository provides a controlled environment for cybersecurity researchers, malware analysts, and threat intelligence engineers to analyze:
- Hybrid cryptographic key exchange & streaming encryption architecture.
- Machine learning-driven file classification and prioritization logic.
- Covert Command and Control (C2) telemetry primitives.
- System persistence vectors and anti-forensic footprint analysis.
- **Defensive Detection & Remediation Strategies** (YARA rules, EDR behavior monitoring, and system hardening).

> **[IMPORTANT] Safety Protocol**
> This project contains a built-in **Safe Demo Mode (`--demo` / `--safe`)** and an isolated **Web Interface (`--web`)** that simulate execution flows and log capabilities without altering system files or causing permanent data loss.

---

## 2. System Architecture & Module Structure

The project is structured modularly in Rust to decouple cryptographic primitives, system telemetry, file discovery algorithms, and diagnostic interfaces.

```
cassandra-ransomeware/
├── src/
│   ├── main.rs           # Entry point: CLI parser, polymorphic key execution pipeline
│   ├── config.rs         # Strongly-typed TOML configuration schema
│   ├── crypto.rs         # Cryptographic engine (ChaCha20Poly1305 + X25519)
│   ├── traversal.rs      # File discovery & K-Means clustering prioritization (linfa)
│   ├── data_thief.rs     # System telemetry & threat assessment simulation
│   ├── stealth_comm.rs   # Covert communication channel prototypes (DNS, ICMP)
│   ├── dropper.rs        # Multi-stage execution flow & secure memory wipe logic
│   ├── persistence.rs    # Registry, Task Scheduler, & startup persistence hooks
│   ├── rootkit.rs        # Kernel-level hook concepts (SSDT / DKOM theoretical models)
│   ├── injection.rs      # Process hollowing & thread injection abstraction
│   ├── reflective.rs     # In-memory PE loading mechanisms
│   ├── wiper.rs          # Irrecoverable file wipe & deadline routines
│   ├── ransom_note.rs    # Dynamic notification & desktop background update
│   └── web.rs            # Embedded Rocket web API server for interactive simulation
├── static/
│   └── index.html        # Glassmorphism research UI dashboard
├── research/             # Academic paper LaTeX source files & Makefile
├── config.toml           # Framework configuration settings
├── Cargo.toml            # Rust manifest & feature declarations
└── build.rs              # Build-time compile key generator
```

---

## 3. Core Technical Components

### 3.1 Cryptographic Architecture (`src/crypto.rs`)
- **Symmetric Cipher**: `ChaCha20Poly1305` AEAD (Authenticated Encryption with Associated Data).
- **Asymmetric Key Exchange**: `X25519` (curve25519-dalek) Diffie-Hellman ephemeral key derivation.
- **Machine Fingerprinting**: Hashes local system metrics (CPU ID, MAC address, Disk serial, Motherboard GUID) via SHA-256 to bind key derivation to specific host hardware.
- **Streaming Pipeline**: File contents are processed in 1MB buffer chunks using Rayon parallel threads.

### 3.2 Machine Learning File Discovery (`src/traversal.rs`)
- **Classifier Engine**: K-Means clustering via `linfa` / `ndarray`.
- **Feature Matrix**:
  1. `size_mb`: File size in megabytes.
  2. `days_since_access`: Temporal access delta.
  3. `days_since_modified`: Temporal modification delta.
  4. `extension_score`: Weight assigned to high-value document/database types.
  5. `path_score`: Directory path weight (`Documents`, `Desktop`, `Pictures`, etc.).

### 3.3 Configuration Schema (`src/config.rs`)
Configurations are managed via `config.toml` covering:
- `[encryption]`: Buffer chunk sizes and thread worker caps.
- `[ai_targeting]`: Target sample size limit and feature toggle.
- `[communication]`: Telemetry channel selection (DNS, ICMP, Domain Fronting, Tor).
- `[demo]`: Safety switches and execution bounds.

---

## 4. Execution Modes & CLI Reference

### 4.1 Safe Demonstration Mode (Recommended)
Simulates all sub-component routines without performing destructive disk operations:
```bash
cargo run -- --demo
# or
cargo run -- --safe
```

### 4.2 Web Interface Simulation Dashboard
Launches the embedded Rocket HTTP server on `http://127.0.0.1:8000`:
```bash
cargo run --features web -- --web
```

### 4.3 Diagnostic & Integration Verification
Runs component self-tests and validates internal state pipelines:
```bash
# Test multi-stage loader abstractions
cargo run -- test

# Perform integration pipeline verification
cargo run -- integration
```

---

## 5. Defensive Countermeasures & Threat Detection

Understanding the mechanics of Cassandra provides actionable insight for enterprise SOCs and incident response teams.

### 5.1 EDR & Behavioral Signatures
1. **Process Injection Detection**: Monitor anomalous `VirtualAllocEx`, `WriteProcessMemory`, and `CreateRemoteThread` API calls targetting `svchost.exe`, `regsvr32.exe`, or `explorer.exe`.
2. **Volume Shadow Copy Deletion**: Alert on execution of `vssadmin delete shadows /all /quiet` or PowerShell WMI calls attempting shadow copy removal.
3. **Mass Renaming Activity**: Monitor high-frequency file write operations appending non-standard file extensions (`.locked`).

### 5.2 YARA Rule Detection Example
```yara
rule Cassandra_Ransomware_Research_Pattern {
    meta:
        description = "Detects Cassandra research binary artifacts"
        author = "Threat Analysis Team"
        severity = "High"
    strings:
        $s1 = "ChaCha20Poly1305" ascii
        $s2 = "cassandra-ransomeware" ascii
        $s3 = "machine_fingerprint" ascii
    condition:
        uint16(0) == 0x5A4D and all of ($s*)
}
```

### 5.3 Hardening & Mitigations
- **Immutable Backups**: Maintain off-site, air-gapped, and write-once-read-many (WORM) backups.
- **Attack Surface Reduction**: Enable Controlled Folder Access in Windows Defender to block unauthorized disk modifications.
- **Network Segmentation**: Restrict SMB/RPC traffic across internal host boundaries to mitigate lateral movement.

---

## 6. Build Instructions

### Requirements
- **Rust Toolchain**: 1.70+ (`rustc`, `cargo`)
- **C Compiler / Windows SDK** (for target native library linkage)

### Compilation Commands
```bash
# Build optimized release binary
cargo build --release

# Build with Web UI feature set
cargo build --release --features web

# Run automated tests
cargo test
```

---

## 7. License & Disclaimer

This project is released under the **MIT License**. It is strictly intended for **academic research, security defense development, and authorized educational demonstrations**. The authors assume no liability for misuse or unauthorized deployment.
