# Cassandra-Ransomware

## Description

This repository contains a comprehensive Rust-based implementation of advanced ransomware for educational and research purposes only. It demonstrates cutting-edge concepts in cryptography, anti-forensic techniques, polymorphic code generation, and command-and-control (C2) communication. **Warning: This code is for learning purposes and should not be used for malicious activities. Always ensure compliance with legal and ethical standards.**

## Goals

- Demonstrate advanced encryption techniques using modern cryptographic libraries.
- Explore file system operations, network share encryption, and traversal.
- Understand persistence, anti-analysis, and ransom note generation.
- Implement polymorphic engines for AV evasion.
- Study C2 communication through Tor networks.
- Research anti-forensic techniques and secure deletion.
- Investigate AI/ML applications in malware targeting and evasion.
- Provide a basis for security research and defensive programming.

## Features

### Core Encryption
- **Streaming File Encryption**: ChaCha20Poly1305 with chunked AEAD encryption for large files
- **Hardware-Bound Keys**: Master keys tied to CPU ID, MAC address, disk serial, and motherboard serial
- **Machine-Specific Decryption**: Files can only be decrypted on the original infected machine

### Advanced Capabilities
- **AI-Powered Targeting**: Uses machine learning (linfa crate) to analyze file characteristics and prioritize encryption of high-value files (large, recently accessed, important types in key directories)
- **Network Share Encryption**: Automatically detects and encrypts mounted network drives
- **Polymorphic Engine**: Compile-time randomization with unique signatures per build
- **Tor C2 Communication**: Anonymous command-and-control via SOCKS5 proxy
- **Screenshot Capture**: Desktop screenshots sent to C2 server
- **Countdown Timer**: Fullscreen HTML timer with 72-hour deadline display

### Anti-Forensic Features
- **Secure File Deletion**: 4-pass overwrite (zeros, random, zeros, ones) before deletion
- **Free Space Wiping**: Overwrites unallocated space to prevent file recovery
- **Event Log Clearing**: Removes Windows system and security logs
- **Self-Deletion**: Automatic malware removal after execution

### Persistence & Evasion
- **Multi-Point Persistence**: Registry keys, startup folder, and scheduled tasks
- **Process Termination**: Kills antivirus and backup processes
- **VM Detection**: Anti-analysis checks for virtual machines
- **String Obfuscation**: XOR-encrypted strings with compile-time keys

### Wiper Mode
- **Deadline Enforcement**: Automatic file destruction after payment deadline
- **Recursive Wipe**: Targets all encrypted files across the system
- **Irrecoverable Deletion**: Military-grade secure deletion standards

## Requirements

- Rust 1.70 or later
- Cargo

## Build

```bash
cargo build --release
```

## Usage

**Do not run this on production systems or without explicit permission.**

```bash
cargo run
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome for educational purposes. Please open an issue to discuss changes before submitting a pull request.

## Disclaimer

This software is provided as-is for educational use. The authors are not responsible for any misuse or damage caused by this code.

