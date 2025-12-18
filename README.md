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
- Examine kernel-level rootkit techniques for stealth and evasion.
- Explore process injection and in-memory execution techniques.
- Research advanced covert communication channels (DNS tunneling, domain fronting, steganography).
- Study multi-stage malware deployment and self-deletion mechanisms.
- Analyze EDR bypass techniques including Heaven's Gate and direct syscalls.
- Provide a basis for security research and defensive programming.

## Features

### Core Encryption
- **Streaming File Encryption**: ChaCha20Poly1305 with chunked AEAD encryption for large files
- **Hardware-Bound Keys**: Master keys tied to CPU ID, MAC address, disk serial, and motherboard serial
- **Machine-Specific Decryption**: Files can only be decrypted on the original infected machine

### Advanced Capabilities
- **AI-Powered Targeting**: Uses machine learning (linfa crate) to analyze file characteristics and prioritize encryption of high-value files (large, recently accessed, important types in key directories)
- **EXTREME Stealth Rootkit**: Advanced kernel-level rootkit with SSDT hooking, DKOM (Direct Kernel Object Manipulation), and dual-mode hiding to completely evade EDR/AV detection
- **Process Injection & Hollowing**: Injects payload into legitimate processes (explorer.exe, svchost.exe, regsvr32.exe, rundll32.exe) using process hollowing and Heaven's Gate for 32-bit to 64-bit transitions
- **In-Memory Execution**: Reflective DLL injection and shellcode execution entirely in memory without touching disk, using techniques like sRDI (Shellcode Reflective DLL Injection)
- **Multi-Stage Dropper Chain**: Office macro downloads encrypted stage 2 in memory, injects into system processes, uses direct syscalls for EDR bypass, with complete self-deletion of all stages
- **Stealth Communication Channels**: Multiple covert C2 channels including DNS tunneling, ICMP exfiltration, domain fronting through CDNs, and steganography in social media images
- **Stream Encryption**: Multithreaded ChaCha20Poly1305 encryption with parallel processing for high-performance file encryption
- **Advanced Self-Deletion**: Secure wipe with multiple random overwrites followed by file deletion and cleanup of all temporary artifacts
- **Network Share Encryption**: Automatically detects and encrypts mounted network drives
- **Polymorphic Engine**: Compile-time randomization with unique signatures per build
- **Tor C2 Communication**: Anonymous command-and-control via SOCKS5 proxy (fallback channel)
- **Screenshot Capture**: Desktop screenshots sent to C2 server
- **Countdown Timer**: Fullscreen HTML timer with 72-hour deadline display

### EXTREME Evasion Features (โหดสุด)
- **Kernel-Level Rootkit**: SSDT hooking for system call interception, DKOM for process/file hiding, signed driver loading for kernel persistence
- **Multi-Channel C2**: Redundant communication using DNS tunneling, ICMP packets, domain fronting via CDNs, and covert channels in social media
- **Heaven's Gate Bypass**: 32-bit to 64-bit syscall transitions to evade EDR syscall monitoring
- **Direct Syscalls**: Raw system calls bypassing Windows API hooks for file operations and process management
- **Office Macro Dropper**: VBA macros in Word/Excel documents that download and execute encrypted payloads in memory
- **Process Hollowing Chain**: Injection into regsvr32.exe -> rundll32.exe -> final payload with each stage self-deleting
- **DNS over HTTPS**: Covert exfiltration using legitimate DNS queries over encrypted HTTPS connections
- **Steganography**: Data hiding in social media images and posts for ultimate backup communication
- **Secure Multi-Pass Wipe**: 3-pass random overwrite + secure deletion for all executable stages

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

