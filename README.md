# cassandra-ransomeware

## Description

This repository contains a comprehensive Rust-based implementation of advanced ransomware for educational and research purposes only. It demonstrates cutting-edge concepts in cryptography, anti-forensic techniques, polymorphic code generation, and command-and-control (C2) communication. **Warning: This code is for learning purposes and should not be used for malicious activities. Always ensure compliance with legal and ethical standards.**

## 🚀 Quick Start (ใช้งานง่ายๆ)

### 🌐 Web Interface (แนะนำสำหรับผู้เริ่มต้น)

```bash
# เริ่ม web interface
cargo run --features web -- --web
```

แล้วเปิด browser ไปที่: **http://127.0.0.1:8000**

**Web Interface มี:**
- 🎮 **เมนูแบบกราฟิก** - เลือกโหมดได้ง่าย
- 🛡️ **Safe Demo Mode** - ทดสอบปลอดภัย 100%
- 📊 **Component Testing** - ทดสอบแต่ละส่วน
- 🔍 **System Status** - ดูสถานะระบบ
- ⚠️ **Disabled Danger Zone** - ปิดการทำงานอันตราย

### สำหรับผู้เริ่มต้น - ใช้ Launcher Script

#### Windows:
```cmd
# ดับเบิลคลิกที่ run.bat หรือรันใน Command Prompt
run.bat
```

#### Linux/Mac:
```bash
# ทำให้ไฟล์ executable ก่อน
chmod +x run.sh
./run.sh
```

Launcher จะแสดงเมนูให้เลือก:
1. **Safe Demo Mode** - ทดสอบปลอดภัย (แนะนำ)
2. **Show Help** - แสดงวิธีใช้
3. **Developer Test** - โหมดทดสอบสำหรับนักพัฒนา
4. **Integration Test** - ทดสอบการทำงานร่วมกัน
5. **Full Execution** - ⚠️ อันตราย! (ใช้ใน VM เท่านั้น)

### 🎯 วิธีที่ง่ายที่สุด - Easy Launcher

#### Windows (แนะนำ):
```cmd
# ดับเบิลคลิกที่ easy-launcher.bat
easy-launcher.bat
```

**Easy Launcher มีเมนูแบบง่าย:**
```
1. SAFE DEMO - See all features (No risk!)
2. QUICK TEST - Test basic functions
3. FULL TEST - Test everything together
4. HELP - Show detailed instructions
```

### ⚙️ Configuration (ตั้งค่าเพิ่มเติม)

แก้ไขไฟล์ `config.toml` เพื่อปรับแต่งการทำงาน:

```toml
[encryption]
chunk_size = 65536  # ขนาด chunk สำหรับ encryption
parallel_workers = 4  # จำนวน thread

[ai_targeting]
enabled = true  # เปิดใช้งาน AI เลือกเป้าหมาย
max_files_to_analyze = 10000

[web_interface]
enabled = false  # เปิด web interface อัตโนมัติ
port = 8000
host = "127.0.0.1"
```

### ไม่ต้องเตรียมไฟล์อะไร!

**รansomware จะทำงานอัตโนมัติ:**
- 🔍 **หาไฟล์เอง** - Scan ระบบหาไฟล์สำคัญโดยอัตโนมัติ
- 🎯 **เลือกเป้าหมายอัตโนมัติ** - ใช้ AI เลือกไฟล์ที่มีค่าที่สุด
- ⚡ **ทำงานทันที** - ไม่ต้องวางไฟล์ไว้ที่ไหนพิเศษ

### ไฟล์ที่มันจะหาโดยอัตโนมัติ:
```
📁 Documents/     (เอกสาร Word, PDF)
📁 Desktop/       (ไฟล์บนเดสก์ท็อป)
📁 Downloads/     (ไฟล์ที่โหลดมา)
📁 Pictures/      (รูปภาพครอบครัว)
📁 Music/Videos/  (เพลงและวิดีโอ)
💾 Network drives (ไดรฟ์เครือข่าย)
💾 USB drives     (แฟลชไดรฟ์ที่เสียบอยู่)
```

### นามสกุลไฟล์ที่ถูกเลือก:
```
📄 .doc, .docx, .pdf    (เอกสารสำคัญ)
🖼️  .jpg, .png, .jpeg   (รูปภาพ)
🎵 .mp3, .mp4          (ไฟล์สื่อ)
📦 .zip, .rar          (ไฟล์บีบอัด)
📝 .txt, .xls, .xlsx   (ไฟล์ทั่วไป)
```

### ขั้นตอนการใช้งานจริง:
1. **รัน Easy Launcher** (`easy-launcher.bat`)
2. **เลือกโหมดที่ต้องการ** (1 สำหรับ Demo)
3. **ดูผลลัพธ์** - มันจะแสดงว่าทำอะไรได้บ้าง
4. **เสร็จแล้ว!** ไม่ต้องทำอะไรเพิ่มเติม

### สำหรับนักพัฒนา - ใช้ Command Line

```bash
# Demo ปลอดภัย (แนะนำสำหรับลองใช้)
cargo run -- --demo

# แสดงวิธีใช้
cargo run -- --help

# ทดสอบ dropper chain
cargo run -- test

# ทดสอบการทำงานร่วมกัน
cargo run -- integration

# เริ่ม web interface
cargo run --features web -- --web

# ⚠️ FULL EXECUTION (อันตราย!)
## 📖 วิธีใช้งาน (How to Use)

### 🌐 Web Interface Mode (แนะนำ)
```bash
cargo run --features web -- --web
```
**เปิด browser ที่:** `http://127.0.0.1:8000`

### 🎭 Demo Mode (ปลอดภัย 100%)
```bash
cargo run -- --demo
```
**ผลลัพธ์:**
```
🎭 Starting cassandra-ransomeware Ransomware Demo Mode
==========================================

1️⃣ 🔧 ROOTKIT CAPABILITIES:
   • SSDT hooking for system call interception
   • DKOM (Direct Kernel Object Manipulation)
   • Dual-mode process/file hiding

2️⃣ 🌐 STEALTH COMMUNICATION:
   • DNS tunneling: Data hidden in DNS queries
   • ICMP exfiltration: Data in ping packets
   • Domain fronting: CDN bypass techniques

... (แสดงทุก features โดยไม่ทำอันตรายจริง)
```

### 🧪 Test Modes (สำหรับนักพัฒนา)

#### Dropper Chain Test:
```bash
cargo run -- test
```
**แสดง:** การทำงานของ multi-stage dropper

#### Integration Test:
```bash
cargo run -- integration
```
**แสดง:** การทำงานร่วมกันของทุก components

### ⚠️ Full Execution (อันตราย!)
```bash
cargo run
```
**⚠️ WARNING:** จะ encrypt ไฟล์จริง! ใช้ใน VM เท่านั้น

## 📁 Project Structure

```
cassandra-ransomeware/
├── src/
│   ├── main.rs           # Main entry point with CLI/web modes
│   ├── crypto.rs         # Encryption/decryption functions
│   ├── traversal.rs      # AI-powered file discovery
│   ├── ransom_note.rs    # Ransom note generation
│   ├── persistence.rs    # System persistence mechanisms
│   ├── wiper.rs          # Deadline enforcement & file destruction
│   ├── bootkit.rs        # Bootkit persistence
│   ├── rootkit.rs        # Advanced kernel-level rootkit
│   ├── injection.rs      # Process injection techniques
│   ├── reflective.rs     # Reflective DLL injection
│   ├── stealth_comm.rs   # Covert C2 communication
│   ├── dropper.rs        # Multi-stage dropper chain
│   └── web.rs            # Web interface (optional)
├── static/
│   └── index.html        # Web UI template
├── Research/             # Academic research materials
├── config.toml           # Configuration file
├── Cargo.toml            # Rust dependencies
├── build.rs              # Build script for polymorphism
├── easy-launcher.bat     # Simple launcher for beginners
├── run.bat               # Advanced launcher
├── run.sh                # Linux/Mac launcher
└── README.md             # This file
```

## ⚙️ Configuration

The `config.toml` file allows you to customize various aspects of the ransomware:

### Core Settings
```toml
[encryption]
algorithm = "ChaCha20Poly1305"
chunk_size = 65536
parallel_workers = 4

[ai_targeting]
enabled = true
max_files_to_analyze = 10000
```

### Communication Channels
```toml
[communication]
dns_tunneling_enabled = true
icmp_exfil_enabled = true
domain_fronting_enabled = true
tor_proxy_enabled = true
```

### Web Interface
```toml
[web_interface]
enabled = false
port = 8000
host = "127.0.0.1"
```

## 🔧 Build & Development

### Prerequisites
- Rust 1.70+
- Cargo

### Build Commands
```bash
# Standard build
cargo build --release

# Build with web interface
cargo build --release --features web

# Run tests
cargo test

# Check code
cargo check
```

### Development Features
```bash
# Demo mode (safe)
cargo run -- --demo

# Integration tests
cargo run -- integration

# Web interface
cargo run --features web -- --web
```

## 🏗️ Architecture

### Core Components

1. **Crypto Engine** (`crypto.rs`)
   - ChaCha20Poly1305 authenticated encryption
   - Hardware-bound key generation
   - Parallel processing with Rayon

2. **AI Targeting** (`traversal.rs`)
   - Machine learning file prioritization
   - Smart directory scanning
   - Value-based file selection

3. **Rootkit System** (`rootkit.rs`)
   - SSDT hooking
   - DKOM techniques
   - Dual-mode hiding

4. **Stealth C2** (`stealth_comm.rs`)
   - DNS tunneling
   - ICMP exfiltration
   - Domain fronting
   - Social steganography

5. **Dropper Chain** (`dropper.rs`)
   - Multi-stage deployment
   - Self-deletion mechanisms
   - Process injection chain

6. **Web Interface** (`web.rs`)
   - Rocket-based API server
   - Responsive HTML interface
   - Safe demo capabilities

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

### EXTREME Evasion Features
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

