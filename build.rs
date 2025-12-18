use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Generate random polymorphic key
    let key = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() % 256) as u8;

    // Write to OUT_DIR
    let out_dir = env::var("OUT_DIR").unwrap();
    let key_file = Path::new(&out_dir).join("poly_key.rs");
    fs::write(key_file, format!("pub const POLY_KEY: u8 = {};", key)).unwrap();

    println!("cargo:rerun-if-changed=build.rs");
}