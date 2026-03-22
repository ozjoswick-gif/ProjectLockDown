use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use indicatif::{ProgressBar, ProgressStyle};
use pbkdf2::pbkdf2_hmac;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use walkdir::WalkDir;

use crate::error::{LockdownError, Result};

/// Magic bytes identifying a lockdown-encrypted file.
const MAGIC: &[u8; 4] = b"LKD1";

/// Key type flag: raw 32-byte key (hex or generated).
pub const KEY_TYPE_RAW: u8 = 0x00;

/// Key type flag: password-derived key; salt is embedded in the file.
pub const KEY_TYPE_PASSWORD: u8 = 0x01;

const NONCE_SIZE: usize = 12;
pub const SALT_SIZE: usize = 32;

/// Directories skipped during recursive encryption/decryption.
const SKIP_DIRS: &[&str] = &[
    "venv", ".git", "__pycache__", "node_modules", ".venv", ".tox", "target",
];

// ── File format ────────────────────────────────────────────────────────────
//
//  Raw key:      "LKD1" [0x00] [12-byte nonce] [ciphertext + 16-byte GCM tag]
//  Password key: "LKD1" [0x01] [32-byte salt]  [12-byte nonce] [ciphertext + 16-byte GCM tag]
//
// The GCM tag is appended to the ciphertext by aes-gcm's encrypt().
// Embedding the salt makes each file self-contained: it can be decrypted
// with just the password, even without the standardize master.key file.

/// Configuration passed to all encrypt/decrypt operations.
#[derive(Clone)]
pub struct CryptoConfig {
    pub key: [u8; 32],
    pub delete_original: bool,
    pub key_type: u8,
    /// PBKDF2 salt embedded in the output file (only for KEY_TYPE_PASSWORD).
    pub salt: Option<[u8; SALT_SIZE]>,
}

/// Counts from a directory operation.
#[derive(Default)]
pub struct Stats {
    pub success: usize,
    pub failed: usize,
}

/// Header parsed from an encrypted file.
pub struct FileHeader {
    pub key_type: u8,
    /// Salt present when key_type == KEY_TYPE_PASSWORD.
    pub salt: Option<[u8; SALT_SIZE]>,
    /// Byte offset where the nonce begins.
    pub data_offset: usize,
}

// ── Key helpers ─────────────────────────────────────────────────────────────

pub fn generate_random_key(len: usize) -> Vec<u8> {
    let mut key = vec![0u8; len];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn derive_key(password: &str, salt: &[u8; SALT_SIZE]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 100_000, &mut key);
    key
}

// ── Secure delete ────────────────────────────────────────────────────────────

/// Overwrite file contents with random bytes, flush, then remove.
/// Note: on SSDs and copy-on-write filesystems this is best-effort only.
pub fn secure_delete(path: &Path) -> Result<()> {
    let size = path.metadata()?.len() as usize;
    let mut random_data = vec![0u8; size.max(1)];
    OsRng.fill_bytes(&mut random_data);
    let mut f = fs::OpenOptions::new().write(true).open(path)?;
    f.write_all(&random_data)?;
    f.sync_all()?;
    drop(f);
    fs::remove_file(path)?;
    Ok(())
}

// ── Header parsing ────────────────────────────────────────────────────────────

pub fn read_header(path: &Path) -> Result<FileHeader> {
    let data = fs::read(path)?;
    parse_header(&data).map_err(|e| LockdownError::Decryption(e.to_string()))
}

fn parse_header(data: &[u8]) -> std::result::Result<FileHeader, &'static str> {
    if data.len() < 5 {
        return Err("file too small");
    }
    if &data[..4] != MAGIC {
        return Err("not a lockdown file (invalid magic bytes)");
    }
    let key_type = data[4];
    match key_type {
        KEY_TYPE_PASSWORD => {
            let min_len = 4 + 1 + SALT_SIZE + NONCE_SIZE + 16;
            if data.len() < min_len {
                return Err("file too small for password header");
            }
            let mut salt = [0u8; SALT_SIZE];
            salt.copy_from_slice(&data[5..5 + SALT_SIZE]);
            Ok(FileHeader {
                key_type,
                salt: Some(salt),
                data_offset: 5 + SALT_SIZE,
            })
        }
        KEY_TYPE_RAW => {
            let min_len = 4 + 1 + NONCE_SIZE + 16;
            if data.len() < min_len {
                return Err("file too small for raw key header");
            }
            Ok(FileHeader {
                key_type,
                salt: None,
                data_offset: 5,
            })
        }
        _ => Err("unknown key type in header"),
    }
}

// ── Single-file operations ────────────────────────────────────────────────────

pub fn encrypt_file(config: &CryptoConfig, input: &Path, output: &Path) -> Result<()> {
    let plaintext = fs::read(input)
        .map_err(|e| LockdownError::Encryption(format!("cannot read {}: {}", input.display(), e)))?;

    let key = Key::<Aes256Gcm>::from_slice(&config.key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|e| LockdownError::Encryption(e.to_string()))?;

    let tmp = tmp_path(output);
    {
        let mut f = fs::File::create(&tmp)
            .map_err(|e| LockdownError::Encryption(format!("cannot create output: {}", e)))?;
        f.write_all(MAGIC)?;
        if config.key_type == KEY_TYPE_PASSWORD {
            f.write_all(&[KEY_TYPE_PASSWORD])?;
            f.write_all(config.salt.as_ref().expect("salt required for password mode"))?;
        } else {
            f.write_all(&[KEY_TYPE_RAW])?;
        }
        f.write_all(&nonce)?;
        f.write_all(&ciphertext)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, output)?;

    if config.delete_original {
        if let Err(e) = secure_delete(input) {
            eprintln!("warning: could not securely delete {}: {}", input.display(), e);
        }
    }
    Ok(())
}

pub fn decrypt_file(config: &CryptoConfig, input: &Path, output: &Path) -> Result<()> {
    let data = fs::read(input)
        .map_err(|e| LockdownError::Decryption(format!("cannot read {}: {}", input.display(), e)))?;

    let header = parse_header(&data)
        .map_err(|e| LockdownError::Decryption(e.to_string()))?;

    let nonce = Nonce::from_slice(&data[header.data_offset..header.data_offset + NONCE_SIZE]);
    let ciphertext = &data[header.data_offset + NONCE_SIZE..];

    let key = Key::<Aes256Gcm>::from_slice(&config.key);
    let cipher = Aes256Gcm::new(key);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| LockdownError::Decryption(
            "decryption failed — wrong key or corrupted file".into(),
        ))?;

    let tmp = tmp_path(output);
    fs::write(&tmp, &plaintext)?;
    fs::rename(&tmp, output)?;

    if config.delete_original {
        if let Err(e) = secure_delete(input) {
            eprintln!("warning: could not securely delete {}: {}", input.display(), e);
        }
    }
    Ok(())
}

// ── Directory operations ──────────────────────────────────────────────────────

pub fn encrypt_directory(config: &CryptoConfig, dir: &Path, mirror: bool) -> Result<Stats> {
    let dir = fs::canonicalize(dir)?;

    let output_root = if mirror {
        let mut name = dir.as_os_str().to_os_string();
        name.push(".enc");
        let p = PathBuf::from(name);
        fs::create_dir_all(&p)?;
        p
    } else {
        dir.clone()
    };

    let files = collect_files_for_encrypt(&dir);
    let pb = progress_bar(files.len() as u64, "cyan");
    let mut stats = Stats::default();

    for src in &files {
        let rel = src.strip_prefix(&dir).unwrap();
        let dst = if mirror {
            let mut name = rel.file_name().unwrap().to_os_string();
            name.push(".enc");
            output_root
                .join(rel.parent().unwrap_or(Path::new("")))
                .join(name)
        } else {
            let mut name = src.file_name().unwrap().to_os_string();
            name.push(".enc");
            src.with_file_name(name)
        };

        pb.set_message(format!("encrypting {}", src.file_name().unwrap().to_string_lossy()));

        if let Some(parent) = dst.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                eprintln!("failed to create dir {}: {}", parent.display(), e);
                stats.failed += 1;
                pb.inc(1);
                continue;
            }
        }

        match encrypt_file(config, src, &dst) {
            Ok(()) => stats.success += 1,
            Err(e) => {
                eprintln!("failed {}: {}", src.display(), e);
                stats.failed += 1;
            }
        }
        pb.inc(1);
    }

    pb.finish_with_message(format!("{}/{} files encrypted", stats.success, files.len()));

    if mirror && config.delete_original && stats.success > 0 {
        if let Err(e) = fs::remove_dir_all(&dir) {
            eprintln!("warning: could not remove original directory: {}", e);
        }
    }
    Ok(stats)
}

pub fn decrypt_directory(config: &CryptoConfig, dir: &Path) -> Result<Stats> {
    let dir = fs::canonicalize(dir)?;

    let dir_str = dir.to_string_lossy();
    let output_root = if dir_str.ends_with(".enc") {
        PathBuf::from(&dir_str[..dir_str.len() - 4])
    } else {
        let mut name = dir.file_name().unwrap().to_os_string();
        name.push("_decrypted");
        dir.parent().unwrap_or(Path::new(".")).join(name)
    };
    fs::create_dir_all(&output_root)?;

    let files = collect_files_for_decrypt(&dir);
    let pb = progress_bar(files.len() as u64, "green");
    let mut stats = Stats::default();

    for enc_file in &files {
        let rel = enc_file.strip_prefix(&dir).unwrap();
        let orig_name = {
            let name = rel.file_name().unwrap().to_string_lossy();
            name[..name.len() - 4].to_string()
        };
        let dst = output_root
            .join(rel.parent().unwrap_or(Path::new("")))
            .join(&orig_name);

        pb.set_message(format!(
            "decrypting {}",
            enc_file.file_name().unwrap().to_string_lossy()
        ));

        if let Some(parent) = dst.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                eprintln!("failed to create dir: {}", e);
                stats.failed += 1;
                pb.inc(1);
                continue;
            }
        }

        match decrypt_file(config, enc_file, &dst) {
            Ok(()) => stats.success += 1,
            Err(e) => {
                eprintln!("failed {}: {}", enc_file.display(), e);
                stats.failed += 1;
            }
        }
        pb.inc(1);
    }

    pb.finish_with_message(format!("{}/{} files decrypted", stats.success, files.len()));

    if config.delete_original && stats.success > 0 {
        if let Err(e) = fs::remove_dir_all(&dir) {
            eprintln!("warning: could not remove encrypted directory: {}", e);
        }
    }
    Ok(stats)
}

// ── Helpers ────────────────────────────────────────────────────────────────────

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

fn collect_files_for_encrypt(dir: &Path) -> Vec<PathBuf> {
    WalkDir::new(dir)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            !(e.file_type().is_dir()
                && (SKIP_DIRS.contains(&name.as_ref()) || name.ends_with(".enc")))
        })
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_type().is_file() && !e.file_name().to_string_lossy().ends_with(".enc")
        })
        .map(|e| e.into_path())
        .collect()
}

fn collect_files_for_decrypt(dir: &Path) -> Vec<PathBuf> {
    WalkDir::new(dir)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            !(e.file_type().is_dir() && SKIP_DIRS.contains(&name.as_ref()))
        })
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_type().is_file() && e.file_name().to_string_lossy().ends_with(".enc")
        })
        .map(|e| e.into_path())
        .collect()
}

fn progress_bar(len: u64, color: &str) -> ProgressBar {
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::with_template(&format!(
            "{{spinner:.{color}}} {{msg}} [{{bar:40.{color}/blue}}] {{pos}}/{{len}}"
        ))
        .unwrap()
        .progress_chars("=> "),
    );
    pb
}
