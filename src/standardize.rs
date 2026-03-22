use std::fs;
use std::path::{Path, PathBuf};

use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::crypto::{derive_key, generate_salt, SALT_SIZE};
use crate::error::{LockdownError, Result};

fn app_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".projectlockdown")
}

fn marks_file() -> PathBuf {
    app_dir().join("marks.json")
}

fn master_key_file() -> PathBuf {
    app_dir().join("master.key")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarkedPath {
    pub path: String,
    pub name: String,
    pub added_at: String,
    pub is_locked: bool,
}

#[derive(Serialize, Deserialize)]
struct MarksFile {
    marks: Vec<MarkedPath>,
}

pub struct StandardizeManager {
    pub marks: Vec<MarkedPath>,
    master_hash: Option<String>,
    kdf_salt: Option<[u8; SALT_SIZE]>,
    master_salt: Option<[u8; SALT_SIZE]>,
}

impl StandardizeManager {
    pub fn load() -> Self {
        let _ = fs::create_dir_all(app_dir());
        let marks = Self::load_marks();
        let (master_hash, kdf_salt, master_salt) = Self::load_master_key();
        Self { marks, master_hash, kdf_salt, master_salt }
    }

    fn load_marks() -> Vec<MarkedPath> {
        let path = marks_file();
        if !path.exists() {
            return Vec::new();
        }
        fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<MarksFile>(&s).ok())
            .map(|f| f.marks)
            .unwrap_or_default()
    }

    fn load_master_key() -> (Option<String>, Option<[u8; SALT_SIZE]>, Option<[u8; SALT_SIZE]>) {
        let path = master_key_file();
        if !path.exists() {
            return (None, None, None);
        }
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(_) => return (None, None, None),
        };
        let parts: Vec<&str> = text.trim().split(':').collect();
        if parts.len() != 3 {
            eprintln!("warning: master key file in legacy format — please reset your master password");
            return (None, None, None);
        }
        let kdf_salt = hex::decode(parts[1])
            .ok()
            .and_then(|b| b.try_into().ok());
        let master_salt = hex::decode(parts[2])
            .ok()
            .and_then(|b| b.try_into().ok());
        (Some(parts[0].to_string()), kdf_salt, master_salt)
    }

    fn save(&self) {
        let file = MarksFile { marks: self.marks.clone() };
        if let Ok(text) = serde_json::to_string_pretty(&file) {
            let _ = fs::write(marks_file(), text);
        }

        if let (Some(hash), Some(kdf), Some(master)) =
            (&self.master_hash, &self.kdf_salt, &self.master_salt)
        {
            let content = format!("{}:{}:{}", hash, hex::encode(kdf), hex::encode(master));
            let path = master_key_file();
            if let Err(e) = fs::write(&path, &content) {
                eprintln!("error: could not save master key: {}", e);
            } else {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
                }
            }
        }
    }

    pub fn has_master_password(&self) -> bool {
        self.master_hash.is_some()
    }

    /// Set master password for the first time. Returns false if already set.
    pub fn set_master_password(&mut self, password: &str) -> bool {
        if self.has_master_password() {
            return false;
        }
        let kdf_salt = generate_salt();
        let master_salt = generate_salt();
        let mut hash_bytes = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), &master_salt, 100_000, &mut hash_bytes);
        self.kdf_salt = Some(kdf_salt);
        self.master_salt = Some(master_salt);
        self.master_hash = Some(hex::encode(hash_bytes));
        self.save();
        true
    }

    pub fn verify_master_password(&self, password: &str) -> bool {
        let (Some(hash), Some(master_salt)) = (&self.master_hash, &self.master_salt) else {
            return false;
        };
        let mut attempt = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), master_salt, 100_000, &mut attempt);
        hex::encode(attempt) == *hash
    }

    /// Return the KDF salt used to derive the encryption key from the master password.
    pub fn kdf_salt(&self) -> Option<&[u8; SALT_SIZE]> {
        self.kdf_salt.as_ref()
    }

    /// Derive the encryption key from the master password using the stored KDF salt.
    pub fn derive_encryption_key(&self, password: &str) -> Result<[u8; 32]> {
        let salt = self.kdf_salt.as_ref().ok_or_else(|| {
            LockdownError::MasterPassword("no KDF salt found — reset your master password".into())
        })?;
        Ok(derive_key(password, salt))
    }

    pub fn add_mark(&mut self, path: &Path, name: Option<&str>) -> Result<()> {
        let canonical = fs::canonicalize(path)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| path.to_string_lossy().to_string());

        if self.marks.iter().any(|m| m.path == canonical) {
            return Err(LockdownError::Other(format!("already marked: {}", canonical)));
        }
        if !path.exists() {
            return Err(LockdownError::Other(format!(
                "path does not exist: {}",
                path.display()
            )));
        }
        let display_name = name
            .unwrap_or_else(|| path.file_name().unwrap_or_default().to_str().unwrap_or("unknown"))
            .to_string();

        self.marks.push(MarkedPath {
            path: canonical,
            name: display_name,
            added_at: chrono::Local::now().to_rfc3339(),
            is_locked: false,
        });
        self.save();
        Ok(())
    }

    pub fn remove_mark(&mut self, index: usize) -> Result<MarkedPath> {
        if index >= self.marks.len() {
            return Err(LockdownError::Other(format!(
                "index {} out of range (have {} marks)",
                index,
                self.marks.len()
            )));
        }
        let removed = self.marks.remove(index);
        self.save();
        Ok(removed)
    }

    pub fn update_lock_status(&mut self, path_str: &str, is_locked: bool) {
        if let Some(mark) = self.marks.iter_mut().find(|m| m.path == path_str) {
            mark.is_locked = is_locked;
            self.save();
        }
    }
}
