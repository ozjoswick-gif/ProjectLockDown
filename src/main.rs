mod crypto;
mod error;
mod standardize;

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use walkdir::WalkDir;

use crypto::{
    CryptoConfig, FileHeader, KEY_TYPE_PASSWORD, KEY_TYPE_RAW, SALT_SIZE,
};
use error::{LockdownError, Result};
use standardize::StandardizeManager;

// ── CLI definitions ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "lockdown",
    version = "2.1.0",
    about = "Secure file/directory encryption tool using AES-256-GCM"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file or directory
    Encrypt {
        /// File or directory to encrypt
        path: PathBuf,

        /// Key input method
        #[arg(short = 'k', long, value_enum, default_value_t = KeyMethod::Generate)]
        key_method: KeyMethod,

        /// Securely delete originals after encryption
        #[arg(short = 'd', long)]
        delete_original: bool,

        /// Encrypt files in-place instead of creating a .enc mirror (directories only)
        #[arg(long)]
        in_place: bool,
    },

    /// Decrypt a .enc file or directory
    Decrypt {
        /// Encrypted file or directory to decrypt
        path: PathBuf,

        /// Delete encrypted files after successful decryption
        #[arg(short = 'd', long)]
        delete_encrypted: bool,
    },

    /// Generate a random AES key and print it
    GenerateKey {
        /// Key size in bits: 128, 192, or 256
        #[arg(short, long, default_value_t = 256,
              value_parser = clap::builder::PossibleValuesParser::new(["128", "192", "256"])
                  .map(|s| s.parse::<u32>().unwrap()))]
        bits: u32,
    },

    /// Manage marked paths protected by a master password
    Standardize {
        #[command(subcommand)]
        command: StandardizeCommands,
    },
}

#[derive(Subcommand)]
enum StandardizeCommands {
    /// Add a path to the marked list
    Add {
        path: PathBuf,
        #[arg(short, long)]
        name: Option<String>,
    },
    /// Remove a marked path by its list index
    Remove { index: usize },
    /// List all marked paths
    List,
    /// Encrypt (lock) all unlocked marked paths using the master password
    Lock,
    /// Decrypt (unlock) all locked marked paths using the master password
    Unlock,
}

#[derive(ValueEnum, Clone)]
enum KeyMethod {
    /// Generate a new random key and display it
    Generate,
    /// Provide an existing hex-encoded key
    Hex,
    /// Derive a key from a password (PBKDF2-HMAC-SHA256)
    Password,
}

// ── Entry point ────────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("{} {}", "error:".red().bold(), e);
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Encrypt { path, key_method, delete_original, in_place } => {
            cmd_encrypt(path, key_method, delete_original, in_place)
        }
        Commands::Decrypt { path, delete_encrypted } => cmd_decrypt(path, delete_encrypted),
        Commands::GenerateKey { bits } => cmd_generate_key(bits),
        Commands::Standardize { command } => match command {
            StandardizeCommands::Add { path, name } => cmd_std_add(path, name.as_deref()),
            StandardizeCommands::Remove { index } => cmd_std_remove(index),
            StandardizeCommands::List => cmd_std_list(),
            StandardizeCommands::Lock => cmd_std_lock(),
            StandardizeCommands::Unlock => cmd_std_unlock(),
        },
    }
}

// ── encrypt ────────────────────────────────────────────────────────────────────

fn cmd_encrypt(path: PathBuf, method: KeyMethod, delete_original: bool, in_place: bool) -> Result<()> {
    let config = build_encrypt_config(method, delete_original)?;

    if path.is_file() {
        let mut output_name = path.file_name().unwrap().to_os_string();
        output_name.push(".enc");
        let output = path.with_file_name(output_name);
        crypto::encrypt_file(&config, &path, &output)?;
        println!("{} {}", "✓".green(), output.display());
    } else if path.is_dir() {
        let stats = crypto::encrypt_directory(&config, &path, !in_place)?;
        println!("{} {} files encrypted", "✓".green(), stats.success);
        if stats.failed > 0 {
            println!("{} {} files failed", "✗".red(), stats.failed);
        }
    } else {
        return Err(LockdownError::Other(format!("{} is not a file or directory", path.display())));
    }
    Ok(())
}

// ── decrypt ────────────────────────────────────────────────────────────────────

fn cmd_decrypt(path: PathBuf, delete_encrypted: bool) -> Result<()> {
    // Auto-detect key type from file header so the user doesn't need --key-method.
    let sample = if path.is_file() {
        path.clone()
    } else {
        find_first_enc_file(&path)?
    };

    let header = crypto::read_header(&sample)?;
    let config = build_decrypt_config_from_header(header, delete_encrypted)?;

    if path.is_file() {
        if !path.to_string_lossy().ends_with(".enc") {
            return Err(LockdownError::Other("file must have .enc extension".into()));
        }
        let output = {
            let s = path.to_string_lossy();
            PathBuf::from(&s[..s.len() - 4])
        };
        crypto::decrypt_file(&config, &path, &output)?;
        println!("{} {}", "✓".green(), output.display());
    } else if path.is_dir() {
        let stats = crypto::decrypt_directory(&config, &path)?;
        println!("{} {} files decrypted", "✓".green(), stats.success);
        if stats.failed > 0 {
            println!("{} {} files failed", "✗".red(), stats.failed);
        }
    } else {
        return Err(LockdownError::Other(format!("{} is not a file or directory", path.display())));
    }
    Ok(())
}

// ── generate-key ────────────────────────────────────────────────────────────────

fn cmd_generate_key(bits: u32) -> Result<()> {
    let bytes = bits as usize / 8;
    let key = crypto::generate_random_key(bytes);
    println!("{}", format!("AES-{bits} key (save this securely):").bold());
    println!("{}", hex::encode(&key).cyan());
    Ok(())
}

// ── standardize subcommands ────────────────────────────────────────────────────

fn cmd_std_add(path: PathBuf, name: Option<&str>) -> Result<()> {
    let mut manager = StandardizeManager::load();
    manager.add_mark(&path, name)?;
    println!("{} added: {} → {}", "✓".green(), name.unwrap_or_default(), path.display());
    Ok(())
}

fn cmd_std_remove(index: usize) -> Result<()> {
    let mut manager = StandardizeManager::load();
    let removed = manager.remove_mark(index)?;
    println!("{} removed: {}", "✓".green(), removed.name);
    Ok(())
}

fn cmd_std_list() -> Result<()> {
    let manager = StandardizeManager::load();
    if manager.marks.is_empty() {
        println!("no marked paths");
        return Ok(());
    }
    println!("{:<4} {:<20} {:<10} {}", "#", "Name", "Status", "Path");
    println!("{}", "-".repeat(80));
    for (i, mark) in manager.marks.iter().enumerate() {
        let status = if mark.is_locked {
            "locked".red().to_string()
        } else {
            "unlocked".green().to_string()
        };
        let date = &mark.added_at[..10.min(mark.added_at.len())];
        println!("{:<4} {:<20} {:<10} {}  (added {})", i, mark.name, status, mark.path, date);
    }
    Ok(())
}

fn cmd_std_lock() -> Result<()> {
    let mut manager = StandardizeManager::load();
    ensure_master_password(&mut manager)?;

    let password = prompt_password("Master password: ")?;
    if !manager.verify_master_password(&password) {
        return Err(LockdownError::MasterPassword("incorrect master password".into()));
    }

    let key = manager.derive_encryption_key(&password)?;
    let kdf_salt = *manager.kdf_salt().unwrap();

    let targets: Vec<_> = manager.marks.iter()
        .filter(|m| !m.is_locked)
        .cloned()
        .collect();

    if targets.is_empty() {
        println!("no unlocked paths to lock");
        return Ok(());
    }

    println!("locking {} path(s)...", targets.len());

    let config = CryptoConfig {
        key,
        delete_original: true,
        key_type: KEY_TYPE_PASSWORD,
        salt: Some(kdf_salt),
    };

    for mark in &targets {
        let path = std::path::Path::new(&mark.path);
        let result = if path.is_file() {
            let mut out_name = path.file_name().unwrap().to_os_string();
            out_name.push(".enc");
            let out = path.with_file_name(out_name);
            crypto::encrypt_file(&config, path, &out).map(|_| ())
        } else if path.is_dir() {
            crypto::encrypt_directory(&config, path, false).map(|_| ())
        } else {
            Err(LockdownError::Other(format!("not found: {}", mark.path)))
        };

        match result {
            Ok(()) => {
                manager.update_lock_status(&mark.path, true);
                println!("  {} {}", "✓".green(), mark.name);
            }
            Err(e) => eprintln!("  {} {}: {}", "✗".red(), mark.name, e),
        }
    }
    Ok(())
}

fn cmd_std_unlock() -> Result<()> {
    let mut manager = StandardizeManager::load();
    ensure_master_password(&mut manager)?;

    let password = prompt_password("Master password: ")?;
    if !manager.verify_master_password(&password) {
        return Err(LockdownError::MasterPassword("incorrect master password".into()));
    }

    let key = manager.derive_encryption_key(&password)?;
    let kdf_salt = *manager.kdf_salt().unwrap();

    let targets: Vec<_> = manager.marks.iter()
        .filter(|m| m.is_locked)
        .cloned()
        .collect();

    if targets.is_empty() {
        println!("no locked paths to unlock");
        return Ok(());
    }

    println!("unlocking {} path(s)...", targets.len());

    let config = CryptoConfig {
        key,
        delete_original: true,
        key_type: KEY_TYPE_PASSWORD,
        salt: Some(kdf_salt),
    };

    for mark in &targets {
        let path = std::path::Path::new(&mark.path);
        let enc_path = if mark.path.ends_with(".enc") {
            PathBuf::from(&mark.path)
        } else {
            let mut s = mark.path.clone();
            s.push_str(".enc");
            PathBuf::from(s)
        };

        let result = if enc_path.is_file() {
            let out = {
                let s = enc_path.to_string_lossy();
                PathBuf::from(&s[..s.len() - 4])
            };
            crypto::decrypt_file(&config, &enc_path, &out).map(|_| ())
        } else if enc_path.is_dir() {
            crypto::decrypt_directory(&config, &enc_path).map(|_| ())
        } else if path.exists() {
            // Already unlocked (e.g. manually decrypted).
            println!("  {} {} (already unlocked)", "i".blue(), mark.name);
            manager.update_lock_status(&mark.path, false);
            continue;
        } else {
            Err(LockdownError::Other(format!("not found: {}", mark.path)))
        };

        match result {
            Ok(()) => {
                manager.update_lock_status(&mark.path, false);
                println!("  {} {}", "✓".green(), mark.name);
            }
            Err(e) => eprintln!("  {} {}: {}", "✗".red(), mark.name, e),
        }
    }
    Ok(())
}

// ── Key / config helpers ────────────────────────────────────────────────────────

fn build_encrypt_config(method: KeyMethod, delete_original: bool) -> Result<CryptoConfig> {
    match method {
        KeyMethod::Generate => {
            let key_bytes = crypto::generate_random_key(32);
            println!("{}", "Generated AES-256 key (save this!):".bold());
            println!("{}", hex::encode(&key_bytes).cyan());
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);
            Ok(CryptoConfig { key, delete_original, key_type: KEY_TYPE_RAW, salt: None })
        }
        KeyMethod::Hex => {
            let hex_str = prompt_password("Hex key: ")?;
            let key_bytes = hex::decode(hex_str.trim())?;
            if key_bytes.len() != 32 {
                return Err(LockdownError::Other(
                    "hex key must be 32 bytes (64 hex chars) for AES-256".into(),
                ));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);
            Ok(CryptoConfig { key, delete_original, key_type: KEY_TYPE_RAW, salt: None })
        }
        KeyMethod::Password => {
            let password = prompt_password("Password: ")?;
            let confirm = prompt_password("Confirm password: ")?;
            if password != confirm {
                return Err(LockdownError::Other("passwords do not match".into()));
            }
            let salt = crypto::generate_salt();
            let key = crypto::derive_key(&password, &salt);
            Ok(CryptoConfig {
                key,
                delete_original,
                key_type: KEY_TYPE_PASSWORD,
                salt: Some(salt),
            })
        }
    }
}

/// Build a decrypt config by reading the key type from an already-parsed header.
fn build_decrypt_config_from_header(header: FileHeader, delete_encrypted: bool) -> Result<CryptoConfig> {
    match header.key_type {
        KEY_TYPE_RAW => {
            let hex_str = prompt_password("Hex key: ")?;
            let key_bytes = hex::decode(hex_str.trim())?;
            if key_bytes.len() != 32 {
                return Err(LockdownError::Other(
                    "hex key must be 32 bytes (64 hex chars)".into(),
                ));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);
            Ok(CryptoConfig { key, delete_original: delete_encrypted, key_type: KEY_TYPE_RAW, salt: None })
        }
        KEY_TYPE_PASSWORD => {
            let salt = header.salt.expect("password file must have salt in header");
            let password = prompt_password("Password: ")?;
            let key = crypto::derive_key(&password, &salt);
            Ok(CryptoConfig {
                key,
                delete_original: delete_encrypted,
                key_type: KEY_TYPE_PASSWORD,
                salt: Some(salt),
            })
        }
        _ => Err(LockdownError::Decryption("unknown key type in file header".into())),
    }
}

// ── Utilities ────────────────────────────────────────────────────────────────────

fn prompt_password(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt)
        .map_err(|e| LockdownError::Other(e.to_string()))
}

fn find_first_enc_file(dir: &Path) -> Result<PathBuf> {
    WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .find(|e| {
            e.file_type().is_file() && e.file_name().to_string_lossy().ends_with(".enc")
        })
        .map(|e| e.into_path())
        .ok_or_else(|| LockdownError::Other(format!("no .enc files found in {}", dir.display())))
}

/// If no master password is set, interactively set one now.
fn ensure_master_password(manager: &mut StandardizeManager) -> Result<()> {
    if manager.has_master_password() {
        return Ok(());
    }
    println!("{}", "No master password set. Please create one now.".yellow().bold());
    let password = prompt_password("New master password: ")?;
    let confirm = prompt_password("Confirm master password: ")?;
    if password != confirm {
        return Err(LockdownError::MasterPassword("passwords do not match".into()));
    }
    manager.set_master_password(&password);
    println!("{} Master password set.", "✓".green());
    Ok(())
}
