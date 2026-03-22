# ProjectLockDown

A CLI tool for encrypting and decrypting files and directories using AES-256-GCM.

## Features

- AES-256-GCM authenticated encryption (confidentiality + integrity in one pass)
- Three key input methods: auto-generated key, hex key, or password (PBKDF2-HMAC-SHA256, 100k iterations)
- Encrypt single files or entire directory trees
- Mirror mode (encrypted copy alongside originals) or in-place encryption
- Secure deletion: overwrites files with random bytes before removing
- **Standardize mode**: mark paths and lock/unlock them all at once with a master password
- Auto-detects key type on decrypt — no need to specify `--key-method` when decrypting
- Salt is embedded in each encrypted file, making every file independently decryptable

## Project structure

```
ProjectLockDown/
├── src/
│   ├── main.rs           # CLI entry point (clap)
│   ├── crypto.rs         # AES-256-GCM encrypt/decrypt, PBKDF2, secure delete
│   ├── standardize.rs    # Marked paths and master password management
│   └── error.rs          # Custom error types
├── tests/
├── Cargo.toml
└── README.md
```

## Build

```bash
cargo build --release
```

The binary is at `target/release/lockdown`.

## Install

```bash
cargo install --path .
```

## Usage

### Encrypt

```bash
lockdown encrypt <path> [OPTIONS]
```

| Option | Description |
|---|---|
| `-k`, `--key-method` | `generate` (default), `hex`, or `password` |
| `-d`, `--delete-original` | Securely delete originals after encryption |
| `--in-place` | Encrypt files in-place (directories only; default is mirror) |

### Decrypt

```bash
lockdown decrypt <path> [OPTIONS]
```

The key type is auto-detected from the file header — no `--key-method` needed.

| Option | Description |
|---|---|
| `-d`, `--delete-encrypted` | Delete encrypted files after successful decryption |

### Generate Key

```bash
lockdown generate-key [--bits 128|192|256]
```

Generates a cryptographically secure random AES key. Default: 256 bits.

### Standardize Mode

```bash
lockdown standardize <subcommand>
```

| Subcommand | Description |
|---|---|
| `add <path> [--name <name>]` | Add a path to the marked list |
| `remove <index>` | Remove a marked path by index |
| `list` | List all marked paths and their lock status |
| `lock` | Encrypt all unlocked marked paths with the master password |
| `unlock` | Decrypt all locked marked paths with the master password |

State is stored in `~/.projectlockdown/`. The master password is prompted on first use.

## Encrypted file format

```
Raw key:      "LKD1" [0x00] [12-byte nonce] [ciphertext + 16-byte GCM tag]
Password key: "LKD1" [0x01] [32-byte salt]  [12-byte nonce] [ciphertext + 16-byte GCM tag]
```

The salt is embedded in password-encrypted files so each file is independently decryptable with just the password, even without access to `~/.projectlockdown/`.
