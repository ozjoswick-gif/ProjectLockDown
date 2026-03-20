#!/usr/bin/env python3
"""
ProjectLockDown - Modern File Encryption Tool

A secure file/directory encryption utility using AES-256-EAX with Standardize Mode
for marked path management and master password protection.
"""

import os
import sys
import secrets
import hashlib
import shutil
import json
import logging
from pathlib import Path
from typing import Optional, Union, List, Dict, Set
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.logging import RichHandler
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger("projectlockdown")
console = Console()

# Constants
APP_DIR = Path.home() / ".projectlockdown"
MARKS_FILE = APP_DIR / "marks.json"
MASTER_KEY_FILE = APP_DIR / "master.key"


class KeyMethod(Enum):
    """Key input methods."""
    HEX = "hex"
    GENERATE = "generate"
    PASSWORD = "password"


@dataclass
class CryptoConfig:
    """Configuration for cryptographic operations."""
    key_bytes: bytes
    delete_original: bool = False


@dataclass
class MarkedPath:
    """Represents a marked path for standardize mode."""
    path: str
    name: str
    added_at: str
    is_locked: bool = False

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "name": self.name,
            "added_at": self.added_at,
            "is_locked": self.is_locked
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MarkedPath":
        return cls(**data)


class ProjectLockDownError(Exception):
    """Base exception for ProjectLockDown errors."""
    pass


class EncryptionError(ProjectLockDownError):
    """Raised when encryption fails."""
    pass


class DecryptionError(ProjectLockDownError):
    """Raised when decryption fails."""
    pass


class SafetyError(ProjectLockDownError):
    """Raised when safety check fails."""
    pass


class MasterPasswordError(ProjectLockDownError):
    """Raised when master password verification fails."""
    pass


class CryptoUtils:
    """Cryptographic utility functions."""

    NONCE_SIZE = 16
    TAG_SIZE = 16
    VALID_KEY_SIZES = (16, 24, 32)  # AES-128, AES-192, AES-256

    @staticmethod
    def hex_key_to_bytes(hex_key: str) -> bytes:
        """Convert hex string to bytes with validation."""
        try:
            key_bytes = bytes.fromhex(hex_key)
        except ValueError as e:
            raise ValueError(f"Invalid hex string: {e}")

        if len(key_bytes) not in CryptoUtils.VALID_KEY_SIZES:
            raise ValueError(
                f"Invalid AES key length: {len(key_bytes)} bytes. "
                f"Must be one of {CryptoUtils.VALID_KEY_SIZES} bytes "
                f"(AES-128/192/256)."
            )
        return key_bytes

    @staticmethod
    def generate_hex_key(bytes_len: int = 32) -> str:
        """Generate cryptographically secure random hex key."""
        if bytes_len not in CryptoUtils.VALID_KEY_SIZES:
            raise ValueError(f"Key length must be one of {CryptoUtils.VALID_KEY_SIZES}")
        return secrets.token_hex(bytes_len)

    @staticmethod
    def password_to_key(password: str) -> bytes:
        """Derive 32-byte key from password using SHA-256."""
        return hashlib.sha256(password.encode("utf-8")).digest()


class SafetyChecker:
    """Safety checks to prevent self-encryption and package damage."""

    def __init__(self):
        self.script_path = Path(__file__).resolve()
        self.script_parent = self.script_path.parent.parent

    def is_safe_to_encrypt(self, target_path: Path) -> bool:
        """
        Check if target is safe to encrypt.
        Returns True if safe, raises SafetyError otherwise.
        """
        target_abs = target_path.resolve()

        # Check 1: Don't encrypt self
        if target_abs == self.script_path:
            raise SafetyError(f"Cannot encrypt the script itself: {target_path}")

        # Check 2: Don't encrypt ProjectLockDown package
        if "ProjectLockDown" in str(self.script_parent):
            try:
                target_abs.relative_to(self.script_parent)
                raise SafetyError(
                    f"Cannot encrypt ProjectLockDown package files: {target_path}"
                )
            except ValueError:
                pass  # target is not within script_parent, safe

        return True


class FileEncryptor:
    """Handles file encryption/decryption operations."""

    SKIP_DIRS = {'venv', '.git', '__pycache__', 'node_modules', '.venv', '.tox'}

    def __init__(self, config: CryptoConfig):
        self.config = config
        self.safety = SafetyChecker()
        self.stats = {'success': 0, 'failed': 0, 'skipped': 0}

    def encrypt_file(self, file_path: Path, output_path: Optional[Path] = None) -> Path:
        """
        Encrypt a single file using AES-256-EAX.

        Args:
            file_path: Path to file to encrypt
            output_path: Optional output path (defaults to file_path.enc)

        Returns:
            Path to encrypted file
        """
        file_path = Path(file_path)

        # Safety check
        self.safety.is_safe_to_encrypt(file_path)

        if not file_path.exists():
            raise EncryptionError(f"File not found: {file_path}")

        if not file_path.is_file():
            raise EncryptionError(f"Not a file: {file_path}")

        # Determine output path
        if output_path is None:
            output_path = file_path.with_suffix(file_path.suffix + '.enc')
        else:
            output_path = Path(output_path)

        # Perform encryption
        cipher = AES.new(self.config.key_bytes, AES.MODE_EAX)

        try:
            plaintext = file_path.read_bytes()
        except (IOError, OSError) as e:
            raise EncryptionError(f"Cannot read file {file_path}: {e}")

        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        # Write encrypted file (atomic write)
        temp_path = output_path.with_suffix(output_path.suffix + '.tmp')
        try:
            with open(temp_path, 'wb') as f:
                f.write(cipher.nonce)
                f.write(tag)
                f.write(ciphertext)
            temp_path.rename(output_path)
        except (IOError, OSError) as e:
            if temp_path.exists():
                temp_path.unlink()
            raise EncryptionError(f"Cannot write encrypted file: {e}")

        # Delete original if requested
        if self.config.delete_original:
            try:
                file_path.unlink()
            except (IOError, OSError) as e:
                logger.warning(f"Could not delete original {file_path}: {e}")

        return output_path

    def decrypt_file(self, enc_path: Path, output_path: Optional[Path] = None) -> Path:
        """
        Decrypt a .enc file.

        Args:
            enc_path: Path to encrypted file
            output_path: Optional output path (defaults to removing .enc suffix)

        Returns:
            Path to decrypted file
        """
        enc_path = Path(enc_path)

        if not enc_path.exists():
            raise DecryptionError(f"File not found: {enc_path}")

        if not enc_path.suffix == '.enc':
            raise DecryptionError(f"File must have .enc extension: {enc_path}")

        # Determine output path
        if output_path is None:
            output_path = enc_path.with_suffix('')
        else:
            output_path = Path(output_path)

        # Read and decrypt
        try:
            with open(enc_path, 'rb') as f:
                nonce = f.read(CryptoUtils.NONCE_SIZE)
                tag = f.read(CryptoUtils.TAG_SIZE)
                ciphertext = f.read()
        except (IOError, OSError) as e:
            raise DecryptionError(f"Cannot read encrypted file: {e}")

        if len(nonce) != CryptoUtils.NONCE_SIZE or len(tag) != CryptoUtils.TAG_SIZE:
            raise DecryptionError(f"Corrupted encrypted file (invalid header): {enc_path}")

        cipher = AES.new(self.config.key_bytes, AES.MODE_EAX, nonce=nonce)

        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError as e:
            raise DecryptionError(f"Decryption failed (wrong key or corrupted file): {e}")

        # Write decrypted file (atomic write)
        temp_path = output_path.with_suffix(output_path.suffix + '.tmp')
        try:
            temp_path.write_bytes(plaintext)
            temp_path.rename(output_path)
        except (IOError, OSError) as e:
            if temp_path.exists():
                temp_path.unlink()
            raise DecryptionError(f"Cannot write decrypted file: {e}")

        # Delete encrypted if requested
        if self.config.delete_original:
            try:
                enc_path.unlink()
            except (IOError, OSError) as e:
                logger.warning(f"Could not delete encrypted file {enc_path}: {e}")

        return output_path

    def encrypt_directory(self, dir_path: Path, mirror: bool = True) -> int:
        """
        Encrypt all files in directory.

        Args:
            dir_path: Directory to encrypt
            mirror: If True, create .enc mirror; if False, encrypt in-place

        Returns:
            Number of files successfully encrypted
        """
        dir_path = Path(dir_path).resolve()

        if not dir_path.is_dir():
            raise EncryptionError(f"Not a directory: {dir_path}")

        if mirror:
            enc_root = Path(str(dir_path) + ".enc")
            enc_root.mkdir(exist_ok=True)
        else:
            enc_root = dir_path

        files_to_process = []

        # Collect files first
        for root, dirs, files in os.walk(dir_path):
            # Skip dangerous directories
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS and not d.endswith('.enc')]

            for file in files:
                src_file = Path(root) / file
                if mirror:
                    rel_path = src_file.relative_to(dir_path)
                    dst_file = enc_root / rel_path
                    dst_file = dst_file.parent / (dst_file.name + '.enc')
                else:
                    dst_file = src_file.with_suffix(src_file.suffix + '.enc')

                files_to_process.append((src_file, dst_file))

        # Process with progress bar
        success_count = 0
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("[cyan]Encrypting...", total=len(files_to_process))

            for src_file, dst_file in files_to_process:
                progress.update(task, description=f"[cyan]Encrypting {src_file.name}...")

                try:
                    self.safety.is_safe_to_encrypt(src_file)
                    dst_file.parent.mkdir(parents=True, exist_ok=True)
                    self.encrypt_file(src_file, dst_file)
                    success_count += 1
                    logger.info(f"✓ {src_file} → {dst_file}")
                except SafetyError as e:
                    logger.warning(f"⚠ Skipped (safety): {e}")
                    self.stats['skipped'] += 1
                except EncryptionError as e:
                    logger.error(f"✗ Failed: {e}")
                    self.stats['failed'] += 1

                progress.advance(task)

        # Delete original directory if requested and mirroring
        if mirror and self.config.delete_original and success_count > 0:
            try:
                shutil.rmtree(dir_path)
                logger.info(f"🗑️  Deleted original directory: {dir_path}")
            except (IOError, OSError) as e:
                logger.warning(f"Could not delete original directory: {e}")

        return success_count

    def decrypt_directory(self, enc_dir: Path) -> int:
        """
        Decrypt all .enc files in directory, restoring original structure.

        Args:
            enc_dir: Directory containing .enc files

        Returns:
            Number of files successfully decrypted
        """
        enc_dir = Path(enc_dir).resolve()

        if not enc_dir.is_dir():
            raise DecryptionError(f"Not a directory: {enc_dir}")

        # Determine output root (remove .enc suffix if present)
        if str(enc_dir).endswith('.enc'):
            orig_root = Path(str(enc_dir)[:-4])
        else:
            orig_root = enc_dir.parent / (enc_dir.name + "_decrypted")

        orig_root.mkdir(exist_ok=True)

        files_to_process = []

        # Collect .enc files
        for root, dirs, files in os.walk(enc_dir):
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]

            for file in files:
                if file.endswith('.enc'):
                    enc_file = Path(root) / file
                    rel_path = enc_file.relative_to(enc_dir)
                    orig_file = orig_root / rel_path.parent / file[:-4]
                    files_to_process.append((enc_file, orig_file))

        # Process with progress bar
        success_count = 0
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("[green]Decrypting...", total=len(files_to_process))

            for enc_file, orig_file in files_to_process:
                progress.update(task, description=f"[green]Decrypting {enc_file.name}...")

                try:
                    orig_file.parent.mkdir(parents=True, exist_ok=True)
                    self.decrypt_file(enc_file, orig_file)
                    success_count += 1
                    logger.info(f"✓ {enc_file} → {orig_file}")
                except DecryptionError as e:
                    logger.error(f"✗ Failed: {e}")
                    self.stats['failed'] += 1

                progress.advance(task)

        # Delete encrypted directory if requested
        if self.config.delete_original and success_count > 0:
            try:
                shutil.rmtree(enc_dir)
                logger.info(f"🗑️  Deleted encrypted directory: {enc_dir}")
            except (IOError, OSError) as e:
                logger.warning(f"Could not delete encrypted directory: {e}")

        return success_count


class StandardizeManager:
    """Manages marked paths and master password for standardize mode."""

    def __init__(self):
        APP_DIR.mkdir(parents=True, exist_ok=True)
        self.marks: List[MarkedPath] = []
        self.master_hash: Optional[str] = None
        self._load_data()

    def _load_data(self):
        """Load marks and master password hash from disk."""
        if MARKS_FILE.exists():
            try:
                with open(MARKS_FILE, 'r') as f:
                    data = json.load(f)
                    self.marks = [MarkedPath.from_dict(m) for m in data.get('marks', [])]
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Could not load marks: {e}")
                self.marks = []

        if MASTER_KEY_FILE.exists():
            try:
                self.master_hash = MASTER_KEY_FILE.read_text().strip()
            except IOError as e:
                logger.warning(f"Could not load master key: {e}")
                self.master_hash = None

    def _save_data(self):
        """Save marks and master password hash to disk."""
        try:
            with open(MARKS_FILE, 'w') as f:
                json.dump({
                    'marks': [m.to_dict() for m in self.marks]
                }, f, indent=2)
        except IOError as e:
            logger.error(f"Could not save marks: {e}")

        if self.master_hash:
            try:
                MASTER_KEY_FILE.write_text(self.master_hash)
                MASTER_KEY_FILE.chmod(0o600)  # Restrict permissions
            except IOError as e:
                logger.error(f"Could not save master key: {e}")

    def has_master_password(self) -> bool:
        """Check if master password has been set."""
        return self.master_hash is not None

    def set_master_password(self, password: str) -> bool:
        """Set master password (only if not already set)."""
        if self.has_master_password():
            return False
        self.master_hash = hashlib.sha256(password.encode()).hexdigest()
        self._save_data()
        return True

    def verify_master_password(self, password: str) -> bool:
        """Verify master password."""
        if not self.has_master_password():
            return False
        attempt_hash = hashlib.sha256(password.encode()).hexdigest()
        return attempt_hash == self.master_hash

    def change_master_password(self, old_password: str, new_password: str) -> bool:
        """Change master password."""
        if not self.verify_master_password(old_password):
            return False
        self.master_hash = hashlib.sha256(new_password.encode()).hexdigest()
        self._save_data()
        return True

    def add_mark(self, path: Path, name: Optional[str] = None) -> bool:
        """Add a path to marks."""
        path_str = str(path.resolve())

        # Check if already marked
        if any(m.path == path_str for m in self.marks):
            console.print(f"[yellow]⚠[/yellow] Path already marked: {path}")
            return False

        if not path.exists():
            console.print(f"[red]✗[/red] Path does not exist: {path}")
            return False

        mark = MarkedPath(
            path=path_str,
            name=name or path.name,
            added_at=datetime.now().isoformat(),
            is_locked=False
        )
        self.marks.append(mark)
        self._save_data()
        return True

    def remove_mark(self, index: int) -> bool:
        """Remove a mark by index."""
        if 0 <= index < len(self.marks):
            removed = self.marks.pop(index)
            self._save_data()
            console.print(f"[green]✓[/green] Removed mark: {removed.name}")
            return True
        return False

    def remove_mark_by_path(self, path: Path) -> bool:
        """Remove a mark by path."""
        path_str = str(path.resolve())
        for i, mark in enumerate(self.marks):
            if mark.path == path_str:
                return self.remove_mark(i)
        return False

    def list_marks(self) -> List[MarkedPath]:
        """Return all marked paths."""
        return self.marks

    def update_lock_status(self, path_str: str, is_locked: bool):
        """Update lock status of a marked path."""
        for mark in self.marks:
            if mark.path == path_str:
                mark.is_locked = is_locked
                self._save_data()
                break

    def get_mark_status(self, path_str: str) -> Optional[bool]:
        """Get lock status of a marked path. Returns None if not marked."""
        for mark in self.marks:
            if mark.path == path_str:
                return mark.is_locked
        return None


def get_key(method: KeyMethod, prompt_hex: bool = False) -> bytes:
    """
    Get encryption key from user based on method.

    Args:
        method: Key input method
        prompt_hex: Whether to prompt for hex key (for decryption)

    Returns:
        32-byte encryption key
    """
    if method == KeyMethod.GENERATE:
        hex_key = CryptoUtils.generate_hex_key(32)
        console.print(Panel(
            Text(f"Generated AES-256 Key (save this!):\n{hex_key}", style="bold green"),
            title="🔐 Key Generated",
            border_style="green"
        ))
        return CryptoUtils.hex_key_to_bytes(hex_key)

    elif method == KeyMethod.HEX or prompt_hex:
        hex_key = click.prompt("Enter hex key", hide_input=True)
        try:
            return CryptoUtils.hex_key_to_bytes(hex_key)
        except ValueError as e:
            raise click.BadParameter(str(e))

    elif method == KeyMethod.PASSWORD:
        password = click.prompt("Enter password", hide_input=True, confirmation_prompt=True)
        return CryptoUtils.password_to_key(password)

    else:
        raise ValueError(f"Unknown key method: {method}")


def interactive_menu():
    """Show original interactive selection process."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cwd = os.getcwd()

    console.print(f"🔒 [cyan]ProjectLockDown[/cyan] - Working directory: {cwd}")
    console.print()

    # Mode selection (original style)
    selection = None
    while selection not in ("1", "2", "3"):
        console.print("[cyan]Select mode:[/cyan]")
        console.print("  [1] Encryption")
        console.print("  [2] Decryption")
        console.print("  [3] Standardize Mode (Marked Paths)")
        selection = console.input("[bold]> [/bold]").strip()

        if selection not in ("1", "2", "3"):
            console.print("[red]Invalid selection. Please choose 1, 2, or 3.[/red]")

    if selection == "3":
        # Go to standardize mode
        standardize_interactive()
        return

    mode = "Encryption" if selection == "1" else "Decryption"

    # Key handling (original style)
    if mode == "Decryption":
        console.print("\n[cyan]Key input method:[/cyan]")
        console.print("  [1] Hex key")
        console.print("  [2] Password → SHA-256")
        method = None
        while method not in ("1", "2"):
            method = console.input("[bold]> [/bold]").strip()

        if method == "1":
            key_hex = console.input("Enter hex key: ").strip()
        else:
            import getpass
            pwd = getpass.getpass("Enter password: ").strip()
            key_hex = hashlib.sha256(pwd.encode("utf-8")).hexdigest()
            console.print("[dim]Derived key from password.[/dim]")
    else:
        console.print("\n[cyan]Key input method:[/cyan]")
        console.print("  [1] Enter hex key")
        console.print("  [2] Generate random hex key")
        console.print("  [3] Enter password → SHA-256")
        method = None
        while method not in ("1", "2", "3"):
            method = console.input("[bold]> [/bold]").strip()

        if method == "1":
            key_hex = console.input("Enter hex key: ").strip()
        elif method == "2":
            key_hex = CryptoUtils.generate_hex_key(32)
            console.print(Panel(
                f"[bold green]Generated hex key (AES-256):[/bold green]\n{key_hex}",
                border_style="green"
            ))
        else:
            import getpass
            pwd = getpass.getpass("Enter password: ").strip()
            key_hex = hashlib.sha256(pwd.encode("utf-8")).hexdigest()
            console.print("[dim]Derived key from password.[/dim]")

    try:
        key_bytes = CryptoUtils.hex_key_to_bytes(key_hex)
    except ValueError as e:
        console.print(f"[red]Error with key: {e}[/red]")
        return

    # Enhanced file/directory selection (original style)
    console.print("\n[cyan]Process what?[/cyan]")
    console.print("  [1] Single file")
    console.print("  [a] All files in current directory")
    console.print("  [2] Multiple files (not implemented in interactive)")
    console.print("  [3] ENTIRE DIRECTORY TREE")
    choice = console.input("[bold]> [/bold]").strip()

    config = CryptoConfig(key_bytes, delete_original=False)
    encryptor = FileEncryptor(config)
    success = 0

    if choice == "3":
        # DIRECTORY ENCRYPTION/DECRYPTION
        target = console.input("Enter directory path (or . for current dir): ").strip()
        target = os.path.abspath(os.path.join(cwd, target))

        console.print(f"\n[yellow]PROCESSING: {target}[/yellow]")
        confirm = console.input("CONFIRM recursive operation? [y/n]: ").lower()

        if confirm in ('y', 'yes'):
            try:
                if mode == "Encryption":
                    delete_orig = console.input("Delete originals after creating .enc directory? [y/n]: ").lower() in ('y', 'yes')
                    config.delete_original = delete_orig
                    success = encryptor.encrypt_directory(Path(target), mirror=True)
                else:
                    delete_enc = console.input("Delete .enc directory after restoring originals? [y/n]: ").lower() in ('y', 'yes')
                    config.delete_original = delete_enc
                    success = encryptor.decrypt_directory(Path(target))
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
        else:
            console.print("[yellow]Cancelled.[/yellow]")

    elif choice == "1":
        # Single file
        rel = console.input("Enter file path: ").strip()
        path = os.path.abspath(os.path.join(cwd, rel))
        try:
            if mode == "Encryption":
                delete_flag = console.input("Delete original? [y/n]: ").lower() in ('y', 'yes')
                config.delete_original = delete_flag
                result = encryptor.encrypt_file(Path(path))
                success = 1
                console.print(f"[green]✓ Encrypted: {result}[/green]")
            else:
                delete_flag = console.input("Delete .enc? [y/n]: ").lower() in ('y', 'yes')
                config.delete_original = delete_flag
                result = encryptor.decrypt_file(Path(path))
                success = 1
                console.print(f"[green]✓ Decrypted: {result}[/green]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")

    elif choice == "a":
        # All files in current dir
        paths = [os.path.join(cwd, f) for f in os.listdir(cwd)
                 if os.path.isfile(os.path.join(cwd, f))]
        delete_flag = console.input(f"Delete originals after processing {len(paths)} files? [y/n]: ").lower() in ('y', 'yes')
        config.delete_original = delete_flag

        for p in paths:
            try:
                if mode == "Encryption":
                    if encryptor.encrypt_file(Path(p)):
                        success += 1
                        console.print(f"[green]✓ {os.path.basename(p)}[/green]")
                elif p.endswith('.enc'):
                    if encryptor.decrypt_file(Path(p)):
                        success += 1
                        console.print(f"[green]✓ {os.path.basename(p)}[/green]")
            except Exception as e:
                console.print(f"[red]✗ {os.path.basename(p)}: {e}[/red]")

    else:
        console.print("[red]Invalid choice.[/red]")

    console.print(f"\n[bold]Done. Success: {success}[/bold]")


def standardize_interactive():
    """Interactive standardize mode (can be called from CLI or interactive menu)."""
    manager = StandardizeManager()

    # Check/setup master password
    if not manager.has_master_password():
        console.print(Panel(
            "[yellow]No master password set. Please set one now.[/yellow]\n"
            "This password will be required to unlock all marked paths.",
            title="🔐 First Time Setup",
            border_style="yellow"
        ))
        import getpass
        password = getpass.getpass("Set master password: ")
        confirm = getpass.getpass("Confirm master password: ")
        if password != confirm:
            console.print("[red]✗ Passwords do not match![/red]")
            return
        if manager.set_master_password(password):
            console.print("[green]✓[/green] Master password set successfully!")
        else:
            console.print("[red]✗[/red] Failed to set master password")
            return

    while True:
        console.print("\n")
        console.print(Panel(
            "[cyan]1.[/cyan] Toggle Encrypt/Decrypt (process all marked)\n"
            "[cyan]2.[/cyan] Add Mark (mark path for encryption)\n"
            "[cyan]3.[/cyan] Remove Mark\n"
            "[cyan]4.[/cyan] List Marks\n"
            "[cyan]5.[/cyan] Exit",
            title="🔒 Standardize Mode",
            border_style="blue"
        ))

        choice = console.input("[bold]> [/bold]").strip()

        if choice == "1":
            _toggle_encrypt_decrypt_interactive(manager)
        elif choice == "2":
            _add_mark_interactive(manager)
        elif choice == "3":
            _remove_mark_interactive(manager)
        elif choice == "4":
            _list_marks_interactive(manager)
        elif choice == "5":
            console.print("[green]Goodbye![/green]")
            break
        else:
            console.print("[red]Invalid option[/red]")


def _toggle_encrypt_decrypt_interactive(manager: StandardizeManager):
    """Handle toggle encrypt/decrypt for all marked paths (interactive version)."""
    marks = manager.list_marks()

    if not marks:
        console.print("[yellow]No marked paths. Add some first![/yellow]")
        return

    # Check if any are locked
    locked_marks = [m for m in marks if m.is_locked]
    unlocked_marks = [m for m in marks if not m.is_locked]

    if locked_marks and unlocked_marks:
        # Mixed state - ask what to do
        console.print("[yellow]Mixed state detected - some locked, some unlocked[/yellow]")
        console.print("[cyan]Choose action:[/cyan]")
        console.print("  [1] Lock all unlocked")
        console.print("  [2] Unlock all locked")
        console.print("  [3] Cancel")
        action = console.input("[bold]> [/bold]").strip()

        if action == "1":
            _encrypt_marks_interactive(manager, unlocked_marks)
        elif action == "2":
            _decrypt_marks_interactive(manager, locked_marks)
    elif locked_marks:
        # All locked - offer unlock
        _decrypt_marks_interactive(manager, locked_marks)
    else:
        # All unlocked - encrypt
        _encrypt_marks_interactive(manager, unlocked_marks)


def _encrypt_marks_interactive(manager: StandardizeManager, marks: List[MarkedPath]):
    """Encrypt all unlocked marked paths (interactive version)."""
    # Generate a single key for all
    key = CryptoUtils.password_to_key(secrets.token_hex(32))
    config = CryptoConfig(key, delete_original=True)
    encryptor = FileEncryptor(config)

    console.print(f"\n[blue]🔒 Locking {len(marks)} marked paths...[/blue]")

    success_count = 0
    for mark in marks:
        path = Path(mark.path)
        if not path.exists():
            console.print(f"[yellow]⚠[/yellow] Skipped (not found): {mark.name}")
            continue

        try:
            if path.is_file():
                encryptor.encrypt_file(path)
            else:
                encryptor.encrypt_directory(path, mirror=False)
            manager.update_lock_status(mark.path, True)
            success_count += 1
            console.print(f"[green]✓[/green] Locked: {mark.name}")
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to lock {mark.name}: {e}")

    console.print(f"\n[green]✓[/green] Successfully locked {success_count}/{len(marks)} paths")


def _decrypt_marks_interactive(manager: StandardizeManager, marks: List[MarkedPath]):
    """Decrypt all locked marked paths (interactive version)."""
    # Verify master password first
    import getpass
    password = getpass.getpass("Enter master password to unlock: ")

    if not manager.verify_master_password(password):
        console.print("[red]✗[/red] Incorrect master password!")
        return

    key = CryptoUtils.password_to_key(password)
    config = CryptoConfig(key, delete_original=True)
    encryptor = FileEncryptor(config)

    console.print(f"\n[green]🔓 Unlocking {len(marks)} marked paths...[/green]")

    success_count = 0
    already_unlocked = 0

    for mark in marks:
        path = Path(mark.path)
        enc_path = path if str(path).endswith('.enc') else Path(str(path) + '.enc')

        # Check if actually encrypted (might have been manually decrypted)
        if not enc_path.exists():
            if path.exists():
                # File exists but not encrypted - note it
                console.print(f"[blue]ℹ[/blue] Already unlocked (not encrypted): {mark.name}")
                manager.update_lock_status(mark.path, False)
                already_unlocked += 1
                continue
            else:
                console.print(f"[yellow]⚠[/yellow] Skipped (not found): {mark.name}")
                continue

        try:
            if enc_path.is_file():
                encryptor.decrypt_file(enc_path)
            else:
                encryptor.decrypt_directory(enc_path)
            manager.update_lock_status(mark.path, False)
            success_count += 1
            console.print(f"[green]✓[/green] Unlocked: {mark.name}")
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to unlock {mark.name}: {e}")

    console.print(f"\n[green]✓[/green] Successfully unlocked {success_count}/{len(marks)} paths")
    if already_unlocked:
        console.print(f"[blue]ℹ[/blue] {already_unlocked} were already unlocked")


def _add_mark_interactive(manager: StandardizeManager):
    """Add a new marked path (interactive version)."""
    path_str = console.input("Enter path to mark: ").strip()
    path = Path(path_str).expanduser()

    if not path.exists():
        console.print(f"[red]✗[/red] Path does not exist: {path}")
        return

    name = console.input(f"Enter name for this mark [{path.name}]: ").strip()
    if not name:
        name = path.name

    if manager.add_mark(path, name):
        console.print(f"[green]✓[/green] Added mark: {name} → {path}")
    else:
        console.print(f"[yellow]⚠[/yellow] Could not add mark (may already exist)")


def _remove_mark_interactive(manager: StandardizeManager):
    """Remove a marked path (interactive version)."""
    marks = manager.list_marks()

    if not marks:
        console.print("[yellow]No marks to remove[/yellow]")
        return

    _list_marks_interactive(manager)

    idx_str = console.input("Enter number of mark to remove (or -1 to cancel): ").strip()
    try:
        idx = int(idx_str)
    except ValueError:
        console.print("[red]Invalid number[/red]")
        return

    if idx >= 0:
        if manager.remove_mark(idx):
            pass  # Message printed in method
        else:
            console.print("[red]✗[/red] Invalid selection")


def _list_marks_interactive(manager: StandardizeManager):
    """List all marked paths (interactive version)."""
    marks = manager.list_marks()

    if not marks:
        console.print("[yellow]No marked paths[/yellow]")
        return

    table = Table(title="🔒 Marked Paths")
    table.add_column("#", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Path", style="white")
    table.add_column("Added", style="blue")
    table.add_column("Status", style="yellow")

    for i, mark in enumerate(marks):
        status = "🔒 Locked" if mark.is_locked else "🔓 Unlocked"
        added = mark.added_at[:10] if mark.added_at else "Unknown"
        table.add_row(str(i), mark.name, mark.path, added, status)

    console.print(table)
    console.print(f"\nTotal: {len(marks)} marked paths")


# Click CLI commands (modern way, available as alternatives)
@click.group(invoke_without_command=True)
@click.version_option(version="2.1.0", prog_name="lockdown")
@click.option('--verbose', '-v', is_flag=True, help="Enable verbose output")
@click.pass_context
def cli(ctx, verbose: bool):
    """
    🔒 ProjectLockDown - Secure File Encryption Tool

    Run without commands to start interactive mode.
    Or use subcommands: encrypt, decrypt, standardize, generate-key
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # If no subcommand invoked, run interactive menu
    if ctx.invoked_subcommand is None:
        interactive_menu()


@cli.command()
@click.argument('path', type=click.Path(exists=True, path_type=Path))
@click.option('--key-method', '-k',
              type=click.Choice(['hex', 'generate', 'password'], case_sensitive=False),
              default='generate', help="Key input method")
@click.option('--delete-original', '-d', is_flag=True,
              help="Delete original files after encryption")
@click.option('--mirror/--in-place', default=True,
              help="Create .enc mirror (default) or encrypt in-place")
def encrypt(path: Path, key_method: str, delete_original: bool, mirror: bool):
    """
    Encrypt files or directories (CLI mode).

    PATH can be a file or directory. By default, creates a .enc mirror directory.
    """
    key = get_key(KeyMethod(key_method), prompt_hex=False)
    config = CryptoConfig(key, delete_original)
    encryptor = FileEncryptor(config)

    try:
        if path.is_file():
            result = encryptor.encrypt_file(path)
            console.print(f"[green]✓[/green] Encrypted: {result}")
        else:
            count = encryptor.encrypt_directory(path, mirror=mirror)
            console.print(f"[green]✓[/green] Encrypted {count} files successfully")

            if encryptor.stats['failed'] > 0:
                console.print(f"[red]✗[/red] Failed: {encryptor.stats['failed']}")
            if encryptor.stats['skipped'] > 0:
                console.print(f"[yellow]⚠[/yellow] Skipped: {encryptor.stats['skipped']}")

    except ProjectLockDownError as e:
        raise click.ClickException(str(e))


@cli.command()
@click.argument('path', type=click.Path(exists=True, path_type=Path))
@click.option('--key-method', '-k',
              type=click.Choice(['hex', 'password'], case_sensitive=False),
              default='hex', help="Key input method")
@click.option('--delete-encrypted', '-d', is_flag=True,
              help="Delete encrypted files after decryption")
def decrypt(path: Path, key_method: str, delete_encrypted: bool):
    """
    Decrypt .enc files or directories (CLI mode).

    PATH can be a .enc file or a directory containing .enc files.
    """
    key = get_key(KeyMethod(key_method), prompt_hex=True)
    config = CryptoConfig(key, delete_encrypted)
    encryptor = FileEncryptor(config)

    try:
        if path.is_file():
            if not path.suffix == '.enc':
                raise click.BadParameter("File must have .enc extension")
            result = encryptor.decrypt_file(path)
            console.print(f"[green]✓[/green] Decrypted: {result}")
        else:
            count = encryptor.decrypt_directory(path)
            console.print(f"[green]✓[/green] Decrypted {count} files successfully")

            if encryptor.stats['failed'] > 0:
                console.print(f"[red]✗[/red] Failed: {encryptor.stats['failed']}")

    except ProjectLockDownError as e:
        raise click.ClickException(str(e))


@cli.command()
@click.option('--length', '-l', default=32,
              type=click.Choice([16, 24, 32], case_sensitive=False),
              help="Key length in bytes (AES-128/192/256)")
def generate_key(length: int):
    """Generate a random encryption key."""
    hex_key = CryptoUtils.generate_hex_key(length)
    console.print(Panel(
        Text(f"{hex_key}", style="bold cyan"),
        title=f"🔐 AES-{length*8} Key",
        subtitle="Save this securely - it cannot be recovered!",
        border_style="cyan"
    ))


@cli.command(name="standardize")
def standardize_cmd():
    """
    Standardize Mode - Manage marked paths with master password protection (CLI mode).
    """
    standardize_interactive()


if __name__ == "__main__":
    cli()
