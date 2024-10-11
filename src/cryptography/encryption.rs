use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::Rng;
use zeroize::Zeroize;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use dirs::home_dir;
use anyhow::anyhow;
use crate::cryptography::input;
use crate::cryptography::derive;


const SALT_FILE: &str = ".commune_salt";
const PASSWORD_ENV: &str = "COMX_PASSWORD";

#[derive(Debug)]
pub enum EncryptionError {
    IoError(std::io::Error),
    AesError(String), // Changed to store a String description
    RandError(rand::Error),
}

impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptionError::IoError(e) => write!(f, "IO error: {}", e),
            EncryptionError::AesError(e) => write!(f, "AES error: {}", e),
            EncryptionError::RandError(e) => write!(f, "Random number generator error: {}", e),
        }
    }
}

impl Error for EncryptionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            EncryptionError::IoError(e) => Some(e),
            EncryptionError::AesError(_) => None, // AesError no longer has a source
            EncryptionError::RandError(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for EncryptionError {
    fn from(error: std::io::Error) -> Self {
        EncryptionError::IoError(error)
    }
}

impl From<aes_gcm::Error> for EncryptionError {
    fn from(error: aes_gcm::Error) -> Self {
        EncryptionError::AesError(error.to_string())
    }
}

impl From<rand::Error> for EncryptionError {
    fn from(error: rand::Error) -> Self {
        EncryptionError::RandError(error)
    }
}

fn get_key_directory() -> Result<PathBuf, EncryptionError> {
    let home = home_dir().ok_or_else(|| EncryptionError::IoError(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "Home directory not found",
    )))?;
    let path = home.join(".commune").join("key");
    println!("Key directory: {:?}", path.display());

    // Create the directory if it doesn't exist
    if !path.exists() {
        fs::create_dir_all(&path).map_err(EncryptionError::IoError)?;
    }

    Ok(path)
}

fn get_key_path(key_name: &str) -> Result<PathBuf, EncryptionError> {
    // println!("Debug: Getting key path for: {}", key_name);
    let mut path = get_key_directory()?;
    path.push(format!("{}.json", key_name));
    // println!("Debug: Key path: {:?}", path);
    Ok(path)
}

fn get_encrypted_key_path(key_name: &str) -> Result<PathBuf, EncryptionError> {
    // println!("Debug: Getting encrypted key path for: {}", key_name);
    let mut path = get_key_directory()?;
    path.push("encrypted");
    path.push(format!("{}.enc", key_name));
    // println!("Debug: Encrypted key path: {:?}", path);
    Ok(path)
}

fn get_or_create_salt() -> Result<[u8; 16], anyhow::Error> {
    let directory_path = get_key_directory()?;
    let salt_path = directory_path.join("encrypted").join(SALT_FILE);

    // Ensure the 'encrypted' directory exists
    if let Some(parent) = salt_path.parent() {
        fs::create_dir_all(parent)?;
    }

    if salt_path.exists() {
        // If the salt file exists, read it
        let salt = fs::read(&salt_path)?;
        Ok(salt.try_into().map_err(|_| anyhow!("Invalid salt length"))?)
    } else {
        // If the salt file doesn't exist, generate it
        let salt = derive::generate_salt();
        fs::write(&salt_path, &salt)?;
        Ok(salt)
    }
}

pub fn get_encryption_key() -> anyhow::Result<[u8; 32]> {
    let salt = get_or_create_salt()?;
    // println!("Debug: Salt for key derivation: {:?}", salt);
    let mut password = input::get_password()?;
    // println!("Debug: Password length: {}", password.len());
    let encryption_key = derive::derive_key_from_password(&password, &salt);
    // println!("Debug: Derived encryption key: {:?}", encryption_key);
    password.zeroize();
    Ok(encryption_key)
}

pub fn encrypt_key_file(key_name: &str, key_bytes: &[u8]) -> Result<(), EncryptionError> {
    // println!("Debug: Encrypting key file for: {}", key_name);
    let key_path = get_key_path(key_name)?;
    // println!("Debug: Key path: {:?}", key_path);
    let encrypted_path = get_encrypted_key_path(key_name)?;
    // println!("Debug: Encrypted key path: {:?}", encrypted_path);
    // Check if the key file exists
    if !key_path.exists() {
        // println!("Debug: Original key file not found: {:?}", key_path);
        let encrypted_key_path = get_encrypted_key_path(key_name)?;
        // println!("Debug: Encrypted key path: {:?}", encrypted_key_path.display());

        if encrypted_key_path.exists() {
            let data = fs::read(&encrypted_key_path)?;
            // println!("Debug: Read {} bytes from encrypted key file", data.len());
            return Ok(());
        }

        return Err(EncryptionError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Encrypted key file not found: {}", encrypted_key_path.display())
        )));
    }

    // println!("Debug: Original key file found: {:?}", key_path);

    let data = fs::read(&key_path)?;
    // println!("Debug: Read {} bytes from original key file", data.len());

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    // println!("Debug: Generated nonce: {:?}", nonce_bytes);

    let key = GenericArray::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    let ciphertext = match cipher.encrypt(nonce, data.as_ref()) {
        Ok(ct) => ct,
        Err(e) => {
            // println!("Debug: Encryption failed: {:?}", e);
            return Err(EncryptionError::AesError(e.to_string()));
        }
    };
    // println!("Debug: Ciphertext length: {}", ciphertext.len());

    let mut encrypted_data = nonce_bytes.to_vec();
    encrypted_data.extend(ciphertext);

    // println!("Debug: Encrypted key path: {:?}", encrypted_path.display());
    
    // Ensure the encrypted directory exists
    if let Some(parent) = encrypted_path.parent() {
        // println!("Debug: Creating encrypted directory: {:?}", parent);
        fs::create_dir_all(parent)?;
    }

    match fs::write(&encrypted_path, &encrypted_data) {
        Ok(_) => println!("Encrypted key file written: {:?}", encrypted_path),
        Err(e) => {
            println!("Failed to write encrypted key file: {:?}", e);
            return Err(EncryptionError::IoError(e));
        }
    }

    match fs::remove_file(&key_path) {
        Ok(_) => println!("Original key file removed: {:?}", key_path),
        Err(e) => {
            println!("Failed to remove original key file: {:?}", e);
            return Err(EncryptionError::IoError(e));
        }
    }

    Ok(())
}

pub fn decrypt_key_file(key_name: &str, key_bytes: &[u8]) -> Result<(), EncryptionError> {
    // println!("Debug: Decrypting key file for: {}", key_name);
    let encrypted_path = get_encrypted_key_path(key_name)?;
    // println!("Debug: Encrypted key path: {:?}", encrypted_path);
    let key_path = get_key_path(key_name)?;
    // println!("Debug: Decrypted key path: {:?}", key_path);
    if key_path.exists() {
        let plaintext = fs::read(&key_path)?;
        fs::write(&encrypted_path, &plaintext)?;
        return Ok(());
    }
    
    
    // println!("Debug: Encrypting to path: {:?}", encrypted_path);
    if !encrypted_path.exists() {
        return Err(EncryptionError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Encrypted key file not found: {}", encrypted_path.display()),
        )));
    }
    let encrypted_data = fs::read(&encrypted_path)?;
    // println!("Debug: Read {} bytes from encrypted file", encrypted_data.len());

    if encrypted_data.len() < 12 {
        return Err(EncryptionError::AesError("Encrypted data too short".to_string()));
    }

    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    // println!("Debug: Nonce: {:?}", nonce_bytes);
    // println!("Debug: Ciphertext length: {}", ciphertext.len());
    let nonce = Nonce::from_slice(nonce_bytes);

    let key = GenericArray::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    let plaintext = match cipher.decrypt(nonce, ciphertext) {
        Ok(pt) => pt,
        Err(e) => {
            // println!("Debug: Decryption failed: {:?}", e);
            return Err(EncryptionError::AesError(e.to_string()));
        }
    };
    // println!("Debug: Decrypted plaintext length: {}", plaintext.len());

    let key_path = get_key_path(key_name)?;
    // println!("Debug: Decrypted key path: {:?}", key_path);

    fs::write(&key_path, &plaintext)?;
    // println!("Debug: Decrypted key written to {:?}", key_path);

    Ok(())
}

// pub fn test_key_derivation() {
    // let password = "test_password";
    // let salt = [0u8; 16]; // Example salt
    // let encryption_key = derive::derive_key_from_password(password, &salt);
    // println!("Test Derived Key: {:?}", encryption_key);
// }