use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::Rng;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use dirs::home_dir;

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
    home_dir()
        .map(|mut path| {
            path.push(".commune");
            path.push("key");
            path
        })
        .ok_or_else(|| EncryptionError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Home directory not found"
        )))
}

pub fn encrypt_key_file(key_name: &str, key_bytes: &[u8]) -> Result<(), EncryptionError> {
    let mut key_path = get_key_directory()?;
    key_path.push(format!("{}.json", key_name));
    
    // Ensure the directory exists
    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent).map_err(EncryptionError::IoError)?;
    }
    
    // Check if the file exists before trying to read it
    if !key_path.exists() {
        return Err(EncryptionError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Key file not found: {}", key_path.display()),
        )));
    }

    let data = fs::read(&key_path)?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let key = GenericArray::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    let ciphertext = cipher.encrypt(nonce, data.as_ref())?;

    let mut encrypted_data = nonce_bytes.to_vec();
    encrypted_data.extend(ciphertext);

    let mut encrypted_path = get_key_directory()?;
    encrypted_path.push("encrypted");
    encrypted_path.push(format!("{}.enc", key_name));
    
    // Ensure the encrypted directory exists
    if let Some(parent) = encrypted_path.parent() {
        fs::create_dir_all(parent).map_err(EncryptionError::IoError)?;
    }

    fs::write(encrypted_path, encrypted_data)?;

    Ok(())
}

pub fn decrypt_key_file(key_name: &str, key_bytes: &[u8]) -> Result<(), EncryptionError> {
    let mut encrypted_path = get_key_directory()?;
    encrypted_path.push("encrypted");
    encrypted_path.push(format!("{}.enc", key_name));
    
    // Check if the encrypted file exists
    if !encrypted_path.exists() {
        return Err(EncryptionError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Encrypted key file not found: {}", encrypted_path.display()),
        )));
    }

    let encrypted_data = fs::read(&encrypted_path)?;

    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let key = GenericArray::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    let plaintext = cipher.decrypt(nonce, ciphertext)?;

    let mut key_path = get_key_directory()?;
    key_path.push(format!("{}.json", key_name));
    
    // Ensure the directory exists
    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent).map_err(EncryptionError::IoError)?;
    }

    fs::write(&key_path, &plaintext)?;

    Ok(())
}
