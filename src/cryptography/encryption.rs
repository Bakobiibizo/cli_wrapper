use std::fmt;
use std::error::Error;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use aes_gcm::aead::generic_array::GenericArray;
use rand::Rng;

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

pub type NonceWrapper<NonceSize> = GenericArray<u8, NonceSize>;

pub fn decrypt_key_file(key_name: &str, key_bytes: &[u8]) -> Result<(), EncryptionError> {
    let encrypted_path = format!("/.commune/key/encrypted/{}.enc", key_name);
    let encrypted_data = std::fs::read(&encrypted_path)?;

    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Explicitly specify the key type
    let key = GenericArray::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    let plaintext = cipher.decrypt(nonce, ciphertext)?;

    let key_path = format!("/.commune/key/{}.json", key_name);
    std::fs::write(&key_path, &plaintext)?;

    Ok(())
}

pub fn encrypt_key_file(key_name: &str, key_bytes: &[u8]) -> Result<(), EncryptionError> {
    let key_path = format!("/.commune/key/{}.json", key_name);
    let data = std::fs::read(&key_path)?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Explicitly specify the key type
    let key = GenericArray::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    let ciphertext = cipher.encrypt(nonce, data.as_ref())?;

    let mut encrypted_data = nonce_bytes.to_vec();
    encrypted_data.extend(ciphertext);

    let encrypted_path = format!("/.commune/key/encrypted/{}.enc", key_name);
    std::fs::write(encrypted_path, encrypted_data)?;

    Ok(())
}
