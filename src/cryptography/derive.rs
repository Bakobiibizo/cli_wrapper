use sha2::{Digest, Sha256};

/// Derive a key from a mnemonic phrase.
pub fn derive_key_from_mnemonic(mnemonic: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(mnemonic.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}
