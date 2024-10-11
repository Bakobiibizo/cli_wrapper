use ring::pbkdf2;
use std::num::NonZeroU32;

// /// Derive a key from a mnemonic phrase.
// pub fn derive_key_from_mnemonic(mnemonic: &str) -> [u8; 32] {
//     let mut hasher = Sha256::new();
//     hasher.update(mnemonic.as_bytes());
//     let result = hasher.finalize();
//     let mut key = [0u8; 32];
//     key.copy_from_slice(&result);
//     key
// }

pub fn derive_key_from_password(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(100_000).unwrap(),
        salt,
        password.as_bytes(),
        &mut key,
    );
    key
}

pub fn generate_salt() -> [u8; 16] {
    use rand::RngCore;
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}
