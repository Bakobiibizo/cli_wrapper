use std::fs;

pub fn cleanup_decrypted_key(key_name: &str) -> std::io::Result<()> {
    let key_path = format!("/.commune/key/{}.json", key_name);
    if fs::metadata(&key_path).is_ok() {
        fs::remove_file(&key_path)?;
    }
    Ok(())
}

pub struct KeyFileGuard {
    pub key_name: String,
}

impl Drop for KeyFileGuard {
    fn drop(&mut self) {
        let _ = cleanup_decrypted_key(&self.key_name);
    }
}