mod wrapper;
mod cryptography;

use std::fs;
use zeroize::Zeroize;
use crate::cryptography::{encryption, derive, input, cleanup};

use anyhow::Result;

pub fn main() -> Result<()> {
    let key_name = "KEY_NAME"; // Replace with your actual key name

    // Securely get the mnemonic phrase
    let mut mnemonic = input::get_mnemonic()?;

    // Derive encryption key from mnemonic
    let encryption_key = derive::derive_key_from_mnemonic(&mnemonic);

    // Zeroize mnemonic after use
    mnemonic.zeroize();

    // Check if the encrypted key exists
    let encrypted_path = format!("/.commune/key/encrypted/{}.enc", key_name);
    if !std::path::Path::new(&encrypted_path).exists() {
        println!("Encrypting the key for the first time...");

        // Encrypt the key file
        encryption::encrypt_key_file(key_name, &encryption_key)?;

        // Delete the original unencrypted key file
        fs::remove_file(format!("/.commune/key/{}.json", key_name))?;

        println!("Key encrypted and stored safely.");
    }

    // Decrypt the key temporarily
    encryption::decrypt_key_file(key_name, &encryption_key)?;

    // Zeroize encryption key after use
    let mut encryption_key_bytes = encryption_key;
    encryption_key_bytes.zeroize();

    // Ensure the key file is deleted after execution
    let _guard = cleanup::KeyFileGuard {
        key_name: key_name.to_string(),
    };

    // Collect CLI arguments (excluding the program name)
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.is_empty() {
        println!("No CLI command provided.");
        return Ok(());
    }

    // Execute the CLI command
    wrapper::execute_cli_command(key_name, &args)?;

    Ok(())
}
