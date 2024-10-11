mod wrapper;
mod cryptography;

use std::fs;
use std::io::{self, BufRead};
use zeroize::Zeroize;
use crate::cryptography::{encryption, derive, input, cleanup};

use anyhow::Result;

fn execute_command(key_name: &str, encryption_key: &[u8], args: &[String]) -> Result<()> {
    // Decrypt the key temporarily
    encryption::decrypt_key_file(key_name, encryption_key)?;

    // Ensure the key file is deleted after execution
    let _guard = cleanup::KeyFileGuard {
        key_name: key_name.to_string(),
    };

    // Execute the CLI command
    wrapper::execute_cli_command(key_name, args)?;

    // Re-encrypt the key file
    encryption::encrypt_key_file(key_name, encryption_key)?;

    Ok(())
}

pub fn main() -> Result<()> {
    // Securely get the mnemonic phrase
    let key_name = input::get_key_name()?;
    let mut mnemonic = input::get_mnemonic()?;

    // Derive encryption key from mnemonic
    let mut encryption_key = derive::derive_key_from_mnemonic(&mnemonic);

    // Zeroize mnemonic after use
    mnemonic.zeroize();

    // Check if the encrypted key exists
    let encrypted_path = format!("/home/administrator/.commune/key/encrypted/{}.enc", key_name);
    if !std::path::Path::new(&encrypted_path).exists() {
        println!("Encrypting the key for the first time...");
 
        // Create the initial key file if it doesn't exist
        let key_path = format!("/home/administrator/.commune/key/{}.json", key_name);
        if !std::path::Path::new(&key_path).exists() {
            // Here you would typically generate or obtain the initial key data
            let initial_key_data = "{}".to_string(); // Replace with actual initial key data
            std::fs::write(&key_path, initial_key_data)?;
        }
 
        // Encrypt the key file
        encryption::encrypt_key_file(&key_name, &encryption_key)
            .map_err(|e| anyhow::anyhow!("Encryption error: {}", e))?;
        println!("Encrypted key file path: {}", encrypted_path);
 
        // Delete the original unencrypted key file
        let old_key_path = format!("/home/administrator/.commune/key/{}.json", key_name);
        if std::path::Path::new(&old_key_path).exists() {   
            fs::remove_file(&old_key_path)?;
        }
 
        println!("Key encrypted and stored safely.");
    }

    println!("Listening for commands. Type 'comx' followed by your command, or 'exit' to quit.");
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let input = line?;
        let parts: Vec<String> = input.split_whitespace().map(String::from).collect();
        
        if parts.get(0) == Some(&"comx".to_string()) && parts.len() > 1 {
            let args = &parts[1..];
            execute_command(&key_name, &encryption_key, args)?;
        } else if input.trim().to_lowercase() == "exit" {
            break;
        } else {
            println!("Invalid command. Use 'comx' followed by your command, or type 'exit' to quit.");
        }
    }

    // Zeroize encryption key after use
    encryption_key.zeroize();

    Ok(())
}