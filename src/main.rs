mod wrapper;
mod cryptography;

use std::env;
use std::io::{self, BufRead};
use cryptography::encryption::get_encryption_key;
use crate::cryptography::{encryption, input, cleanup};
use anyhow::{Result, anyhow};



fn execute_command(key_name: &str, encryption_key: &[u8], args: &[String]) -> Result<()> {
    // println!("Debug: Starting execute_command for key '{}'", key_name);
    // println!("Debug: Command args: {:?}", args);
    
    match encryption::decrypt_key_file(key_name, encryption_key) {
        Ok(_) => println!("Key file decrypted successfully"),
        Err(e) => {
            println!("Failed to decrypt key file: {:?}", e);
            return Err(e.into());
        }
    }
    
    let _guard = cleanup::KeyFileGuard {
        key_name: key_name.to_string(),
    };
    
    // Display the command being executed
    println!("Executing command: comx {}", args.join(" "));
    
    match wrapper::execute_cli_command(key_name, args) {
        Ok(output) => {
            println!("Command executed successfully");
            println!("Output:");
            println!("{:?}", output);
        },
        Err(e) => {
            println!("Failed to execute CLI command: {:?}", e);
            return Err(e);
        }
    }
    
    match encryption::encrypt_key_file(key_name, encryption_key) {
        Ok(_) => println!("Key file encrypted successfully"),
        Err(e) => {
            println!("Failed to encrypt key file: {:?}", e);
            return Err(e.into());
        }
    }
    
    Ok(())
}

fn interactive_mode(key_name: &str, encryption_key: &[u8]) -> Result<()> {
    // println!("Debug: Entered interactive_mode with key: {}", key_name);
    println!("Listening for commands. Type 'comx' followed by your command, or 'exit' to quit.");
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let input = line?;
        let parts: Vec<String> = input.split_whitespace().map(String::from).collect();
        
        // println!("Debug: Received command: {:?}", parts);
        
        if parts.get(0) == Some(&"comx".to_string()) && parts.len() > 1 {
            let args = &parts[1..];
            // println!("Debug: Executing command for key: {} with args: {:?}", key_name, args);
            match execute_command(key_name, encryption_key, args) {
                Ok(_) => println!("Command executed successfully"),
                Err(e) => println!("Error executing command: {:?}", e),
            }
        } else if input.trim().to_lowercase() == "exit" {
            break;
        } else {
            println!("Invalid command. Use 'comx' followed by your command, or type 'exit' to quit.");
        }
    }
    Ok(())
}

pub fn main() -> Result<()> {
    // encryption::test_key_derivation();
    let args: Vec<String> = env::args().collect();
    
    // println!("Debug: Command line args: {:?}", args);

    let key_name = if args.len() < 2 {
        let input_key_name = input::get_key_name()?;
        // println!("Debug: Input key name from user: {}", input_key_name);
        input_key_name
    } else {
        let input_key_name = args[1].clone();
        // println!("Debug: Input key name from args: {}", input_key_name);
        input_key_name
    };
    
    // println!("Debug: Final key_name in main: {}", key_name);

    match args.get(2).map(String::as_str) {
        Some("decrypt") => {
            // println!("Debug: Decrypting key: {}", key_name);
            let encryption_key = get_encryption_key()?;
            encryption::decrypt_key_file(&key_name, &encryption_key)?
        },
        Some("encrypt") => {
            // println!("Debug: Encrypting key: {}", key_name);
            let encryption_key = get_encryption_key()?;
            encryption::encrypt_key_file(&key_name, &encryption_key)?;
        },
        _ => {
            if args.len() < 2 {
                // println!("Debug: Entering interactive mode with key: {}", key_name);
                let encryption_key = get_encryption_key()?;
                interactive_mode(&key_name, &encryption_key)?;
            } else if args.len() < 3 {
                return Err(anyhow!("Usage: {} <key_name> <command> [args...] or <key_name> decrypt|encrypt", args[0]));
            } else {
                // println!("Debug: Executing command for key: {}", key_name);
                let encryption_key = get_encryption_key()?;
                let command_args = &args[2..];
                execute_command(&key_name, &encryption_key, command_args)?;
            }
        }
    }

    Ok(())
}
