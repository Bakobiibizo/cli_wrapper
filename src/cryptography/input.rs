use rpassword::read_password;
use std::io::stdin;

/// Get the mnemonic phrase from the user.
pub fn get_mnemonic() -> anyhow::Result<String> {
    println!("Please enter your mnemonic phrase (input will be hidden):");
    let mnemonic = read_password()?;
    Ok(mnemonic)
}

pub fn get_key_name() -> anyhow::Result<String> {
    println!("Please enter your key name:");
    let mut key_name = String::new();
    stdin().read_line(&mut key_name)?;
    Ok(key_name.trim().to_string())
}