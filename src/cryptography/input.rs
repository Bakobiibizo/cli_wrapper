use rpassword::read_password;
use std::io::stdin;


pub fn get_key_name() -> anyhow::Result<String> {
    println!("Please enter your key name:");
    let mut key_name = String::new();
    stdin().read_line(&mut key_name)?;
    Ok(key_name.trim().to_string())
}

pub fn get_password() -> anyhow::Result<String> {
    // if let Ok(password) = std::env::var("COMX_PASSWORD") {
    //     if !password.is_empty() {
    //         return Ok(password);
    //     }
    // }
    println!("Please enter your password (input will be hidden):");
    let password = read_password()?;
    Ok(password)
}

pub fn get_mnemonic() -> anyhow::Result<String> {
    println!("Please enter your mnemonic (input will be hidden):");
    let mnemonic = read_password()?;
    Ok(mnemonic.trim().to_string())
}
