use rpassword::read_password;

/// Get the mnemonic phrase from the user.
pub fn get_mnemonic() -> anyhow::Result<String> {
    println!("Please enter your mnemonic phrase (input will be hidden):");
    let mnemonic = read_password()?;
    Ok(mnemonic)
}
