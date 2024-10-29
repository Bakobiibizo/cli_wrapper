use std::process::{Command, Stdio};

pub fn execute_cli_command(_key_name: &str, args: &[String]) -> anyhow::Result<()> {
    let output = Command::new("comx")
        .args(args)
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Command failed with status: {}",
            output.status
        );
        eprintln!(
            "Error output: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err(anyhow::anyhow!("CLI command failed"));
    }

    println!("{}", String::from_utf8_lossy(&output.stdout));

    Ok(())
}

pub fn regen_key_command(key_name: &str, mnemonic: &str) -> anyhow::Result<()> {
    let mut child = Command::new("comx")
        .arg("key")
        .arg("regen")
        .arg(key_name)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    {
        // Write the mnemonic to the command's stdin
        use std::io::Write;
        if let Some(stdin) = &mut child.stdin {
            stdin.write_all(mnemonic.as_bytes())?;
        }
    }

    let output = child.wait_with_output()?;

    if !output.status.success() {
        eprintln!(
            "Key regeneration failed with status: {}",
            output.status
        );
        eprintln!(
            "Error output: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err(anyhow::anyhow!("Failed to regenerate key"));
    }

    println!("{}", String::from_utf8_lossy(&output.stdout));

    Ok(())
}
