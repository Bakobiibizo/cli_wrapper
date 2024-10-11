use std::process::Command;

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
