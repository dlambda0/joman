use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::joman::encryption::hyb_encrypt;

pub fn new_file(title: Option<&str>) -> Result<(), Box<dyn Error>> {
    if !Path::new("Journal").exists() {
        return Err("Journal not initialized. Please run 'joman init' first.".into());
    }

    let tmp_dir = std::env::temp_dir();
    let tmp_path = tmp_dir.join(format!("joman_{}.tmp", std::process::id()));

    fs::write(&tmp_path, "").map_err(|e| format!("Failed to create temporary file: {}", e))?;

    // Sorry losers, I use vim
    let editor = Command::new("vim")
        .arg(&tmp_path)
        .status()
        .map_err(|e| format!("Failed to open editor: {}", e))?;

    if !editor.success() {
        let _ = fs::remove_file(&tmp_path);
        return Err("Editor exited with an error.".into());
    }

    let plaintext = fs::read_to_string(&tmp_path)
        .map_err(|e| format!("Failed to read temporary file: {}", e))?;

    if plaintext.trim().is_empty() {
        let _ = fs::remove_file(&tmp_path);
        return Err("Journal entry is empty. Aborting.".into());
    }

    let filename = if let Some(t) = title {
        format!("{}.enc", t)
    } else {
        generate_next_entry_name()?
    };

    let pub_key = fs::read_to_string("Journal/public.pem")
        .map_err(|e| format!("Failed to read public key: {}", e))?;

    let ciphertext = hyb_encrypt(&plaintext, &pub_key)
        .map_err(|e| format!("Failed to encrypt journal entry: {}", e))?;

    let dest_path = format!("Journal/{}", filename);

    fs::write(&dest_path, &ciphertext)
        .map_err(|e| format!("Failed to write journal entry: {}", e))?;

    let _ = fs::remove_file(&tmp_path);
    Ok(())
}

fn generate_next_entry_name() -> Result<String, Box<dyn Error>> {
    let mut max_index = 0;

    let entries =
        fs::read_dir("Journal").map_err(|e| format!("Failed to read journal directory: {}", e))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to get directory entry: {}", e))?;
        let path = entry.path();

        if path.is_file() {
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if file_name.ends_with(".enc") {
                    if let Some(index_str) = file_name
                        .strip_prefix("entry_")
                        .and_then(|s| s.strip_suffix(".enc"))
                    {
                        if let Ok(index) = index_str.parse::<u32>() {
                            if index > max_index {
                                max_index = index;
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(format!("entry_{}.enc", max_index + 1))
}
