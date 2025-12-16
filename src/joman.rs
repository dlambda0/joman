use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::encryption::{hyb_decrypt, hyb_encrypt, rsa_gen_keypair};

pub fn initialize() -> Result<(), Box<dyn Error>> {
    if Path::new("Journal").exists() {
        println!("Journal already initialized in this directory.");
        return Err("Journal already initialized".into());
    }

    fs::create_dir_all("Journal")
        .map_err(|e| format!("Failed to create journal directory: {}", e))?;

    let (priv_key, pub_key) =
        rsa_gen_keypair().map_err(|e| format!("Failed to generate RSA keypair: {}", e))?;

    let pub_key_path = format!("Journal/public.pem");
    let priv_key_path = format!("./private.pem");

    fs::write(pub_key_path, &pub_key).map_err(|e| format!("Failed to save public key: {}", e))?;

    fs::write(priv_key_path, &priv_key)
        .map_err(|e| format!("Failed to save private key: {}", e))?;

    Ok(())
}

pub fn add_file(file_path: &str) -> Result<(), Box<dyn Error>> {
    if !Path::new(file_path).exists() {
        return Err(format!("File not found: {}", file_path).into());
    }

    let plaintext =
        fs::read_to_string(file_path).map_err(|e| format!("Failed to read file: {}", e))?;

    let pub_key = fs::read_to_string("Journal/public.pem")
        .map_err(|e| format!("Failed to read file: {}", e))?;

    let ciphertext =
        hyb_encrypt(&plaintext, &pub_key).map_err(|e| format!("failed to encrypt: {}", e))?;

    let encrypted_file = format!(
        "Journal/{}.enc",
        Path::new(file_path).file_name().unwrap().to_str().unwrap()
    );

    fs::write(encrypted_file, &ciphertext)
        .map_err(|e| format!("Failed to write to file: {}", e))?;

    Ok(())
}

pub fn add_directory(dir_path: &str) -> Result<(), Box<dyn Error>> {
    if !Path::new(dir_path).exists() {
        return Err(format!("Directory not found: {}", dir_path).into());
    }

    let entries = fs::read_dir(dir_path).map_err(|e| format!("Failed to read directory: {}", e))?;

    let pub_key = fs::read_to_string("Journal/public.pem")
        .map_err(|e| format!("Failed to read public key: {}", e))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to get directory entry: {}", e))?;

        let path = entry.path();

        if path.is_file() {
            let plaintext =
                fs::read_to_string(&path).map_err(|e| format!("Failed to read file: {}", e))?;

            let ciphertext = hyb_encrypt(&plaintext, &pub_key)
                .map_err(|e| format!("Failed to encrypt file: {}", e))?;

            let dest_path = format!(
                "Journal/{}.enc",
                path.file_name().unwrap().to_str().unwrap()
            );

            fs::write(dest_path, &ciphertext)
                .map_err(|e| format!("Failed to write encrypted file: {}", e))?;
        }
    }

    Ok(())
}

pub fn read_file(file_path: &str, key_path: &str) -> Result<String, Box<dyn Error>> {
    if !Path::new(file_path).exists() {
        return Err(format!("File not found: {}", file_path).into());
    }

    let data = fs::read(file_path).map_err(|e| format!("Failed to read entry file: {}", e))?;

    let priv_key = fs::read_to_string(key_path)
        .map_err(|e| format!("Failed to read private key file: {}", e))?;

    let encrypted_str = std::str::from_utf8(&data)
        .map_err(|e| format!("Failed to convert entry data to string: {}", e))?;

    let plaintext_str = hyb_decrypt(encrypted_str, &priv_key)
        .map_err(|e| format!("Failed to decrypt entry: {}", e))?;

    Ok(plaintext_str)
}

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
