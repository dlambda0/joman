use aes_gcm::{
    AeadCore, Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use base64::{Engine as _, engine::general_purpose};
use rsa::{
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
};
use std::error::Error;

const RSA_KEY_SIZE: usize = 2048;
const RSA_BLOCK_SIZE: usize = 256;
const NONCE_SIZE: usize = 12;

fn decode_b64(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    general_purpose::STANDARD
        .decode(input)
        .map_err(|e| format!("Base64 decoding failed: {}", e).into())
}

fn encode_b64(input: &[u8]) -> String {
    general_purpose::STANDARD.encode(input)
}

pub fn rsa_gen_keypair() -> Result<(String, String), Box<dyn Error>> {
    let mut rng = OsRng;

    let bits = RSA_KEY_SIZE;

    let private_key = RsaPrivateKey::new(&mut rng, bits)
        .map_err(|e| format!("Failed to generate RSA private key: {}", e))?;

    let public_key = RsaPublicKey::from(&private_key);

    let private_pem = private_key
        .to_pkcs8_pem(Default::default())
        .map_err(|e| format!("Failed to encode private key to PEM: {}", e))?;

    let public_pem = public_key
        .to_public_key_pem(Default::default())
        .map_err(|e| format!("Failed to encode public key to PEM: {}", e))?;

    Ok((private_pem.to_string(), public_pem.to_string()))
}

pub fn hyb_encrypt(plaintext: &str, pub_key: &str) -> Result<String, Box<dyn Error>> {
    let aes_key = Aes256Gcm::generate_key(&mut OsRng);
    let cipher = Aes256Gcm::new(&aes_key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let aes_ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes().as_ref())
        .map_err(|e| format!("AES encryption failed: {}", e))?;

    let public_key = RsaPublicKey::from_public_key_pem(pub_key)
        .map_err(|e| format!("Invalid RSA public key: {}", e))?;

    let enc_aes_key = public_key
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, aes_key.as_slice())
        .map_err(|e| format!("RSA encryption failed: {}", e))?;

    let mut combined_ciphertext = Vec::new();
    combined_ciphertext.extend_from_slice(&enc_aes_key);
    combined_ciphertext.extend_from_slice(&nonce);
    combined_ciphertext.extend_from_slice(&aes_ciphertext);

    Ok(encode_b64(&combined_ciphertext))
}

pub fn hyb_decrypt(ciphertext_b64: &str, priv_key: &str) -> Result<String, Box<dyn Error>> {
    let ciphertext = decode_b64(ciphertext_b64)?;

    if ciphertext.len() < RSA_BLOCK_SIZE + NONCE_SIZE {
        return Err("Invalid ciphertext length".into());
    }

    let (enc_aes_key, ciphertext) = ciphertext.split_at(RSA_BLOCK_SIZE);
    let (nonce_bytes, aes_ciphertext) = ciphertext.split_at(NONCE_SIZE);

    let private_key = RsaPrivateKey::from_pkcs8_pem(priv_key)
        .map_err(|e| format!("Invalid RSA private key: {}", e))?;
    let aes_key_bytes = private_key
        .decrypt(Pkcs1v15Encrypt, enc_aes_key)
        .map_err(|e| format!("RSA decryption failed: {}", e))?;

    let key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext_bytes = cipher
        .decrypt(nonce, aes_ciphertext)
        .map_err(|e| format!("AES decryption failed: {}", e))?;

    Ok(String::from_utf8(plaintext_bytes)?)
}
