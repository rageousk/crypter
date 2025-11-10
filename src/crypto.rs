// --- Cryptography Imports ---
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use aes_gcm::aead::rand_core::RngCore;
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use std::process;

/// Derives a 32-byte AES key from a password and salt using Argon2.
fn derive_key(password: &str, salt: &SaltString) -> [u8; 32] {
    let argon2 = Argon2::default();
    
    // Hash the password to generate a secure key
    let password_hash = argon2
        .hash_password(password.as_bytes(), salt)
        .expect("Error: Failed to hash password."); // Panics on failure
    
    let hash_output = password_hash
        .hash
        .expect("Error: Argon2 hash output is missing."); // Should not happen
    
    let mut key = [0u8; 32];
    key.copy_from_slice(hash_output.as_bytes());
    key
}

/// Encrypts the given data using a password.
pub fn encrypt_data(data: &[u8], password: &str) -> Vec<u8> {
    // 1. Generate a unique, random salt for this encryption
    let salt = SaltString::generate(&mut OsRng);
    
    // 2. Derive the 32-byte encryption key from the password and salt
    let key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new(&key.into());

    // 3. Generate a 12-byte random nonce (number used once)
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    // 4. Encrypt the data
    let encrypted = match cipher.encrypt(&nonce, data) {
        Ok(ciphertext) => ciphertext,
        Err(_) => {
            eprintln!("Error: Encryption failed.");
            process::exit(1);
        }
    };

    // 5. Pack output: [salt_len (1 byte)] + [salt (variable)] + [nonce (12 bytes)] + [ciphertext]
    let salt_bytes = salt.as_str().as_bytes();
    let mut output = Vec::new();
    output.push(salt_bytes.len() as u8);
    output.extend_from_slice(salt_bytes);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&encrypted);
    output
}

/// Decrypts the given data using a password.
/// Returns a Result containing the plaintext or a static error message.
pub fn decrypt_data(data: &[u8], password: &str) -> Result<Vec<u8>, &'static str> {
    // 1. Parse Salt
    if data.is_empty() { return Err("File too short."); }
    let salt_len = data[0] as usize;
    if data.len() < 1 + salt_len + 12 { return Err("File too short."); }
    
    let salt_bytes = &data[1..1 + salt_len];
    let salt_str = std::str::from_utf8(salt_bytes).map_err(|_| "Invalid salt.")?;
    let salt = SaltString::from_b64(salt_str).map_err(|_| "Invalid salt.")?;

    // 2. Parse Nonce
    let nonce_start = 1 + salt_len;
    let nonce_slice = &data[nonce_start..nonce_start + 12];
    let nonce_bytes: [u8; 12] = nonce_slice.try_into().map_err(|_| "Invalid nonce.")?;
    let nonce = Nonce::from(nonce_bytes);

    // 3. Parse Ciphertext
    let ciphertext = &data[nonce_start + 12..];

    // 4. Derive Key & Decrypt
    let key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new(&key.into());

    // This will fail if the key is wrong or data is corrupt (auth tag check)
    cipher.decrypt(&nonce, ciphertext).map_err(|_| "Decryption failed.")
}