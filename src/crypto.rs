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

// Helper Function: Derives a 32-byte AES key from a password and a salt
fn derive_key(password: &str, salt: &SaltString) -> [u8; 32] {
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), salt)
        .expect("Error: Failed to hash password.");
    let hash_output = password_hash
        .hash
        .expect("Error: Argon2 hash output is missing.");
    let mut key = [0u8; 32];
    key.copy_from_slice(hash_output.as_bytes());
    key
}

// Public function to handle encryption logic
pub fn encrypt_data(data: &[u8], password: &str) -> Vec<u8> {
    // 1. Generate Salt
    let salt = SaltString::generate(&mut OsRng);
    // 2. Derive Key
    let key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new(&key.into());
    // 3. Generate Nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes); // FIX 1: Use .from() directly on the array

    // 4. Encrypt
    let encrypted = match cipher.encrypt(&nonce, data) {
        Ok(ciphertext) => ciphertext,
        Err(_) => {
            eprintln!("Error: Encryption failed.");
            process::exit(1);
        }
    };

    // 5. Pack Output: [Salt Len (1 byte)] + [Salt] + [Nonce (12 bytes)] + [Ciphertext]
    let salt_bytes = salt.as_str().as_bytes();
    let mut output = Vec::new();
    output.push(salt_bytes.len() as u8);
    output.extend_from_slice(salt_bytes);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&encrypted);
    output
}

// Public function to handle decryption logic
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
    // FIX 2: Convert slice to fixed-size array first
    let nonce_bytes: [u8; 12] = nonce_slice.try_into().map_err(|_| "Invalid nonce.")?;
    let nonce = Nonce::from(nonce_bytes);

    // 3. Parse Ciphertext
    let ciphertext = &data[nonce_start + 12..];

    // 4. Derive Key & Decrypt
    let key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new(&key.into());

    cipher.decrypt(&nonce, ciphertext).map_err(|_| "Decryption failed.")
}