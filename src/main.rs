// ## crypter: A Simple File Encryption/Decryption Tool ##
// @author: Sahil Kamboj
// Project for Programming Languages (Rust) - Prof. Benjamin Weidner
//
// --- Work Log ---
//
// Started: October 20, 2025
//  - Initial project setup using 'cargo new'.
//  - Added 'clap' dependency for command-line argument parsing.
//  - Implemented basic CLI structure ('Cli' struct) and argument parsing.
//  - Added file reading logic using 'std::fs::read' with basic error handling.
//  - Set up Git repository and made initial commit.
//
// Modified: October 23, 2025
//  - Added 'aes-gcm' and 'rand' dependencies for encryption.
//  - Implemented core encryption logic (generating nonce, calling 'encrypt').
//  - Implemented core decryption logic (splitting nonce/ciphertext, calling 'decrypt').
//  - Added file writing logic using 'std::fs::write'.
//  - Debugged build issues on Windows (Installed C++ Build Tools, switched to MSVC toolchain).
//  - Debugged 'RngCore' trait import error (E0599).
//  - Debugged 'Nonce' type conversion issues (E0107, E0277) using '.into()' and '.try_into()'.
//  - Refactored code to use an 'enum Mode' for better type safety and alignment with lectures.
//  - Refactored crypto operations to use 'match' for error handling instead of '.expect()'.
//  - Added detailed inline comments explaining the code logic and crate usage.
//
// --- End Work Log ---

// --- Crates (External Libraries) ---
use clap::{Parser, ValueEnum}; // For parsing command-line arguments
use std::fs; // For file system operations (read/write)
use std::process; // For exiting the program on error

// --- Cryptography Crates & Traits ---
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng}, // Core crypto traits and OS random number generator
    Aes256Gcm, // Specific algorithm: AES-256-GCM
};
use aes_gcm::aead::rand_core::RngCore; // Trait needed for OsRng.fill_bytes()

// --- NEW IMPORTS for Password Security ---
use argon2::{ 
    password_hash::{PasswordHasher, SaltString}, // Traits for password hashing
    Argon2,
};
use rpassword; // For securely reading passwords from terminal

// Enum for operating modes (encrypt/decrypt) - used by clap
#[derive(ValueEnum, Clone, Debug)]
enum Mode {
    Encrypt,
    Decrypt,
}

// Struct to define and parse command-line arguments using clap
#[derive(Parser)]
#[command(version, about = "A simple CLI tool to encrypt and decrypt files.", long_about = None)]
struct Cli {
    /// The mode of operation (encrypt or decrypt)
    #[clap(value_enum)]
    mode: Mode,

    /// The path to the input file
    input_file: String,

    /// The path to the output file
    output_file: String,
}

// --- Helper Function for Key Derivation ---
// Derives a 32-byte AES key from a password and a salt using Argon2.
fn derive_key_from_password(password: &str, salt: &SaltString) -> [u8; 32] {
    // Argon2 with default parameters is very secure.
    let argon2 = Argon2::default();
    
    // Hash the password with the salt.
    let password_hash = argon2
        .hash_password(password.as_bytes(), salt)
        .expect("Error: Failed to hash password for key derivation.");

    // Extract the raw hash output.
    let hash_output = password_hash
        .hash
        .expect("Error: Argon2 hash output is missing.");

    // Ensure the hash output is exactly 32 bytes (Argon2 default is 32 bytes).
    let mut key = [0u8; 32];
    // Copy the hash output into our 32-byte key array.
    // We use .as_bytes() to get the byte slice of the Output.
    let hash_bytes = hash_output.as_bytes();
    if hash_bytes.len() != 32 {
         eprintln!("Error: Derived key is not 32 bytes long.");
         process::exit(1);
    }
    key.copy_from_slice(hash_bytes);

    key
}

// --- Main Program Logic ---
fn main() {
    // Parse command-line arguments based on the Cli struct
    let cli = Cli::parse();

    // Read the input file into a vector of bytes (Vec<u8>)
    let contents = match fs::read(&cli.input_file) {
        Ok(data) => data, // Success: data is Vec<u8>
        Err(e) => { // Failure: print error and exit
            eprintln!("Error reading input file '{}': {}", cli.input_file, e);
            process::exit(1);
        }
    };
    println!("Successfully read {} bytes from {}.", contents.len(), &cli.input_file);

    // --- Main Control Flow ---
    // Use 'match' on the Mode enum to decide whether to encrypt or decrypt
    let output_data: Vec<u8> = match cli.mode {
        // --- Encryption Path ---
    Mode::Encrypt => {
            println!("Encrypting data...");

            // 1. Securely Prompt for Password (with re-try loop)
            let password = loop {
                let p1 = rpassword::prompt_password("Enter a strong password: ")
                    .unwrap_or_else(|e| {
                        eprintln!("Error reading password: {}", e);
                        process::exit(1);
                    });
                let p2 = rpassword::prompt_password("Confirm password: ")
                    .unwrap_or_else(|e| {
                        eprintln!("Error reading confirmation password: {}", e);
                        process::exit(1);
                    });

                if p1 == p2 && !p1.is_empty() {
                     // Passwords match and are not empty, break loop and return password
                     break p1;
                } else if p1.is_empty() {
                     println!("Password cannot be empty. Please try again.\n");
                } else {
                     println!("Passwords do not match. Please try again.\n");
                }
            };

            // 2. Generate a random Salt
            let salt = SaltString::generate(&mut OsRng);

            // 3. Derive the 32-byte AES key
            println!("Deriving key from password...");
            let key_bytes = derive_key_from_password(&password, &salt);
            let cipher = Aes256Gcm::new((&key_bytes).into());

            // 4. Generate a Nonce
            let mut nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = nonce_bytes.into();

            // 5. Encrypt the data
            let encrypted_data = match cipher.encrypt(&nonce, contents.as_ref()) {
                Ok(data) => data,
                Err(_) => {
                    eprintln!("Error: Encryption failed!");
                    process::exit(1);
                }
            };

            // 6. Pack everything into the output file
            let salt_str = salt.as_str();
            let salt_bytes = salt_str.as_bytes();
            let salt_len = salt_bytes.len() as u8;

            let mut data_to_write = Vec::new();
            data_to_write.push(salt_len);
            data_to_write.extend_from_slice(salt_bytes);
            data_to_write.extend_from_slice(&nonce_bytes);
            data_to_write.extend_from_slice(&encrypted_data);

            data_to_write
        }

        // --- Decryption Path ---
       Mode::Decrypt => {
            println!("Decrypting data...");

            // 1. Parse the Salt
            if contents.len() < 1 {
                 eprintln!("Error: File too short."); process::exit(1);
            }
            let salt_len = contents[0] as usize;
            let mut current_index = 1;

            if contents.len() < current_index + salt_len {
                eprintln!("Error: File too short to contain salt."); process::exit(1);
            }
            let salt_bytes = &contents[current_index..current_index + salt_len];
            current_index += salt_len;

            let salt_str = std::str::from_utf8(salt_bytes)
                .unwrap_or_else(|_| { eprintln!("Error: Invalid salt in file."); process::exit(1); });
            let salt = SaltString::from_b64(salt_str)
                .unwrap_or_else(|e| { eprintln!("Error parsing salt: {}", e); process::exit(1); });

            // 2. Parse the Nonce (next 12 bytes)
             if contents.len() < current_index + 12 {
                eprintln!("Error: File too short to contain nonce."); process::exit(1);
            }
            let nonce_slice = &contents[current_index..current_index + 12];
            current_index += 12;
            let nonce_bytes: [u8; 12] = nonce_slice.try_into().unwrap();
            let nonce = nonce_bytes.into();

            // 3. The rest is encrypted data
            let encrypted_data = &contents[current_index..];

            // 4. Loop until valid password is provided
            loop {
                let password = rpassword::prompt_password("Enter password to decrypt: ")
                     .unwrap_or_else(|e| { eprintln!("Error reading password: {}", e); process::exit(1); });

                // 5. Derive key and attempt decryption
                println!("Deriving key and attempting decryption...");
                let key_bytes = derive_key_from_password(&password, &salt);
                let cipher = Aes256Gcm::new((&key_bytes).into());

                match cipher.decrypt(&nonce, encrypted_data) {
                    Ok(data) => {
                        // Success! Break the loop and return the decrypted data.
                        break data;
                    }
                    Err(_) => {
                        // Failure! Print message and let loop repeat.
                        println!("Decryption failed: Wrong password. Please try again.\n");
                    }
                }
            }
        }
    }; // End of main 'match cli.mode'

    // --- File Writing ---
    // Write the resulting data (ciphertext or plaintext) to the output file
    match fs::write(&cli.output_file, output_data) {
        Ok(_) => println!("Successfully wrote output to {}.", &cli.output_file), // Success
        Err(e) => { // Failure: print error and exit
            eprintln!("Error writing to output file '{}': {}", &cli.output_file, e);
            process::exit(1);
        }
    };
} // End of main: All variables go out of scope, memory is cleaned up by Rust.