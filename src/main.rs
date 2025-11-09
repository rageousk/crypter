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
// Modified: November 9, 2025
//  - Implemented secure password handling using 'argon2' for key derivation and 'rpassword' for safe input.
//  - Added password confirmation loop for encryption and retry loop for decryption failures.
//  - Updated file format to include a unique random salt for every encryption.
//  - Refactored project structure into modules (Code Organization requirement):
//      - Created 'src/cli.rs' for command-line argument definitions (structs/enums).
//      - Created 'src/crypto.rs' for core encryption/decryption logic.
//      - Simplified 'src/main.rs' to act as the high-level coordinator.
//
// --- End Work Log ---

mod cli;
mod crypto;

use clap::Parser;
use std::fs;
use std::process;
use crate::cli::Mode;

fn main() {
    // 1. Parse Command-Line Arguments
    let args = cli::Cli::parse();

    // 2. Read Input File
    let contents = match fs::read(&args.input_file) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error reading input file '{}': {}", args.input_file, e);
            process::exit(1);
        }
    };

    // 3. Perform Operation
    let output_data = match args.mode {
        Mode::Encrypt => {
            println!("Encrypting '{}'...", args.input_file);

            // UI Logic: Prompt for password with confirmation
            let password = loop {
                let p1 = rpassword::prompt_password("Enter a strong password: ")
                    .unwrap_or_else(|e| { eprintln!("Error reading password: {}", e); process::exit(1); });
                let p2 = rpassword::prompt_password("Confirm password: ")
                    .unwrap_or_else(|e| { eprintln!("Error reading confirmation: {}", e); process::exit(1); });
                if p1 == p2 && !p1.is_empty() { break p1; }
                println!("Passwords do not match or are empty. Try again.\n");
            };

            // Delegate to crypto module
            crypto::encrypt_data(&contents, &password)
        }
        Mode::Decrypt => {
            println!("Decrypting '{}'...", args.input_file);

            // UI Logic: Loop until correct password
            loop {
                let password = rpassword::prompt_password("Enter password to decrypt: ")
                     .unwrap_or_else(|e| { eprintln!("Error reading password: {}", e); process::exit(1); });

                // Attempt decryption via crypto module
                match crypto::decrypt_data(&contents, &password) {
                    Ok(data) => break data,
                    Err(_) => println!("Decryption failed (wrong password?). Please try again.\n"),
                }
            }
        }
    };

    // 4. Write Output File
    match fs::write(&args.output_file, output_data) {
        Ok(_) => println!("Success! Output written to '{}'.", args.output_file),
        Err(e) => {
            eprintln!("Error writing output file '{}': {}", args.output_file, e);
            process::exit(1);
        }
    }
}