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

    // --- Cryptography Setup ---
    // !!! INSECURE: Hardcoded key for demonstration ONLY. Must be 32 bytes for AES-256. !!!
    let key_bytes = b"an example very very secret key.";
    // Create the AES-GCM cipher instance from the key bytes
    let cipher = Aes256Gcm::new(key_bytes.into());

    // --- Main Control Flow ---
    // Use 'match' on the Mode enum to decide whether to encrypt or decrypt
    let output_data: Vec<u8> = match cli.mode {
        // --- Encryption Path ---
        Mode::Encrypt => {
            println!("Encrypting data...");
            // Generate a unique 12-byte nonce for this encryption
            let mut nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut nonce_bytes); // Fill with secure random data
            let nonce = nonce_bytes.into(); // Convert array to Nonce type

            // Encrypt the data, handle potential errors using 'match'
            let encrypted_data = match cipher.encrypt(&nonce, contents.as_ref()) {
                Ok(data) => data, // Success: data is ciphertext + auth tag
                Err(_) => { // Failure: print error and exit
                    eprintln!("Error: Encryption failed!");
                    process::exit(1);
                }
            };

            // Prepend the nonce to the ciphertext for storage (nonce is not secret)
            let mut data_to_write = nonce_bytes.to_vec();
            data_to_write.extend_from_slice(&encrypted_data);
            data_to_write // Return the combined (nonce + ciphertext) Vec<u8>
        }

        // --- Decryption Path ---
        Mode::Decrypt => {
            println!("Decrypting data...");
            // Basic check: file must be large enough to contain the 12-byte nonce
            if contents.len() <= 12 {
                eprintln!("Error: Input file too short (missing nonce?).");
                process::exit(1);
            }

            // Split the input data into the nonce (first 12 bytes) and the ciphertext (the rest)
            let (nonce_slice, encrypted_data) = contents.split_at(12);

            // Convert nonce slice (&[u8]) into a fixed-size array ([u8; 12])
            let nonce_bytes: [u8; 12] = match nonce_slice.try_into() {
                Ok(arr) => arr, // Success: arr is [u8; 12]
                Err(_) => { // Failure (shouldn't happen after length check)
                    eprintln!("Error: Failed to parse nonce.");
                    process::exit(1);
                }
            };
            let nonce = nonce_bytes.into(); // Convert array to Nonce type

            // Decrypt the data, handle errors (e.g., wrong key, corrupted data) using 'match'
            match cipher.decrypt(&nonce, encrypted_data.as_ref()) {
                Ok(data) => data, // Success: data is the original plaintext Vec<u8>
                Err(_) => { // Failure: print error and exit
                    eprintln!("Error: Decryption failed! (Wrong key or corrupt data?)");
                    process::exit(1);
                }
            } // Return the plaintext Vec<u8>
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