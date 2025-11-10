// ## crypter: A Simple File Encryption/Decryption Tool ##
// @author: Sahil Kamboj

// This file contains the main entry point and orchestrates the CLI,
// file I/O, and cryptographic operations.

// Declare the external modules (cli.rs and crypto.rs)
mod cli;
mod crypto;

use clap::Parser;
use std::fs;
use std::io::{self, Write}; // For user prompts (flush stdout, read stdin)
use std::path::Path;        // To check if a file path exists
use std::process;
use crate::cli::Mode; // Import the Mode enum from our cli module

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

    // 3. Perform Operation based on mode
    let output_data = match args.mode {
        Mode::Encrypt => {
            println!("Encrypting '{}'...", args.input_file);

            // Loop until passwords match
            let password = loop {
                let p1 = rpassword::prompt_password("Enter a strong password: ")
                    .unwrap_or_else(|e| { eprintln!("Error reading password: {}", e); process::exit(1); });
                let p2 = rpassword::prompt_password("Confirm password: ")
                    .unwrap_or_else(|e| { eprintln!("Error reading confirmation: {}", e); process::exit(1); });
                
                if p1 == p2 && !p1.is_empty() {
                    break p1; // Success
                }
                println!("Passwords do not match or are empty. Try again.\n");
            };

            // Delegate encryption to the crypto module
            crypto::encrypt_data(&contents, &password)
        }
        Mode::Decrypt => {
            println!("Decrypting '{}'...", args.input_file);

            // Loop until decryption is successful (correct password)
            loop {
                let password = rpassword::prompt_password("Enter password to decrypt: ")
                     .unwrap_or_else(|e| { eprintln!("Error reading password: {}", e); process::exit(1); });

                // Attempt decryption
                match crypto::decrypt_data(&contents, &password) {
                    Ok(data) => break data, // Success! Exit loop with data.
                    Err(e) => println!("Decryption failed ({}). Please try again.\n", e),
                }
            }
        }
    };

    // 4. Overwrite Protection Check
    if Path::new(&args.output_file).exists() {
        print!("Warning: Output file '{}' already exists. Overwrite? [Y/N]: ", args.output_file);
        // Flush stdout to ensure the prompt appears before stdin waits for input
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        // Exit if the user does not explicitly say 'y'
        if input.trim().to_lowercase() != "y" {
            println!("Operation cancelled. File not overwritten.");
            process::exit(0);
        }
    }

    // 5. Write Output File
    match fs::write(&args.output_file, output_data) {
        Ok(_) => println!("Success! Output written to '{}'.", args.output_file),
        Err(e) => {
            eprintln!("Error writing output file '{}': {}", args.output_file, e);
            process::exit(1);
        }
    }
}