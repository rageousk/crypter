use clap::Parser;
use std::fs; // Import the file system module from the standard library

/// A simple CLI tool to encrypt and decrypt files.
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// The mode of operation: 'encrypt' or 'decrypt'
    mode: String,

    /// The path to the input file
    input_file: String,

    /// The path to the output file
    output_file: String,
}

fn main() {
    let cli = Cli::parse();

    println!("Mode: {}", cli.mode);
    println!("Input file: {}", cli.input_file);
    println!("Output file: {}", cli.output_file);

    // --- NEW CODE START ---
    // Read the contents of the input file into a vector of bytes.
    let contents = match fs::read(&cli.input_file) {
        Ok(data) => data, // If successful, 'data' contains the file contents.
        Err(e) => {
            // If the file can't be read, print a user-friendly error and exit.
            eprintln!("Error reading input file '{}': {}", cli.input_file, e);
            std::process::exit(1);
        }
    };

    println!("\nSuccessfully read {} bytes from {}.", contents.len(), cli.input_file);
    // --- NEW CODE END ---

    // (Encryption/Decryption logic will go here!)
}