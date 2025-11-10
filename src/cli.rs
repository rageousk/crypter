// This module defines the command-line interface structure using clap.

use clap::{Parser, ValueEnum};

// Defines the two modes of operation for the CLI.
// Deriving ValueEnum allows clap to validate user input (only "encrypt" or "decrypt").
#[derive(ValueEnum, Clone, Debug)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

// Defines the complete set of command-line arguments.
// clap's 'derive(Parser)' macro automatically generates the argument parser.
#[derive(Parser)]
#[command(version, about = "A simple CLI tool to encrypt and decrypt files.", long_about = None)]
pub struct Cli {
    /// The mode of operation (encrypt or decrypt)
    #[clap(value_enum)]
    pub mode: Mode,

    /// The path to the input file
    pub input_file: String,

    /// The path to the output file
    pub output_file: String,
}