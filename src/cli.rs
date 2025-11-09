use clap::{Parser, ValueEnum};

// Enum for operating modes (encrypt/decrypt) - used by clap
#[derive(ValueEnum, Clone, Debug)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

// Struct to define and parse command-line arguments using clap
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