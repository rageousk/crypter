# 🔒 crypter

A secure, simple command-line tool written in Rust for encrypting and decrypting files.

This project was built for a Programming Languages course, focusing on applying core Rust concepts—Ownership, Structs, Enums, and Modules—to a practical cybersecurity problem. The tool is fully functional and secure.

## Features

- **Secure Encryption:** Uses AES-256-GCM, a modern authenticated encryption standard.
- **Strong Key Derivation:** Uses Argon2 to derive a strong 32-byte encryption key from your password. (_No hardcoded keys!_)
- **Salting:** Generates a unique, random salt for every encryption, ensuring the same password produces a different result each time. This protects against pre-computation attacks.
- **User-Friendly Prompts:** Securely prompts for passwords (no on-screen echoing) and includes retry loops for mistyped entries.
- **Overwrite Protection:** Confirmation before overwriting existing output files to prevent data loss.

## Getting Started

You’ll need **Rust** and **Cargo** installed on your system.

### Installing Rust and Cargo

If you don't already have Rust and Cargo, install them using the official installer:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
This command works on most Unix-based systems (Linux, macOS).  
For Windows, download and run the installer from [rustup.rs](https://rustup.rs).

After installation, **restart your terminal** and verify:

```sh
rustc --version
cargo --version
```

### 1. Clone the Repository

```sh
git clone https://github.com/rageousk/crypter.git
```

### 2. Change Directory

```sh
cd crypter
```

### 3. Run with Cargo

#### To Encrypt

Run the encrypt command, providing input and output file paths:
```sh
cargo run -- encrypt test_doc.txt my_file.bin
```
_You will be prompted to enter and confirm a password. If it's wrong, you can try again._

#### To Decrypt

Run the decrypt command:
```sh
cargo run -- decrypt my_file.bin test_doc_decrypted.txt
```
_You will be prompted for your password. If it's wrong, you can try again._
