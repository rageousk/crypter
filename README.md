# 🔒 crypter

A simple command-line tool written in Rust to encrypt and decrypt files using AES-256-GCM.

**(Project for Programming Languages - Prof. Benjamin Weidner)**

---

## Current Status

**🚧 In Development 🚧**

The core encryption and decryption functionality is implemented and working. However, the encryption key is currently **hardcoded** in the source code, which is **insecure** and only for demonstration purposes.

---

## Usage

You need Rust and Cargo installed to build and run this project.

1.  **Clone the repository** (or download the source code).
2.  **Navigate** to the project directory (`crypter`) in your terminal.
3.  **Run with Cargo:**

    * **To Encrypt:**
        ```bash
        cargo run -- encrypt <path/to/your/input_file> <path/to/your/output_file.bin>
        ```
        *Example:* `cargo run -- encrypt my_document.txt secret_data.bin`

    * **To Decrypt:**
        ```bash
        cargo run -- decrypt <path/to/your/encrypted_file.bin> <path/to/your/decrypted_file>
        ```
        *Example:* `cargo run -- decrypt secret_data.bin my_document_restored.txt`

    The program will read the input file, perform the operation, and write the result to the output file. The hardcoded key (`an example very very secret key.`) is used for both encryption and decryption.

---

## Next Steps

The immediate next step is to remove the hardcoded key and implement secure key handling:

* Prompt the user to enter a password/key securely (without echoing it to the terminal).
* Potentially derive the encryption key from the user's password using a key derivation function (like Argon2 or PBKDF2) for better security.

---

*(This README will be updated as the project progresses.)*