🔒 crypter

A secure, simple command-line tool I wrote in Rust for encrypting and decrypting files.

This was a project for my Programming Languages course where I focused on applying core Rust concepts (like Ownership, Structs, Enums, and Modules) to a practical cybersecurity problem. The tool is now fully functional and secure.

Features

Secure Encryption: Uses AES-256-GCM, a modern authenticated encryption standard.

Strong Key Derivation: Uses Argon2 to derive a strong 32-byte encryption key from your password. (No hardcoded keys!)

Salting: Generates a unique, random salt for every encryption, meaning the same password encrypting the same file will produce a different result every time, protecting against pre-computation attacks.

User-Friendly Prompts: Securely prompts for passwords (no on-screen echoing) and includes retry loops for typos.

Overwrite Protection: Asks for confirmation before overwriting an existing output file to prevent data loss.

How to Use

You'll need Rust and Cargo installed on your system.

1. Clone the Repository:

git clone https://github.com/rageousk/crypter.git


2. Change Directory:

cd crypter


3. Run with Cargo:

To Encrypt

Run the encrypt command, providing an input and output file path:

cargo run -- encrypt test_doc.txt my_file.bin


(You will be prompted to enter and confirm a password. If it's wrong, you can try again.)

To Decrypt

Run the decrypt command:

cargo run -- decrypt my_file.bin test_doc_decrypted.txt


(You will be prompted for your password. If it's wrong, you can try again.)