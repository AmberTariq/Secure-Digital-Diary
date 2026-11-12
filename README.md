# Secure Digital Diary (Advanced C++ & Libsodium)

A terminal-based secure personal journal application built in C++ that demonstrates advanced Object-Oriented Programming (OOP) design patterns and replaces vulnerable toy ciphers with production-grade cryptography.

## Academic Context
* **Course:** Object-Oriented Programming (CT-260)
* **Institution:** NED University of Engineering and Technology, Karachi
* **Instructor:** Dr. Muhammad Imran
* **Contributors:** Alishba Habib, Daniya Ali, Amber Tariq

---

## Security Architecture: From Toy Cipher to Real Encryption

The original iteration of this project implemented a **Caesar cipher** for "Encryption at Rest." While effective for learning basic ASCII manipulation loops, Caesar ciphers offer zero real-world security (vulnerable to frequency analysis and brute-force in milliseconds). 

This upgraded version integrates **[libsodium](https://libsodium.gitbook.io/)**, implementing modern Authenticated Encryption with Associated Data (AEAD):
1. **Key Derivation (Argon2id):** Uses `crypto_pwhash` to safely stretch user passwords into cryptographically secure 256-bit keys, defending against GPU-based brute-force and dictionary attacks.
2. **Symmetric Encryption (XSalsa20-Poly1305):** Ensures both complete confidentiality and data integrity via `crypto_secretbox`. If an attacker or script modifies even a single bit of your saved diary file on disk, decryption immediately fails.
3. **Random Nonces:** Every save operation generates a unique cryptographic nonce (`randombytes_buf`), ensuring identical diary entries encrypt into completely different ciphertexts across sessions.

---

## Core OOP Concepts Demonstrated
* **Encapsulation:** Private sensitive fields (`password`, `text`) with validation methods (`Entry::setText()`) preventing corrupted data states.
* **Inheritance:** `DiaryEntry` and `LockedEntry` derive from a common base `Entry` class.
* **Polymorphism:** Virtual `display()` functions resolved via dynamic binding using `Entry*` vectors.

---

## Getting Started & Compilation

### Prerequisites
Ensure you have a C++ compiler (`g++` or `clang`) and `libsodium` installed:
* **Ubuntu/Debian:** `sudo apt install libsodium-dev pkg-config`
* **macOS (Homebrew):** `brew install libsodium pkg-config`

### Building with CMake
```bash
mkdir build
cd build
cmake ..
make
./secure_diary
