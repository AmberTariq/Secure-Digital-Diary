# Secure Digital Diary

A terminal-based diary in C++ that encrypts entries before saving them to disk.

This repository holds **two versions** of the same project, so you can see how it changed:

| Version | Folder | Encryption | Status |
|---|---|---|---|
| v1 | [`v1-caesar-cipher/`](v1-caesar-cipher/) | Caesar cipher with a key derived from the password | Original course project, kept for reference. **Not secure.** |
| v2 | [`v2-libsodium/`](v2-libsodium/) | Argon2id key derivation + authenticated encryption (libsodium) | My rebuild, replacing the weak cipher |

## Background

v1 was a team project for the Object-Oriented Programming course (CT-260) at NED University of Engineering & Technology, built with two classmates, Alishba Habib and Daniya Ali. It focused on OOP concepts: a class hierarchy (`Entry`, `DiaryEntry`, `LockedEntry`), virtual functions and polymorphism, a templated `SecureVault<T>` class, and file I/O.

Its encryption was a Caesar cipher, which is a teaching tool and not real protection. After the course I rebuilt the encryption layer on my own with [libsodium](https://doc.libsodium.org/), and fixed the design problems that came with it. The OOP structure of v1 is kept in v2.

## What was wrong with v1

- **Tiny key space.** The shift was `(sum of password character codes % 25) + 1`, so there are only 25 possible keys, and an attacker can try all of them instantly. Many different passwords also map to the same key.
- **Only letters are shifted.** Digits, dashes and punctuation are stored unchanged. For example, the entry date `2026-11-13` appears in plain text in the saved file.
- **No integrity check.** Nothing detects a modified file, and nothing tells you whether the password was correct.
- **No way to read the file back.** v1 only saves; it has no load/decrypt path.

## What v2 does

- **Key derivation:** the key is derived from your password with **Argon2id** (`crypto_pwhash`) and a random 16-byte salt, so each password guess is slow and expensive to attack.
- **Encryption:** each entry is encrypted with libsodium's `crypto_secretbox` (XSalsa20-Poly1305), which gives **authenticated** encryption. Wrong passwords and edited files are detected and rejected.
- **Fresh nonce per entry:** a random 24-byte nonce is generated for every entry.
- **Salt stored with the file:** the salt is saved as the first line, so the same password derives the same key next time.
- **Safe failure:** if decryption fails, the program stops and does not overwrite the file.
- **Key wiping:** the key is zeroed in memory when the vault is destroyed.

### File format (v2)

```
<salt, 32 hex characters>
<nonce hex>:<ciphertext hex>     <- one line per entry
<nonce hex>:<ciphertext hex>
...
```

Each entry is encrypted as `date|mood|text`.

## Build and run

Install libsodium, then compile:

```bash
# Ubuntu / Debian
sudo apt install libsodium-dev
# macOS
brew install libsodium
# Windows (MSYS2)
pacman -S mingw-w64-x86_64-libsodium

# build and run v2
cd v2-libsodium
g++ -std=c++17 secure_diary.cpp -o secure_diary -lsodium
./secure_diary
```

v1 needs no extra library:

```bash
cd v1-caesar-cipher
g++ -std=c++11 secure_diary_v1.cpp -o secure_diary_v1
./secure_diary_v1
```

## Limitations of v2

This is a learning project. It has not been audited, and it should not be used to protect real secrets.

- Entry count and entry lengths are visible in the file.
- The password and decrypted entries are kept in ordinary `std::string` memory, which is not locked or wiped.
- The `|` character is used as a field separator, so the mood field should not contain it.
- There is no password-change feature, and the Argon2id cost settings use libsodium's "interactive" preset.

## What I learned

- Why a Caesar-style cipher is not encryption in any real sense.
- Why a password should go through a slow key-derivation function before it is used as a key.
- The difference between encryption and **authenticated** encryption.
- How easy it is to lose data with a design mistake, such as forgetting to store the salt, and why failing safely matters.
