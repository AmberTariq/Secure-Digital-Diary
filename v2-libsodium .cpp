#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstdio>
#include <sodium.h>

using namespace std;

// ---------- Utility functions ----------
bool isValidDate(string d) {
    if ((int)d.size() != 10) return false;
    if (d[4] != '-' || d[7] != '-') return false;
    for (int i = 0; i < 10; i++) {
        if (i == 4 || i == 7) continue;
        if (d[i] < '0' || d[i] > '9') return false;
    }
    return true;
}

// Binary -> hex string for safe text storage
string toHex(const unsigned char* data, size_t len) {
    string hexStr;
    char buf[3];
    for (size_t i = 0; i < len; i++) {
        snprintf(buf, sizeof(buf), "%02x", data[i]);
        hexStr += buf;
    }
    return hexStr;
}

// Hex string -> binary; rejects malformed input instead of reading garbage
vector<unsigned char> fromHex(const string& hexStr) {
    if (hexStr.size() % 2 != 0) throw runtime_error("Corrupted file: bad hex length!");
    vector<unsigned char> data;
    for (size_t i = 0; i < hexStr.size(); i += 2) {
        unsigned int byte;
        if (sscanf(hexStr.substr(i, 2).c_str(), "%2x", &byte) != 1)
            throw runtime_error("Corrupted file: bad hex digit!");
        data.push_back((unsigned char)byte);
    }
    return data;
}

// ---------- Cryptographic vault (libsodium: Argon2id + XSalsa20-Poly1305) ----------
class CryptoVault {
private:
    unsigned char key[crypto_secretbox_KEYBYTES];
    bool keyDerived;

public:
    CryptoVault() : keyDerived(false) {
        if (sodium_init() < 0) throw runtime_error("Failed to initialize libsodium!");
    }
    ~CryptoVault() { sodium_memzero(key, sizeof(key)); }  // wipe key from memory

    // New random salt, returned as hex so it can be stored with the file
    string newSaltHex() {
        unsigned char salt[crypto_pwhash_SALTBYTES];
        randombytes_buf(salt, sizeof(salt));
        return toHex(salt, sizeof(salt));
    }

    // Derive a 256-bit key from the password with Argon2id and the stored salt
    void deriveKey(const string& password, const string& saltHex) {
        vector<unsigned char> salt = fromHex(saltHex);
        if (salt.size() != crypto_pwhash_SALTBYTES)
            throw runtime_error("Corrupted file: bad salt length!");

        if (crypto_pwhash(key, sizeof(key),
                          password.c_str(), password.size(),
                          salt.data(),
                          crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE,
                          crypto_pwhash_ALG_DEFAULT) != 0) {
            throw runtime_error("Out of memory or key derivation failed!");
        }
        keyDerived = true;
    }

    // Encrypt: random nonce per entry, output "nonceHex:ciphertextHex"
    string encryptData(const string& plaintext) {
        if (!keyDerived) throw runtime_error("Key not derived!");

        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        randombytes_buf(nonce, sizeof(nonce));

        vector<unsigned char> ciphertext(plaintext.size() + crypto_secretbox_MACBYTES);
        crypto_secretbox_easy(ciphertext.data(),
                              (const unsigned char*)plaintext.c_str(),
                              plaintext.size(), nonce, key);

        return toHex(nonce, sizeof(nonce)) + ":" + toHex(ciphertext.data(), ciphertext.size());
    }

    // Decrypt: fails if the password is wrong or the data was modified
    string decryptData(const string& cipherBundle) {
        if (!keyDerived) throw runtime_error("Key not derived!");

        size_t pos = cipherBundle.find(':');
        if (pos == string::npos) throw runtime_error("Invalid storage format!");

        vector<unsigned char> nonce = fromHex(cipherBundle.substr(0, pos));
        vector<unsigned char> ciphertext = fromHex(cipherBundle.substr(pos + 1));

        if (nonce.size() != crypto_secretbox_NONCEBYTES || ciphertext.size() < crypto_secretbox_MACBYTES)
            throw runtime_error("Corrupted file: bad entry size!");

        vector<unsigned char> decrypted(ciphertext.size() - crypto_secretbox_MACBYTES);
        if (crypto_secretbox_open_easy(decrypted.data(), ciphertext.data(),
                                       ciphertext.size(), nonce.data(), key) != 0) {
            throw runtime_error("Decryption failed! Wrong password or corrupted file.");
        }
        return string(decrypted.begin(), decrypted.end());
    }
};

// ---------- Entry hierarchy ----------
class Entry {
    string date;
    string text;
public:
    Entry() {}
    Entry(string d, string t) : date(d), text(t) {}
    virtual ~Entry() {}
    string getDate() { return date; }
    string getText() { return text; }
    void setDate(string d) { if (isValidDate(d)) date = d; }
    void setText(string t) { text = t; }
    virtual void display(int number) {
        cout << " [" << number << "] " << date << "\n\t" << text << endl;
    }
};

class DiaryEntry : public Entry {
    string mood;
public:
    DiaryEntry() {}
    DiaryEntry(string d, string t, string m) : Entry(d, t), mood(m) {}
    string getMood() { return mood; }
    void display(int number) override {
        cout << " [" << number << "] " << getDate() << " (Mood: " << mood << ")\n\t" << getText() << endl;
    }
};

class LockedEntry : public Entry {
    bool isUnlocked;
public:
    LockedEntry(string d, string t) : Entry(d, t), isUnlocked(false) {}
    void display(int number) override {
        cout << " [" << number << "] " << getDate() << "\n\t"
             << (isUnlocked ? getText() : "[LOCKED TEXT]") << endl;
    }
};

class User {
    string name;
    string password;
public:
    User(string n, string p) : name(n), password(p) {}
    string getName() { return name; }
    string getPassword() { return password; }
};

// ---------- Diary ----------
// File format: line 1 = salt (hex); every following line = one encrypted entry.
class Diary {
    vector<DiaryEntry> entries;
    string filename;
    CryptoVault vault;
    string saltHex;

public:
    Diary(string f, User& u) : filename(f) {
        // Reuse the salt stored in an existing file; otherwise create a new one.
        ifstream in(filename);
        string first;
        if (in.is_open() && getline(in, first) && !first.empty()) saltHex = first;
        else saltHex = vault.newSaltHex();
        vault.deriveKey(u.getPassword(), saltHex);
    }

    void addEntry(DiaryEntry e) { entries.push_back(e); }

    void saveToFile() {
        ofstream file(filename, ios::trunc);
        if (!file.is_open()) throw runtime_error("Could not open file for writing!");
        file << saltHex << "\n";
        for (auto &e : entries) {
            string combined = e.getDate() + "|" + e.getMood() + "|" + e.getText();
            file << vault.encryptData(combined) << "\n";
        }
    }

    // Throws if the password is wrong or a line was tampered with.
    void loadFromFile() {
        ifstream file(filename);
        if (!file.is_open()) return;       // no file yet: first run
        string line;
        getline(file, line);               // skip the salt line
        entries.clear();
        while (getline(file, line)) {
            if (line.empty()) continue;
            string decrypted = vault.decryptData(line);
            size_t p1 = decrypted.find('|');
            size_t p2 = (p1 == string::npos) ? string::npos : decrypted.find('|', p1 + 1);
            if (p1 != string::npos && p2 != string::npos) {
                entries.push_back(DiaryEntry(decrypted.substr(0, p1),
                                             decrypted.substr(p2 + 1),
                                             decrypted.substr(p1 + 1, p2 - p1 - 1)));
            }
        }
    }

    void showAllEntries() {
        if (entries.empty()) { cout << "No entries found.\n"; return; }
        for (int i = 0; i < (int)entries.size(); i++) entries[i].display(i + 1);
    }
};

int main() {
    try {
        string name, pass;
        cout << "================================\n";
        cout << " SECURE DIGITAL DIARY (LIBSODIUM)\n";
        cout << "================================\n";
        cout << "Enter Name: "; getline(cin, name);
        cout << "Enter Pass: "; getline(cin, pass);

        User u(name, pass);
        Diary myDiary(name + "_diary.enc", u);
        myDiary.loadFromFile();   // wrong password -> exception -> exit WITHOUT overwriting the file

        bool running = true;
        while (running) {
            cout << "\n1. Add Entry\n2. View Entries\n3. Save & Exit\nChoice: ";
            string ch;
            getline(cin, ch);

            if (ch == "1") {
                string d, m, t;
                cout << "Date (YYYY-MM-DD): "; getline(cin, d);
                cout << "Mood: "; getline(cin, m);
                cout << "Text: "; getline(cin, t);
                if (isValidDate(d)) {
                    myDiary.addEntry(DiaryEntry(d, t, m));
                    cout << "Entry added successfully.\n";
                } else {
                    cout << "Invalid date format! Use YYYY-MM-DD.\n";
                }
            } else if (ch == "2") {
                myDiary.showAllEntries();
            } else if (ch == "3") {
                myDiary.saveToFile();
                cout << "Encrypted and saved to " << name << "_diary.enc. Goodbye!" << endl;
                running = false;
            }
        }
    } catch (exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    return 0;
}
