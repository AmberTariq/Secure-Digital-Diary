#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>
#include <sodium.h>

using namespace std;

// Utility functions for string formatting and validation
string trim(string s) {
    int start = 0;
    while (start < (int)s.size() && s[start] == ' ') start++;
    int end = (int)s.size() - 1;
    while (end >= start && s[end] == ' ') end--;
    return (start > end) ? "" : s.substr(start, end - start + 1);
}

bool isValidDate(string d) {
    if ((int)d.size() != 10) return false;
    if (d[4] != '-' || d[7] != '-') return false;
    for (int i = 0; i < 10; i++) {
        if (i == 4 || i == 7) continue;
        if (d[i] < '0' || d[i] > '9') return false;
    }
    return true;
}

string sanitise(string s) {
    for (int i = 0; i < (int)s.size(); i++) if (s[i] == '|') s[i] = '/';
    return s;
}

// Helper to convert binary data to a hex string for safe file storage
string toHex(const unsigned char* data, size_t len) {
    string hexStr = "";
    char buf[3];
    for (size_t i = 0; i < len; i++) {
        sprintf(buf, "%02x", data[i]);
        hexStr += buf;
    }
    return hexStr;
}

// Helper to convert hex string back to binary data
vector<unsigned char> fromHex(const string& hexStr) {
    vector<unsigned char> data;
    for (size_t i = 0; i < hexStr.size(); i += 2) {
        unsigned int byte;
        sscanf(hexStr.substr(i, 2).c_str(), "%x", &byte);
        data.push_back((unsigned char)byte);
    }
    return data;
}

// Cryptographic Vault using libsodium (Argon2id + XSalsa20-Poly1305)
class CryptoVault {
private:
    unsigned char key[crypto_secretbox_KEYBYTES];
    bool keyDerived;

public:
    CryptoVault() : keyDerived(false) {
        if (sodium_init() < 0) {
            throw runtime_error("Failed to initialize libsodium!");
        }
    }

    // Derive a 256-bit encryption key from the user's password using Argon2id
    void deriveKey(const string& password, const string& saltHex) {
        unsigned char salt[crypto_pwhash_SALTBYTES];
        
        if (saltHex.empty()) {
            randombytes_buf(salt, sizeof(salt));
        } else {
            vector<unsigned char> decodedSalt = fromHex(saltHex);
            for (size_t i = 0; i < crypto_pwhash_SALTBYTES; i++) salt[i] = decodedSalt[i];
        }

        if (crypto_pwhash(key, sizeof(key),
                          password.c_str(), password.size(),
                          salt,
                          crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE,
                          crypto_pwhash_ALG_DEFAULT) != 0) {
            throw runtime_error("Out of memory or key derivation failed!");
        }
        keyDerived = true;
    }

    // Encrypt plaintext string into an authenticated ciphertext bundle (Nonce + Ciphertext)
    string encryptData(const string& plaintext) {
        if (!keyDerived) throw runtime_error("Key not derived!");

        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        randombytes_buf(nonce, sizeof(nonce));

        vector<unsigned char> ciphertext(plaintext.size() + crypto_secretbox_MACBYTES);
        
        crypto_secretbox_easy(ciphertext.data(),
                              (const unsigned char*)plaintext.c_str(),
                              plaintext.size(),
                              nonce,
                              key);

        // Package nonce + ciphertext as hex strings separated by a colon
        return toHex(nonce, sizeof(nonce)) + ":" + toHex(ciphertext.data(), ciphertext.size());
    }

    // Decrypt ciphertext bundle back to plaintext. Throws if password is wrong or data is tampered with.
    string decryptData(const string& cipherBundle) {
        if (!keyDerived) throw runtime_error("Key not derived!");

        size_t delimiterPos = cipherBundle.find(':');
        if (delimiterPos == string::npos) throw runtime_error("Invalid storage format!");

        string nonceHex = cipherBundle.substr(0, delimiterPos);
        string cipherHex = cipherBundle.substr(delimiterPos + 1);

        vector<unsigned char> nonce = fromHex(nonceHex);
        vector<unsigned char> ciphertext = fromHex(cipherHex);

        vector<unsigned char> decrypted(ciphertext.size() - crypto_secretbox_MACBYTES);

        if (crypto_secretbox_open_easy(decrypted.data(),
                                       ciphertext.data(),
                                       ciphertext.size(),
                                       nonce.data(),
                                       key) != 0) {
            throw runtime_error("Decryption failed! Wrong password or corrupted file.");
        }

        return string(decrypted.begin(), decrypted.end());
    }
};

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

class Diary {
vector<DiaryEntry> entries; 
string filename;
CryptoVault vault;
string saltHex;

public:
    Diary(string f, User& u) : filename(f) {
        // Generate a random salt for this user session or load existing
        saltHex = ""; // In a full app, persist/load salt alongside the file
        vault.deriveKey(u.getPassword(), saltHex);
    } 

    void addEntry(DiaryEntry e) { entries.push_back(e); } 
    
    void saveToFile() {
        ofstream file(filename); 
        for (auto &e : entries) {
            string combined = e.getDate() + "|" + e.getMood() + "|" + e.getText();
            file << vault.encryptData(combined) << "\n";
        }
    }

    void loadFromFile() {
        ifstream file(filename);
        if (!file.is_open()) return;
        string line;
        entries.clear();
        while (getline(file, line)) {
            if (line.empty()) continue;
            string decrypted = vault.decryptData(line);
            
            // Parse back delimited fields: Date|Mood|Text
            size_t p1 = decrypted.find('|');
            size_t p2 = decrypted.find('|', p1 + 1);
            if (p1 != string::npos && p2 != string::npos) {
                string d = decrypted.substr(0, p1);
                string m = decrypted.substr(p1 + 1, p2 - p1 - 1);
                string t = decrypted.substr(p2 + 1);
                entries.push_back(DiaryEntry(d, t, m));
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
        
        // Attempt to load and decrypt existing diary records
        try {
            myDiary.loadFromFile();
        } catch (...) {
            cout << "Notice: Could not decrypt existing file or file does not exist. Starting fresh.\n";
        }

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
    }
    return 0;
}
