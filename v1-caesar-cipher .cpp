// Secure Digital Diary - VERSION 1 (original course submission, OOP CT-260, NED University)
//
// Kept for reference. This is the original team project, lightly repaired so it compiles
// (missing includes, "template<typename T>", and the main menu loop). The logic is unchanged.
// The Caesar cipher used here is NOT secure. See README.md and v2-libsodium/ for the rebuild.
//
// Build: g++ -std=c++11 secure_diary_v1.cpp -o secure_diary_v1

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>

using namespace std;

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

// Caesar cipher: shifts letters only; digits and punctuation are left unchanged.
string encrypt(string text, int shift) {
    string res = text;
    for (int i = 0; i < (int)res.size(); i++) {
        if (res[i] >= 'a' && res[i] <= 'z')
            res[i] = (res[i] - 'a' + shift) % 26 + 'a';
        else if (res[i] >= 'A' && res[i] <= 'Z')
            res[i] = (res[i] - 'A' + shift) % 26 + 'A';
    }
    return res;
}

template <typename T>
class SecureVault {
    T data;
    int pin;
public:
    SecureVault(int p) : pin(p) {}
    void store(T value) { data = value; }
    T unlock(int enteredPin) {
        if (enteredPin != pin) throw invalid_argument("Wrong PIN!");
        return data;
    }
    static int makePin(string password) {
        int total = 0;
        for (char c : password) total += (int)c;
        return (total % 25) + 1;
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
        cout << " [" << number << "] " << date << "\n " << text << endl;
    }
};

class DiaryEntry : public Entry {
    string mood;
public:
    DiaryEntry() {}
    DiaryEntry(string d, string t, string m) : Entry(d, t), mood(m) {}
    string getMood() { return mood; }
    void display(int number) override {
        cout << " [" << number << "] " << getDate() << " (Mood: " << mood << ")\n "
             << getText() << endl;
    }
};

class LockedEntry : public Entry {
    bool isUnlocked;
public:
    LockedEntry(string d, string t) : Entry(d, t), isUnlocked(false) {}
    void display(int number) override {
        cout << " [" << number << "] " << getDate() << "\n "
             << (isUnlocked ? getText() : "[LOCKED TEXT]") << endl;
    }
};

class User {
    string name;
    string password;
public:
    User(string n, string p) : name(n), password(p) {}
    string getName() { return name; }
    int getShift() { return SecureVault<int>::makePin(password); }
};

class Diary {
    vector<DiaryEntry> entries;
    string filename;
    int shift;
public:
    Diary(string f, int s) : filename(f), shift(s) {}
    void addEntry(DiaryEntry e) { entries.push_back(e); }
    void saveToFile() {
        ofstream file(filename);
        for (auto &e : entries) {
            file << encrypt(e.getDate(), shift) << "|" << encrypt(e.getMood(), shift)
                 << "|" << encrypt(e.getText(), shift) << "\n";
        }
    }
    void showWithPolymorphism() {
        if (entries.empty()) return;
        DiaryEntry de = entries[0];
        LockedEntry le(entries[0].getDate(), entries[0].getText());
        vector<Entry*> mixed = {&de, &le};
        for (int i = 0; i < (int)mixed.size(); i++) mixed[i]->display(i + 1);
    }
    friend void showAllEntries(Diary& d);
};

void showAllEntries(Diary& d) {
    if (d.entries.empty()) { cout << "No entries found.\n"; return; }
    for (int i = 0; i < (int)d.entries.size(); i++) d.entries[i].display(i + 1);
}

int main() {
    try {
        string name, pass;
        cout << "================================" << endl;
        cout << " SECURE DIGITAL DIARY " << endl;
        cout << "================================" << endl;
        cout << "Enter Name: "; getline(cin, name);
        cout << "Enter Pass: "; getline(cin, pass);

        User u(name, pass);
        Diary myDiary(name + "_diary.txt", u.getShift());

        bool running = true;
        while (running) {
            cout << "\n1. Add 2. View 3. Demo 4. Exit\nChoice: ";
            string ch; getline(cin, ch);
            if (ch == "1") {
                string d, m, t;
                cout << "Date (YYYY-MM-DD): "; getline(cin, d);
                cout << "Mood: "; getline(cin, m);
                cout << "Text: "; getline(cin, t);
                myDiary.addEntry(DiaryEntry(d, t, m));
            } else if (ch == "2") {
                showAllEntries(myDiary);
            } else if (ch == "3") {
                myDiary.showWithPolymorphism();
            } else if (ch == "4") {
                myDiary.saveToFile();
                cout << "Saved to " << name << "_diary.txt. Goodbye!" << endl;
                running = false;
            }
        }
    } catch (exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    return 0;
}
