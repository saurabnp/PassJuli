# 🔐 PassJuli - Secure Password Manager

PassJuli is a simple yet secure password manager built with Python **PyQt6**, designed to help users store and retrieve all their passwords efficiently and conveniently in one place. It uses **Argon2** for hashing the master password and **AES-GCM-256** encryption to keep your data safe even if compromised.

## 🚀 Features

- 🔐 Save and manage passwords securely
- 🧠 Remember only one master password
- 🛡️ Encrypt passwords using AES-GCM-256 before storage
- 🔒 Hash master password using Argon2 (winner of the Password Hashing Competition)
- 🔍 Retrieve and decrypt passwords securely
- 🧬 Strong password generator built-in
- 💻 Intuitive and responsive GUI built using PyQt6

## 🛠️ Tech Stack

- **Frontend**: PyQt6
- **Security**:
  - Argon2 (for master password hashing)
  - AES-GCM-256 (for password encryption)
  - CryptoDome (cryptographic library)

## 📦 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/PassJuli.git
   cd PassJuli

2. **Install dependencies**:
   ```bash
    pip install -r requirements.txt

4. **Run The Application**:
   ```bash
    python main.py

🔐 Security Overview:
PassJuli takes your security seriously

- Master Password Protection: Your master password is never stored in plain text. It is hashed using Argon2, a memory-hard and CPU-intensive hash function designed to resist brute-force attacks.

- Password Encryption: All saved passwords are encrypted with AES-GCM-256, an authenticated encryption algorithm that ensures both confidentiality and integrity.

- Secure by Design: Even if a hacker gains access to your storage, they’ll only see encrypted data.



