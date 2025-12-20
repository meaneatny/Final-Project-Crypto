# Secure-File-Sharing-System

A Python-based secure multi-user file sharing system using AES-256-GCM for file encryption and RSA-2048 for key distribution.

- Admin encrypts files for authorized users.
- Users decrypt files assigned to them.
- Server maintains metadata and logs for auditing.

---

## Overview

This project enables confidential, authenticated, and integrity-protected file sharing between an admin and multiple users.

### Workflow Summary

1. Admin encrypts files with AES-256-GCM.
2. AES keys are encrypted for each recipient using RSA-2048 public keys.
3. Admin signs files with their RSA private key.
4. Server stores metadata and logs actions.
5. Users decrypt files using their private key and verify authenticity.

---

## Project Structure

```bash
project_root/
├─ code/
│  ├─ encryptor.py        # Admin encryption
│  ├─ decryptor.py        # User decryption
│  ├─ generate_keys.py    # RSA key generation
│  └─ server.py           # Flask API server
├─ config/
│  └─ config.yaml
├─ keys/                  # RSA key pairs
├─ logs/                  # Operation & security logs
├─ storage/
│  ├─ input/              # Files to encrypt
│  ├─ encrypted/          # Encrypted files
│  └─ decrypted/          # Decrypted files
├─ users/
│  └─ users.json          # Credentials and roles
├─ metadata/
│  └─ file_index.json     # File metadata
├─ venv/                  # Python virtual environment (gitignored)
└─ requirements.txt       # Dependencies
```

---

## Setup

### Clone the repository

```bash
git clone <repo_url>
cd project_root
```

### Create a virtual environment and activate it

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate
```

### Install dependencies

```bash
pip install -r requirements.txt
```

### Generate RSA keys

```bash
python code/generate_keys.py
```

Enter passphrases for admin and users.

### Start the server

```bash
python code/server.py
```

Runs at http://127.0.0.1:5000

---

## Usage

### Admin: Encrypt Files

python code/encryptor.py

1. Authenticate as admin.
2. Select files from storage/input/.
3. Choose recipients.
4. Encrypted files are saved in storage/encrypted/.
5. Metadata registered on server.

### User: Decrypt Files

python code/decryptor.py

1. Authenticate as user.
2. Select authorized encrypted files.
3. Decrypted files are saved in storage/decrypted/.
4. Server is notified of successful decryption.

---

## Security

- AES-256-GCM → encrypts file contents securely.
- RSA-2048 → encrypts AES key per recipient.
- SHA-256 → ensures file integrity.
- RSA Digital Signature → verifies authenticity.
- Server logs → track operations and access.

---

## Logs

- logs/operation.log → Tracks file operations (encrypt/decrypt).  
- logs/security.log → Tracks login attempts and security events.  
- logs/system.log → Tracks server errors and system events.
