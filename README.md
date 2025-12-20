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
project_root/
├─ code/
│ ├─ encryptor.py # Admin encryption
│ ├─ decryptor.py # User decryption
│ ├─ generate_keys.py # RSA key generation
│ └─ server.py # Flask API server
├─ config/
│ └─ config.yaml
├─ keys/ # RSA key pairs
├─ logs/ # Operation & security logs
├─ storage/
│ ├─ input/ # Files to encrypt
│ ├─ encrypted/ # Encrypted files
│ └─ decrypted/ # Decrypted files
├─ users/
│ └─ users.json # Credentials and roles
├─ metadata/
│ └─ file_index.json # File metadata
├─ venv/ # Python virtual environment (gitignored)
└─ requirements.txt # Dependencies

---

## Setup

### Clone the repository

```bash
git clone <repo_url>
cd project_root

Create a virtual environment and activate it

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate

Install dependencies

```bash
pip install -r requirements.txt

Generate RSA keys