from pathlib import Path
from Crypto.PublicKey import RSA
from getpass import getpass

BASE_DIR = Path(__file__).resolve().parent.parent
KEYS_DIR = BASE_DIR / "keys"
KEYS_DIR.mkdir(exist_ok=True)

USERS = ["admin", "alice", "bob"]

for username in USERS:
    priv_path = KEYS_DIR / f"{username}_private.pem"
    pub_path = KEYS_DIR / f"{username}_pub.pem"

    if not priv_path.exists() or not pub_path.exists():
        key = RSA.generate(2048)
        # Encrypt private key with passphrase
        passphrase = getpass(f"Enter passphrase for {username}'s private key: ")
        priv_path.write_bytes(key.export_key(passphrase=passphrase, pkcs=8))
        pub_path.write_bytes(key.publickey().export_key())
        print(f"[OK] Keys generated for {username}")
    else:
        print(f"[SKIP] Keys already exist for {username}")