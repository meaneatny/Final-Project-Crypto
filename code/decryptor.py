import json, yaml, requests, hashlib, traceback
from pathlib import Path
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from datetime import datetime, timezone
from getpass import getpass

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config/config.yaml"
with open(CONFIG_PATH) as f:
    config = yaml.safe_load(f)

ENCRYPTED_DIR = BASE_DIR / config['folders']['encrypted']
DECRYPTED_DIR = BASE_DIR / config['folders']['decrypted']
OP_LOG = BASE_DIR / "logs/operation.log"
SYSTEM_LOG = BASE_DIR / "logs/system.log"
KEYS_DIR = BASE_DIR / "keys"
SERVER_URL = config['server']['host']

ENCRYPTED_DIR.mkdir(exist_ok=True)
DECRYPTED_DIR.mkdir(exist_ok=True)
OP_LOG.touch(exist_ok=True)
SYSTEM_LOG.touch(exist_ok=True)
KEYS_DIR.mkdir(exist_ok=True)

# --- Logging ---
def log_system(message, **kwargs):
    entry = {"timestamp": datetime.now(timezone.utc).isoformat(), "message": message, **kwargs}
    with open(SYSTEM_LOG, "a") as f: f.write(json.dumps(entry) + "\n")
    print(f"[SYSTEM] {message}")

def log_op(filename, step, message, status="ok", user=None, **kwargs):
    entry = {"timestamp": datetime.now(timezone.utc).isoformat(),
             "file": filename, "step": step, "message": message, "status": status, "user": user, **kwargs}
    with open(OP_LOG, "a") as f: f.write(json.dumps(entry) + "\n")
    print(f"[{status.upper()}] {step}: {message}")

# --- Load public keys ---
def load_pub_keys():
    keys = {}
    for pub_file in KEYS_DIR.glob("*_pub.pem"):
        keys[pub_file.stem.replace("_pub", "")] = pub_file
    return keys

NAME_TO_KEY = load_pub_keys()

# --- User Authentication ---
def authenticate_user():
    print("\n=== User Dashboard ===")
    username = input("Username: ").strip().lower()
    password = getpass("Password: ")
    try:
        resp = requests.post(f"{SERVER_URL}/login/", json={"username": username, "password": password})
        if resp.status_code == 200 and resp.json().get("role") == "user":
            print("[OK] User authenticated!\n")
            return username
        print("[ERROR] Login failed (only users can decrypt files)")
        return None
    except Exception:
        print("[ERROR] Server connection error")
        return None

# --- Decrypt file ---
def decrypt_file(filepath, username):
    filename = filepath.name
    try:
        data = filepath.read_bytes()
        meta_len = int.from_bytes(data[:4], "big")
        metadata = json.loads(data[4:4+meta_len])
        encrypted_data = data[4+meta_len:]

        # Extract AES-GCM components
        nonce, tag, signature = encrypted_data[:16], encrypted_data[16:32], encrypted_data[-256:]
        ciphertext = encrypted_data[32:-256]

        # Check if user is authorized
        if username not in metadata.get("encrypted_keys", {}):
            log_op(filename, "decrypt", f"User '{username}' is not a recipient", status="error", user=username)
            print(f"[ERROR] You are not authorized to decrypt {filename}")
            return

        # Decrypt AES key
        try:
            priv_passphrase = getpass(f"Enter passphrase for {username}'s private key: ")
            priv_key_path = KEYS_DIR / f"{username}_private.pem"
            priv_key = RSA.import_key(priv_key_path.read_bytes(), passphrase=priv_passphrase)
            aes_key = PKCS1_OAEP.new(priv_key).decrypt(bytes.fromhex(metadata["encrypted_keys"][username]))
        except ValueError:
            print("[ERROR] Incorrect passphrase or key.")
            log_op(filename, "decrypt", "Incorrect passphrase or key", status="error", user=username)
            return
        except Exception:
            print("[ERROR] Failed to load private key.")
            log_op(filename, "decrypt", "Failed to load private key", status="error", user=username)
            return

        # Decrypt file content
        try:
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            print("[ERROR] Decryption failed (integrity check failed).")
            log_op(filename, "decrypt", "MAC check failed", status="error", user=username)
            return

        # Verify signature using admin's public key
        try:
            owner_pub = RSA.import_key(NAME_TO_KEY["admin"].read_bytes())
            pkcs1_15.new(owner_pub).verify(SHA256.new(ciphertext), signature)
            sig_status = "Signature OK"
        except:
            sig_status = "Signature INVALID"

        # Write decrypted file
        out_path = DECRYPTED_DIR / filename.replace(".enc", "")
        out_path.write_bytes(plaintext)

        log_op(filename, "decrypt", "Decrypted successfully", user=username,
               size=len(plaintext), hash=hashlib.sha256(plaintext).hexdigest(),
               signature_status=sig_status)
        print(f"[OK] Decrypted {filename} -> {out_path}")

        # Notify server
        try:
            requests.post(f"{SERVER_URL}/mark_decrypted/", json={"username": username, "filename": filename})
        except Exception:
            log_system(f"Failed to mark {filename} as decrypted")

    except Exception as e:
        log_system(f"Decryption failed for {filename}: {e}\n{traceback.format_exc()}")
        log_op(filename, "error", f"Decryption failed: {e}", status="error", user=username)
        print("[ERROR] Decryption failed.")

# --- User dashboard ---
def user_dashboard(username):
    while True:
        print("\n=== User Menu ===")
        print("1. Decrypt files")
        print("2. Exit")
        choice = input("Select an option: ").strip()
        if choice == "1":
            try:
                resp = requests.get(f"{SERVER_URL}/metadata/")
                metadata = resp.json()
            except Exception:
                print("[ERROR] Failed fetching metadata")
                continue

            # Filter files user can decrypt
            user_files = [
                ENCRYPTED_DIR/fname for fname, meta in metadata.items()
                if username in meta.get("recipients", []) 
                and (ENCRYPTED_DIR/fname).exists()
                and username not in meta.get("decrypted_by", [])
            ]

            if not user_files:
                print("No files available for decryption")
                continue

            print("\n=== Files available for you ===")
            for i, f in enumerate(user_files, 1):
                print(f"{i}. {f.name}")
            sel = input("Choose files to decrypt (comma-separated numbers): ")
            try:
                selected = [user_files[int(i)-1] for i in sel.split(",")]
            except (ValueError, IndexError):
                print("Invalid selection!")
                continue

            for f in selected:
                decrypt_file(f, username)

        elif choice == "2":
            print("Exiting User Dashboard.")
            break
        else:
            print("Invalid option!")


if __name__ == "__main__":
    user = authenticate_user()
    if user:
        user_dashboard(user)