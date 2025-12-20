import json, yaml, requests, hashlib, traceback
from pathlib import Path
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from datetime import datetime, timezone
from getpass import getpass

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config/config.yaml"
with open(CONFIG_PATH) as f:
    config = yaml.safe_load(f)

FILES_DIR = BASE_DIR / config['folders']['input']
OUTPUT_DIR = BASE_DIR / config['folders']['encrypted']
OP_LOG = BASE_DIR / "logs/operation.log"
SYSTEM_LOG = BASE_DIR / "logs/system.log"
KEYS_DIR = BASE_DIR / "keys"
SERVER_URL = config['server']['host']

FILES_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
OP_LOG.touch(exist_ok=True)
SYSTEM_LOG.touch(exist_ok=True)
KEYS_DIR.mkdir(exist_ok=True)

# --- System logger ---
def log_system(message, **kwargs):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": message,
        **kwargs
    }
    with open(SYSTEM_LOG,"a") as f: f.write(json.dumps(entry)+"\n")
    print(f"[SYSTEM] {message}")

# --- Operation logger ---
def log_op(filename, step, message, status="ok", user=None, **kwargs):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "file": filename,
        "step": step,
        "message": message,
        "status": status,
        "user": user,
        **kwargs
    }
    with open(OP_LOG,"a") as f: f.write(json.dumps(entry)+"\n")
    print(f"[{status.upper()}] {step}: {message}")

# --- Load public keys ---
def load_pub_keys():
    keys = {}
    try:
        for pub_file in KEYS_DIR.glob("*_pub.pem"):
            keys[pub_file.stem.replace("_pub","")] = pub_file
    except Exception as e:
        log_system(f"Failed to load public keys: {e}")
    return keys

NAME_TO_KEY = load_pub_keys()

# --- Admin Authentication ---
def authenticate_admin():
    print("\n=== System Dashboard ===")
    username = input("Username: ").strip().lower()
    password = getpass("Password: ")
    try:
        resp = requests.post(f"{SERVER_URL}/login/", json={"username":username,"password":password})
        if resp.status_code==200 and resp.json().get("role")=="admin":
            print("[OK] Admin authenticated!\n")
            return username
        print("[ERROR] Login failed (only admins can encrypt files)")
        return None
    except Exception as e:
        log_system(f"Admin authentication error: {e}\n{traceback.format_exc()}")
        print("[ERROR] Server connection error")
        return None

# --- Encrypt file ---
def encrypt_file(filepath, recipients, username):
    filename = filepath.name
    try:
        log_op(filename, "detect", f"Detected {filename}", user=username)
        data = filepath.read_bytes()

        out_path = OUTPUT_DIR / f"{filename}.enc"
        if out_path.exists():
            # --- Load existing metadata ---
            existing_data = out_path.read_bytes()
            meta_len = int.from_bytes(existing_data[:4], "big")
            metadata = json.loads(existing_data[4:4+meta_len])
            encrypted_data = existing_data[4+meta_len:]

            # --- FIX: Decrypt AES key using admin's own key ---
            if "admin" not in metadata["encrypted_keys"]:
                log_system(f"Cannot re-encrypt {filename}: admin's key missing")
                log_op(filename, "encrypt", "Admin key missing in existing file", status="error", user=username)
                return
            encrypted_aes_key = bytes.fromhex(metadata["encrypted_keys"]["admin"])
            priv_passphrase = getpass(f"Enter passphrase for admin's private key to re-encrypt AES key for new recipients: ")
            priv_key = RSA.import_key(open(KEYS_DIR/"admin_private.pem","rb").read(), passphrase=priv_passphrase)
            aes_key = PKCS1_OAEP.new(priv_key).decrypt(encrypted_aes_key)

        else:
            metadata = {"recipients": [], "encrypted_keys": {}}
            encrypted_data = b""
            aes_key = get_random_bytes(32)

        # --- Encrypt AES key for recipients ---
        enc_keys = metadata.get("encrypted_keys", {})
        valid_recipients = []
        for r in recipients:
            if r not in NAME_TO_KEY:
                log_system(f"Recipient {r} has no public key, skipping")
                continue
            pub_key = RSA.import_key(open(NAME_TO_KEY[r],"rb").read())
            enc_keys[r] = PKCS1_OAEP.new(pub_key).encrypt(aes_key).hex()
            valid_recipients.append(r)

        # Ensure admin can always decrypt
        if "admin" not in enc_keys:
            priv_passphrase = getpass(f"Enter passphrase for admin's private key: ")
            priv_key = RSA.import_key(open(KEYS_DIR/"admin_private.pem","rb").read(), passphrase=priv_passphrase)
            pub_key = RSA.import_key(open(KEYS_DIR/"admin_pub.pem","rb").read())
            enc_keys["admin"] = PKCS1_OAEP.new(pub_key).encrypt(aes_key).hex()

        if not valid_recipients:
            log_op(filename, "encrypt", "No valid recipients, encryption skipped", status="error", user=username)
            print("[ERROR] No valid recipients to encrypt for")
            return

        # Encrypt file
        cipher_aes = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)

        # Sign
        signature = pkcs1_15.new(priv_key).sign(SHA256.new(ciphertext))

        # Update metadata
        metadata["recipients"] = list(set(metadata.get("recipients", [])).union(valid_recipients))
        metadata["encrypted_keys"] = enc_keys

        # Write file
        meta_bytes = json.dumps(metadata).encode()
        with open(out_path,"wb") as f:
            f.write(len(meta_bytes).to_bytes(4,"big"))
            f.write(meta_bytes)
            f.write(cipher_aes.nonce + tag + ciphertext + signature)

        log_op(filename, "write", f"Encrypted {filename} -> {out_path}", user=username,
               recipients=valid_recipients, encryption_algo="AES-256-GCM",
               size=len(data), hash=hashlib.sha256(data).hexdigest())

        # Register metadata to server
        try:
            requests.post(f"{SERVER_URL}/register_file/", json={
                "filename": f"{filename}.enc",
                "owner": username,
                "recipients": metadata["recipients"],
                "size": len(data),
                "hash": hashlib.sha256(data).hexdigest(),
                "encryption_algo": "AES-256-GCM",
                "signature_algo": "RSA-2048-PKCS1v15",
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
            log_op(filename, "server", "Metadata registered", user=username)
        except Exception as e:
            log_system(f"Failed to register metadata: {e}")
            log_op(filename, "server", f"Failed to register metadata: {e}", status="error", user=username)

    except Exception as e:
        log_system(f"Encryption failed for {filename}: {e}\n{traceback.format_exc()}")
        log_op(filename, "error", str(e), status="error", user=username)

# --- Admin dashboard ---
def admin_dashboard(username):
    while True:
        print("\n=== Admin Menu ===")
        print("1. Encrypt files")
        print("2. Exit")
        choice = input("Select an option: ").strip()
        if choice=="1":
            recs = [r for r in NAME_TO_KEY.keys() if r!="admin"]
            if not recs:
                print("No recipients available!")
                continue
            print("\n=== Recipients available ===")
            for i,r in enumerate(recs,1): print(f"{i}. {r}")
            sel = input("Select recipients (comma-separated numbers): ")
            try:
                recipients = [recs[int(i.strip())-1] for i in sel.split(",")]
            except (ValueError, IndexError):
                print("Invalid selection of recipients!")
                continue

            files = list(FILES_DIR.glob("*"))
            if not files:
                print("No files available to encrypt!")
                continue
            print("\n=== Files available ===")
            for i,f in enumerate(files,1): print(f"{i}. {f.name}")
            sel_files = input("Select files (comma-separated numbers): ")
            try:
                selected_files = [files[int(i)-1] for i in sel_files.split(",")]
            except (ValueError, IndexError):
                print("Invalid selection of files!")
                continue

            for f in selected_files:
                encrypt_file(f, recipients, username)

        elif choice=="2":
            print("Exiting Admin Dashboard.")
            break
        else:
            print("Invalid option!")

if __name__=="__main__":
    admin = authenticate_admin()
    if admin:
        admin_dashboard(admin)