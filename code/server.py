from flask import Flask, request, jsonify
from pathlib import Path
import json, logging, hashlib, uuid
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
USERS_FILE = BASE_DIR / "users/users.json"
METADATA_FILE = BASE_DIR / "metadata/file_index.json"
SEC_LOG = BASE_DIR / "logs/security.log"
SYSTEM_LOG = BASE_DIR / "logs/system.log"

# --- System Logger ---
SYSTEM_LOG.parent.mkdir(parents=True, exist_ok=True)
system_logger = logging.getLogger("system_logger")
system_logger.setLevel(logging.INFO)
handler = RotatingFileHandler(SYSTEM_LOG, maxBytes=5*1024*1024, backupCount=3)
formatter = logging.Formatter(
    '{"timestamp":"%(asctime)s","level":"%(levelname)s","message":"%(message)s"}'
)
handler.setFormatter(formatter)
system_logger.addHandler(handler)

def log_system(message, level="ERROR", **kwargs):
    entry = json.dumps({**kwargs, "message": message})
    if level.upper() == "INFO":
        system_logger.info(entry)
    elif level.upper() == "WARNING":
        system_logger.warning(entry)
    elif level.upper() == "CRITICAL":
        system_logger.critical(entry)
    else:
        system_logger.error(entry)

# --- Security Logger ---
SEC_LOG.parent.mkdir(exist_ok=True)
SEC_LOG.touch(exist_ok=True)

def log_security(username, action, status="ok", **kwargs):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "username": username,
        "action": action,
        "status": status,
        "request_id": str(uuid.uuid4()),
        **kwargs
    }
    with open(SEC_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
    if status != "ok":
        print(f"[SECURITY] {username} - {action} - {status}")

# --- Helpers ---
USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
METADATA_FILE.parent.mkdir(parents=True, exist_ok=True)
if not METADATA_FILE.exists(): METADATA_FILE.write_text(json.dumps({}))

def load_users():
    try:
        return json.loads(USERS_FILE.read_text())
    except:
        return {}

def load_metadata():
    try:
        return json.loads(METADATA_FILE.read_text())
    except:
        return {}

def save_metadata(metadata):
    try:
        METADATA_FILE.write_text(json.dumps(metadata, indent=2))
    except Exception as e:
        log_system(f"Failed to save metadata: {e}", level="ERROR")

# --- Routes ---
@app.route("/login/", methods=["POST"])
def login():
    try:
        data = request.get_json(force=True)
        username = str(data.get("username","")).lower()
        password = str(data.get("password",""))
        users = load_users()
        if username not in users:
            log_security(username, "login_attempt", status="failed_invalid_username")
            return jsonify({"error":"Invalid username"}), 401
        stored_hash = users[username]["password"]
        if hashlib.sha256(password.encode()).hexdigest() != stored_hash:
            log_security(username, "login_attempt", status="failed_invalid_password")
            return jsonify({"error":"Invalid password"}), 401
        log_security(username, "login_attempt", status="success", role=users[username]["role"])
        return jsonify({"msg":"Authenticated","role":users[username]["role"]}), 200
    except Exception as e:
        log_system(f"Login route error: {e}", level="ERROR")
        return jsonify({"error":"Internal server error"}), 500

@app.route("/register_file/", methods=["POST"])
@app.route("/register_file/", methods=["POST"])
def register_file():
    try:
        data = request.get_json(force=True)
        required = ["filename","owner","recipients","size","hash","encryption_algo","signature_algo","timestamp"]
        if not all(f in data for f in required):
            log_security(data.get("owner"), "register_file", status="failed_missing_fields")
            return jsonify({"error":"Missing fields"}), 400
        metadata = load_metadata()
        filename = data["filename"]

        # Overwrite recipients and metadata instead of merging
        metadata[filename] = {k: data[k] for k in required}

        save_metadata(metadata)
        log_security(data["owner"], "register_file", status="success", filename=filename, recipients=data["recipients"])
        return jsonify({"msg":f"File {filename} registered"}), 200
    except Exception as e:
        log_system(f"Register_file route error: {e}", level="ERROR")
        return jsonify({"error":"Internal server error"}), 500

@app.route("/metadata/", methods=["GET"])
def metadata_list():
    try:
        return jsonify(load_metadata()), 200
    except Exception as e:
        log_system(f"Metadata route error: {e}", level="ERROR")
        return jsonify({"error":"Internal server error"}), 500

@app.route("/mark_decrypted/", methods=["POST"])
def mark_decrypted():
    try:
        data = request.get_json(force=True)
        username = data.get("username")
        filename = data.get("filename")
        if not username or not filename:
            return jsonify({"error":"Missing fields"}), 400
        metadata = load_metadata()
        if filename not in metadata: return jsonify({"error":"File not found"}), 404
        metadata.setdefault(filename, {}).setdefault("decrypted_by", [])
        if username not in metadata[filename]["decrypted_by"]:
            metadata[filename]["decrypted_by"].append(username)
            save_metadata(metadata)
            log_security(username, "file_decrypted", status="success", filename=filename)
        return jsonify({"msg": f"{username} marked as decrypted {filename}"}), 200
    except Exception as e:
        log_system(f"Mark decrypted route error: {e}", level="ERROR")
        return jsonify({"error":"Internal server error"}), 500

if __name__=="__main__":
    try:
        import logging
        logging.getLogger('werkzeug').setLevel(logging.ERROR)  # suppress Flask access logs
        print("Server running at http://127.0.0.1:5000")
        app.run(host="127.0.0.1", port=5000)
    except Exception as e:
        log_system(f"Server failed to start: {e}", level="CRITICAL")