import os, json, hashlib, hmac, secrets, time
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

SECRET_KEY   = os.environ.get("SECRET_KEY",   "QuantTerminal2024geheim")
ADMIN_TOKEN  = os.environ.get("ADMIN_TOKEN",  "meinadmin123")
DATA_FILE    = "licenses.json"

def load_db():
    try:
        with open(DATA_FILE) as f:
            return json.load(f)
    except:
        return {"licenses": {}, "stats": {"total_sales": 0}}

def save_db(db):
    with open(DATA_FILE, "w") as f:
        json.dump(db, f, indent=2)

def generate_key():
    parts = [secrets.token_hex(2).upper() for _ in range(4)]
    return "QT-" + "-".join(parts)

def is_expired(lic):
    try:
        return datetime.utcnow() > datetime.fromisoformat(lic["expires"])
    except:
        return True

def verify_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.headers.get("X-Admin-Token") != ADMIN_TOKEN:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/v1/verify", methods=["POST"])
def verify():
    data = request.get_json(silent=True) or {}
    key  = str(data.get("key", "")).upper().strip()
    if not key:
        return jsonify({"valid": False, "reason": "no_key"})
    db  = load_db()
    lic = db["licenses"].get(key)
    if not lic:
        return jsonify({"valid": False, "reason": "invalid_key"})
    if lic.get("suspended"):
        return jsonify({"valid": False, "reason": "suspended"})
    if is_expired(lic):
        return jsonify({"valid": False, "reason": "expired"})
    db["licenses"][key]["last_seen"] = datetime.utcnow().isoformat()
    save_db(db)
    return jsonify({"valid": True, "expires": lic.get("expires"), "email": lic.get("email",""), "_sig": "ok"})

@app.route("/admin/create", methods=["POST"])
@verify_admin
def admin_create():
    data  = request.get_json(silent=True) or {}
    email = data.get("email", "")
    days  = int(data.get("days", 31))
    key   = generate_key()
    expires = (datetime.utcnow() + timedelta(days=days)).isoformat()
    db = load_db()
    db["licenses"][key] = {"email": email, "expires": expires,
        "created": datetime.utcnow().isoformat(), "suspended": False}
    db["stats"]["total_sales"] += 1
    save_db(db)
    return jsonify({"key": key, "expires": expires, "email": email})

@app.route("/admin/renew", methods=["POST"])
@verify_admin
def admin_renew():
    data = request.get_json(silent=True) or {}
    key  = str(data.get("key","")).upper().strip()
    days = int(data.get("days", 31))
    db   = load_db()
    lic  = db["licenses"].get(key)
    if not lic:
        return jsonify({"error": "Not found"}), 404
    try:
        current = datetime.fromisoformat(lic["expires"])
        new_exp = max(current, datetime.utcnow()) + timedelta(days=days)
    except:
        new_exp = datetime.utcnow() + timedelta(days=days)
    db["licenses"][key]["expires"] = new_exp.isoformat()
    save_db(db)
    return jsonify({"key": key, "new_expires": new_exp.isoformat()})

@app.route("/admin/suspend", methods=["POST"])
@verify_admin
def admin_suspend():
    data = request.get_json(silent=True) or {}
    key  = str(data.get("key","")).upper().strip()
    db   = load_db()
    if key not in db["licenses"]:
        return jsonify({"error": "Not found"}), 404
    db["licenses"][key]["suspended"] = True
    save_db(db)
    return jsonify({"ok": True})

@app.route("/admin/list", methods=["GET"])
@verify_admin
def admin_list():
    db = load_db()
    result = []
    for key, lic in db["licenses"].items():
        result.append({"key": key, "email": lic.get("email",""),
            "expires": lic.get("expires",""), "expired": is_expired(lic),
            "suspended": lic.get("suspended", False),
            "last_seen": lic.get("last_seen","")})
    result.sort(key=lambda x: x["expires"], reverse=True)
    return jsonify({"licenses": result, "stats": db.get("stats", {})})

@app.route("/admin/stats", methods=["GET"])
@verify_admin
def admin_stats():
    db    = load_db()
    lics  = list(db["licenses"].values())
    active = [l for l in lics if not is_expired(l) and not l.get("suspended")]
    return jsonify({"total": len(lics), "active": len(active),
        "expired": len(lics)-len(active),
        "mrr_eur": round(len(active)*20, 2),
        "total_sales": db.get("stats",{}).get("total_sales", 0)})

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Server starting on port {port}")
    app.run(host="0.0.0.0", port=port)
