"""
server.py — Real-Time Security Monitoring & Intrusion Detection
Run:  python server.py
URL:  http://127.0.0.1:5050
"""

import datetime
import json
import time
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps

from flask import (
    Flask, Response, jsonify, render_template,
    render_template_string, request, stream_with_context,
    session, redirect, url_for
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "nexus-soc-2026-secret")

# ══════════════════════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════════════════════
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "Arnab@2026")  

EMAIL_SENDER   = "sender123@gmail.com" #sender email address
EMAIL_PASSWORD = "aaaa bbbb cccc dddd" #give the unique password
EMAIL_RECEIVER = "reciver123@gmail.com" #reciver email address this can be same with sender 
EMAIL_ENABLED  = True
# ══════════════════════════════════════════════════════════════


# ── Block by device name ──────────────────────────────────────
blocked_devices = set()
clients = []


# ── Login required decorator ──────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


# ── File helpers ──────────────────────────────────────────────

def load_logs():
    try:
        with open("logs.json", "r") as f:
            return json.load(f)
    except Exception:
        return []


def save_logs(logs):
    with open("logs.json", "w") as f:
        json.dump(logs, f, indent=4)


def load_authorized_devices():
    try:
        with open("authorized_devices.json") as f:
            return json.load(f)
    except Exception:
        return {}


# ── Email alert via Gmail SMTP ────────────────────────────────

def send_email_alert(severity, device, ip, file_name, action):
    if not EMAIL_ENABLED:
        return

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if severity == "HIGH":
        color  = "#ff4466"
        footer = "INTRUSION DETECTED! Device " + device + " has been blocked."
    else:
        color  = "#ffaa00"
        footer = "Suspicious activity detected from an authorized device."

    subject = "[" + severity + "] Security Alert - " + device + " | " + file_name

    plain = (
        "SECURITY ALERT: " + severity + "\n"
        "============================\n"
        "Time   : " + now + "\n"
        "Device : " + device + "\n"
        "IP     : " + ip + "\n"
        "File   : " + file_name + "\n"
        "Action : " + action + "\n"
        "============================\n"
        + footer
    )

    html = (
        "<html><body style='background:#0a0d13;font-family:monospace;'>"
        "<div style='max-width:560px;margin:30px auto;background:#111820;"
        "border:1px solid #1e2d3d;border-radius:12px;overflow:hidden;'>"
        "<div style='background:" + color + ";padding:18px 24px;'>"
        "<h2 style='margin:0;color:#fff;font-size:18px;'>"
        "SECURITY ALERT - " + severity +
        "</h2></div>"
        "<div style='padding:24px;color:#c9d1d9;font-size:14px;'>"
        "<p><b>Time:</b> " + now + "</p>"
        "<p><b>Device:</b> <span style='color:" + color + "'>" + device + "</span></p>"
        "<p><b>IP:</b> <span style='color:#00d4ff'>" + ip + "</span></p>"
        "<p><b>File:</b> <span style='color:#e8b86d'>" + file_name + "</span></p>"
        "<p><b>Action:</b> " + action + "</p>"
        "<div style='padding:14px;border-left:4px solid " + color + ";margin-top:16px;'>"
        "<p style='margin:0;color:" + color + "'>" + footer + "</p>"
        "</div></div>"
        "<div style='padding:14px;border-top:1px solid #1e2d3d;text-align:center;'>"
        "<p style='color:#4a6070;font-size:11px;'>SOC SECURITY MONITORING DASHBOARD</p>"
        "</div></div></body></html>"
    )

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = EMAIL_SENDER
        msg["To"]      = EMAIL_RECEIVER
        msg.attach(MIMEText(plain, "plain"))
        msg.attach(MIMEText(html,  "html"))
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        print("[EMAIL] Alert sent to " + EMAIL_RECEIVER)
    except smtplib.SMTPAuthenticationError:
        print("[EMAIL] Wrong email or App Password")
    except Exception as e:
        print("[EMAIL] Error: " + str(e))


# ── Business logic ────────────────────────────────────────────

def is_authorized(device, ip):
    allowed = load_authorized_devices()
    return device in allowed and allowed[device] == ip


def classify_severity(device, ip, action):
    if not is_authorized(device, ip):
        return "HIGH"
    if "failed" in action.lower():
        return "MEDIUM"
    return "NORMAL"


def write_log(device, ip, file_name, action, severity):
    entry = {
        "time":     datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "device":   device,
        "ip":       ip,
        "file":     file_name,
        "action":   action,
        "severity": severity,
    }
    logs = load_logs()
    logs.insert(0, entry)
    save_logs(logs)
    return entry


def block_device(device):
    blocked_devices.add(device)
    print("[BLOCK] Device blocked -> " + device)


def protect_file(file_name):
    print("[PROTECT] Simulating encryption -> " + file_name)


def handle_intrusion(device, ip, file_name, action):
    print("=" * 48)
    print("  INTRUSION DETECTED")
    print("  Device : " + device)
    print("  IP     : " + ip)
    print("  File   : " + file_name)
    print("=" * 48)
    block_device(device)
    protect_file(file_name)
    send_email_alert("HIGH", device, ip, file_name, action)


# ── Login / Logout routes ─────────────────────────────────────

LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
  <title>NEXUS SOC Login</title>
  <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=Share+Tech+Mono&display=swap" rel="stylesheet"/>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      min-height: 100vh;
      background: #050810;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: 'Share Tech Mono', monospace;
    }
    .bg-grid {
      position: fixed; inset: 0;
      background-image:
        linear-gradient(rgba(0,245,160,0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,245,160,0.03) 1px, transparent 1px);
      background-size: 40px 40px;
      pointer-events: none;
    }
    .card {
      background: #0a0f1e;
      border: 1px solid rgba(0,245,160,0.15);
      border-radius: 16px;
      padding: 48px 40px;
      width: 100%;
      max-width: 400px;
      position: relative;
      box-shadow: 0 0 60px rgba(0,245,160,0.05);
      z-index: 1;
    }
    .card::before {
      content: '';
      position: absolute;
      top: 0; left: 20%; right: 20%;
      height: 1px;
      background: linear-gradient(90deg, transparent, #00f5a0, transparent);
    }
    .logo { text-align: center; margin-bottom: 32px; }
    .logo svg { width: 60px; height: 60px; filter: drop-shadow(0 0 12px rgba(0,245,160,0.5)); }
    .logo-title {
      font-family: 'Orbitron', monospace;
      font-size: 22px;
      font-weight: 900;
      letter-spacing: 6px;
      color: #00f5a0;
      text-shadow: 0 0 20px rgba(0,245,160,0.4);
      display: block;
      margin-top: 14px;
    }
    .logo-sub {
      font-size: 10px; letter-spacing: 4px;
      color: #4a5568; display: block; margin-top: 6px;
    }
    .divider { height: 1px; background: rgba(0,245,160,0.08); margin: 24px 0; }
    .form-group { margin-bottom: 20px; }
    label { display: block; font-size: 10px; letter-spacing: 3px; color: #4a5568; margin-bottom: 8px; }
    input[type=password] {
      width: 100%; background: #080c14;
      border: 1px solid rgba(0,245,160,0.1);
      border-radius: 8px; padding: 12px 16px;
      color: #e2e8f0; font-family: 'Share Tech Mono', monospace;
      font-size: 14px; letter-spacing: 4px; outline: none;
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    input[type=password]:focus {
      border-color: rgba(0,245,160,0.4);
      box-shadow: 0 0 0 3px rgba(0,245,160,0.05);
    }
    .btn {
      width: 100%; padding: 13px;
      background: rgba(0,245,160,0.1);
      border: 1px solid rgba(0,245,160,0.3);
      border-radius: 8px; color: #00f5a0;
      font-family: 'Orbitron', monospace;
      font-size: 12px; font-weight: 700;
      letter-spacing: 4px; cursor: pointer;
      transition: all 0.2s; margin-top: 8px;
    }
    .btn:hover {
      background: rgba(0,245,160,0.15);
      border-color: #00f5a0;
      box-shadow: 0 0 20px rgba(0,245,160,0.1);
    }
    .error {
      background: rgba(255,68,102,0.1);
      border: 1px solid rgba(255,68,102,0.2);
      border-radius: 8px; padding: 10px 14px;
      color: #ff4466; font-size: 11px;
      letter-spacing: 1px; margin-bottom: 16px; text-align: center;
    }
    .footer-text { text-align: center; font-size: 10px; letter-spacing: 2px; color: #2d3748; margin-top: 24px; }
  </style>
</head>
<body>
  <div class="bg-grid"></div>
  <div class="card">
    <div class="logo">
      <svg viewBox="0 0 60 60" fill="none">
        <polygon points="30,3 57,18 57,42 30,57 3,42 3,18" stroke="#00f5a0" stroke-width="1.5" fill="none"/>
        <polygon points="30,10 50,21 50,39 30,50 10,39 10,21" stroke="#00f5a0" stroke-width="0.8" fill="none" opacity="0.4"/>
        <circle cx="30" cy="30" r="6" fill="#00f5a0" opacity="0.9"/>
        <circle cx="30" cy="30" r="10" stroke="#00f5a0" stroke-width="0.5" fill="none" opacity="0.3"/>
      </svg>
      <span class="logo-title">NEXUS</span>
      <span class="logo-sub">SOC SECURITY PLATFORM</span>
    </div>
    <div class="divider"></div>
    {% if error %}
    <div class="error">⚠ {{ error }}</div>
    {% endif %}
    <form method="POST">
      <div class="form-group">
        <label>ACCESS PASSWORD</label>
        <input type="password" name="password" placeholder="Enter password..." autofocus autocomplete="off"/>
      </div>
      <button type="submit" class="btn">AUTHENTICATE →</button>
    </form>
    <p class="footer-text">// AUTHORIZED PERSONNEL ONLY</p>
  </div>
</body>
</html>
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        password = request.form.get("password", "")
        if password == ADMIN_PASSWORD:
            session["logged_in"] = True
            return redirect(url_for("home"))
        else:
            error = "Invalid password. Access denied."
    return render_template_string(LOGIN_HTML, error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ── Protected Routes ──────────────────────────────────────────

@app.route("/")
@app.route("/dashboard")
@login_required
def home():
    logs = load_logs()
    return render_template("index.html", logs=logs)


@app.route("/logs")
@login_required
def get_logs():
    return jsonify(load_logs())


@app.route("/stats")
@login_required
def get_stats():
    logs   = load_logs()
    counts = {"HIGH": 0, "MEDIUM": 0, "NORMAL": 0}
    for log in logs:
        sev = log.get("severity", "NORMAL").upper()
        if sev in counts:
            counts[sev] += 1
    return jsonify({
        "total":           len(logs),
        "counts":          counts,
        "blocked_devices": sorted(blocked_devices),
    })


@app.route("/log", methods=["POST"])
def receive_log():
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "No JSON received"}), 400
        for field in ("device", "file", "action"):
            if field not in data:
                return jsonify({"error": "Missing field: " + field}), 400

        ip     = request.headers.get("X-Forwarded-For", request.remote_addr)
        device = data["device"]

        if device in blocked_devices:
            return jsonify({"error": "Device '" + device + "' is blocked"}), 403

        severity = classify_severity(device, ip, data["action"])
        entry    = write_log(device, ip, data["file"], data["action"], severity)

        for q in clients:
            q.append(entry)

        if severity == "HIGH":
            handle_intrusion(device, ip, data["file"], data["action"])
        elif severity == "MEDIUM":
            send_email_alert("MEDIUM", device, ip, data["file"], data["action"])

        print("[LOG] " + severity + " | " + device + " | " + data["file"] + " | " + data["action"])
        return jsonify({"status": "ok", "severity": severity})

    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/unblock", methods=["POST"])
@login_required
def unblock():
    data   = request.get_json(silent=True)
    device = data.get("device") if data else None
    if device and device in blocked_devices:
        blocked_devices.discard(device)
        print("[UNBLOCK] Device unblocked -> " + device)
        return jsonify({"status": "unblocked", "device": device})
    return jsonify({"error": "Device not found"}), 404


@app.route("/clear", methods=["POST"])
@login_required
def clear_logs():
    save_logs([])
    for q in clients:
        q.append({"type": "clear"})
    return jsonify({"status": "cleared"})


@app.route("/stream")
@login_required
def stream():
    def event_stream():
        q = []
        clients.append(q)
        try:
            while True:
                if q:
                    yield "data: " + json.dumps(q.pop(0)) + "\n\n"
                time.sleep(0.1)
        finally:
            if q in clients:
                clients.remove(q)

    return Response(
        stream_with_context(event_stream()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    app.run(host="0.0.0.0", port=port, debug=True, threaded=True)
