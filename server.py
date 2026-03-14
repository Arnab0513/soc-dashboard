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
import requests
import pytz
IST = pytz.timezone("Asia/Kolkata")
from gevent import sleep as gevent_sleep

from flask import Flask, Response, jsonify, render_template, request, stream_with_context # type: ignore

app = Flask(__name__)


# ══════════════════════════════════════════════════════════════
#  NOTIFICATION CONFIG
#  For LOCAL testing  → fill values directly below
#  For RENDER deploy  → set these in Render Environment tab
#                       (do NOT put real passwords on GitHub)
# ══════════════════════════════════════════════════════════════

# ── Email ───────────────────────────────────────────────────
EMAIL_PASSWORD = os.environ.get("RESEND_API_KEY ", "re_gQttV7cc_LhpeLYn5yqyaSo9xBta3FPkB")
EMAIL_RECEIVER = os.environ.get("EMAIL_RECEIVER", "arnabjana536@gmail.com")
EMAIL_ENABLED  = os.environ.get("EMAIL_ENABLED",  "false").lower() == "true"

# ══════════════════════════════════════════════════════════════


# ── Block by device name ──────────────────────────────────────
blocked_devices: set = set()
clients: list = []


# ── File helpers ──────────────────────────────────────────────

def load_logs() -> list:
    try:
        with open("logs.json", "r") as f:
            return json.load(f)
    except Exception:
        return []


def save_logs(logs: list) -> None:
    with open("logs.json", "w") as f:
        json.dump(logs, f, indent=4)


def load_authorized_devices() -> dict:
    try:
        with open("authorized_devices.json") as f:
            return json.load(f)
    except Exception:
        return {}

# ── Email alert ───────────────────────────────────────────────

def send_email_alert(severity, device, ip, file, action):
    if not EMAIL_ENABLED:
        return 
    now   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    color = "#ff3b3b" if severity == "HIGH" else "#ffb020"
    icon  = "🔴" if severity == "HIGH" else "🟡"

    plain = f"""
SECURITY ALERT — {severity}
============================
Time   : {now}
Device : {device}
IP     : {ip}
File   : {file}
Action : {action}
============================
{'INTRUSION DETECTED — Device has been blocked.' if severity == 'HIGH' else 'Suspicious activity from authorized device.'}
    """.strip()

    html = f"""
    <html><body style="margin:0;padding:0;background:#0a0d13;font-family:'Courier New',monospace;">
      <div style="max-width:560px;margin:30px auto;background:#111820;border:1px solid #1e2d3d;border-radius:12px;overflow:hidden;">
        <div style="background:{color};padding:18px 24px;">
          <h2 style="margin:0;color:#fff;font-size:18px;letter-spacing:2px;">
            {icon} SECURITY ALERT — {severity}
          </h2>
        </div>
        <div style="padding:24px;">
          <table style="width:100%;border-collapse:collapse;color:#c9d1d9;font-size:14px;">
            <tr style="border-bottom:1px solid #1e2d3d;">
              <td style="padding:10px 0;color:#4a6070;width:90px;">📅 TIME</td>
              <td style="padding:10px 0;color:#fff;">{now}</td>
            </tr>
            <tr style="border-bottom:1px solid #1e2d3d;">
              <td style="padding:10px 0;color:#4a6070;">💻 DEVICE</td>
              <td style="padding:10px 0;color:{color};font-weight:bold;">{device}</td>
            </tr>
            <tr style="border-bottom:1px solid #1e2d3d;">
              <td style="padding:10px 0;color:#4a6070;">🌐 IP</td>
              <td style="padding:10px 0;color:#00d4ff;">{ip}</td>
            </tr>
            <tr style="border-bottom:1px solid #1e2d3d;">
              <td style="padding:10px 0;color:#4a6070;">📄 FILE</td>
              <td style="padding:10px 0;color:#e8b86d;">{file}</td>
            </tr>
            <tr>
              <td style="padding:10px 0;color:#4a6070;">⚡ ACTION</td>
              <td style="padding:10px 0;color:#c9d1d9;">{action}</td>
            </tr>
          </table>
          <div style="margin-top:20px;padding:14px;background:rgba({'255,59,59' if severity=='HIGH' else '255,176,32'},.1);border-left:4px solid {color};border-radius:4px;">
            <p style="margin:0;color:{color};font-size:13px;">
              {'🚨 Intrusion detected! Device <b>' + device + '</b> has been blocked.' if severity == 'HIGH' else '⚠️ Suspicious activity detected from an authorized device.'}
            </p>
          </div>
        </div>
        <div style="padding:14px 24px;border-top:1px solid #1e2d3d;text-align:center;">
          <p style="margin:0;color:#4a6070;font-size:11px;letter-spacing:1px;">SOC SECURITY MONITORING DASHBOARD</p>
        </div>
      </div>
    </body></html>
    """

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[{severity}] Security Alert — {device} | {file}"
        msg["From"]    = EMAIL_SENDER
        msg["To"]      = EMAIL_RECEIVER
        msg.attach(MIMEText(plain, "plain"))
        msg.attach(MIMEText(html,  "html"))
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        print(f"[EMAIL] ✅ Alert sent to {EMAIL_RECEIVER}")
    except smtplib.SMTPAuthenticationError:
        print("[EMAIL] ❌ Authentication failed — check App Password")
    except Exception as e:
        print(f"[EMAIL] ❌ Error: {e}")
 
# ── Send via all enabled methods ──────────────────────────────

def send_alert(severity, device, ip, file, action):
    send_email_alert(severity, device, ip, file, action)


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


def write_log(device, ip, file, action, severity):
    entry = {
        "time": datetime.datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S"),
        "device":   device,
        "ip":       ip,
        "file":     file,
        "action":   action,
        "severity": severity,
    }
    logs = load_logs()
    logs.insert(0, entry)
    save_logs(logs)
    return entry


def block_device(device):
    blocked_devices.add(device)
    print(f"[BLOCK]   Device blocked -> {device}")


def protect_file(file):
    print(f"[PROTECT] Simulating encryption -> {file}")


def handle_intrusion(device, ip, file, action):
    print("=" * 48)
    print("  INTRUSION DETECTED")
    print(f"  Device : {device}")
    print(f"  IP     : {ip}")
    print(f"  File   : {file}")
    print("=" * 48)
    block_device(device)
    protect_file(file)
    send_alert("HIGH", device, ip, file, action)


# ── Routes ────────────────────────────────────────────────────

@app.route("/")
@app.route("/dashboard")
def home():
    logs = load_logs()
    return render_template("index.html", logs=logs)


@app.route("/logs")
def get_logs():
    return jsonify(load_logs())


@app.route("/stats")
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
                return jsonify({"error": f"Missing field: {field}"}), 400

        ip     = request.headers.get("X-Forwarded-For", request.remote_addr)
        device = data["device"]

        if device in blocked_devices:
            return jsonify({"error": f"Device '{device}' is blocked"}), 403

        severity = classify_severity(device, ip, data["action"])
        entry    = write_log(device, ip, data["file"], data["action"], severity)

        for q in clients:
            q.append(entry)

        if severity == "HIGH":
            handle_intrusion(device, ip, data["file"], data["action"])
        elif severity == "MEDIUM":
            send_alert("MEDIUM", device, ip, data["file"], data["action"])

        print(f"[LOG] {severity:6s} | {device} | {data['file']} | {data['action']}")
        return jsonify({"status": "ok", "severity": severity})

    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/unblock", methods=["POST"])
def unblock():
    data   = request.get_json(silent=True)
    device = data.get("device") if data else None
    if device and device in blocked_devices:
        blocked_devices.discard(device)
        print(f"[UNBLOCK] Device unblocked -> {device}")
        return jsonify({"status": "unblocked", "device": device})
    return jsonify({"error": "Device not found in block list"}), 404


@app.route("/clear", methods=["POST"])
def clear_logs():
    save_logs([])
    for q in clients:
        q.append({"type": "clear"})
    return jsonify({"status": "cleared"})


@app.route("/stream")
def stream():
    def event_stream():
        q = []
        clients.append(q)
        try:
            while True:
                if q:
                    yield f"data: {json.dumps(q.pop(0))}\n\n"
                gevent_sleep(0.1)
        finally:
            if q in clients:
                clients.remove(q)

    return Response(
        stream_with_context(event_stream()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Entry point ───────────────────────────────────────────────
# Use gunicorn on Render, flask dev server locally
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)