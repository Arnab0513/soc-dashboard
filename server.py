"""
server.py — Real-Time Security Monitoring & Intrusion Detection
"""

import datetime
import json
import time
import os
import requests
import urllib.request
import urllib.error
import ssl

from flask import Flask, Response, jsonify, render_template, request, stream_with_context

app = Flask(__name__)

# ── Email Config ──────────────────────────────────────────────
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
EMAIL_RECEIVER = os.environ.get("EMAIL_RECEIVER", "arnabjana078@gmail.com")
EMAIL_ENABLED  = os.environ.get("EMAIL_ENABLED",  "true").lower() == "true"

# ── Block by device name ──────────────────────────────────────
blocked_devices = set()
clients = []


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


# ── Email via Resend ──────────────────────────────────────────

def send_email_alert(severity, device, ip, file_name, action):
    if not EMAIL_ENABLED:
        print("[EMAIL] Skipped - EMAIL_ENABLED is false")
        return
    if not RESEND_API_KEY:
        print("[EMAIL] Skipped - RESEND_API_KEY is empty")
        return

    now = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).astimezone(datetime.timezone(datetime.timedelta(hours=5, minutes=30))).strftime("%Y-%m-%d %H:%M:%S IST")

    if severity == "HIGH":
        color = "#ff3b3b"
        icon = "RED ALERT"
        footer_msg = "INTRUSION DETECTED. Device " + device + " has been blocked."
    else:
        color = "#ffb020"
        icon = "WARNING"
        footer_msg = "Suspicious activity detected from an authorized device."

    subject = "[" + severity + "] Security Alert - " + device + " | " + file_name

    html_body = (
        "<html><body style='background:#0a0d13;font-family:monospace;'>"
        "<div style='max-width:560px;margin:30px auto;background:#111820;"
        "border:1px solid #1e2d3d;border-radius:12px;overflow:hidden;'>"
        "<div style='background:" + color + ";padding:18px 24px;'>"
        "<h2 style='margin:0;color:#fff;font-size:18px;'>"
        + icon + " SECURITY ALERT - " + severity +
        "</h2></div>"
        "<div style='padding:24px;color:#c9d1d9;font-size:14px;'>"
        "<p><b>Time:</b> " + now + "</p>"
        "<p><b>Device:</b> <span style='color:" + color + "'>" + device + "</span></p>"
        "<p><b>IP:</b> <span style='color:#00d4ff'>" + ip + "</span></p>"
        "<p><b>File:</b> <span style='color:#e8b86d'>" + file_name + "</span></p>"
        "<p><b>Action:</b> " + action + "</p>"
        "<div style='padding:14px;border-left:4px solid " + color + ";margin-top:16px;'>"
        "<p style='margin:0;color:" + color + "'>" + footer_msg + "</p>"
        "</div></div>"
        "<div style='padding:14px;border-top:1px solid #1e2d3d;text-align:center;'>"
        "<p style='color:#4a6070;font-size:11px;'>SOC SECURITY MONITORING DASHBOARD</p>"
        "</div></div></body></html>"
    )

    payload = json.dumps({
        "from":    "SOC Alert <onboarding@resend.dev>",
        "to":      [EMAIL_RECEIVER],
        "subject": subject,
        "html":    html_body
    }).encode("utf-8")

    try:
        # Use urllib instead of requests to avoid gevent recursion conflict
        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            "https://api.resend.com/emails",
            data=payload,
            headers={
                "Authorization": "Bearer " + RESEND_API_KEY,
                "Content-Type":  "application/json"
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            if resp.status == 200:
                print("[EMAIL] Alert sent to " + EMAIL_RECEIVER)
            else:
                print("[EMAIL] Failed with status " + str(resp.status))
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
        "time":     datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
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


def handle_intrusion(device, ip, file_name, action):
    print("=" * 48)
    print("  INTRUSION DETECTED")
    print("  Device : " + device)
    print("  IP     : " + ip)
    print("  File   : " + file_name)
    print("=" * 48)
    block_device(device)
    send_email_alert("HIGH", device, ip, file_name, action)


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
def unblock():
    data   = request.get_json(silent=True)
    device = data.get("device") if data else None
    if device and device in blocked_devices:
        blocked_devices.discard(device)
        return jsonify({"status": "unblocked", "device": device})
    return jsonify({"error": "Device not found"}), 404


@app.route("/clear", methods=["POST"])
def clear_logs():
    save_logs([])
    for q in clients:
        q.append({"type": "clear"})
    return jsonify({"status": "cleared"})


@app.route("/stream")
def stream():
    from gevent import sleep as gsleep
    def event_stream():
        q = []
        clients.append(q)
        try:
            while True:
                if q:
                    yield "data: " + json.dumps(q.pop(0)) + "\n\n"
                gsleep(0.1)
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
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)