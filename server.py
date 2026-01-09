from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from datetime import datetime

PORT = 8000
ALERT_LOG = "alert.log"

class LogHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)
        log = json.loads(body.decode("utf-8"))

        print(f"[RECEIVED] {log}")

        # 仮検知ルール
        if log.get("event_type") == "NETWORK_CONNECT":
            msg = f"{datetime.now()} ALERT {log}\n"
            with open(ALERT_LOG, "a", encoding="utf-8") as f:
                f.write(msg)
            print(msg.strip())
        else:
            print("[INFO] 異常なし")

        self.send_response(200)
        self.end_headers()

if __name__ == "__main__":
    print("[INFO] 検知サーバー起動（待ち受け中）")
    server = HTTPServer(("localhost", PORT), LogHandler)
    server.serve_forever()
