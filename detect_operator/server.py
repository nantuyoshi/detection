from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl
import json
import datetime
import os

ALERT_LOG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "alert.log"
)

def is_suspicious(event: dict) -> bool:
    if event.get("event_type") == "NETWORK_CONNECT":
        if "unknown" in event.get("detail", ""):
            return True
    return False


class DetectionHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        try:
            event = json.loads(body)
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            return

        print(f"[RECEIVED] {event}")

        if is_suspicious(event):
            self.write_alert(event)
            print(f"{datetime.datetime.now()} ALERT {event}")
        else:
            print("[INFO] 異常なし")

        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        return

    @staticmethod
    def write_alert(event: dict):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(ALERT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"{timestamp} ALERT {event}\n")


def run_server(host="127.0.0.1", port=5000):
    httpd = HTTPServer((host, port), DetectionHandler)

    # ★ HTTPS化の核心部分 ★
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print(f"[INFO] 検知サーバー起動 https://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[INFO] サーバー停止")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    run_server()
