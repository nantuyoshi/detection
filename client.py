import urllib.request
import json
import time

SERVER_URL = "http://localhost:8000"

logs = [
    {"event_type": "PROCESS_CREATE", "detail": "cmd.exe"},
    {"event_type": "FILE_ACCESS", "detail": "secret.txt"},
    {"event_type": "NETWORK_CONNECT", "detail": "unknown.exe"},
]

for log in logs:
    data = json.dumps(log).encode("utf-8")
    req = urllib.request.Request(
        SERVER_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    print(f"[SEND] {log}")
    urllib.request.urlopen(req)
    time.sleep(3)
