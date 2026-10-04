# -*- coding: utf-8 -*-
import os
import sys
import time
import json
import socket
import argparse
from datetime import datetime

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent, FileDeletedEvent
except ImportError:
    print("Install watchdog: pip install watchdog")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)

DEFAULT_SERVER = "http://127.0.0.1:5000"
DEFAULT_WATCH = "." if os.name != "nt" else os.path.expanduser("~\\Documents")

# إمكانية الربط بالهاردوير مستقبلاً (Raspberry Pi, Mini-PC)
def _load_config():
    try:
        import sys
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)
        from config import HARDWARE
        return HARDWARE.get('server_url', DEFAULT_SERVER), HARDWARE.get('auto_register_agent', True)
    except ImportError:
        return DEFAULT_SERVER, True


def get_hostname():
    try:
        return socket.gethostname()
    except Exception:
        return "edge-agent"


class FileActivityHandler(FileSystemEventHandler):

    def __init__(self, server_url, user_id, ignored_patterns=None, agent_id=None, agent_source='hardware',
                 verify_tls=True):
        super().__init__()
        self.server_url = server_url.rstrip("/")
        self.user_id = user_id
        self.agent_id = agent_id or user_id  # للربط بالهاردوير مستقبلاً
        self.agent_source = agent_source  # 'hardware' عند تشغيل على Raspberry Pi
        self.verify_tls = verify_tls
        self.ignored = set(ignored_patterns or [])
        self._last_modified = {}

    def _should_ignore(self, path):
        path_lower = path.lower()
        for ign in self.ignored:
            if ign in path_lower:
                return True
        return False

    def _send_event(self, activity_type, src_path):
        if not src_path or not os.path.basename(src_path):
            return
        if self._should_ignore(src_path):
            return
        path_norm = src_path.replace("\\", "/")
        payload = {
            "user_id": self.user_id,
            "activity_type": activity_type,
            "file_path": path_norm,
        }
        if getattr(self, 'agent_id', None):
            payload["agent_id"] = self.agent_id
            payload["agent_source"] = getattr(self, 'agent_source', 'hardware')
        try:
            r = requests.post(
                f"{self.server_url}/api/events",
                json=payload,
                timeout=10,
                verify=self.verify_tls,
            )
            if r.status_code == 200:
                data = r.json()
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {activity_type} {path_norm} -> {data.get('risk_level', '?')}")
            else:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {activity_type} {path_norm} -> Server error {r.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {activity_type} {path_norm} -> Connection failed: {e}")

    def on_created(self, event):
        if event.is_directory:
            return
        self._send_event("Create", event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        path = event.src_path
        now = time.time()
        if path in self._last_modified and (now - self._last_modified[path]) < 2:
            return
        self._last_modified[path] = now
        if len(self._last_modified) > 500:
            self._last_modified.clear()
        self._send_event("Modify", path)

    def on_deleted(self, event):
        if event.is_directory:
            return
        self._send_event("Delete", event.src_path)


def main():
    parser = argparse.ArgumentParser(description="Guardian-X Edge Agent - Real-time file monitoring")
    parser.add_argument("--path", "-p", default=DEFAULT_WATCH, help="Directory to monitor")
    parser.add_argument("--server", "-s", default=None, help="Guardian-X server URL (default: config or 127.0.0.1:5000)")
    parser.add_argument("--user", "-u", default=None, help="Endpoint/user ID (default: hostname)")
    parser.add_argument("--agent-id", "-a", default=None, help="Agent ID for hardware registration (Raspberry Pi, Mini-PC)")
    parser.add_argument("--ignore", "-i", action="append", default=[],
                        help="Ignore paths containing this string (e.g. .git, __pycache__)")
    parser.add_argument("--insecure", action="store_true",
                        help="تعطيل التحقق من شهادة TLS (للتطوير مع شهادة ذاتية)")
    args = parser.parse_args()

    watch_path = os.path.abspath(args.path)
    if not os.path.isdir(watch_path):
        print(f"Error: {watch_path} is not a directory")
        sys.exit(1)

    user_id = args.user or get_hostname()
    server_url = args.server or _load_config()[0]
    agent_id = args.agent_id or user_id
    ignored = list(args.ignore) + [".git", "__pycache__", "node_modules", ".cursor", 
    "desktop.ini", ".tmp", "~$", ".TMP", ".lnk", "thumbs.db"]
    print(f"Guardian-X Edge Agent")
    print(f"  Watch: {watch_path}")
    print(f"  Server: {server_url}")
    print(f"  Endpoint ID: {user_id}")
    print(f"  Agent ID: {agent_id} (for hardware registration)")
    print("  Monitoring... (Ctrl+C to stop)\n")

    handler = FileActivityHandler(
        server_url, user_id, ignored, agent_id=agent_id, agent_source='hardware',
        verify_tls=not args.insecure,
    )
    observer = Observer()
    observer.schedule(handler, watch_path, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
    print("\nStopped.")


if __name__ == "__main__":
    main()
