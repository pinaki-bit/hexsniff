import threading
import time
import webview
import uvicorn
import socket
import sys

def run_server():
    from app.main import app
    # Uvicorn run blocking call
    # We must suppress access logs for performance
    uvicorn.run(app, host="127.0.0.1", port=8000, access_log=False)

def wait_for_server(port):
    """Wait for the local server to be ready."""
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            result = sock.connect_ex(('127.0.0.1', port))
            if result == 0:
                break
        time.sleep(0.1)

class Api:
    def __init__(self):
        self._window = None

    def set_window(self, window):
        self._window = window

    def save_base64(self, default_filename, content_b64):
        try:
            import base64
            result = self._window.create_file_dialog(
                webview.SAVE_DIALOG, directory='', save_filename=default_filename
            )
            if result and len(result) > 0:
                with open(result[0], 'wb') as f:
                    f.write(base64.b64decode(content_b64))
                return True
        except Exception as e:
            print(f"Error saving base64: {e}")
        return False

    def save_pcap(self, default_filename):
        try:
            import os, shutil
            result = self._window.create_file_dialog(
                webview.SAVE_DIALOG, directory='', save_filename=default_filename
            )
            if result and len(result) > 0:
                temp_pcap = os.path.join(os.getcwd(), "temp", "capture.pcap")
                if os.path.exists(temp_pcap):
                    shutil.copy2(temp_pcap, result[0])
                    return True
        except Exception as e:
            print(f"Error saving pcap: {e}")
        return False

if __name__ == "__main__":
    # Start the FastAPI server in a daemon thread
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    # Wait until Uvicorn actually binds to the port
    wait_for_server(8000)

    # Launch PyWebView native window
    api = Api()
    window = webview.create_window(
        'HexSniff NDR', 
        'http://127.0.0.1:8000',
        width=1400,
        height=900,
        min_size=(1024, 768),
        background_color='#05080f',
        js_api=api
    )
    api.set_window(window)
    
    # Run the webview event loop (blocks until window is closed)
    webview.start(debug=False)
    
    # Exit gracefully when window is closed
    sys.exit(0)
