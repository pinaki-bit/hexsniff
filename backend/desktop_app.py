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

if __name__ == "__main__":
    # Start the FastAPI server in a daemon thread
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    # Wait until Uvicorn actually binds to the port
    wait_for_server(8000)

    # Launch PyWebView native window
    # We load the root URL which will now serve our static React build
    window = webview.create_window(
        'HexSniff NDR', 
        'http://127.0.0.1:8000',
        width=1400,
        height=900,
        min_size=(1024, 768),
        background_color='#05080f'
    )
    
    # Run the webview event loop (blocks until window is closed)
    webview.start(debug=False)
    
    # Exit gracefully when window is closed
    sys.exit(0)
