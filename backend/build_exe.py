import os
import subprocess
import sys
import shutil

def run_command(cmd, cwd=None):
    print(f"[*] Running: {cmd}")
    result = subprocess.run(cmd, shell=True, cwd=cwd)
    if result.returncode != 0:
        print(f"[!] Command failed: {cmd}")
        sys.exit(1)

def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    frontend_dir = os.path.join(base_dir, "frontend")
    backend_dir = os.path.join(base_dir, "backend")

    print("========================================")
    print("      HexSniff Desktop App Builder      ")
    print("========================================")

    # 1. Build the Frontend
    print("\n[1] Building React Frontend...")
    run_command("npm install", cwd=frontend_dir)
    run_command("npm run build", cwd=frontend_dir)

    # 2. Compile the Executable
    print("\n[2] Compiling Python Backend and Packaging Executable...")
    
    # We use ';' separator for Windows, ':' for Linux
    sep = ';' if os.name == 'nt' else ':'
    
    dist_source = os.path.join(frontend_dir, "dist")
    
    pyinstaller_cmd = [
        sys.executable,
        "-m", "PyInstaller",
        "--name", "HexSniff",
        "--onefile",
        "--windowed", # Don't show command prompt (Windowless mode)
        "--add-data", f"{dist_source}{sep}frontend/dist",
        "--hidden-import", "scapy.layers.all",
        "--hidden-import", "scapy.layers.inet",
        "--hidden-import", "uvicorn.logging",
        "--hidden-import", "uvicorn.loops",
        "--hidden-import", "uvicorn.loops.auto",
        "--hidden-import", "uvicorn.protocols",
        "--hidden-import", "uvicorn.protocols.http",
        "--hidden-import", "uvicorn.protocols.http.auto",
        "--hidden-import", "uvicorn.protocols.websockets",
        "--hidden-import", "uvicorn.protocols.websockets.auto",
        "--hidden-import", "uvicorn.lifespan",
        "--hidden-import", "uvicorn.lifespan.on",
        "--hidden-import", "webview",
        "desktop_app.py"
    ]

    # Convert list to string for shell execution
    cmd_str = " ".join(f'"{arg}"' if " " in arg else arg for arg in pyinstaller_cmd)
    
    run_command(cmd_str, cwd=backend_dir)

    print("\n[✓] Build Complete!")
    print(f"[*] Your executable is located at: {os.path.join(backend_dir, 'dist', 'HexSniff.exe')}")

if __name__ == "__main__":
    main()
