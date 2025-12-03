#!/usr/bin/env python3
"""
honeypot_server.py

A corrected, robust honeypot SSH-like TCP service that:
- simulates a minimal Debian server prompt
- handles common shell commands locally (cd, pwd, ls, whoami, id, uname, cat)
- optionally calls Google GenAI (gemini) if GEMINI_API_KEY is set and SDK import succeeds
- logs sessions to a sqlite3 database
- normalizes paths using posixpath
- uses safe retry/backoff logic for remote LLM calls
"""

import os
import socket
import threading
import sqlite3
import json
import datetime
import time
import posixpath
import traceback

# Optional (safe) attempt to import genai SDK. If unavailable, we'll fallback to local handlers.
GEMINI_AVAILABLE = False
gemini_client = None
try:
    # Prefer new-style SDK if available
    from google import genai
    from google.genai import types  # may or may not exist depending on SDK version
    API_KEY = os.environ.get("GEMINI_API_KEY")
    if API_KEY:
        try:
            # Try to initialize client with api_key kwarg (common in newer SDKs)
            gemini_client = genai.Client(api_key=API_KEY)
            GEMINI_AVAILABLE = True
            print("[+] genai.Client initialized using google.genai (new SDK style).")
        except Exception:
            # Try without api_key (some environments read from env automatically)
            try:
                gemini_client = genai.Client()
                GEMINI_AVAILABLE = True
                print("[+] genai.Client initialized (API key may be read from env).")
            except Exception as e:
                print("[!] genai import succeeded but client init failed:", e)
                GEMINI_AVAILABLE = False
    else:
        print("[*] GEMINI_API_KEY not set; LLM integration disabled. Running local-only honeypot.")
except Exception:
    # Try older 'google.generativeai' style fallback
    try:
        import google.generativeai as genai_old
        API_KEY = os.environ.get("GEMINI_API_KEY")
        if API_KEY:
            genai_old.configure(api_key=API_KEY)
            gemini_client = genai_old
            GEMINI_AVAILABLE = True
            print("[+] google.generativeai initialized (old SDK style).")
        else:
            print("[*] GEMINI_API_KEY not set; LLM integration disabled. Running local-only honeypot.")
    except Exception:
        print("[*] genai SDK not available -- LLM integration disabled. Running local-only honeypot.")

# Server bind configuration
HOST = "0.0.0.0"
PORT = 2222  # non-privileged port

# Database file
DB_FILE = "honeypot_logs.db"

# SYSTEM_PROMPT is used only when connecting to LLM; keep it concise and safe.
SYSTEM_PROMPT = (
    "You are a simulated minimal Debian server 'server-dev-01'.\n"
    "Respond only with the exact output of the requested shell command followed by a newline.\n"
    'If a command is unknown, return "bash: [command]: command not found\\n".\n'
    "Current directory: {current_dir}\n"
)

# --- Database setup and logging ---


def setup_database():
    conn = sqlite3.connect(DB_FILE)
    try:
        c = conn.cursor()
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY,
                ip_address TEXT,
                start_time TEXT,
                final_dir TEXT,
                command_count INTEGER,
                commands_json TEXT,
                timestamp TEXT
            )
            """
        )
        conn.commit()
    finally:
        conn.close()
    print(f"[+] Database setup complete ({DB_FILE}).")


def log_session(session_data):
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        ip = session_data.get("ip_address", "")
        start_time = session_data.get("start_time", "")
        final_dir = session_data.get("current_dir", "/")
        commands = session_data.get("command_history", [])
        command_count = len(commands)
        commands_json = json.dumps(commands, ensure_ascii=True)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        c.execute(
            """
            INSERT INTO sessions (ip_address, start_time, final_dir, command_count, commands_json, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (ip, start_time, final_dir, command_count, commands_json, timestamp),
        )
        conn.commit()
        print(f"[+] Session logged: {ip} commands={command_count}")
    except sqlite3.Error as e:
        print("[-] Database error while logging session:", e)
    finally:
        if conn:
            conn.close()


# --- Path / state handling ---


def normalize_dir(path):
    """
    Normalize and ensure trailing slash if not root.
    Accepts posix-style paths only (we're simulating a Unix system).
    """
    if not path:
        return "/"
    normalized = posixpath.normpath(path)
    if normalized == ".":
        normalized = "/"
    if normalized != "/" and not normalized.endswith("/"):
        normalized = normalized + "/"
    return normalized


def update_state(command, current_dir):
    """
    Update directory for 'cd' commands. Returns new current_dir.
    """
    cmd = command.strip()
    if cmd == "cd" or cmd.startswith("cd "):
        parts = cmd.split(maxsplit=1)
        target = parts[1] if len(parts) > 1 else ""
        if not target or target == "~":
            return "/"
        # absolute?
        if target.startswith("/"):
            return normalize_dir(target)
        # relative
        joined = posixpath.join(current_dir, target)
        return normalize_dir(joined)
    return current_dir


# --- Local command handlers (common commands) ---


def handle_local_command(command, session_state):
    """
    Handle a set of commands locally to avoid external calls.
    Returns (output_str or None). If None, means not handled locally.
    """
    cmd = command.strip()
    cmd_lower = cmd.lower()
    cur = session_state["current_dir"]

    # cd (silent)
    if cmd == "cd" or cmd_lower.startswith("cd "):
        new_dir = update_state(cmd, cur)
        session_state["current_dir"] = new_dir
        session_state["command_history"].append(cmd)
        return ""  # silent

    # pwd
    if cmd_lower == "pwd":
        session_state["command_history"].append(cmd)
        return cur + "\n"

    # whoami
    if cmd_lower == "whoami":
        session_state["command_history"].append(cmd)
        return "user\n"

    # id
    if cmd_lower == "id":
        session_state["command_history"].append(cmd)
        return "uid=1000(user) gid=1000(user) groups=1000(user)\n"

    # uname -a
    if cmd_lower.startswith("uname"):
        session_state["command_history"].append(cmd)
        return "Linux server-dev-01 4.19.0-21-amd64 #1 SMP Debian 9 x86_64 GNU/Linux\n"

    # ls (very simple simulation)
    if cmd_lower.startswith("ls"):
        session_state["command_history"].append(cmd)
        # Basic behavior: if path present, show a few directories; otherwise default root listing
        tokens = cmd.split(maxsplit=1)
        target = tokens[1].strip() if len(tokens) > 1 else cur
        # Normalize target but don't allow traversal above root in listing
        try:
            target_norm = normalize_dir(posixpath.join(cur, target)) if not target.startswith("/") else normalize_dir(target)
        except Exception:
            target_norm = cur
        # Provide a plausible listing
        if target_norm == "/":
            return "bin\nboot\ndev\netc\nhome\nlib\nproc\nroot\nrun\nsbin\ntmp\nusr\nvar\n"
        elif target_norm.endswith("home/"):
            return "user\n"
        else:
            # Generic single-file placeholder
            return "file.txt\n"

    # cat (very simple simulation for a few known files)
    if cmd_lower.startswith("cat "):
        session_state["command_history"].append(cmd)
        target = cmd.split(maxsplit=1)[1]
        if target in ("/etc/passwd", "etc/passwd"):
            return "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:User,,,:/home/user:/bin/bash\n"
        if target in ("/etc/hostname", "etc/hostname"):
            return "server-dev-01\n"
        # Default fallback for cat on unknown file
        return f"cat: {target}: No such file or directory\n"

    # echo
    if cmd_lower.startswith("echo "):
        session_state["command_history"].append(cmd)
        content = cmd.split(" ", 1)[1]
        return content + "\n"

    # help placeholder
    if cmd_lower in ("help", "--help", "-h"):
        session_state["command_history"].append(cmd)
        return (
            "Supported (simulated) commands: cd, pwd, ls, whoami, id, uname, cat, echo\n"
        )

    # Not handled locally
    return None


# --- LLM integration (optional) ---


def call_llm_for_command(command, session_state, max_retries=3):
    """
    Attempt to call LLM to generate an output for a command.
    If LLM unavailable or all retries fail, returns None.
    """
    if not GEMINI_AVAILABLE or gemini_client is None:
        return None

    # Build a safe system instruction and prompt
    current_dir = session_state["current_dir"]
    system_instruction = SYSTEM_PROMPT.format(current_dir=current_dir)
    prompt_text = f"{system_instruction}\n{command}\n"
    backoff = 0.5

    for attempt in range(1, max_retries + 1):
        try:
            # Try the new SDK style (google.genai.Client)
            try:
                # Some SDK versions accept 'contents' as list of strings
                if hasattr(gemini_client, "models") and hasattr(gemini_client.models, "generate_content"):
                    # prefer typed config if available; otherwise pass minimal config
                    config_kwargs = {"temperature": 0.2, "max_output_tokens": 300}
                    # Avoid manipulating safety settings; use provider defaults.

                    # The 'contents' parameter accepts a list of strings or structured Content depending on SDK
                    contents = [system_instruction, command]
                    response = gemini_client.models.generate_content(
                        model="gemini-2.5-pro",
                        contents=contents,
                        config=types.GenerateContentConfig(**config_kwargs)
                        if "types" in globals() and hasattr(types, "GenerateContentConfig")
                        else None,
                    )
                    # Try to extract text robustly depending on SDK return shape
                    text = None
                    if hasattr(response, "text"):
                        text = response.text
                    elif isinstance(response, dict):
                        text = response.get("candidates", [{}])[0].get("content", {}).get("text")
                    else:
                        # Best-effort extract
                        text = str(response)
                    if text and text.strip():
                        return text.strip() + "\n"
            except Exception:
                # fallback: older SDK (google.generativeai)
                if hasattr(gemini_client, "generate_text"):
                    # old-style
                    response = gemini_client.generate_text(
                        model="chat-bison",
                        prompt=prompt_text,
                        temperature=0.2,
                        max_output_tokens=300,
                    )
                    # Many older returns use .text or .content
                    text = getattr(response, "text", None) or response.get("candidates", [{}])[0].get("content")
                    if text and text.strip():
                        return text.strip() + "\n"
                # If above fails, raise to get caught below and retry
                raise

        except Exception as e:
            # Print details for debugging, but continue retrying
            print(f"[-] LLM call attempt {attempt}/{max_retries} failed: {e}")
            # For debugging you can uncomment the next line:
            # traceback.print_exc()
            if attempt < max_retries:
                time.sleep(backoff)
                backoff *= 2
                continue
            else:
                # All retries exhausted
                return None

    return None


# --- Main AI/handler dispatch ---


def get_command_output(command, session_state):
    """
    Returns (output_string, session_state).
    Attempts local handling first, then optional LLM, then fallback 'command not found'.
    """
    # 1) Local handlers
    local = handle_local_command(command, session_state)
    if local is not None:
        # local may be empty string for silent commands
        return local, session_state

    # 2) Try LLM (if available)
    llm_out = call_llm_for_command(command, session_state)
    if llm_out is not None:
        # On success, we treat as a valid response and log the command into history
        session_state["command_history"].append(command)
        return llm_out, session_state

    # 3) Fallback: unknown command
    # Do not append to history in fallback to avoid polluting logs with false attempts (keeps parity with your earlier logic)
    return f"bash: {command}: command not found\n", session_state


# --- Networking / socket handling ---


def safe_send(sock, data_bytes):
    try:
        sock.sendall(data_bytes)
        return True
    except (BrokenPipeError, ConnectionResetError) as e:
        print(f"[-] Socket send failed: {e}")
        return False
    except Exception as e:
        print(f"[-] Unexpected socket error on send: {e}")
        return False


def handle_client(client_socket, address):
    ip = address[0]
    port = address[1]
    print(f"[!] New connection from {ip}:{port}")

    session_state = {
        "current_dir": "/",
        "command_history": [],
        "ip_address": ip,
        "start_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    try:
        # Send initial banner and prompt
        if not safe_send(client_socket, b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\n"):
            return
        prompt = f"user@server-dev-01:{session_state['current_dir']}$ "
        if not safe_send(client_socket, prompt.encode("utf-8")):
            return

        # Main receive/send loop
        while True:
            try:
                data = client_socket.recv(4096)
                if not data:
                    # client closed connection
                    break

                try:
                    command = data.decode("utf-8", errors="ignore").strip()
                except Exception:
                    command = ""

                if not command:
                    # re-send prompt and continue
                    prompt = f"user@server-dev-01:{session_state['current_dir']}$ "
                    if not safe_send(client_socket, prompt.encode("utf-8")):
                        break
                    continue

                print(f"[*] Received command from {ip}: '{command}' (cwd={session_state['current_dir']})")

                output, session_state = get_command_output(command, session_state)

                # Send output (may be empty for silent commands like 'cd')
                if output:
                    if not safe_send(client_socket, output.encode("utf-8")):
                        break

                # Send prompt
                prompt = f"user@server-dev-01:{session_state['current_dir']}$ "
                if not safe_send(client_socket, prompt.encode("utf-8")):
                    break

            except ConnectionResetError:
                print(f"[-] ConnectionResetError from {ip}:{port}")
                break
            except Exception as e:
                print(f"[-] Unexpected error while handling client {ip}:{port}: {e}")
                traceback.print_exc()
                break
    finally:
        # Connection closed, log session and cleanup
        try:
            print(f"[-] Connection closed from {ip}:{port}. Captured commands: {len(session_state['command_history'])}")
            log_session(session_state)
        finally:
            try:
                client_socket.close()
            except Exception:
                pass


def start_honeypot(bind_host=HOST, bind_port=PORT):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((bind_host, bind_port))
    server.listen(10)
    print(f"[*] Honeypot listening on {bind_host}:{bind_port} ...")

    try:
        while True:
            client, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(client, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("[*] KeyboardInterrupt received, shutting down server.")
    except Exception as e:
        print("[-] Server exception:", e)
    finally:
        try:
            server.close()
        except Exception:
            pass


# --- Entry point ---


if __name__ == "__main__":
    setup_database()
    start_honeypot()
