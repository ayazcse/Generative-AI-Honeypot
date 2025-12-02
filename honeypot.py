import os
import socket
import threading
import sqlite3
import json
import datetime
import requests 


# --- LLM API CONFIGURATION ---

# Configuration (REPLACE THE KEY WITH YOUR VERIFIED API KEY)
# --- Groq Configuration ---
LLM_API_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions" 
API_KEY = os.environ.get("GROQ_API_KEY") 

if not API_KEY:
    print("[-] FATAL: GROQ_API_KEY environment variable not set.")
    # Exit or handle error if key is missing
    raise EnvironmentError("GROQ_API_KEY not found. Please set the environment variable.")
# --------------------------

# The core persona rules
SYSTEM_PROMPT = """
You are a minimal, low-privilege Linux server running Debian 9. 
Your responses must STRICTLY emulate the output of the executed command. 
The current directory is {current_dir}. Use the conversation history to maintain context.
NEVER explain yourself, break character, or mention that you are an AI model or simulation.
If a command runs silently (like 'cd'), return no output.
"""

# Configuration for the server listener
HOST = '0.0.0.0'  
PORT = 2222        

# --- DATABASE LOGGING FUNCTIONS ---

def setup_database():
    """Initializes the SQLite database and creates the sessions table."""
    conn = sqlite3.connect('honeypot_logs.db')
    c = conn.cursor()
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY,
            ip_address TEXT,
            start_time TEXT,
            final_dir TEXT,
            command_count INTEGER,
            commands_json TEXT,  -- Stored as a JSON string
            timestamp TEXT
        )
    ''')
    conn.commit()
    conn.close()
    print("[+] Database setup complete.")

def log_session(session_data):
    """Connects to the DB and inserts the captured session data."""
    conn = None
    try:
        conn = sqlite3.connect('honeypot_logs.db')
        c = conn.cursor()
        
        # Prepare data for insertion
        ip = session_state['ip_address']
        start_time = session_state['start_time']
        final_dir = session_state['current_dir']
        commands = session_state['command_history']
        command_count = len(commands)
        
        # FIX: Use ensure_ascii=True to handle potentially problematic characters in commands
        commands_json = json.dumps(commands, ensure_ascii=True)
        
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        c.execute("""
            INSERT INTO sessions (ip_address, start_time, final_dir, command_count, commands_json, timestamp) 
            VALUES (?, ?, ?, ?, ?, ?)
        """, (ip, start_time, final_dir, command_count, commands_json, timestamp))
        
        conn.commit()
        print(f"[+] Session logged successfully (Commands: {command_count})")
        
    except sqlite3.Error as e:
        print(f"[-] Database Error: {e}")
    finally:
        if conn:
            conn.close()

# --- STATE MANAGEMENT FUNCTION ---

def update_state(command, current_dir):
    """Parses 'cd' commands to simulate directory changes."""
    if command.lower().startswith("cd "):
        new_dir = command[3:].strip()
        
        if new_dir == "..":
            parts = [p for p in current_dir.split('/') if p]
            return '/' + '/'.join(parts[:-1]) + '/' if parts else '/'
        
        elif new_dir.startswith("/"):
            return new_dir.rstrip('/') + '/'
        
        elif new_dir:
            return current_dir.rstrip('/') + '/' + new_dir.rstrip('/') + '/'
            
    return current_dir

# --- AI RESPONSE FUNCTION (FINAL CORRECTED VERSION FOR GROQ) ---

def get_ai_response(command, session_state):
    """
    REAL LLM: Makes an API call to a generative model, processes the output.
    """
    current_dir = session_state['current_dir']
    
    # *** START: LOCAL COMMAND HANDLERS (for reliable state check) ***
    command_lower = command.lower().strip()
    
    if command_lower.startswith("cd ") or command_lower == "cd":
        # Handle 'cd' locally, update state, and return empty output (silent command)
        new_dir = update_state(command, current_dir)
        session_state['current_dir'] = new_dir
        session_state['command_history'].append(command)
        print(f"[*] LOCAL HANDLER: 'cd' to {new_dir}")
        return "", session_state
    
    if command_lower == "pwd":
        # Handle 'pwd' locally, update state, and return current directory
        new_dir = update_state(command, current_dir)
        session_state['current_dir'] = new_dir
        session_state['command_history'].append(command)
        print(f"[*] LOCAL HANDLER: 'pwd' returned {current_dir}")
        return current_dir + "\n", session_state
    # *** END: LOCAL COMMAND HANDLERS ***
    
    # 1. Construct the message history (CORRECT OPENAI/GROQ FORMAT)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT.format(current_dir=current_dir)}
    ]
    
    # Add past commands/responses to maintain state
    for past_command in session_state['command_history']:
        messages.append({"role": "user", "content": past_command}) 
    
    # Add the current command
    messages.append({"role": "user", "content": command})

    try:
        # 2. Make the API call (Final Minimal Groq Payload)
        headers = {
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": "mixtral-8x7b-32768", # <-- Changed model to Mixtral
            "messages": messages,     
        }
        
        response = requests.post(LLM_API_ENDPOINT, headers=headers, json=payload)
        response.raise_for_status()
        
        # 3. Process the response and clean up (CORRECTED OPENAI/GROQ PARSING)
        ai_output = response.json()['choices'][0]['message']['content'].strip() + "\n"
        
        # 4. State Update (Log non-local commands for context)
        session_state['command_history'].append(command)
        
        return ai_output, session_state

    except requests.exceptions.RequestException as e:
        print(f"[-] LLM API Error: {e}")
        # Fallback response for stability if the API fails
        fallback_response = "bash: connection error: command failed\n"
        session_state['command_history'].append(command) 
        return fallback_response, session_state

# --- NETWORK CORE FUNCTIONS ---

def handle_client(client_socket, address):
    print(f"[!] New connection from {address[0]}:{address[1]}")
    
    # Initialize the state for this specific attacker session
    session_state = {
        'current_dir': '/',
        'command_history': [],
        'ip_address': address[0],
        'start_time': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    client_socket.send(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\n")
    
    while True:
        try:
            data = client_socket.recv(1024)
            if not data:
                break
            
            # FIX: Use errors='ignore' to robustly decode potentially dirty input
            command = data.decode('utf-8', errors='ignore').strip()
            print(f"[*] Command: {command} in {session_state['current_dir']}")
            
            # CORE LOGIC: Get AI response and update state
            response, session_state = get_ai_response(command, session_state)
            
            client_socket.send(response.encode('utf-8'))
            
        except ConnectionResetError:
            break
            
    print(f"[-] Connection closed. Commands captured: {len(session_state['command_history'])}")
    
    # LOGGING STEP: Save the session data to the database
    log_session(session_state)
    
    client_socket.close()

def start_honeypot():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[*] Honeypot listening on port {PORT}...")
    
    while True:
        client, addr = server.accept()
        client_handler = threading.Thread(target=handle_client, args=(client, addr))
        client_handler.start()

# --- STARTUP LOGIC ---
if __name__ == "__main__":
    setup_database()
    start_honeypot()