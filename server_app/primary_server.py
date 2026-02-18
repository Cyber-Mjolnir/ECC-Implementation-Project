import socket
import json
import hashlib
import os
import uuid

# Configuration
HOST = '127.0.0.1'
PORT = 3000
USER_DB = 'server_app/ledger/users.json'

# Ensure the database directory exists
os.makedirs(os.path.dirname(USER_DB), exist_ok=True)
if not os.path.exists(USER_DB):
    with open(USER_DB, 'w') as f:
        json.dump({}, f)

def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()

def handle_auth(data):
    action = data.get("action")
    username = data.get("username")
    password = data.get("password")
    
    if not username or not password:
        return {"status": "error", "message": "Missing credentials."}

    hashed_user = hash_data(username)
    hashed_pass = hash_data(password)
    
    with open(USER_DB, 'r') as f:
        try:
            users = json.load(f)
        except json.JSONDecodeError:
            users = {}

    if action == "signup":
        if hashed_user in users:
            return {"status": "error", "message": "User already exists!"}
        
        public_id = f"BID-{str(uuid.uuid4())[:8].upper()}"
        users[hashed_user] = {
            "password": hashed_pass,
            "public_id": public_id
        }
        
        with open(USER_DB, 'w') as f:
            json.dump(users, f)
            
        print(f"[Auth] New User Registered: {public_id}")
        return {"status": "success", "message": "Signup successful!", "public_id": public_id}

    elif action == "login":
        if hashed_user in users and users[hashed_user]["password"] == hashed_pass:
            assigned_id = users[hashed_user]["public_id"]
            print(f"[Auth] Login Successful: {assigned_id}")
            return {"status": "success", "message": "Login successful!", "public_id": assigned_id}
        
        return {"status": "error", "message": "Invalid username or password."}

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((HOST, PORT))
        server.listen(5)
        print("="*60)
        print(f"CSePS PRIMARY SERVER - LISTENING ON PORT {PORT}")
        print("SECURE USER AUTHENTICATION & PRIVACY MODE: ENABLED")
        print("="*60)
        print("[Status] Waiting for Bidder connections...")

        while True:
            client, addr = server.accept()
            # print(f"[Log] Connection from {addr}") # For debugging
            
            try:
                # Increased buffer size and added basic validation
                raw_data = client.recv(4096).decode('utf-8')
                
                if not raw_data:
                    continue
                
                request = json.loads(raw_data)
                response = handle_auth(request)
                
                # Ensure the response is sent back before closing
                client.sendall(json.dumps(response).encode('utf-8'))
                
            except Exception as e:
                print(f"[Error] Failed to process request: {e}")
            finally:
                client.close()

    except KeyboardInterrupt:
        print("\n[System] Primary Server shutting down...")
    finally:
        server.close()

if __name__ == "__main__":
    start_server()