

import socket

import json
import os

from module.configuration import SERVER_HOST, SERVER_PORT

def send_request(action, username, password):
    """Handles network communication with the Primary Server."""
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5) 
        client.connect((SERVER_HOST, SERVER_PORT))
        
        request = {"action": action, "username": username, "password": password}
        client.sendall(json.dumps(request).encode('utf-8'))
        
        response_data = client.recv(4096).decode('utf-8')
        client.close()
        
        return json.loads(response_data) if response_data else {"status": "error", "message": "No response"}
    except Exception as e:
        return {"status": "error", "message": f"Connection failed: {str(e)}"}