import socket
import json
import os
from module.configuration import SERVER_HOST, SERVER_PORT

def send_request_raw(request_dict):
    """General network communication that sends a dictionary to the server."""
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(10) # 10 seconds timeout for reliability
        client.connect((SERVER_HOST, SERVER_PORT))
        
        client.sendall(json.dumps(request_dict).encode('utf-8'))
        
        response_data = client.recv(4096).decode('utf-8')
        client.close()
        
        return json.loads(response_data) if response_data else {"status": "error", "message": "No response"}
    except Exception as e:
        return {"status": "error", "message": f"Connection failed: {str(e)}"}

def send_request(action, username, password):
    """Backward compatibility for bidder logins/signup."""
    request = {"action": action, "username": username, "password": password}
    return send_request_raw(request)
