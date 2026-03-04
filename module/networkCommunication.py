import socket
import json
import os
from module.configuration import SERVER_HOST, SERVER_PORT
import module.ecc_helper as ecc
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Global Cache for Server Public Key
SERVER_PUBKEY = None

def get_server_pubkey():
    """Fetches the server's public key for the encryption layer."""
    global SERVER_PUBKEY
    if SERVER_PUBKEY:
        return SERVER_PUBKEY
    
    # Simple unencrypted request to get the key
    try:
        req = {"action": "get_server_pubkey"}
        raw_res = send_request_unencrypted(req)
        if raw_res.get("status") == "success":
            SERVER_PUBKEY = raw_res.get("pubkey")
            return SERVER_PUBKEY
    except:
        pass
    return None

def send_request_unencrypted(request_dict):
    """Internal use for the initial key exchange."""
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(10)
        client.connect((SERVER_HOST, SERVER_PORT))
        client.sendall(json.dumps(request_dict).encode('utf-8'))
        response_data = client.recv(8192).decode('utf-8')
        client.close()
        return json.loads(response_data) if response_data else {}
    except:
        return {}

def send_request_raw(request_dict):
    """
    UPGRADED: Automatically wraps all communication in an ECIES encryption layer.
    """
    server_pub = get_server_pubkey()
    if not server_pub:
        return {"status": "error", "message": "Could not establish secure connection to server."}

    helper = ecc.ECCHelper()
    
    # 1. Generate Ephemeral Session Key for this specific request/response
    session_priv = ec.generate_private_key(ec.SECP256K1())
    session_pub_pem = session_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    # 2. Encrypt actual request for the Server
    request_json = json.dumps(request_dict).encode('utf-8')
    encrypted_req = helper.encrypt_data(server_pub, request_json)
    
    # 3. Wrap into a transport envelope
    envelope = {
        "type": "wrapped_request",
        "payload": encrypted_req,
        "client_pub": session_pub_pem
    }
    
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(10)
        client.connect((SERVER_HOST, SERVER_PORT))
        
        client.sendall(json.dumps(envelope).encode('utf-8'))
        
        # 4. Receive Wrapped Response
        response_data = client.recv(16384).decode('utf-8') # Increased buffer for encrypted blobs
        client.close()
        
        if not response_data:
            return {"status": "error", "message": "No response"}
            
        outer_response = json.loads(response_data)
        
        if outer_response.get("type") == "wrapped_response":
            # 5. Decrypt the actual response using our session private key
            decrypted_bytes = helper.decrypt_data(session_priv, outer_response.get("payload"))
            if not decrypted_bytes:
                return {"status": "error", "message": "Response Decryption Failed."}
            return json.loads(decrypted_bytes.decode('utf-8'))
        else:
            return outer_response
            
    except Exception as e:
        return {"status": "error", "message": f"Connection failed: {str(e)}"}

def send_request(action, username, password):
    """Backward compatibility for bidder logins/signup."""
    request = {"action": action, "username": username, "password": password}
    return send_request_raw(request)
