import socket
import json
import datetime
import threading

# Configuration
TARGET_HOST = '127.0.0.1'
TARGET_PORT = 3000  # The real server
PROXY_HOST = '127.0.0.1'
PROXY_PORT = 3001  # The "Attacker" port

def handle_client(client_socket):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    
    try:
        # 1. RECEIVE FROM CLIENT (The Bidder/Officer App)
        client_data = client_socket.recv(8192)
        if not client_data:
            return

        print(f"\n[{timestamp}] MITM INTERCEPTED REQUEST (Client -> Server)")
        print(f"{'='*70}")
        try:
            # Show the encrypted/hashed data
            parsed = json.loads(client_data.decode('utf-8'))
            print(json.dumps(parsed, indent=4))
        except:
            print(f"RAW BLOB: {client_data.hex()}")
        print(f"{'='*70}")

        # 2. FORWARD TO REAL SERVER
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((TARGET_HOST, TARGET_PORT))
        server_socket.sendall(client_data)

        # 3. RECEIVE RESPONSE FROM REAL SERVER
        server_response = server_socket.recv(8192)
        server_socket.close()

        print(f"[{timestamp}] MITM INTERCEPTED RESPONSE (Server -> Client)")
        print(f"{'-'*70}")
        try:
            parsed_res = json.loads(server_response.decode('utf-8'))
            print(json.dumps(parsed_res, indent=4))
        except:
            print(f"RAW BLOB: {server_response.hex()}")
        print(f"{'-'*70}")

        # 4. SEND BACK TO CLIENT
        client_socket.sendall(server_response)

    except Exception as e:
        print(f"Error in proxy: {e}")
    finally:
        client_socket.close()

def start_proxy():
    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        proxy.bind((PROXY_HOST, PROXY_PORT))
        proxy.listen(10)
        print(f"MITM PROXY ACTIVE: Listening on {PROXY_PORT}, Forwarding to {TARGET_PORT}")
        print("Point your apps to Port 3001 to simulate an intercepted connection.\n")

        while True:
            client, addr = proxy.accept()
            # Handle in a thread so multiple requests can flow
            threading.Thread(target=handle_client, args=(client,)).start()

    except KeyboardInterrupt:
        print("\n[!] Shutting down proxy...")
    finally:
        proxy.close()

if __name__ == "__main__":
    start_proxy()
