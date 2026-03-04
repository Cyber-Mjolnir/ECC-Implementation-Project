import socket
import json
import datetime

# Configuration matching the project
HOST = '127.0.0.1'
PORT = 3000

def start_monitor():
    """
    Listens on port 3000 and prints the RAW data received.
    This demonstrates that data is encrypted/hashed before it hits the network.
    """
    watcher = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    watcher.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        watcher.bind((HOST, PORT))
        watcher.listen(5)
        
        print("="*70)
        print(f"📡 CSePS NETWORK TRAFFIC MONITOR - LISTENING ON PORT {PORT}")
        print("STATUS: OPERATIONAL")
        print("NOTE: This script shows the raw data 'over the wire'.")
        print("="*70)

        while True:
            client, addr = watcher.accept()
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            try:
                raw_data = client.recv(8192).decode('utf-8', errors='replace')
                if not raw_data:
                    continue
                
                print(f"
[{timestamp}] 📥 Incoming Connection from {addr}")
                print(f"{'-'*70}")
                
                try:
                    # Attempt to format as JSON for readability, but show the encrypted blobs
                    parsed = json.loads(raw_data)
                    print(json.dumps(parsed, indent=4))
                except:
                    # If it's not valid JSON, show raw text
                    print(f"RAW DATA: {raw_data}")
                
                print(f"{'-'*70}")
                
                # Send a dummy error response so the client doesn't hang
                error_response = {"status": "error", "message": "TRAFFIC_MONITOR_MODE: Primary server is offline."}
                client.sendall(json.dumps(error_response).encode('utf-8'))
                
            except Exception as e:
                print(f"[{timestamp}] ❌ Error reading data: {e}")
            finally:
                client.close()

    except KeyboardInterrupt:
        print("
[System] Monitor shutting down...")
    except Exception as e:
        print(f"
[System] Port Error: {e}")
        print("TIP: Make sure the Primary Server is NOT running on port 3000.")
    finally:
        watcher.close()

if __name__ == "__main__":
    start_monitor()
