import socket
import json
import hashlib
import os
import uuid
import sys

# Add the project root to sys.path to allow importing from 'module/'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import module.ecc_helper as ecc
import module.zkp_engine as zkp

# Configuration
HOST = '127.0.0.1'
PORT = 3000
# Database Paths
USER_DB = 'server_app/ledger/users.json'             # For Bidders
OFFICER_DB = 'server_app/ledger/officers.json'       # For Registered Officers
ADMIN_DB = 'server_app/ledger/system_admin.json'     # For the Single Admin
SECRET_KEY_DB = 'server_app/ledger/secret_keys.json' # For Officer Invitation Tokens
TENDER_DB = 'server_app/ledger/tenders.json'         # For Published Tenders
BIDS_DB = 'server_app/ledger/bids.json'              # For Secure Bid Blockchain
SHARES_DB = 'server_app/ledger/shares.json'          # For Threshold Key Shares
CONSENSUS_DB = 'server_app/ledger/consensus.json'    # For Bidder Consensus tracking

# Ensure the database directories and files exist
for db_path in [USER_DB, OFFICER_DB, ADMIN_DB, SECRET_KEY_DB, TENDER_DB, BIDS_DB, SHARES_DB, CONSENSUS_DB]:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    if not os.path.exists(db_path):
        with open(db_path, 'w') as f:
            if "secret_keys" in db_path:
                json.dump([], f)
            elif "bids" in db_path:
                json.dump({"chain": [], "last_hash": "GENESIS_HASH_0000000000000000000"}, f)
            else:
                json.dump({}, f)

def hash_data(data):
    """Secure SHA-256 Hashing."""
    return hashlib.sha256(data.encode()).hexdigest()

def load_json(path):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        if "bids.json" in path:
            return {"chain": [], "last_hash": "GENESIS_HASH_0000000000000000000"}
        if "secret_keys.json" in path:
            return []
        return {}

    with open(path, 'r') as f:
        try: 
            data = json.load(f)
            # Extra check for bids
            if "bids.json" in path and "chain" not in data:
                 return {"chain": [], "last_hash": "GENESIS_HASH_0000000000000000000"}
            return data
        except: 
            if "bids.json" in path:
                return {"chain": [], "last_hash": "GENESIS_HASH_0000000000000000000"}
            return [] if "secret_keys.json" in path else {}

def save_json(path, data):
    with open(path, 'w') as f:
        json.dump(data, f, indent=4)

def handle_auth(data):
    """Handles Bidder, Officer, and Admin Authentication Logic."""
    role = data.get("role", "bidder") # Default to bidder if not specified
    action = data.get("action")
    username = data.get("username")
    password = data.get("password")
    
    hashed_user = hash_data(username) if username else None
    hashed_pass = hash_data(password) if password else None

    # --- BIDDER LOGIC ---
    if role == "bidder":
        users = load_json(USER_DB)
        if action == "signup":
            if hashed_user in users: return {"status": "error", "message": "User exists!"}
            public_id = f"BID-{str(uuid.uuid4())[:8].upper()}"
            users[hashed_user] = {"password": hashed_pass, "public_id": public_id}
            save_json(USER_DB, users)
            return {"status": "success", "message": "Signup successful!", "public_id": public_id}
        
        elif action == "login":
            if hashed_user in users and users[hashed_user]["password"] == hashed_pass:
                return {"status": "success", "public_id": users[hashed_user]["public_id"]}
            return {"status": "error", "message": "Invalid credentials."}

        elif action == "fetch_tenders":
            tenders = load_json(TENDER_DB)
            return {"status": "success", "tenders": tenders}

        elif action == "submit_bid":
            bid_data = data.get("bid_data")
            zkp_proof = data.get("zkp_proof")
            signature = data.get("signature")
            public_key = data.get("public_key")
            bidder_id = data.get("bidder_id")
            tender_id = bid_data.get("tender_id")
            
            if not all([bid_data, zkp_proof, signature, public_key, bidder_id, tender_id]):
                return {"status": "error", "message": "Missing required bid parameters."}
            
            # Verify ZKP Range Proof
            zkp_engine = zkp.ZKPEngine()
            if not zkp_engine.verify_range_proof(zkp_proof):
                return {"status": "error", "message": "ZKP Range Verification Failed!"}

            # Verify Digital Signature
            helper = ecc.ECCHelper()
            bid_json = json.dumps(bid_data, sort_keys=True)
            if not helper.verify_signature(public_key, bid_json, signature):
                return {"status": "error", "message": "Digital Signature Invalid!"}

            # ASSIGN DECRYPTION SHARE TO BIDDER
            shares_db = load_json(SHARES_DB)
            if tender_id not in shares_db or not shares_db[tender_id]:
                return {"status": "error", "message": f"Tender {tender_id} share pool not found."}
            
            # Robust Format Check
            if isinstance(shares_db[tender_id], list):
                # Auto-upgrade to the new pool/assigned/released format
                shares_db[tender_id] = {
                    "pool": shares_db[tender_id],
                    "assigned": {},
                    "released": []
                }
            elif "pool" not in shares_db[tender_id]:
                 # Invalid dictionary format
                 return {"status": "error", "message": f"Corrupted share pool for tender {tender_id}."}

            if not shares_db[tender_id]["pool"]:
                 return {"status": "error", "message": "All consensus shares have been issued."}

            # Give the bidder the next share from the pool
            bidder_share = shares_db[tender_id]["pool"].pop(0)
            shares_db[tender_id]["assigned"][bidder_id] = bidder_share
            save_json(SHARES_DB, shares_db)

            # Blockchain: Create Block
            bids_db = load_json(BIDS_DB)
            prev_hash = bids_db.get("last_hash", "GENESIS_HASH_0000000000000000000")
            block_content = {
                "prev_hash": prev_hash,
                "bid_data": bid_data,
                "zkp_proof": zkp_proof,
                "signature": signature,
                "bidder_pub_key": public_key
            }
            block_json = json.dumps(block_content, sort_keys=True)
            new_hash = hashlib.sha256(block_json.encode()).hexdigest()
            bids_db["chain"].append({"hash": new_hash, "block": block_content})
            bids_db["last_hash"] = new_hash
            save_json(BIDS_DB, bids_db)

            # Update Tender Bidder Count
            tenders = load_json(TENDER_DB)
            if tender_id in tenders:
                tenders[tender_id]["bidder_count"] = tenders[tender_id].get("bidder_count", 0) + 1
                save_json(TENDER_DB, tenders)
            
            return {
                "status": "success", 
                "message": "Bid Secured! Consensus share assigned.", 
                "bid_hash": new_hash,
                "decryption_share": bidder_share
            }

        elif action == "release_share":
            tender_id = data.get("tender_id")
            bidder_id = data.get("bidder_id")
            share = data.get("share")
            
            shares_db = load_json(SHARES_DB)
            if tender_id not in shares_db:
                return {"status": "error", "message": "Tender not found."}
            
            # Ensure proper pool format
            if isinstance(shares_db[tender_id], list):
                shares_db[tender_id] = {"pool": shares_db[tender_id], "assigned": {}, "released": []}

            # Check if this share was already released
            if any(s["index"] == share["index"] for s in shares_db[tender_id]["released"]):
                 return {"status": "success", "message": "Share already released."}
            
            shares_db[tender_id]["released"].append(share)
            save_json(SHARES_DB, shares_db)
            print(f"[Consensus] Bidder {bidder_id} released share for {tender_id}.")
            return {"status": "success", "message": "Decryption share released."}

    # --- OFFICER LOGIC (Requires Secret ID Token) ---
    elif role == "officer":
        officers = load_json(OFFICER_DB)
        secret_keys = load_json(SECRET_KEY_DB)
        
        if action == "officer_signup":
            secret_id = data.get("secret_id")
            hashed_secret = hash_data(secret_id) if secret_id else None
            
            if hashed_secret not in secret_keys:
                return {"status": "error", "message": "Invalid or expired Secret ID Token!"}
            
            if hashed_user in officers:
                return {"status": "error", "message": "Officer account already exists!"}
            
            # Create Officer
            officer_id = f"OFF-{username.upper()}"
            officers[hashed_user] = {"password": hashed_pass, "officer_id": officer_id}
            secret_keys.remove(hashed_secret) # Token is used once (one-shot)
            
            save_json(OFFICER_DB, officers)
            save_json(SECRET_KEY_DB, secret_keys)
            return {"status": "success", "message": "Officer Registration Successful!", "officer_id": officer_id}

        elif action == "login":
            if hashed_user in officers and officers[hashed_user]["password"] == hashed_pass:
                return {"status": "success", "message": "Welcome Officer", "officer_id": officers[hashed_user]["officer_id"]}
            return {"status": "error", "message": "Invalid Officer credentials."}

        elif action == "fetch_tenders":
            tenders = load_json(TENDER_DB)
            return {"status": "success", "tenders": tenders}

        elif action == "fetch_bids":
            tenders = load_json(TENDER_DB)
            tender_id = data.get("tender_id")
            
            if tender_id not in tenders:
                return {"status": "error", "message": "Tender not found."}
                
            # 1. DEADLINE STATUS (Informative only)
            deadline_str = tenders[tender_id]["data"]["deadline"]
                
            # 2. CONSENSUS CHECK (>50% of bidders must have released shares)
            shares_db = load_json(SHARES_DB)
            total_bidders = tenders[tender_id].get("bidder_count", 0)
            released_shares = shares_db.get(tender_id, {}).get("released", [])
            
            consensus_met = len(released_shares) > (total_bidders / 2) if total_bidders > 0 else False
            
            if not consensus_met:
                return {
                    "status": "error", 
                    "message": f"CONSENSUS NOT MET. Released: {len(released_shares)}/{total_bidders}. Need > 50%.",
                    "consensus_met": False,
                    "released_count": len(released_shares),
                    "total_bidders": total_bidders,
                    "deadline": deadline_str
                }

            # 3. Return Bids and Released Shares
            bids_db = load_json(BIDS_DB)
            tender_bids = []
            for block_wrapper in bids_db.get("chain", []):
                if block_wrapper["block"]["bid_data"]["tender_id"] == tender_id:
                    tender_bids.append(block_wrapper)
            
            return {
                "status": "success", 
                "bids": tender_bids, 
                "shares": released_shares,
                "wrapped_tender_key": tenders[tender_id].get("wrapped_tender_key"), # RECOVERY DATA
                "consensus_met": True
            }

        elif action == "create_tender":
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import serialization
            import secrets
            import base64
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            tender_data = data.get("tender_data")
            signature = data.get("signature")
            officer_pub_key = data.get("public_key")
            client_hash = data.get("data_hash")
            off_id = tender_data.get("officer_id")
            
            if not all([tender_data, signature, officer_pub_key, client_hash, off_id]):
                return {"status": "error", "message": "Missing required security parameters."}
            
            # 1. Identity Verification for Officer
            officers = load_json(OFFICER_DB)
            target_user_hash = None
            for u_hash, info in officers.items():
                if info.get("officer_id") == off_id:
                    target_user_hash = u_hash
                    break
            if not target_user_hash: return {"status": "error", "message": "Invalid Officer ID."}
            pinned_key = officers[target_user_hash].get("public_key")
            if pinned_key and pinned_key != officer_pub_key:
                return {"status": "error", "message": "Identity Mismatch!"}
            if not pinned_key:
                officers[target_user_hash]["public_key"] = officer_pub_key
                save_json(OFFICER_DB, officers)

            # 2. GENERATE TENDER-SPECIFIC THRESHOLD KEY (Master Key Wrap)
            helper = ecc.ECCHelper()
            tender_priv_key_obj = ec.generate_private_key(ec.SECP256K1())
            tender_pub_key_obj = tender_priv_key_obj.public_key()
            
            # Raw Private Key for Encryption
            priv_raw_bytes = tender_priv_key_obj.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # A. Generate 16-byte Master Key (Limited by pycryptodome Shamir)
            master_key = secrets.token_bytes(16)
            
            # B. Split Master Key (100 shares, Threshold 1 for prototype ease)
            shares = helper.split_tender_key(master_key, 100, 1)
            
            # C. Encrypt Tender Private Key using Master Key (AES-GCM)
            aesgcm = AESGCM(master_key)
            nonce = secrets.token_bytes(12)
            encrypted_tender_priv = aesgcm.encrypt(nonce, priv_raw_bytes, None)

            # D. Format Encrypted Payload
            wrapped_key_payload = {
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "ciphertext": base64.b64encode(encrypted_tender_priv).decode('utf-8')
            }

            # Public Key PEM
            tender_pub_pem = tender_pub_key_obj.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

            # 3. Store Shares Pool and Tender
            shares_db = load_json(SHARES_DB)
            t_id = tender_data.get("tender_id")
            shares_db[t_id] = {
                "pool": shares,
                "assigned": {},
                "released": []
            }
            save_json(SHARES_DB, shares_db)

            tenders = load_json(TENDER_DB)
            tenders[t_id] = {
                "data": tender_data,
                "data_hash": client_hash,
                "signature": signature,
                "public_key": tender_pub_pem,
                "officer_pub_key": officer_pub_key,
                "status": "OPEN",
                "bidder_count": 0,
                "wrapped_tender_key": wrapped_key_payload # Encrypted key stored here
            }
            save_json(TENDER_DB, tenders)
            print(f"[Server] Tender {t_id} created. Consensus Decryption ACTIVE.")
            return {"status": "success", "message": "Tender created. Decryption requires > 50% Bidder Consensus."}

    # --- ADMIN LOGIC (Token Generation) ---
    elif role == "admin":
        admin_data = load_json(ADMIN_DB)
        
        # Verify Hashed Admin Username and Password
        if admin_data.get("admin_user") == hashed_user and admin_data.get("password") == hashed_pass:
            if action == "admin_login":
                return {"status": "success", "message": "Admin login verified."}

            if action == "generate_token":
                new_token = str(uuid.uuid4())[:12].upper()
                keys = load_json(SECRET_KEY_DB)
                keys.append(hash_data(new_token))
                save_json(SECRET_KEY_DB, keys)
                print(f"[Admin] Generated Officer Token: {new_token}")
                return {"status": "success", "token": new_token}
        
        return {"status": "error", "message": "Unauthorized Admin Access."}

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((HOST, PORT))
        server.listen(5)
        print("="*60)
        print(f"CSePS MULTI-ROLE SERVER - PORT {PORT}")
        print("BIDDER | OFFICER | ADMIN ROLES: ACTIVE")
        print("="*60)

        while True:
            client, addr = server.accept()
            try:
                raw_data = client.recv(4096).decode('utf-8')
                if not raw_data: continue
                
                request = json.loads(raw_data)
                try:
                    response = handle_auth(request)
                except Exception as auth_error:
                    print(f"[Critical Error] {auth_error}")
                    response = {"status": "error", "message": f"Server Logic Error: {str(auth_error)}"}
                
                client.sendall(json.dumps(response).encode('utf-8'))
                
            except Exception as e:
                print(f"[Network Error] {e}")
            finally:
                client.close()

    except KeyboardInterrupt:
        print("\n[System] Shutting down...")
    finally:
        server.close()

if __name__ == "__main__":
    start_server()