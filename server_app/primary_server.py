import socket
import json
import hashlib
import os
import uuid
import sys
import hmac

# Add the project root to sys.path to allow importing from 'module/'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import module.ecc_helper as ecc
import module.zkp_engine as zkp

# Configuration
HOST = '127.0.0.1'
PORT = 3000

# Security Configuration (System Secret Pepper)
# In production, this should be in a protected environment variable.
SYSTEM_PEPPER = "SECURE_CSePS_PEPPER_2026_#$!" 

# Database Paths
USER_DB = 'server_app/ledger/users.json'             # For Bidders
OFFICER_DB = 'server_app/ledger/officers.json'       # For Registered Officers
ADMIN_DB = 'server_app/admins_details/admin_credentials.json'     # For the Single Admin
SERVER_KEY_PATH = 'server_app/admins_details/server_keys/' # Persistent Server Identity
SECRET_KEY_DB = 'server_app/ledger/secret_keys.json' # For Officer Invitation Tokens
TENDER_DB = 'server_app/ledger/tenders.json'         # For Published Tenders
BIDS_DB = 'server_app/ledger/bids.json'              # For Secure Bid Blockchain
SHARES_DB = 'server_app/ledger/shares.json'          # For Threshold Key Shares
CONSENSUS_DB = 'server_app/ledger/consensus.json'    # For Bidder Consensus tracking

# Ensure the database directories and files exist
for db_path in [USER_DB, OFFICER_DB, ADMIN_DB, SECRET_KEY_DB, TENDER_DB, BIDS_DB, SHARES_DB, CONSENSUS_DB, SERVER_KEY_PATH]:
    os.makedirs(os.path.dirname(db_path) if not db_path.endswith('/') else db_path, exist_ok=True)
    if not os.path.exists(db_path) and not db_path.endswith('/'):
        with open(db_path, 'w') as f:
            if "bids" in db_path:
                json.dump({"chain": [], "last_hash": "GENESIS_HASH_0000000000000000000"}, f)
            else:
                json.dump({}, f)

# Initialize Server ECC Identity for Network Encryption
_helper_init = ecc.ECCHelper()
if not os.path.exists(os.path.join(SERVER_KEY_PATH, "private_key.pem")):
    print("[System] Generating Server Network Identity Keys...")
    _helper_init.generate_and_save_keys(SERVER_KEY_PATH, "SERVER_INTERNAL_SECRET_99")

def get_server_keys():
    h = ecc.ECCHelper()
    priv = h.load_private_key(SERVER_KEY_PATH, "SERVER_INTERNAL_SECRET_99")
    with open(os.path.join(SERVER_KEY_PATH, "public_key.pem"), "r") as f:
        pub_pem = f.read()
    return priv, pub_pem

SERVER_PRIV, SERVER_PUB_PEM = get_server_keys()

def hash_data(data):
    """Secure SHA-256 Hashing with System Pepper to prevent manual hashing/tampering."""
    combined = data + SYSTEM_PEPPER
    return hashlib.sha256(combined.encode()).hexdigest()

def verify_file_integrity(file_path):
    """Verifies the HMAC-SHA256 signature of a database file."""
    sig_path = file_path + ".sig"
    if not os.path.exists(file_path): return True # File doesn't exist, fine
    if not os.path.exists(sig_path): return False # Modified or Signature missing!
    
    with open(file_path, 'rb') as f:
        content = f.read()
    with open(sig_path, 'r') as f:
        stored_sig = f.read().strip()
    
    expected_sig = hmac.new(SYSTEM_PEPPER.encode(), content, hashlib.sha256).hexdigest()
    return hmac.compare_digest(stored_sig, expected_sig)

def sign_file(file_path):
    """Generates an HMAC-SHA256 signature for a file to lock its contents."""
    with open(file_path, 'rb') as f:
        content = f.read()
    sig = hmac.new(SYSTEM_PEPPER.encode(), content, hashlib.sha256).hexdigest()
    with open(file_path + ".sig", 'w') as f:
        f.write(sig)

def load_json(path):
    """Loads JSON with integrity verification for sensitive files (Admins)."""
    if "admin_credentials" in path:
        if not verify_file_integrity(path):
            print(f"[SECURITY ALERT] INTEGRITY COMPROMISED: {path} has been modified externally!")
            return {} # Block access if tampered
            
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        if "bids.json" in path:
            return {"chain": [], "last_hash": "GENESIS_HASH_0000000000000000000"}
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
            return {}

def save_json(path, data):
    """Saves JSON and re-signs sensitive files for future verification."""
    with open(path, 'w') as f:
        json.dump(data, f, indent=4)
    
    # Sign sensitive files to prevent manual modification
    if "admin_credentials" in path:
        sign_file(path)

def verify_and_repair_chain():
    """
    Scans the blockchain for integrity. If a broken link is found, 
    it prunes the invalid blocks and synchronizes the tenders and shares DBs.
    """
    print("[System] Running Blockchain Integrity Audit...")
    bids_db = load_json(BIDS_DB)
    tenders = load_json(TENDER_DB)
    shares_db = load_json(SHARES_DB)
    
    chain = bids_db.get("chain", [])
    if not chain:
        return

    valid_until_index = -1
    last_known_hash = "GENESIS_HASH_0000000000000000000"
    
    for i, block_wrapper in enumerate(chain):
        block = block_wrapper["block"]
        actual_hash = block_wrapper["hash"]
        
        # 1. Verify Hash of the block itself (Optional but good)
        block_json = json.dumps(block, sort_keys=True)
        recalculated_hash = hashlib.sha256(block_json.encode()).hexdigest()
        
        # 2. Verify Linkage
        if block.get("prev_hash") != last_known_hash or recalculated_hash != actual_hash:
            print(f"[SECURITY] Integrity Breach detected at block index {i}!")
            print(f"[*] Block Hash: {actual_hash[:16]}... | Expected Prev: {last_known_hash[:16]}...")
            valid_until_index = i
            break
        
        last_known_hash = actual_hash

    if valid_until_index != -1:
        print(f"[System] Self-Healing Protocol Initiated: Pruning chain from index {valid_until_index}...")
        
        # Identify bids being removed to update counts and shares
        removed_blocks = chain[valid_until_index:]
        pruned_chain = chain[:valid_until_index]
        
        for b_wrap in removed_blocks:
            bid_data = b_wrap["block"].get("bid_data", {})
            t_id = bid_data.get("tender_id")
            bidder_id = b_wrap["block"].get("bidder_id") # Use our new field
            
            # Decrement bidder count
            if t_id in tenders:
                if tenders[t_id].get("bidder_count", 0) > 0:
                    tenders[t_id]["bidder_count"] -= 1
            
            # Restore share to pool
            if t_id in shares_db and bidder_id:
                pool = shares_db[t_id]
                if "bidder_assigned" in pool and bidder_id in pool["bidder_assigned"]:
                    share = pool["bidder_assigned"].pop(bidder_id)
                    pool.setdefault("bidder_pool", []).insert(0, share) # Put it back at the front
                    # Also remove from released if it was there
                    pool["bidder_released"] = [s for s in pool.get("bidder_released", []) if s["index"] != share["index"]]

        # Save corrected states
        bids_db["chain"] = pruned_chain
        bids_db["last_hash"] = pruned_chain[-1]["hash"] if pruned_chain else "GENESIS_HASH_0000000000000000000"
        
        save_json(BIDS_DB, bids_db)
        save_json(TENDER_DB, tenders)
        save_json(SHARES_DB, shares_db)
        print("[System] Blockchain Integrity Restored. (Credentials Unaffected)")
    else:
        print("[System] Blockchain Integrity Verified. No issues found.")

def handle_auth(data):
    """Handles Bidder, Officer, and Admin Authentication Logic."""
    # Special Unencrypted Action
    if data.get("action") == "get_server_pubkey":
        return {"status": "success", "pubkey": SERVER_PUB_PEM}

    # --- NETWORK ENCRYPTION LAYER (ECIES WRAPPER) ---
    if data.get("type") == "wrapped_request":
        try:
            encrypted_payload = data.get("payload")
            client_pub = data.get("client_pub") # Used to encrypt the response back
            
            # Decrypt the request using Server Private Key
            h = ecc.ECCHelper()
            decrypted_bytes = h.decrypt_data(SERVER_PRIV, encrypted_payload)
            if not decrypted_bytes:
                return {"status": "error", "message": "Network Decryption Failed."}
            
            # Process the actual request
            actual_request = json.loads(decrypted_bytes.decode('utf-8'))
            response = handle_auth(actual_request) # Recursive call to internal logic
            
            # Encrypt the response using Client's Ephemeral Public Key
            response_json = json.dumps(response).encode('utf-8')
            encrypted_response = h.encrypt_data(client_pub, response_json)
            
            return {
                "type": "wrapped_response",
                "payload": encrypted_response
            }
        except Exception as e:
            return {"status": "error", "message": f"Transport Security Error: {str(e)}"}

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

        elif action == "fetch_ledger":
            bids_db = load_json(BIDS_DB)
            # Return the chain for public auditing. Payloads remain encrypted.
            return {"status": "success", "chain": bids_db.get("chain", []), "last_hash": bids_db.get("last_hash")}

        elif action == "submit_bid":
            bid_data = data.get("bid_data")
            zkp_proof = data.get("zkp_proof")
            signature = data.get("signature")
            public_key = data.get("public_key")
            bidder_id = data.get("bidder_id")
            tender_id = bid_data.get("tender_id")
            
            if not all([bid_data, zkp_proof, signature, public_key, bidder_id, tender_id]):
                return {"status": "error", "message": "Missing required bid parameters."}
            
            # Check Tender Status
            tenders = load_json(TENDER_DB)
            if tender_id not in tenders:
                return {"status": "error", "message": "Tender not found."}
            if tenders[tender_id].get("status") != "OPEN":
                return {"status": "error", "message": "Tender is closed for bidding."}

            # Verify ZKP Range Proof
            zkp_engine = zkp.ZKPEngine()
            if not zkp_engine.verify_range_proof(zkp_proof):
                return {"status": "error", "message": "ZKP Range Verification Failed!"}

            # Verify Digital Signature
            helper = ecc.ECCHelper()
            bid_json = json.dumps(bid_data, sort_keys=True)
            if not helper.verify_signature(public_key, bid_json, signature):
                return {"status": "error", "message": "Digital Signature Invalid!"}

            # Blockchain: Verify and Repair before adding new block
            verify_and_repair_chain()

            # ASSIGN DECRYPTION SHARE TO BIDDER
            shares_db = load_json(SHARES_DB)
            if tender_id not in shares_db or not shares_db[tender_id]:
                return {"status": "error", "message": f"Tender {tender_id} share pool not found."}
            
            pool = shares_db[tender_id]
            # --- Robust Dual-Consensus Format Check ---
            if "bidder_pool" not in pool:
                 # Auto-upgrade from legacy pool to bidder_pool if it's an old tender
                 if "pool" in pool:
                      pool["bidder_pool"] = pool.pop("pool")
                      pool["bidder_assigned"] = pool.pop("assigned", {})
                      pool["bidder_released"] = pool.pop("released", [])
                 else:
                      return {"status": "error", "message": f"Corrupted share pool for tender {tender_id}."}

            if not pool["bidder_pool"]:
                 return {"status": "error", "message": "All consensus shares have been issued."}

            # Give the bidder the next share from the pool
            bidder_share = pool["bidder_pool"].pop(0)
            pool.setdefault("bidder_assigned", {})[bidder_id] = bidder_share
            save_json(SHARES_DB, shares_db)

            # Blockchain: Create Block
            bids_db = load_json(BIDS_DB)
            prev_hash = bids_db.get("last_hash", "GENESIS_HASH_0000000000000000000")
            block_content = {
                "prev_hash": prev_hash,
                "bidder_id": bidder_id,
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
            # tenders = load_json(TENDER_DB) # Reloaded to ensure fresh count after potential repair
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
            
            pool = shares_db[tender_id]
            # Ensure proper pool format
            if "bidder_released" not in pool:
                 # Legacy upgrade
                 if "released" in pool:
                      pool["bidder_released"] = pool.pop("released")
                      pool["bidder_assigned"] = pool.pop("assigned", {})
                      pool["bidder_pool"] = pool.pop("pool", [])
                 else:
                      pool["bidder_released"] = []

            # Check if this share was already released
            if any(s["index"] == share["index"] for s in pool["bidder_released"]):
                 return {"status": "success", "message": "Share already released."}
            
            pool["bidder_released"].append(share)
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
            
            # Find which admin invited this officer
            invited_by = secret_keys[hashed_secret]
            
            # Create Officer
            officer_id = f"OFF-{username.upper()}"
            officers[hashed_user] = {
                "password": hashed_pass, 
                "officer_id": officer_id,
                "invited_by": invited_by
            }
            del secret_keys[hashed_secret] # Token is used once (one-shot)
            
            save_json(OFFICER_DB, officers)
            save_json(SECRET_KEY_DB, secret_keys)
            return {"status": "success", "message": "Officer Registration Successful!", "officer_id": officer_id}

        elif action == "login":
            if hashed_user in officers and officers[hashed_user]["password"] == hashed_pass:
                return {"status": "success", "message": "Welcome Officer", "officer_id": officers[hashed_user]["officer_id"]}
            return {"status": "error", "message": "Invalid Officer credentials."}

        elif action == "delete_self":
            if hashed_user in officers and officers[hashed_user]["password"] == hashed_pass:
                del officers[hashed_user]
                save_json(OFFICER_DB, officers)
                print(f"[Officer] Account deleted by user.")
                return {"status": "success", "message": "Your account has been permanently deleted."}
            return {"status": "error", "message": "Authentication failed."}

        elif action == "fetch_officers":
            officers = load_json(OFFICER_DB)
            officer_ids = [info.get("officer_id") for info in officers.values()]
            return {"status": "success", "officer_list": officer_ids}

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
            evaluators = data.get("evaluators", []) # List of Officer IDs
            
            if not all([tender_data, signature, officer_pub_key, client_hash, off_id]):
                return {"status": "error", "message": "Missing required security parameters."}
            
            if len(evaluators) < 2:
                return {"status": "error", "message": "At least 2 additional evaluators required."}

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

            # 2. GENERATE TENDER-SPECIFIC THRESHOLD KEY (Dual Consensus Wrap)
            helper = ecc.ECCHelper()
            tender_priv_key_obj = ec.generate_private_key(ec.SECP256K1())
            tender_pub_key_obj = tender_priv_key_obj.public_key()
            
            priv_raw_bytes = tender_priv_key_obj.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # A. Generate 16-byte Master Key components
            # Master_Key = MK_B (Bidders) ^ MK_O (Officers)
            mk_b = secrets.token_bytes(16)
            mk_o = secrets.token_bytes(16)
            master_key = bytes(a ^ b for a, b in zip(mk_b, mk_o))
            
            # B. Split components
            # Split MK_B for Bidders (100 total, threshold 1 for demo ease, but logic uses >50%)
            bidder_shares = helper.split_tender_key(mk_b, 100, 1)
            
            # Split MK_O for Officers (The creator + evaluators)
            all_evals = [off_id] + evaluators
            n_evals = len(all_evals)
            k_evals = 2 if n_evals == 3 else (n_evals * 2 // 3 + 1) # ~2/3 threshold
            officer_shares_raw = helper.split_tender_key(mk_o, n_evals, k_evals)
            
            officer_shares_map = {}
            for i, o_id in enumerate(all_evals):
                officer_shares_map[o_id] = officer_shares_raw[i]

            # C. Encrypt Tender Private Key using Master Key (AES-GCM)
            aesgcm = AESGCM(master_key)
            nonce = secrets.token_bytes(12)
            encrypted_tender_priv = aesgcm.encrypt(nonce, priv_raw_bytes, None)

            wrapped_key_payload = {
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "ciphertext": base64.b64encode(encrypted_tender_priv).decode('utf-8')
            }

            tender_pub_pem = tender_pub_key_obj.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

            # 3. Store Shares Pool and Tender
            t_id = tender_data.get("tender_id")
            shares_db = load_json(SHARES_DB)
            shares_db[t_id] = {
                "bidder_pool": bidder_shares,
                "bidder_assigned": {},
                "bidder_released": [],
                "officer_assigned": officer_shares_map,
                "officer_released": []
            }
            save_json(SHARES_DB, shares_db)

            tenders = load_json(TENDER_DB)
            tenders[t_id] = {
                "data": tender_data,
                "evaluators": evaluators,
                "officer_threshold": k_evals,
                "data_hash": client_hash,
                "signature": signature,
                "public_key": tender_pub_pem,
                "officer_pub_key": officer_pub_key,
                "status": "OPEN",
                "bidder_count": 0,
                "wrapped_tender_key": wrapped_key_payload
            }
            save_json(TENDER_DB, tenders)
            print(f"[Server] Tender {t_id} created with 2/3 Officer Consensus and Bidder Threshold.")
            return {"status": "success", "message": f"Tender created. Decryption requires > 50% Bidders AND {k_evals}/{n_evals} Officers."}

        elif action == "officer_release_share":
            tender_id = data.get("tender_id")
            officer_id = data.get("officer_id")
            
            shares_db = load_json(SHARES_DB)
            if tender_id not in shares_db:
                return {"status": "error", "message": "Tender not found."}
            
            pool = shares_db[tender_id]
            if officer_id not in pool.get("officer_assigned", {}):
                return {"status": "error", "message": "You are not an evaluator for this tender."}
                
            share = pool["officer_assigned"][officer_id]
            if any(s["index"] == share["index"] for s in pool["officer_released"]):
                 return {"status": "success", "message": "Share already released."}
            
            pool["officer_released"].append(share)
            save_json(SHARES_DB, shares_db)
            print(f"[Consensus] Officer {officer_id} released share for {tender_id}.")
            return {"status": "success", "message": "Evaluator consensus share released."}

        elif action == "fetch_tenders":
            tenders = load_json(TENDER_DB)
            return {"status": "success", "tenders": tenders}

        elif action == "fetch_bids":
            tenders = load_json(TENDER_DB)
            tender_id = data.get("tender_id")
            
            if tender_id not in tenders:
                return {"status": "error", "message": "Tender not found."}
                
            target_tender = tenders[tender_id]
            n_evaluators = len(target_tender.get("evaluators", [])) + 1 # +1 for creator
            k_threshold = target_tender.get("officer_threshold", 2)

            # 1. CONSENSUS CHECK PART A: Bidders (>= 50%)
            shares_db = load_json(SHARES_DB)
            pool = shares_db.get(tender_id, {})
            total_bidders = target_tender.get("bidder_count", 0)
            released_bidder_shares = pool.get("bidder_released", [])
            bidder_consensus = len(released_bidder_shares) >= (total_bidders / 2) if total_bidders > 0 else False
            
            # 2. CONSENSUS CHECK PART B: Officers (>= 2/3)
            released_officer_shares = pool.get("officer_released", [])
            officer_consensus = len(released_officer_shares) >= k_threshold
            
            if not bidder_consensus or not officer_consensus:
                msg = "DUAL CONSENSUS NOT MET. "
                msg += f"\nBidders: {len(released_bidder_shares)}/{total_bidders} (Need >= 50%)"
                msg += f"\nOfficers: {len(released_officer_shares)}/{k_threshold} (Need 2/3 Committee)"
                
                return {
                    "status": "error", 
                    "message": msg,
                    "bidder_consensus": bidder_consensus,
                    "officer_consensus": officer_consensus
                }

            # 3. Return Bids and Both sets of Released Shares
            bids_db = load_json(BIDS_DB)
            tender_bids = []
            for block_wrapper in bids_db.get("chain", []):
                if block_wrapper["block"]["bid_data"]["tender_id"] == tender_id:
                    tender_bids.append(block_wrapper)
            
            return {
                "status": "success", 
                "bids": tender_bids, 
                "bidder_shares": released_bidder_shares,
                "officer_shares": released_officer_shares,
                "wrapped_tender_key": target_tender.get("wrapped_tender_key"),
                "bidder_consensus": True,
                "officer_consensus": True
            }

        elif action == "close_tender":
            tender_id = data.get("tender_id")
            officer_id = data.get("officer_id")
            winner_id = data.get("winner_id")
            winning_bid = data.get("winning_bid")
            
            tenders = load_json(TENDER_DB)
            if tender_id not in tenders:
                return {"status": "error", "message": "Tender not found."}
            
            if tenders[tender_id]["data"]["officer_id"] != officer_id:
                return {"status": "error", "message": "Unauthorized: Only the tender creator can close it."}
            
            tenders[tender_id]["status"] = "CLOSED"
            tenders[tender_id]["winner"] = {
                "bidder_id": winner_id,
                "amount": winning_bid
            }
            save_json(TENDER_DB, tenders)
            print(f"[Server] Tender {tender_id} CLOSED. Winner: {winner_id}")
            return {"status": "success", "message": f"Tender {tender_id} successfully closed and awarded."}

    # --- ADMIN LOGIC (Token Generation & User Management) ---
    elif role == "admin":
        admins = load_json(ADMIN_DB)
        
        # Verify Hashed Admin Username and Password
        if hashed_user in admins and admins[hashed_user]["password"] == hashed_pass:
            if action == "admin_login":
                return {"status": "success", "message": "Admin login verified."}

            if action == "generate_token":
                raw_token = data.get("token")
                signature = data.get("signature")
                admin_pub_key = data.get("public_key")
                
                if not all([raw_token, signature, admin_pub_key]):
                    return {"status": "error", "message": "Signature or token missing for verification."}
                
                # 1. Identity Verification for Admin (Pinning Public Key)
                if "public_key" not in admins[hashed_user]:
                    admins[hashed_user]["public_key"] = admin_pub_key
                    save_json(ADMIN_DB, admins)
                elif admins[hashed_user]["public_key"] != admin_pub_key:
                    return {"status": "error", "message": "Admin Identity Mismatch! Incorrect Private Key used."}

                # 2. Verify Signature
                helper = ecc.ECCHelper()
                if not helper.verify_signature(admin_pub_key, raw_token, signature):
                    return {"status": "error", "message": "ECC Signature Verification Failed! Token authenticity not proven."}

                # 3. Store Hashed Token for Signup with Admin ID
                keys = load_json(SECRET_KEY_DB)
                keys[hash_data(raw_token)] = username # Store which admin created it
                save_json(SECRET_KEY_DB, keys)
                print(f"[Admin] Authenticated Signed Token Generated by {username}: {raw_token}")
                return {"status": "success", "token": raw_token}

            if action == "fetch_officers":
                officers = load_json(OFFICER_DB)
                # Prepare a clean list for the admin UI
                officer_list = []
                for u_hash, info in officers.items():
                    officer_list.append({
                        "id": info.get("officer_id"),
                        "invited_by": info.get("invited_by", "Legacy/Unknown"),
                        "hash": u_hash # Hidden from UI, used for deletion
                    })
                return {"status": "success", "officers": officer_list}

            if action == "delete_officer":
                target_hash = data.get("officer_hash")
                officers = load_json(OFFICER_DB)
                if target_hash in officers:
                    # Security: Only the inviting admin can delete
                    if officers[target_hash].get("invited_by") == username:
                        del officers[target_hash]
                        save_json(OFFICER_DB, officers)
                        return {"status": "success", "message": "Officer account removed."}
                    else:
                        return {"status": "error", "message": "Access Denied: You did not invite this officer."}
                return {"status": "error", "message": "Officer not found."}

            if action == "fetch_tokens":
                secret_keys = load_json(SECRET_KEY_DB)
                # We can't show raw tokens (they are hashed), but we can show hashes 
                # or better, just list the hashes created by this admin.
                # Actually, tokens are better kept as 'unknown' strings to admin for deletion.
                my_tokens = []
                for t_hash, creator in secret_keys.items():
                    if creator == username:
                        my_tokens.append(t_hash)
                return {"status": "success", "tokens": my_tokens}

            if action == "delete_token":
                t_hash = data.get("token_hash")
                secret_keys = load_json(SECRET_KEY_DB)
                if t_hash in secret_keys:
                    if secret_keys[t_hash] == username:
                        del secret_keys[t_hash]
                        save_json(SECRET_KEY_DB, secret_keys)
                        return {"status": "success", "message": "Invitation token revoked."}
                    else:
                        return {"status": "error", "message": "Access Denied: You did not create this token."}
                return {"status": "error", "message": "Token not found."}

            if action == "create_admin":
                new_admin_user = data.get("new_username")
                new_admin_pass = data.get("new_password")
                
                if not new_admin_user or not new_admin_pass:
                    return {"status": "error", "message": "New admin details missing."}
                
                h_new_user = hash_data(new_admin_user)
                h_new_pass = hash_data(new_admin_pass)
                
                if h_new_user in admins:
                    return {"status": "error", "message": "Admin already exists!"}
                
                admins[h_new_user] = {"password": h_new_pass}
                save_json(ADMIN_DB, admins)
                print(f"[Admin] New Admin created: {new_admin_user}")
                return {"status": "success", "message": f"Admin '{new_admin_user}' created successfully."}

            if action == "update_admin":
                new_admin_user = data.get("new_username")
                new_admin_pass = data.get("new_password")
                
                if not new_admin_user or not new_admin_pass:
                    return {"status": "error", "message": "Update details missing."}
                
                h_new_user = hash_data(new_admin_user)
                h_new_pass = hash_data(new_admin_pass)
                
                # Delete old account and create new one (since username is part of hash)
                del admins[hashed_user]
                admins[h_new_user] = {"password": h_new_pass}
                save_json(ADMIN_DB, admins)
                print(f"[Admin] Credentials updated for admin.")
                return {"status": "success", "message": "Credentials updated. Please login with new details next time."}
        
        return {"status": "error", "message": "Unauthorized Admin Access."}

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Audit Blockchain on Startup
    verify_and_repair_chain()
    
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