import os
import sys
import json

# Add the project root to sys.path to allow importing from 'module/'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import time
import questionary
import module.configuration as cfg
import module.style as style
import module.networkCommunication as network
import module.uiCMD as ui
import module.ecc_helper as ecc

# Configuration
custom_style = style.custom_style
indent = "    "

def send_officer_request(data):
    """Wraps the network call specifically for Officer/Admin roles."""
    return network.send_request_raw(data) # Assumes a raw data sender in network module

def admin_dashboard(admin_user, admin_pass):
    while True:
        ui.clear_console()
        ui.center_print("⚡ SYSTEM ADMINISTRATION CONSOLE ⚡")
        ui.center_print("="*50)
        
        choice = questionary.select(
            f"{indent}Select Admin Task:",
            choices=[
                '🎟️  Generate Officer Token',
                '👥 View Active Officers',
                '🛡️  System Audit Logs',
                '🚪 Logout'
            ],
            style=custom_style
        ).ask()

        if choice == '🎟️  Generate Officer Token':
            print(f"\n{indent}[*] Requesting new Secret ID from server...")
            
            request = {
                "role": "admin",
                "action": "generate_token",
                "username": admin_user,
                "password": admin_pass 
            }
            result = network.send_request_raw(request)
            if result.get("status") == "success":
                token = result.get("token")
                print(f"\n{indent}✅ NEW TOKEN GENERATED: {token}")
                print(f"{indent}[!] Provide this to the new Officer for signup.")
            else:
                print(f"\n{indent}❌ Error: {result.get('message')}")
            input(f"\n{indent}Press Enter to return...")

        elif choice == '🚪 Logout':
            break

def officer_dashboard(username, password, officer_id):
    while True:
        ui.clear_console()
        ui.center_print(f"📋 OFFICER PANEL | {username.upper()} ({officer_id})")
        ui.center_print("-" * 50)
        
        choice = questionary.select(
            f"{indent}Operations:",
            choices=[
                '🔓 Open Tender for Bidding',
                '📊 View Submitted Bids',
                '⚖️  Evaluate & Close Tender',
                '🔑 Manage ECC Keys',
                '🚪 Logout'
            ],
            style=custom_style
        ).ask()

        if choice == '🚪 Logout':
            break
        elif choice == '🔑 Manage ECC Keys':
            manage_officer_keys(officer_id, password)
        elif choice == '🔓 Open Tender for Bidding':
            create_new_tender(officer_id, password)
        elif choice == '📊 View Submitted Bids':
            view_submitted_bids(officer_id, password)
        else:
            print(f"\n{indent}[Notice] {choice} requires ZKP Verification module.")
            input(f"\n{indent}Press Enter...")

def view_submitted_bids(officer_id, password):
    ui.clear_console()
    ui.center_print("📊 EVALUATE SUBMITTED BIDS")
    ui.center_print("="*45)

    profile_path = os.path.join("officer_app", "profiles", officer_id)
    helper = ecc.ECCHelper()
    private_key = helper.load_private_key(profile_path, password)
    
    if not private_key:
        print(f"\n{indent}❌ Error: Failed to load private key. Ensure you have generated it and your password is correct.")
        input(f"\n{indent}Press Enter to return...")
        return

    print(f"\n{indent}[*] Fetching your tenders...")
    req = {"role": "officer", "action": "fetch_tenders"}
    res = network.send_request_raw(req)
    if res.get("status") != "success" or not res.get("tenders"):
        print(f"{indent}[!] No tenders found.")
        input(f"\n{indent}Press Enter to return...")
        return

    # Filter to only show this officer's tenders
    my_tenders = {tid: tdata for tid, tdata in res["tenders"].items() if tdata["data"]["officer_id"] == officer_id}
    if not my_tenders:
        print(f"{indent}[!] You haven't created any tenders yet.")
        input(f"\n{indent}Press Enter to return...")
        return

    choices = [f"ID: {tid} | {tdata['data']['title']}" for tid, tdata in my_tenders.items()]
    choices.append("❌ Cancel")
    
    selected = questionary.select(
        f"{indent}Select a Tender to Evaluate:",
        choices=choices,
        style=custom_style
    ).ask()
    
    if selected == "❌ Cancel":
        return
        
    tender_id = selected.split(" |")[0].replace("ID: ", "").strip()
    
    print(f"\n{indent}[*] Requesting Sealed Bids and Threshold Shares for {tender_id}...")
    req = {"role": "officer", "action": "fetch_bids", "tender_id": tender_id}
    res = network.send_request_raw(req)
    
    if res.get("status") != "success":
        print(f"\n{indent}❌ REJECTED: {res.get('message')}")
        input(f"\n{indent}Press Enter...")
        return

    bids = res.get("bids", [])
    shares = res.get("shares", [])
    
    if not bids:
        print(f"{indent}[!] No bids found for this tender.")
        input(f"\n{indent}Press Enter to return...")
        return
        
    # --- 🏗️  RECONSTRUCT TENDER KEY (Master Key Wrap Decryption) ---
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import serialization

    print(f"{indent}[*] Reconstructing Master Key from Bidder Consensus Shares...")
    master_key = helper.reconstruct_tender_key(shares)
    
    if not master_key:
        print(f"{indent}❌ Error: Failed to reconstruct Master Key (Insufficient shares).")
        input(f"\n{indent}Press Enter...")
        return

    # Decrypt the Wrapped Tender Key
    wrapped = res.get("wrapped_tender_key")
    if not wrapped:
        print(f"{indent}❌ Error: No wrapped tender key found on server.")
        input(f"\n{indent}Press Enter...")
        return

    try:
        aesgcm = AESGCM(master_key)
        nonce = base64.b64decode(wrapped["nonce"])
        ciphertext = base64.b64decode(wrapped["ciphertext"])
        raw_tender_priv_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        
        tender_private_key = serialization.load_der_private_key(
            raw_tender_priv_bytes,
            password=None
        )
    except Exception as e:
        print(f"{indent}❌ Error: Failed to unwrap Tender Key: {str(e)}")
        input(f"\n{indent}Press Enter...")
        return

    print(f"\n{indent}--- 📜 DECRYPTING BIDS (CONSENSUS-GATE OPENED) ---")
    for b_wrap in bids:
        block = b_wrap["block"]
        bid_hash = b_wrap["hash"]
        encrypted_payload = block["bid_data"]["encrypted_payload"]
        
        print(f"\n{indent}🔗 Block Hash: {bid_hash[:16]}...")
        # Verify ZKP locally
        import module.zkp_engine as zkp
        engine = zkp.ZKPEngine()
        is_valid_range = engine.verify_range_proof(block["zkp_proof"])
        print(f"{indent}🛡️  ZKP Range Proof Valid: {'✅ YES' if is_valid_range else '❌ NO'}")
        
        # Decrypt using the RECONSTRUCTED TENDER KEY
        try:
            decrypted_bytes = helper.decrypt_data(tender_private_key, encrypted_payload)
            if decrypted_bytes:
                decrypted_json = json.loads(decrypted_bytes.decode('utf-8'))
                print(f"{indent}💰 Decrypted Bid Amount: ${decrypted_json['amount']}")
            else:
                print(f"{indent}❌ Decryption failed.")
        except Exception as e:
             print(f"{indent}❌ Decryption Error: {str(e)}")
             
    input(f"\n{indent}Press Enter to return...")

def manage_officer_keys(officer_id, password):
    ui.clear_console()
    ui.center_print("🔑 OFFICER ECC KEY MANAGEMENT")
    ui.center_print("="*45)
    
    helper = ecc.ECCHelper()
    profile_path = os.path.join("officer_app", "profiles", officer_id)
    if not os.path.exists(profile_path):
        os.makedirs(profile_path)
    
    print(f"\n{indent}[*] Generating & Encrypting NIST P-256 key pair...")
    success, msg = helper.generate_and_save_keys(profile_path, password)
    
    if success:
        print(f"{indent}✅ {msg}")
        print(f"{indent}[*] Your Private Key is locked with your login password.")
    else:
        print(f"{indent}❌ {msg}")
    
    input(f"\n{indent}Press Enter to return...")

def create_new_tender(officer_id, password):
    ui.clear_console()
    ui.center_print("🔓 CREATE NEW TENDER")
    ui.center_print("="*45)

    profile_path = os.path.join("officer_app", "profiles", officer_id)
    priv_path = os.path.join(profile_path, "private_key.pem")
    pub_path = os.path.join(profile_path, "public_key.pem")

    if not os.path.exists(priv_path) or not os.path.exists(pub_path):
        print(f"\n{indent}❌ Error: ECC Keys not found! Please generate them first.")
        input(f"\n{indent}Press Enter to return...")
        return

    # 1. Take Tender Details
    t_id = questionary.text("Tender ID:", qmark=f"{indent}?", style=custom_style).ask()
    title = questionary.text("Tender Title:", qmark=f"{indent}?", style=custom_style).ask()
    desc = questionary.text("Description:", qmark=f"{indent}?", style=custom_style).ask()
    deadline = questionary.text("Deadline (YYYY-MM-DD):", qmark=f"{indent}?", style=custom_style).ask()

    if not all([t_id, title, desc, deadline]):
        print(f"\n{indent}❌ Error: All fields are required.")
        input(f"\n{indent}Press Enter...")
        return

    tender_data = {
        "tender_id": t_id,
        "title": title,
        "description": desc,
        "deadline": deadline,
        "officer_id": officer_id
    }
    
    # 2. Sign the Tender Data
    print(f"\n{indent}[*] Generating Immutability Seal (Hashing)...")
    helper = ecc.ECCHelper()
    data_hash = helper.generate_data_hash(tender_data)
    
    print(f"{indent}[*] Signing Seal with ECC Private Key...")
    private_key = helper.load_private_key(profile_path, password)
    
    if not private_key:
        print(f"{indent}❌ Error: Failed to load private key (Wrong password or corrupted file).")
        input(f"\n{indent}Press Enter...")
        return

    tender_json = json.dumps(tender_data, sort_keys=True)
    signature = helper.sign_data(private_key, tender_json)

    with open(pub_path, "r") as f:
        public_key_pem = f.read()

    # 3. Send to Server
    request = {
        "role": "officer",
        "action": "create_tender",
        "tender_data": tender_data,
        "data_hash": data_hash, # Explicit hash for auditing
        "signature": signature,
        "public_key": public_key_pem
    }

    result = network.send_request_raw(request)
    if result.get("status") == "success":
        print(f"\n{indent}✅ SUCCESS: {result.get('message')}")
    else:
        print(f"\n{indent}❌ FAILED: {result.get('message')}")

    input(f"\n{indent}Press Enter to return...")

def main():
    while True:
        ui.clear_console()
        ui.center_print("==================================================")
        center_text = "CSePS - OFFICER & ADMIN PORTAL"
        ui.center_print(center_text)
        ui.center_print("==================================================")
        print("\n")

        choice = questionary.select(
            f"{indent}Portal Access:",
            choices=[
                '👤 Officer Login',
                '🆕 Officer Registration (Secret ID Required)',
                '⚡ System Admin Login',
                '❌ Exit'
            ],
            style=custom_style
        ).ask()

        if choice == '🆕 Officer Registration (Secret ID Required)':
            ui.clear_console()
            print(f"\n{indent}--- OFFICER ENROLLMENT ---")
            secret_id = questionary.text(f"Enter Secret ID Token:", qmark=f"{indent}?", style=custom_style).ask()
            username = questionary.text(f"Set Username:", qmark=f"{indent}?", style=custom_style).ask()
            password = questionary.password(f"Set Password:", qmark=f"{indent}?", style=custom_style).ask()

            request = {
                "role": "officer",
                "action": "officer_signup",
                "secret_id": secret_id,
                "username": username,
                "password": password
            }
            result = network.send_request_raw(request)
            if result.get("status") == "success":
                print(f"\n{indent}✅ Registration Successful! You can now login.")
            else:
                print(f"\n{indent}❌ Registration Failed: {result.get('message')}")
            input(f"\n{indent}Press Enter...")

        elif choice == '👤 Officer Login':
            username = questionary.text(f"Username:", qmark=f"{indent}?", style=custom_style).ask()
            password = questionary.password(f"Password:", qmark=f"{indent}?", style=custom_style).ask()
            
            request = {"role": "officer", "action": "login", "username": username, "password": password}
            result = network.send_request_raw(request)
            
            if result.get("status") == "success":
                officer_id = result.get("officer_id")
                print(f"\n{indent}✅ {result.get('message')} ({officer_id})")
                time.sleep(1)
                officer_dashboard(username, password, officer_id)
            else:
                print(f"\n{indent}❌ Login Failed.")
                time.sleep(2)

        elif choice == '⚡ System Admin Login':
            username = questionary.text(f"Admin Username:", qmark=f"{indent}?", style=custom_style).ask()
            password = questionary.password(f"Admin Access Code:", qmark=f"{indent}?", style=custom_style).ask()
            
            # Send request to server for validation
            request = {
                "role": "admin", 
                "action": "admin_login", 
                "username": username, 
                "password": password
            }
            result = network.send_request_raw(request)
            
            if result.get("status") == "success":
                admin_dashboard(username, password)
            else:
                print(f"\n{indent}❌ Unauthorized.")
                time.sleep(2)

        elif choice == '❌ Exit':
            sys.exit()

if __name__ == "__main__":
    main()