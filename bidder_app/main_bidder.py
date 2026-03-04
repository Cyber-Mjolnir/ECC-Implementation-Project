import os
import sys

# Add the project root to sys.path to allow importing from 'module/'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import time
import questionary
import json

import module.configuration as cfg
import module.style as style
import module.networkCommunication as network
import module.uiCMD as ui
import module.setup_bidder_profile as setup
import module.ecc_helper as ecc
import module.zkp_engine as zkp

# Configuration
SERVER_HOST = cfg.SERVER_HOST
SERVER_PORT = cfg.SERVER_PORT

# Custom Style: Yellow elements with Light Green Underlined Selection
custom_style = style.custom_style

def main_menu():
    ui.clear_console()
    
    header_line = "=" * 50
    ui.center_print(header_line)
    ui.center_print("CSePS - SECURE E-PROCUREMENT SYSTEM")
    ui.center_print("[Authentication Module - v1.0]")
    ui.center_print(header_line)
    print("\n")

    indent = "    " 
    choice = questionary.select(
        f"{indent}Main Menu Selection:",
        choices=[
            '🔑 Login to Account',
            '📝 Create New Account',
            'ℹ️  System Information',
            '❌ Exit System'
        ],
        style=custom_style
    ).ask()

    if choice and 'Account' in choice:
        action = "signup" if 'Create' in choice else "login"
        mode = "SIGN UP" if action == "signup" else "LOGIN"
        print(f"\n{indent}--- {mode} MODE ---")
        
        username = questionary.text(
            "Enter Username:",
            style=custom_style,
            qmark=f"{indent}?"
        ).ask()
        
        password = questionary.password(
            "Enter Password:",
            style=custom_style,
            qmark=f"{indent}?"
        ).ask()

        if action == "signup":
            confirm_p = questionary.password(
                "Confirm Password:",
                style=custom_style,
                qmark=f"{indent}?"
            ).ask()
            
            if password != confirm_p:
                print(f"\n{indent}❌ Error: Passwords do not match.")
                time.sleep(1.5)
                return
        
        if not username or not password:
            print(f"\n{indent}[!] Error: Fields cannot be empty.")
            time.sleep(1.5)
            return

        print(f"\n{indent}[*] Connecting to Primary Server...")
        result = network.send_request(action, username, password)
        
        if result.get("status") == "success":
            public_id = result.get("public_id")
            print(f"\n{indent}✅ SUCCESS: {result.get('message')}")
            print(f"{indent}[*] Assigned Public ID: {public_id}")
            
            if 'Login' in choice:
                setup.setup_bidder_profile(public_id)
                input(f"\n{indent}Press Enter to access Dashboard...")
                # PASSING PASSWORD TO DASHBOARD FOR KEY ENCRYPTION
                bidder_dashboard(public_id, password) 
            else:
                input(f"\n{indent}Press Enter to return and Login...")
        else:
            print(f"\n{indent}❌ FAILED: {result.get('message')}")
            input(f"\n{indent}Press Enter to retry...")
            
    elif choice == 'ℹ️  System Information':
        ui.clear_console()
        print("\n")
        ui.center_print("="*50)
        ui.center_print("SYSTEM ARCHITECTURE INFO")
        ui.center_print("="*50)
        ui.center_print("Encryption  : Elliptic Curve Cryptography (ECC)")
        ui.center_print("Anonymity   : Hashed Pseudonyms (Privacy Mode)")
        ui.center_print("Storage     : At-Rest AES Encryption for Keys")
        ui.center_print("="*50)
        input(f"\n{indent}Press Enter to return...")
        
    elif choice == '❌ Exit System':
        sys.exit()

def bidder_dashboard(public_id, session_password):
    indent = "    "
    while True:
        ui.clear_console()
        ui.center_print("-" * 60)
        ui.center_print(f"DASHBOARD | AUTHORIZED AS: {public_id}")
        ui.center_print("-" * 60)
        print("\n")
        
        choice = questionary.select(
            f"{indent}Select a secure operation:",
            choices=[
                '🆕 Submit Secure Bid',
                '📜 View Bid History',
                '🔓 Release Decryption Consensus',
                '🔑 Manage ECC Keys',
                '🚪 Secure Logout'
            ],
            style=custom_style
        ).ask()

        if choice == '🚪 Secure Logout':
            print(f"\n{indent}[*] Clearing session cache...")
            time.sleep(1)
            break
            
        elif choice == '🔑 Manage ECC Keys':
            ui.clear_console()
            ui.center_print("🔑 ECC KEY MANAGEMENT")
            ui.center_print("="*45)
            
            helper = ecc.ECCHelper()
            profile_path = os.path.join("bidder_app", "profiles", public_id)
            if not os.path.exists(profile_path):
                os.makedirs(profile_path)
            
            print(f"\n{indent}[*] Generating & Encrypting NIST P-256 key pair...")
            # USING THE LOGIN PASSWORD TO ENCRYPT THE PEM FILE
            success, msg = helper.generate_and_save_keys(profile_path, session_password)
            
            if success:
                print(f"{indent}✅ {msg}")
                print(f"{indent}[*] Your Private Key is locked with your login password.")
            else:
                print(f"{indent}❌ {msg}")
            
            input(f"\n{indent}Press Enter to return...")
            # No break here, we want to stay in the dashboard
            
        elif choice == '🆕 Submit Secure Bid':
            submit_secure_bid(public_id, session_password, indent)
            
        elif choice == '📜 View Bid History':
            view_bid_history(public_id, indent)

        elif choice == '🔓 Release Decryption Consensus':
            release_consensus_shares(public_id, session_password, indent)

def release_consensus_shares(public_id, session_password, indent):
    ui.clear_console()
    ui.center_print("🔓 RELEASE DECRYPTION CONSENSUS")
    ui.center_print("="*45)
    
    # --- 🔐 PASSWORD RE-VERIFICATION ---
    confirm_pass = questionary.password(
        f"{indent}Verify Session Password to release consensus shares:",
        qmark="?",
        style=custom_style
    ).ask()
    
    if confirm_pass != session_password:
        print(f"\n{indent}❌ Error: Incorrect Password. Access Denied.")
        input(f"\n{indent}Press Enter...")
        return

    bids_path = os.path.join("bidder_app", "profiles", public_id, "my_bids.json")
    if not os.path.exists(bids_path):
        print(f"\n{indent}[!] No bid history found.")
        input(f"\n{indent}Press Enter...")
        return
        
    with open(bids_path, "r") as f:
        bids = json.load(f)
    
    active_bids = [b for b in bids if not b.get("released", False)]
    if not active_bids:
        print(f"\n{indent}[!] No pending shares to release.")
        input(f"\n{indent}Press Enter...")
        return
        
    print(f"\n{indent}[*] Releasing shares to allow Officer decryption...")
    for bid in bids:
        if not bid.get("released", False):
            req = {
                "role": "bidder",
                "action": "release_share",
                "bidder_id": public_id,
                "tender_id": bid["tender_id"],
                "share": bid["decryption_share"]
            }
            res = network.send_request_raw(req)
            if res.get("status") == "success":
                bid["released"] = True
                print(f"{indent}✅ Share released for Tender: {bid['tender_id']}")
            else:
                 print(f"{indent}❌ Failed for {bid['tender_id']}: {res.get('message')}")
                 
    with open(bids_path, "w") as f:
        json.dump(bids, f, indent=4)
        
    input(f"\n{indent}Press Enter to return...")

def view_bid_history(public_id, indent):
    ui.clear_console()
    ui.center_print("📜 MY BID HISTORY (LOCAL HASH LEDGER)")
    ui.center_print("="*45)
    
    bids_path = os.path.join("bidder_app", "profiles", public_id, "my_bids.json")
    if not os.path.exists(bids_path):
        print(f"\n{indent}[!] No local bid history found.")
    else:
        with open(bids_path, "r") as f:
            bids = json.load(f)
        for bid in bids:
            print(f"\n{indent}Tender ID: {bid['tender_id']}")
            print(f"{indent}Blockchain Hash: {bid['blockchain_hash']}")
            print(f"{indent}ZKP Blinding Factor: {bid['blinding_factor']}")
            print("-" * 40)
            
    input(f"\n{indent}Press Enter to return...")

def submit_secure_bid(public_id, session_password, indent):
    ui.clear_console()
    ui.center_print("🆕 SECURE BID SUBMISSION (E2EE + ZKP)")
    ui.center_print("="*45)
    
    profile_path = os.path.join("bidder_app", "profiles", public_id)
    helper = ecc.ECCHelper()
    private_key = helper.load_private_key(profile_path, session_password)
    
    if not private_key:
        print(f"\n{indent}❌ Error: ECC Keys not found or wrong password! Please generate keys first.")
        input(f"\n{indent}Press Enter to return...")
        return
        
    pub_path = os.path.join(profile_path, "public_key.pem")
    with open(pub_path, "r") as f:
        my_public_key = f.read()

    print(f"\n{indent}[*] Fetching Open Tenders from Server...")
    req = {"role": "bidder", "action": "fetch_tenders"}
    res = network.send_request_raw(req)
    
    if res.get("status") != "success" or not res.get("tenders"):
        print(f"{indent}[!] No open tenders available right now.")
        input(f"\n{indent}Press Enter to return...")
        return
        
    tenders = res["tenders"]
    choices = [f"ID: {tid} | {tdata['data']['title']} (Ends: {tdata['data']['deadline']})" for tid, tdata in tenders.items()]
    choices.append("❌ Cancel")
    
    selected = questionary.select(
        f"{indent}Select a Tender:",
        choices=choices,
        style=custom_style
    ).ask()
    
    if selected == "❌ Cancel":
        return
        
    tender_id = selected.split(" |")[0].replace("ID: ", "").strip()
    target_tender = tenders[tender_id]
    officer_pub_key = target_tender["public_key"]
    
    # Range parameters (hardcoded for prototype, usually provided in tender data)
    min_val = 1000
    max_val = 1000000
    
    print(f"\n{indent}Tender Rules: Bid must be between ${min_val} and ${max_val}")
    try:
        bid_amount = int(questionary.text(f"Enter Bid Amount ($):", qmark=f"{indent}?", style=custom_style).ask())
    except ValueError:
        print(f"{indent}❌ Invalid amount.")
        input(f"\n{indent}Press Enter...")
        return

    # 1. ZKP Generation
    print(f"{indent}[*] Generating Zero-Knowledge Range Proof...")
    engine = zkp.ZKPEngine()
    try:
        proof_data = engine.generate_range_proof(bid_amount, min_val, max_val)
    except ValueError as e:
        print(f"{indent}❌ {e}")
        input(f"\n{indent}Press Enter...")
        return
        
    # 2. E2EE Encryption
    print(f"{indent}[*] Encrypting Bid Data (E2EE) for Evaluators...")
    bid_payload = json.dumps({"amount": bid_amount, "tender_id": tender_id}).encode('utf-8')
    encrypted_bid = helper.encrypt_data(officer_pub_key, bid_payload)
    
    # 3. Signing
    print(f"{indent}[*] Signing encrypted payload...")
    bid_data_for_server = {
        "tender_id": tender_id,
        "encrypted_payload": encrypted_bid
    }
    bid_json = json.dumps(bid_data_for_server, sort_keys=True)
    signature = helper.sign_data(private_key, bid_json)
    
    # 4. Submit to Server
    print(f"{indent}[*] Submitting to Blockchain Ledger...")
    req = {
        "role": "bidder",
        "action": "submit_bid",
        "bidder_id": public_id,
        "bid_data": bid_data_for_server,
        "zkp_proof": {
            "commitment": proof_data["commitment"],
            "proof": proof_data["proof"],
            "min_val": min_val,
            "max_val": max_val
        },
        "signature": signature,
        "public_key": my_public_key
    }
    
    res = network.send_request_raw(req)
    if res.get("status") == "success":
        print(f"\n{indent}✅ SUCCESS: {res.get('message')}")
        print(f"{indent}🔗 Hash: {res.get('bid_hash')}")
        
        # Save to local log
        bids_path = os.path.join(profile_path, "my_bids.json")
        bids_list = []
        if os.path.exists(bids_path):
            with open(bids_path, "r") as f:
                bids_list = json.load(f)
                
        bids_list.append({
            "tender_id": tender_id,
            "blockchain_hash": res.get("bid_hash"),
            "blinding_factor": proof_data["blinding_factor"],
            "decryption_share": res.get("decryption_share"), # KEY PIECE FROM SERVER
            "timestamp": time.time(),
            "released": False
        })
        with open(bids_path, "w") as f:
            json.dump(bids_list, f, indent=4)
            
    else:
        print(f"\n{indent}❌ FAILED: {res.get('message')}")

    input(f"\n{indent}Press Enter to return...")

if __name__ == "__main__":
    if not os.path.exists("bidder_app/profiles"):
        os.makedirs("bidder_app/profiles")
        
    while True:
        main_menu()