import os
import sys
import json
import uuid

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
                '🎟️  Manage Pending Tokens',
                '🔑 Manage Admin ECC Keys',
                '➕ Create New Admin',
                '🔐 Update My Credentials',
                '👥 View Active Officers',
                '🛡️  System Audit Logs',
                '🚪 Logout'
            ],
            style=custom_style
        ).ask()

        if choice == '🎟️  Generate Officer Token':
            admin_profile_id = f"ADMIN-{admin_user.upper()}"
            profile_path = os.path.join("officer_app", "profiles", admin_profile_id)
            helper = ecc.ECCHelper()
            
            # Load Private Key for Signing
            private_key = helper.load_private_key(profile_path, admin_pass)
            if not private_key:
                print(f"\n{indent}❌ Error: Admin ECC Keys not found or wrong password!")
                print(f"{indent}[!] Please generate keys first using 'Manage Admin ECC Keys'.")
                input(f"\n{indent}Press Enter...")
                continue

            # Load Public Key PEM
            with open(os.path.join(profile_path, "public_key.pem"), "r") as f:
                admin_pub_pem = f.read()

            raw_token = str(uuid.uuid4())[:12].upper()
            print(f"\n{indent}[*] Signing Token with Admin Private Key...")
            signature = helper.sign_data(private_key, raw_token)

            request = {
                "role": "admin",
                "action": "generate_token",
                "username": admin_user,
                "password": admin_pass,
                "token": raw_token,
                "signature": signature,
                "public_key": admin_pub_pem
            }
            
            result = network.send_request_raw(request)
            if result.get("status") == "success":
                print(f"\n{indent}✅ SIGNED TOKEN GENERATED: {raw_token}")
                print(f"{indent}[!] Verification Signature: {signature[:16]}...")
            else:
                print(f"\n{indent}❌ Error: {result.get('message')}")
            input(f"\n{indent}Press Enter to return...")

        elif choice == '🔑 Manage Admin ECC Keys':
            admin_profile_id = f"ADMIN-{admin_user.upper()}"
            manage_admin_keys(admin_profile_id, admin_pass)

        elif choice == '➕ Create New Admin':
            ui.clear_console()
            print(f"\n{indent}--- REGISTER NEW ADMIN ---")
            new_u = questionary.text(f"Set New Admin Username:", qmark=f"{indent}?", style=custom_style).ask()
            new_p = questionary.password(f"Set New Admin Password:", qmark=f"{indent}?", style=custom_style).ask()
            confirm_p = questionary.password(f"Confirm New Admin Password:", qmark=f"{indent}?", style=custom_style).ask()

            if not new_u or not new_p:
                print(f"\n{indent}❌ Error: All fields required.")
                input(f"\n{indent}Press Enter...")
                continue
            
            if new_p != confirm_p:
                print(f"\n{indent}❌ Error: Passwords do not match.")
                input(f"\n{indent}Press Enter...")
                continue

            request = {
                "role": "admin",
                "action": "create_admin",
                "username": admin_user,
                "password": admin_pass,
                "new_username": new_u,
                "new_password": new_p
            }
            result = network.send_request_raw(request)
            if result.get("status") == "success":
                print(f"\n{indent}✅ {result.get('message')}")
            else:
                print(f"\n{indent}❌ Failed: {result.get('message')}")
            input(f"\n{indent}Press Enter...")

        elif choice == '🔐 Update My Credentials':
            ui.clear_console()
            print(f"\n{indent}--- UPDATE ADMIN CREDENTIALS ---")
            
            # Re-verify to proceed
            curr_pass = questionary.password(f"Current Admin Password to verify:", qmark=f"{indent}?", style=custom_style).ask()
            if curr_pass != admin_pass:
                print(f"\n{indent}❌ Error: Incorrect password verification.")
                input(f"\n{indent}Press Enter...")
                continue

            new_u = questionary.text(f"Set New Username:", qmark=f"{indent}?", style=custom_style).ask()
            new_p = questionary.password(f"Set New Password:", qmark=f"{indent}?", style=custom_style).ask()
            confirm_p = questionary.password(f"Confirm New Password:", qmark=f"{indent}?", style=custom_style).ask()

            if not new_u or not new_p:
                print(f"\n{indent}❌ Error: All fields required.")
                input(f"\n{indent}Press Enter...")
                continue

            if new_p != confirm_p:
                print(f"\n{indent}❌ Error: Passwords do not match.")
                input(f"\n{indent}Press Enter...")
                continue

            request = {
                "role": "admin",
                "action": "update_admin",
                "username": admin_user,
                "password": admin_pass,
                "new_username": new_u,
                "new_password": new_p
            }
            result = network.send_request_raw(request)
            if result.get("status") == "success":
                print(f"\n{indent}✅ {result.get('message')}")
                print(f"{indent}[!] Session will close. Please log in with new details.")
                input(f"\n{indent}Press Enter to return to main portal...")
                break # Logout to force fresh login with new details
            else:
                print(f"\n{indent}❌ Failed: {result.get('message')}")
            input(f"\n{indent}Press Enter...")

        elif choice == '🎟️  Manage Pending Tokens':
            ui.clear_console()
            ui.center_print("🎟️  MY PENDING INVITATION TOKENS")
            ui.center_print("="*60)
            
            req = {"role": "admin", "action": "fetch_tokens", "username": admin_user, "password": admin_pass}
            res = network.send_request_raw(req)
            
            if res.get("status") == "success":
                tokens = res.get("tokens", [])
                if not tokens:
                    print(f"\n{indent}[!] No pending tokens created by you.")
                else:
                    choices = [f"Token Hash: {t}" for t in tokens]
                    choices.append("❌ Cancel")
                    
                    sel = questionary.select(f"{indent}Select a token to revoke:", choices=choices, style=custom_style).ask()
                    if sel != "❌ Cancel":
                        idx = choices.index(sel)
                        token_hash = tokens[idx]
                        
                        confirm = questionary.confirm(f"{indent}Are you sure you want to revoke this invitation?", default=False).ask()
                        if confirm:
                            del_req = {
                                "role": "admin", "action": "delete_token", 
                                "username": admin_user, "password": admin_pass,
                                "token_hash": token_hash
                            }
                            del_res = network.send_request_raw(del_req)
                            print(f"\n{indent}✅ {del_res.get('message')}")
            else:
                print(f"\n{indent}❌ Error: {res.get('message')}")
            input(f"\n{indent}Press Enter...")

        elif choice == '👥 View Active Officers':
            ui.clear_console()
            ui.center_print("👥 ACTIVE OFFICER DIRECTORY (INVITATION TRACKING)")
            ui.center_print("="*60)
            
            request = {
                "role": "admin",
                "action": "fetch_officers",
                "username": admin_user,
                "password": admin_pass
            }
            result = network.send_request_raw(request)
            
            if result.get("status") == "success":
                officers = result.get("officers", [])
                if not officers:
                    print(f"\n{indent}[!] No officers registered in the system yet.")
                else:
                    # Simple Table Display
                    print(f"\n{indent}{'OFFICER ID':<25} | {'INVITED BY ADMIN':<20}")
                    print(f"{indent}{'-'*25}-+-{'-'*20}")
                    for off in officers:
                        off_id = off.get("id", "N/A")
                        invited_by = off.get("invited_by", "Unknown")
                        print(f"{indent}{off_id:<25} | {invited_by:<20}")
                    
                    # Deletion Logic
                    my_officers = [o for o in officers if o.get("invited_by") == admin_user]
                    if my_officers:
                        choices = [f"Remove: {o['id']}" for o in my_officers]
                        choices.append("❌ Cancel Deletion")
                        
                        sel = questionary.select(f"\n{indent}Manage your invited officers:", choices=choices, style=custom_style).ask()
                        if sel != "❌ Cancel Deletion":
                            idx = choices.index(sel)
                            target = my_officers[idx]
                            
                            confirm = questionary.confirm(f"{indent}Permanently delete officer account '{target['id']}'?", default=False).ask()
                            if confirm:
                                del_req = {
                                    "role": "admin", "action": "delete_officer", 
                                    "username": admin_user, "password": admin_pass,
                                    "officer_hash": target['hash']
                                }
                                del_res = network.send_request_raw(del_req)
                                print(f"\n{indent}✅ {del_res.get('message')}")
            else:
                print(f"\n{indent}❌ Error fetching list: {result.get('message')}")
            
            input(f"\n{indent}Press Enter to return...")

        elif choice == '🚪 Logout':
            break

def manage_admin_keys(profile_id, password):
    ui.clear_console()
    ui.center_print("🔑 ADMIN ECC KEY MANAGEMENT")
    ui.center_print("="*45)
    
    helper = ecc.ECCHelper()
    profile_path = os.path.join("officer_app", "profiles", profile_id)
    if not os.path.exists(profile_path):
        os.makedirs(profile_path)
    
    print(f"\n{indent}[*] Generating & Encrypting NIST P-256 key pair for Admin...")
    success, msg = helper.generate_and_save_keys(profile_path, password)
    
    if success:
        print(f"{indent}✅ {msg}")
        print(f"{indent}[*] Admin Private Key is locked with your login password.")
    else:
        print(f"{indent}❌ {msg}")
    
    input(f"\n{indent}Press Enter to return...")

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
                '🔓 Release My Evaluator Share',
                '⚖️  Evaluate & Close Tender',
                '🔑 Manage ECC Keys',
                '🗑️  Delete My Account',
                '🚪 Logout'
            ],
            style=custom_style
        ).ask()

        if choice == '🚪 Logout':
            break
        elif choice == '🗑️  Delete My Account':
            ui.clear_console()
            ui.center_print("🗑️  PERMANENT ACCOUNT DELETION")
            ui.center_print("="*50)
            print(f"\n{indent}[!] WARNING: All your tender data and keys will be inaccessible.")
            
            confirm = questionary.confirm(f"{indent}Are you absolutely sure you want to delete your account?", default=False).ask()
            if confirm:
                # Require password for final confirmation
                re_pass = questionary.password(f"{indent}Enter password to authorize deletion:", qmark="?", style=custom_style).ask()
                
                req = {
                    "role": "officer", "action": "delete_self",
                    "username": username, "password": re_pass
                }
                res = network.send_request_raw(req)
                
                if res.get("status") == "success":
                    print(f"\n{indent}✅ {res.get('message')}")
                    time.sleep(2)
                    break # Break the dashboard loop to logout
                else:
                    print(f"\n{indent}❌ Error: {res.get('message')}")
                    input(f"\n{indent}Press Enter...")
        
        elif choice == '🔑 Manage ECC Keys':
            manage_officer_keys(officer_id, password)
        elif choice == '🔓 Open Tender for Bidding':
            create_new_tender(officer_id, password)
        elif choice == '🔓 Release My Evaluator Share':
            release_officer_consensus(officer_id, password)
        elif choice == '📊 View Submitted Bids':
            view_submitted_bids(officer_id, password)
        elif choice == '⚖️  Evaluate & Close Tender':
            evaluate_and_close_tender(officer_id, password)
        else:
            print(f"\n{indent}[Notice] {choice} requires ZKP Verification module.")
            input(f"\n{indent}Press Enter...")

def evaluate_and_close_tender(officer_id, password):
    ui.clear_console()
    ui.center_print("⚖️  EVALUATE & CLOSE TENDER")
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

    # Only show OPEN tenders owned by this officer
    my_tenders = {tid: tdata for tid, tdata in res["tenders"].items() 
                  if tdata["data"]["officer_id"] == officer_id and tdata.get("status") == "OPEN"}
    
    if not my_tenders:
        print(f"{indent}[!] You have no open tenders to evaluate.")
        input(f"\n{indent}Press Enter to return...")
        return

    choices = [f"ID: {tid} | {tdata['data']['title']}" for tid, tdata in my_tenders.items()]
    choices.append("❌ Cancel")
    
    selected = questionary.select(
        f"{indent}Select a Tender to Evaluate & Close:",
        choices=choices,
        style=custom_style
    ).ask()
    
    if selected == "❌ Cancel":
        return
        
    tender_id = selected.split(" |")[0].replace("ID: ", "").strip()
    
    print(f"\n{indent}[*] Requesting Dual-Consensus Data for {tender_id}...")
    req = {"role": "officer", "action": "fetch_bids", "tender_id": tender_id}
    res = network.send_request_raw(req)
    
    if res.get("status") != "success":
        print(f"\n{indent}❌ ACCESS DENIED: {res.get('message')}")
        input(f"\n{indent}Press Enter...")
        return

    bids = res.get("bids", [])
    bidder_shares = res.get("bidder_shares", [])
    officer_shares = res.get("officer_shares", [])
    
    if not bids:
        print(f"{indent}[!] No bids found to evaluate.")
        input(f"\n{indent}Press Enter to return...")
        return

    # --- 🏗️  RECONSTRUCT TENDER KEY (Dual-Consensus XOR Wrap) ---
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import serialization

    print(f"{indent}[*] Reconstructing Master Key from Consensus Shares...")
    mk_b = helper.reconstruct_tender_key(bidder_shares)
    mk_o = helper.reconstruct_tender_key(officer_shares)
    
    if not mk_b or not mk_o:
        print(f"{indent}❌ Error: Failed to reconstruct consensus components.")
        input(f"\n{indent}Press Enter...")
        return

    # Combine Components: Master_Key = MK_B ^ MK_O
    master_key = bytes(a ^ b for a, b in zip(mk_b, mk_o))

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

    print(f"\n{indent}--- 📜 DECRYPTING & VERIFYING BID BLOCKCHAIN ---")
    
    # --- 🔗 BLOCKCHAIN INTEGRITY CHECK ---
    print(f"{indent}[*] Verifying Ledger Chain Integrity...")
    ledger_valid = True
    for i in range(1, len(bids)):
        current_block = bids[i]["block"]
        prev_hash_in_block = current_block.get("prev_hash")
        actual_prev_hash = bids[i-1]["hash"]
        
        if prev_hash_in_block != actual_prev_hash:
            print(f"{indent}❌ LEDGER ERROR: Chain broken at block {bids[i]['hash'][:16]}!")
            ledger_valid = False
            break
    
    if not ledger_valid:
        print(f"{indent}❌ Error: Blockchain integrity compromised. Evaluation aborted.")
        input(f"\n{indent}Press Enter...")
        return
    print(f"{indent}✅ Ledger Integrity Verified (Genesis to Tip)")

    decrypted_bids = []
    for b_wrap in bids:
        block = b_wrap["block"]
        bidder_id = block.get("bidder_id", "Unknown")
        encrypted_payload = block["bid_data"]["encrypted_payload"]
        
        # Verify ZKP locally
        import module.zkp_engine as zkp
        engine = zkp.ZKPEngine()
        is_valid_zkp = engine.verify_range_proof(block["zkp_proof"])
        
        status_icon = "✅" if is_valid_zkp else "❌"
        print(f"{indent}🔗 Block: {b_wrap['hash'][:16]}... | ZKP: {status_icon}")

        if not is_valid_zkp:
            print(f"{indent}⚠️  Warning: Skipping bid from {bidder_id} due to invalid ZKP.")
            continue

        # Decrypt using the RECONSTRUCTED TENDER KEY
        try:
            decrypted_bytes = helper.decrypt_data(tender_private_key, encrypted_payload)
            if decrypted_bytes:
                decrypted_json = json.loads(decrypted_bytes.decode('utf-8'))
                decrypted_bids.append({
                    "bidder_id": bidder_id,
                    "amount": float(decrypted_json['amount']),
                    "hash": b_wrap["hash"]
                })
            else:
                print(f"{indent}❌ Decryption failed for block {b_wrap['hash'][:8]}.")
        except Exception as e:
             print(f"{indent}❌ Decryption Error: {str(e)}")

    if not decrypted_bids:
        print(f"\n{indent}❌ No valid bids could be decrypted for evaluation.")
        input(f"\n{indent}Press Enter...")
        return

    # --- ⚖️  SORT AND EVALUATE ---
    # Sort Bids by Amount (Minimum first as requested)
    decrypted_bids.sort(key=lambda x: x['amount'])

    print(f"\n{indent}{'BIDDER ID':<15} | {'AMOUNT':<10} | {'INTEGRITY'}")
    print(f"{indent}{'-'*15}-+-{'-'*10}-+-{'-'*15}")
    for b in decrypted_bids:
        print(f"{indent}{b['bidder_id']:<15} | ${b['amount']:<9} | ✅ Verified Block")

    winner = decrypted_bids[0]
    print(f"\n{indent}🏆 Winning Candidate: {winner['bidder_id']} with lowest bid of ${winner['amount']}")
    
    confirm = questionary.confirm(f"{indent}Permanently close this tender and award to {winner['bidder_id']}?", default=True).ask()
    
    if confirm:
        close_req = {
            "role": "officer", "action": "close_tender",
            "tender_id": tender_id, "officer_id": officer_id,
            "winner_id": winner['bidder_id'], "winning_bid": winner['amount']
        }
        close_res = network.send_request_raw(close_req)
        
        if close_res.get("status") == "success":
            print(f"\n{indent}✅ {close_res.get('message')}")
        else:
            print(f"\n{indent}❌ Server Error: {close_res.get('message')}")
    else:
        print(f"\n{indent}[!] Evaluation aborted. Tender remains OPEN.")

    input(f"\n{indent}Press Enter to return...")

def release_officer_consensus(officer_id, password):
    ui.clear_console()
    ui.center_print("🔓 RELEASE EVALUATOR CONSENSUS")
    ui.center_print("="*45)
    
    # Verify password to release
    re_pass = questionary.password(f"{indent}Verify password to release consensus share:", qmark="?", style=custom_style).ask()
    if re_pass != password:
        print(f"\n{indent}❌ Error: Incorrect password.")
        input(f"\n{indent}Press Enter...")
        return

    print(f"\n{indent}[*] Fetching Tenders for evaluation...")
    req = {"role": "officer", "action": "fetch_tenders"}
    res = network.send_request_raw(req)
    
    if res.get("status") != "success" or not res.get("tenders"):
        print(f"{indent}[!] No tenders found.")
        input(f"\n{indent}Press Enter...")
        return
        
    # List all tenders to see if we are evaluators
    choices = [f"ID: {tid} | {tdata['data']['title']}" for tid, tdata in res["tenders"].items()]
    choices.append("❌ Cancel")
    
    selected = questionary.select(
        f"{indent}Select a Tender to release share for:",
        choices=choices,
        style=custom_style
    ).ask()
    
    if selected == "❌ Cancel": return
    tender_id = selected.split(" |")[0].replace("ID: ", "").strip()
    
    req = {
        "role": "officer", "action": "officer_release_share",
        "tender_id": tender_id, "officer_id": officer_id
    }
    res = network.send_request_raw(req)
    if res.get("status") == "success":
        print(f"\n{indent}✅ {res.get('message')}")
    else:
        print(f"\n{indent}❌ Failed: {res.get('message')}")
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
    bidder_shares = res.get("bidder_shares", [])
    officer_shares = res.get("officer_shares", [])
    
    if not bids:
        print(f"{indent}[!] No bids found for this tender.")
        input(f"\n{indent}Press Enter to return...")
        return
        
    # --- 🏗️  RECONSTRUCT TENDER KEY (Dual-Consensus XOR Wrap) ---
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import serialization

    print(f"{indent}[*] Reconstructing Bidder Component (MK_B)...")
    mk_b = helper.reconstruct_tender_key(bidder_shares)
    
    print(f"{indent}[*] Reconstructing Officer Component (MK_O)...")
    mk_o = helper.reconstruct_tender_key(officer_shares)
    
    if not mk_b or not mk_o:
        print(f"{indent}❌ Error: Failed to reconstruct one of the key components.")
        input(f"\n{indent}Press Enter...")
        return

    # Combine Components: Master_Key = MK_B ^ MK_O
    master_key = bytes(a ^ b for a, b in zip(mk_b, mk_o))

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
        
        print(f"\n{indent}🔗 Block Hash: {bid_hash}")
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

    # --- 👥 SELECT EVALUATORS (Dual Consensus Requirement) ---
    print(f"\n{indent}[*] Fetching available officers for evaluator pool...")
    req_off = {"role": "officer", "action": "fetch_officers"}
    res_off = network.send_request_raw(req_off)
    
    if res_off.get("status") != "success":
        print(f"{indent}❌ Error: Could not fetch officer list.")
        input(f"\n{indent}Press Enter...")
        return
        
    all_officers = res_off.get("officer_list", [])
    # Filter out self
    other_officers = [o for o in all_officers if o != officer_id]
    
    if len(other_officers) < 2:
        print(f"{indent}❌ Error: Not enough registered officers to form an evaluator committee (Need 2 more).")
        input(f"\n{indent}Press Enter...")
        return
        
    evaluators = questionary.checkbox(
        f"{indent}Select at least 2 additional Officers as Evaluators:",
        choices=other_officers,
        style=custom_style
    ).ask()
    
    if not evaluators or len(evaluators) < 2:
        print(f"{indent}❌ Error: You must select at least 2 additional evaluators.")
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
        "public_key": public_key_pem,
        "evaluators": evaluators
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
            confirm_p = questionary.password(f"Confirm Password:", qmark=f"{indent}?", style=custom_style).ask()

            if not all([secret_id, username, password]):
                print(f"\n{indent}❌ Error: All fields are required.")
                input(f"\n{indent}Press Enter...")
                continue

            if password != confirm_p:
                print(f"\n{indent}❌ Error: Passwords do not match.")
                input(f"\n{indent}Press Enter...")
                continue

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