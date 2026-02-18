import os
import sys
import time
import questionary

import module.configuration as cfg
import module.style as style
import module.networkCommunication as network
import module.uiCMD as ui
import module.setup_bidder_profile as setup
import module.ecc_helper as ecc

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
        mode = "SIGN UP" if 'Create' in choice else "LOGIN"
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
        
        if not username or not password:
            print(f"\n{indent}[!] Error: Fields cannot be empty.")
            time.sleep(1.5)
            return

        action = "signup" if 'Create' in choice else "login"
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
            
        else:
            ui.clear_console()
            ui.center_print(f"!!! NOTICE: {choice.upper()} IS LOCKED !!!")
            ui.center_print("="*45)
            ui.center_print("Reason: Cryptographic signing logic pending.")
            ui.center_print("="*45)
            input(f"\n{indent}Press Enter to return to dashboard...")

if __name__ == "__main__":
    if not os.path.exists("bidder_app/profiles"):
        os.makedirs("bidder_app/profiles")
        
    while True:
        main_menu()