# CSePS: Cryptographically Secure Government e-Procurement System

**CSePS** (Centralized Secure e-Procurement System) is a secure, distributed e-procurement prototype designed to ensure bidder anonymity, bid integrity, and non-repudiation. It leverages Elliptic Curve Cryptography (ECC), digital signatures, timestamping, and Zero-Knowledge Proofs (ZKP) to guarantee a verifiable and fair procurement process.

---

## 🚀 Key Features

*   **ECC & ECIES Security:** All network traffic and sensitive data are protected using Elliptic Curve Integrated Encryption Scheme (ECIES) with the `SECP256k1` curve.
*   **Dual-Consensus Decryption:** Bids can only be opened if >50% of bidders and >= 2/3 of the assigned officer committee release their decryption shares (Shamir's Secret Sharing).
*   **Zero-Knowledge Proofs (ZKP):** Bidders can prove their bid is within a valid range without revealing the actual amount until the deadline.
*   **Data Integrity Locking:** Sensitive JSON databases are protected by HMAC signatures and a secret System Pepper to prevent manual tampering.
*   **MITM Simulation:** Includes a dedicated proxy tool to demonstrate that intercepted network traffic remains encrypted and unreadable.
*   **Admin Accountability:** Signed invitation system for officer tokens, ensuring all administrative actions are traceable.

---

## 🏗️ Project Structure

```text
ECC-Implementation-Project/
├── bidder_app/          # Client app for bidders (Main: main_bidder.py)
│   └── profiles/        # Local storage for bidder keys and bids
├── officer_app/         # Admin/Officer app (Main: main_officer.py)
│   └── profiles/        # Local storage for officer/admin keys
├── server_app/          # Socket Servers (Primary & Backup)
│   ├── primary_server.py # Main server logic and ledger management
│   ├── backup_server.py  # Standby server for redundancy
│   └── ledger/          # Secure JSON-based storage for bids, tenders, etc.
├── traffic_monitor/     # Security demonstration tools
│   ├── mitm_proxy.py    # Intercepts and logs encrypted traffic
│   └── monitor.py       # Traffic analysis tool
├── module/              # Core shared modules (ECC, ZKP, UI, Network)
├── requirements.txt     # Python dependencies
└── run_*.bat            # Batch files for easy execution
```

---

## 🛡️ Security Stack

*   **Asymmetric Encryption:** ECC (SECP256k1) / ECIES
*   **Threshold Cryptography:** Shamir's Secret Sharing (2-of-3 Officers + 50% Bidders)
*   **Integrity:** HMAC-SHA256 with Secret Pepper
*   **Privacy:** Zero-Knowledge Proofs (Range Proofs)
*   **Immutability:** Blockchain-linked Hash Ledger

---

## 🛠️ Installation & Setup

### 1. Clone the Repository
Open your terminal (Command Prompt or PowerShell) and run:
```cmd
git clone https://github.com/Cyber-Mjolnir/ECC-Implementation-Project.git
cd ECC-Implementation-Project
```

### 2. Create a Virtual Environment
It is recommended to use a virtual environment to manage dependencies:
```cmd
python -m venv venv
```

### 3. Activate the Virtual Environment
*   **Windows:**
    ```cmd
    venv\Scripts\activate
    ```
*   **Linux/macOS:**
    ```bash
    source venv/bin/activate
    ```

### 4. Install Dependencies
Install the required Python packages:
```cmd
pip install -r requirements.txt
```

---

## 🚦 How to Run the System

The project includes several batch (`.bat`) files to simplify the startup process. Run them in the following order:

1.  **Start the Primary Server:**
    Run `run_primary_server.bat`. This starts the main server on port 3000.
2.  **Start the Backup Server (Optional):**
    Run `run_backup_server.bat` for redundancy.
3.  **Start the MITM Proxy (Optional):**
    Run `run_mitm_proxy.bat` if you want to monitor and intercept encrypted traffic on port 3001.
4.  **Launch the Officer Application:**
    Run `run_officer_app.bat` to manage tenders, officers, and evaluate bids.
5.  **Launch the Bidder Application:**
    Run `run_bidder_app.bat` to register as a bidder and submit secure bids.

---

## 📝 Usage Notes
*   Ensure the **Primary Server** is running before launching any client applications.
*   All data stored in `server_app/ledger/` is integrity-protected; manual edits will cause verification failures.
*   Private keys are stored locally in the `profiles/` directories of the respective apps. **Do not share these keys.**
