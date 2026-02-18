# ECC-Implementation-Project" 
## CSePS: Cryptographically Secure Government e-Procurement System

**CSePS** is A mini system that uses ECC cryptography, digital signatures, timestamping, and hashing toguarantee bid integrity, bidder anonymity (until deadline), non-repudiation, and verifiablefairness in a procurement process.



---

## 🏗️ Project Structure

The project follows a **Monorepo** structure to manage the distributed components:

```text
CSePS_Project/
├── shared_lib/          # Core ECC, ZKP, and Time-lock logic
├── server_app/          # Socket Servers (Primary & Backup)
│   └── ledger/          # Tamper-proof JSON/DB storage
├── bidder_app/          # Client app for bidders
│   └── profiles/        # Isolated folders for bidder keys
├── officer_app/         # Admin app for officials
│   └── officer_shares/  # Isolated folders for key shares
├── venv/                # Virtual environment (ignored by Git)
├── requirements.txt     # Python dependencies
└── README.md            # Project documentation

```

## Implementation Instructions :

### Clone and Navigate
```cmd

git clone [https://github.com/Cyber-Mjolnir/ECC-Implementation-Project.git](https://github.com/Cyber-Mjolnir/ECC-Implementation-Project.git)

cd ECC-Implementation-Project


```

### Set Up Virtual Environment

```cmd
python -m venv venv
venv\Scripts\activate
```

### install Dependencies

```cmd
pip install -r requirements.txt
```
