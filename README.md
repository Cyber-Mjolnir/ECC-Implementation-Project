# ECC-Implementation-Project" 
## CSePS: Cryptographically Secure Government e-Procurement System

**CSePS** is a distributed, high-security e-tendering system designed to ensure fairness, transparency, and data integrity in government procurement. This project addresses the **CIA Triad** (Confidentiality, Integrity, and Availability) using advanced cryptographic primitives.

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
