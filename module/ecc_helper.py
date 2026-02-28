import os
from ecdsa import SigningKey, SECP256k1
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

class ECCHelper:
    def __init__(self):
        # Using SECP256k1 (Bitcoin/Ethereum standard)
        self.curve = SECP256k1

    def generate_and_save_keys(self, profile_path, password):
        """
        Generates ECC keys and saves the private key ENCRYPTED 
        using standard PKCS#8 encryption via the cryptography library.
        """
        try:
            # 1. Generate Private Key using ecdsa
            sk = SigningKey.generate(curve=self.curve)
            vk = sk.verifying_key

            priv_path = os.path.join(profile_path, "private_key.pem")
            pub_path = os.path.join(profile_path, "public_key.pem")

            # 2. Convert ecdsa key to cryptography-compatible object
            # This allows us to use high-level encryption features
            priv_num = sk.privkey.secret_multiplier
            crypto_priv_key = ec.derive_private_key(priv_num, ec.SECP256K1())

            # 3. Serialize and Encrypt Private Key (AES-256)
            priv_pem = crypto_priv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
            )

            # 4. Serialize Public Key (Public keys are not encrypted)
            pub_pem = vk.to_pem()

            # 5. Write to files
            with open(priv_path, "wb") as f:
                f.write(priv_pem)
            with open(pub_path, "wb") as f:
                f.write(pub_pem)

            return True, "Keys generated and safely encrypted with AES-256."
        except Exception as e:
            return False, f"Encryption failed: {str(e)}"

    def load_private_key(self, profile_path, password):
        """
        Loads and decrypts the private key using the session password.
        """
        priv_path = os.path.join(profile_path, "private_key.pem")
        try:
            with open(priv_path, "rb") as f:
                pem_data = f.read()
            
            # Decrypt the PEM data
            return serialization.load_pem_private_key(
                pem_data,
                password=password.encode()
            )
        except Exception:
            return None

    def sign_data(self, private_key, data):
        """Signs data using the provided ECC private key."""
        from cryptography.hazmat.primitives import hashes
        signature = private_key.sign(
            data.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        return signature.hex()

    def verify_signature(self, public_key_pem, data, signature_hex):
        """Verifies an ECC signature using the public key PEM."""
        from cryptography.hazmat.primitives import hashes
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            public_key.verify(
                bytes.fromhex(signature_hex),
                data.encode(),
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception:
            return False

    def generate_data_hash(self, data_dict):
        """Generates a SHA-256 hash of a dictionary for auditing."""
        import hashlib
        import json
        # Ensure keys are sorted for a consistent hash
        data_json = json.dumps(data_dict, sort_keys=True)
        return hashlib.sha256(data_json.encode()).hexdigest()

    def encrypt_data(self, public_key_pem, plaintext_bytes):
        """Encrypts data using ECIES (ECDH + AES-GCM) for a given public key."""
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives import hashes
        import secrets

        recipient_public_key = serialization.load_pem_public_key(public_key_pem.encode())
        
        # 1. Generate Ephemeral Key
        ephemeral_private_key = ec.generate_private_key(ec.SECP256K1())
        ephemeral_public_key = ephemeral_private_key.public_key()
        
        # 2. Perform ECDH
        shared_key = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)
        
        # 3. Derive AES Key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)
        
        # 4. Encrypt with AES-GCM
        aesgcm = AESGCM(derived_key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
        
        # 5. Return (Ephemeral Public Key PEM, Nonce, Ciphertext)
        eph_pub_pem = ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        import base64
        return {
            "eph_pub": eph_pub_pem.decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
        }

    def decrypt_data(self, private_key, encrypted_payload):
        """Decrypts ECIES (ECDH + AES-GCM) data using the recipient's private key."""
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives import hashes
        import base64

        eph_pub_pem = encrypted_payload["eph_pub"].encode('utf-8')
        nonce = base64.b64decode(encrypted_payload["nonce"])
        ciphertext = base64.b64decode(encrypted_payload["ciphertext"])

        ephemeral_public_key = serialization.load_pem_public_key(eph_pub_pem)

        # 1. Perform ECDH
        shared_key = private_key.exchange(ec.ECDH(), ephemeral_public_key)

        # 2. Derive AES Key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)

        # 3. Decrypt with AES-GCM
        aesgcm = AESGCM(derived_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext
        except Exception:
            return None

    def split_tender_key(self, private_key_bytes, n, k):
        """Splits a key into N shares with a threshold of K using Shamir's Secret Sharing."""
        from Crypto.Protocol.SecretSharing import Shamir
        import base64
        
        # Split the raw private key bytes
        shares = Shamir.split(k, n, private_key_bytes)
        
        # Format shares as base64 for JSON storage
        formatted_shares = []
        for index, share in shares:
            formatted_shares.append({
                "index": index,
                "data": base64.b64encode(share).decode('utf-8')
            })
        return formatted_shares

    def reconstruct_tender_key(self, share_dicts):
        """Reconstructs the key from a list of share dictionaries."""
        from Crypto.Protocol.SecretSharing import Shamir
        import base64
        
        shares = []
        for s in share_dicts:
            shares.append((s["index"], base64.b64decode(s["data"])))
            
        try:
            return Shamir.combine(shares)
        except Exception:
            return None