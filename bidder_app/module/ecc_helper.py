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