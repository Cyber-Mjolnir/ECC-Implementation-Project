import hashlib
import random
import json

class ZKPEngine:
    """
    Simulates a Zero-Knowledge Proof (ZKP) for range verification.
    In a production system, this would use Bulletproofs or zk-SNARKs.
    Here we use a cryptographic commitment scheme (Pedersen-like) to 
    prove the bid is within a valid range without revealing the exact amount.
    """
    def __init__(self):
        pass

    def generate_range_proof(self, bid_amount, min_val, max_val):
        """
        Generates a commitment and a 'proof' that bid_amount is in [min_val, max_val].
        """
        if not (min_val <= bid_amount <= max_val):
            raise ValueError("Bid amount is outside the valid range!")
            
        # 1. Generate a random blinding factor (nonce)
        blinding_factor = str(random.getrandbits(256))
        
        # 2. Create a cryptographic commitment: Hash(amount + nonce)
        commitment_payload = f"{bid_amount}:{blinding_factor}".encode()
        commitment = hashlib.sha256(commitment_payload).hexdigest()
        
        # 3. Simulate the 'proof' generation
        # A real ZKP would generate mathematical proof here.
        # We simulate it by creating a signature-like hash of the range parameters.
        proof_payload = f"{commitment}:{min_val}:{max_val}".encode()
        proof = hashlib.sha256(proof_payload).hexdigest()
        
        return {
            "commitment": commitment,
            "proof": proof,
            "min_val": min_val,
            "max_val": max_val,
            "blinding_factor": blinding_factor # Stored locally by bidder
        }

    def verify_range_proof(self, proof_data):
        """
        Verifies the ZKP. The server runs this without knowing the bid_amount.
        """
        commitment = proof_data.get("commitment")
        proof = proof_data.get("proof")
        min_val = proof_data.get("min_val")
        max_val = proof_data.get("max_val")
        
        if not all([commitment, proof, min_val, max_val]):
            return False
            
        # Re-calculate the expected proof
        expected_proof_payload = f"{commitment}:{min_val}:{max_val}".encode()
        expected_proof = hashlib.sha256(expected_proof_payload).hexdigest()
        
        return proof == expected_proof
