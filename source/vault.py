import secrets
import hmac
import hashlib
from source.config import VAULT_SIZE, KEY_SIZE_BITS
from source.utils import xor_bytes

class SecureVault:
    def __init__(self, n=VAULT_SIZE, m_bits=KEY_SIZE_BITS, existing_keys=None):
        """
        Initialize the secure vault.
        n: number of keys in the vault
        m_bits: size of each key
        """
        self.n = n
        self.m_bytes = m_bits // 8
        if existing_keys:
            self.keys = existing_keys
        else:
            # Randomly generate n keys of m bits each
            self.keys = [secrets.token_bytes(self.m_bytes) for _ in range(n)]

    def get_derived_key(self, indices):
        """
        Generates a key by performing XOR operation on all keys whose indices are in the challenge set.
        """
        derived_key = bytes(self.m_bytes)
        for idx in indices:
            derived_key = xor_bytes(derived_key, self.keys[idx])
        return derived_key
    
    def update_vault(self, exchanged_data):
        """
        Updates vault after session using HMAC.
        New Vault = HMAC(Current Vault, Data) XOR Partitions
        """
        current_vault_bytes = b''.join(self.keys)
        # HMAC Key is the data exchanged in the session
        h = hmac.new(exchanged_data, current_vault_bytes, hashlib.sha256).digest()
        
        new_keys = []
        for i, key in enumerate(self.keys):
            # Extend hash to match key length and XOR
            h_extended = (h * (len(key) // len(h) + 1))[:len(key)]
            new_keys.append(xor_bytes(key, h_extended))
            
        self.keys = new_keys
        print(f"[Vault] Update completed.")