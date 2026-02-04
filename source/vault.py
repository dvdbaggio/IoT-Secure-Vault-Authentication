import secrets
from config import VAULT_SIZE, KEY_SIZE_BITS
from utils import xor_bytes

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